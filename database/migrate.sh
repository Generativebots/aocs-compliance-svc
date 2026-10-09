#!/usr/bin/env bash
# =============================================================================
# migrate.sh — AOCS incremental schema migration runner (one per module)
# =============================================================================
# CANONICAL COPY: aocs-system-svc/database/migrate.sh. Every module repo carries
# an identical copy at database/migrate.sh so its CI can run it standalone.
# Keep the copies byte-identical (aocs-system-svc/database/check_migrate_sync.sh).
#
# MODEL
#   database/schema/[0-9]*.sql        Base files. Always the full current state.
#                                     Fresh installs use these only
#                                     (aocs-system-svc/database/install_all.sh).
#   database/schema/migrations/*.sql  Incremental changes for EXISTING databases.
#                                     Every change goes into a migration AND the
#                                     base files in the same commit.
#   public.aocs_schema_migrations     One registry for all modules:
#                                     (module, version) -> sha256, applied_at.
#
# RULES
#   * Name files YYYYMMDD_NN_description.sql; they apply in name order.
#   * A file runs in ONE transaction together with its registry row, so it is
#     either fully applied and recorded, or not at all.
#   * A file whose first line is `-- aocs:no-transaction` runs without a wrapping
#     transaction (needed for CREATE/DROP INDEX CONCURRENTLY). Such files MUST
#     be idempotent (IF [NOT] EXISTS); they are recorded after they succeed.
#   * Editing an applied file is refused (checksum mismatch). Add a new file.
#   * Concurrent runners are serialised with an advisory lock.
#
# USAGE
#   database/migrate.sh [--dry-run|--status|--baseline] [DATABASE_URL]
#     (default)   apply pending files
#     --dry-run   run each pending file inside BEGIN … ROLLBACK and report;
#                 no-transaction files are listed but not executed
#     --status    list files and whether each is applied
#     --baseline  record every file as applied WITHOUT running it. Only for a
#                 database just built from the base files (install_all.sh).
#   AOCS_MODULE overrides the module name (default: repo directory name).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
MIG_DIR="$SCRIPT_DIR/schema/migrations"
MODULE="${AOCS_MODULE:-$(basename "$REPO_DIR")}"

MODE=apply
DB_URL=""
for a in "$@"; do
  case "$a" in
    --dry-run) MODE=dry ;;
    --status) MODE=status ;;
    --baseline) MODE=baseline ;;
    -h|--help) sed -n '2,38p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $a" >&2; exit 2 ;;
    *) DB_URL="$a" ;;
  esac
done
if [[ -z "$DB_URL" ]]; then
  if [[ -n "${DATABASE_URL:-}" ]]; then DB_URL="$DATABASE_URL"
  elif [[ -f "$REPO_DIR/.env" ]]; then DB_URL="$(grep -E '^DATABASE_URL=' "$REPO_DIR/.env" | head -1 | cut -d= -f2-)"
  fi
fi
DB_URL="${DB_URL%\"}"; DB_URL="${DB_URL#\"}"; DB_URL="${DB_URL%\'}"; DB_URL="${DB_URL#\'}"
[[ -n "$DB_URL" ]] || { echo "DATABASE_URL not set (arg, env, or $REPO_DIR/.env)" >&2; exit 1; }
command -v psql >/dev/null || { echo "psql not found" >&2; exit 1; }

export PGOPTIONS="${PGOPTIONS:-} -c client_min_messages=warning"
PSQL=(psql "$DB_URL" -X -q -v ON_ERROR_STOP=1 -v VERBOSITY=terse)
q() { "${PSQL[@]}" -Atc "$1"; }
sha() { shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1 || sha256sum "$1" | cut -d' ' -f1; }
lit() { printf "'%s'" "${1//\'/\'\'}"; }

# Registry (also defined in aocs-system-svc 01_tables.sql; kept here so the
# runner can bootstrap a database that predates it).
"${PSQL[@]}" <<'SQL'
CREATE TABLE IF NOT EXISTS public.aocs_schema_migrations (
    module      TEXT        NOT NULL,
    version     TEXT        NOT NULL,
    checksum    TEXT        NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_by  TEXT        NOT NULL DEFAULT current_user,
    baseline    BOOLEAN     NOT NULL DEFAULT false,
    CONSTRAINT aocs_schema_migrations_pkey PRIMARY KEY (module, version)
);
ALTER TABLE public.aocs_schema_migrations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.aocs_schema_migrations FROM PUBLIC;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL ON public.aocs_schema_migrations FROM anon, authenticated';
  END IF;
END $$;
SQL

shopt -s nullglob
files=()
[[ -d "$MIG_DIR" ]] && files=("$MIG_DIR"/*.sql)
echo "module=$MODULE mode=$MODE files=${#files[@]}"

applied=0; pending=0
for f in ${files[@]+"${files[@]}"}; do
  v="$(basename "$f" .sql)"
  sum="$(sha "$f")"
  have="$(q "SELECT checksum FROM public.aocs_schema_migrations WHERE module=$(lit "$MODULE") AND version=$(lit "$v")")"
  if [[ -n "$have" ]]; then
    if [[ "$have" != "$sum" ]]; then
      echo "FAIL $v: applied with checksum $have but file is now $sum. Applied migrations are immutable; add a new file." >&2
      exit 1
    fi
    [[ "$MODE" == status ]] && echo "  applied  $v"
    continue
  fi
  pending=$((pending+1))
  notx=0; head -1 "$f" | grep -q '^-- aocs:no-transaction' && notx=1
  reg="INSERT INTO public.aocs_schema_migrations(module,version,checksum,baseline) VALUES ($(lit "$MODULE"),$(lit "$v"),$(lit "$sum"),$([[ $MODE == baseline ]] && echo true || echo false))"
  case "$MODE" in
    status) echo "  PENDING  $v$([[ $notx == 1 ]] && echo ' (no-transaction)')" ;;
    baseline) q "$reg" >/dev/null; echo "  baseline $v" ;;
    dry)
      if [[ $notx == 1 ]]; then echo "  skip     $v (no-transaction: cannot dry-run)"; continue; fi
      { echo "BEGIN;"; echo "SELECT pg_advisory_xact_lock(hashtext('aocs_schema_migrations'));"; cat "$f"; echo; echo "ROLLBACK;"; } \
        | "${PSQL[@]}" -f - >/dev/null
      echo "  ok (rolled back) $v" ;;
    apply)
      echo "  apply    $v"
      if [[ $notx == 1 ]]; then
        "${PSQL[@]}" -f "$f" >/dev/null
        q "$reg ON CONFLICT DO NOTHING" >/dev/null
      else
        { echo "BEGIN;"; echo "SELECT pg_advisory_xact_lock(hashtext('aocs_schema_migrations'));"
          echo "SELECT 1/(1-count(*))::int FROM public.aocs_schema_migrations WHERE module=$(lit "$MODULE") AND version=$(lit "$v");"
          cat "$f"; echo; echo "$reg;"; echo "COMMIT;"; } | "${PSQL[@]}" -f - >/dev/null
      fi
      applied=$((applied+1)) ;;
  esac
done
echo "done: pending=$pending applied=$applied"
