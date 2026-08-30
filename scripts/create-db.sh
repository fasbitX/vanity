#!/usr/bin/env bash
#
# Create the `vanity` role and database. Run once, on the machine that will
# hold the results. Needs postgres superuser, which is the only step here that
# does.
#
#   ./scripts/create-db.sh              # generates a password, writes .env
#   ./scripts/create-db.sh <password>   # uses the one you give it
#
# Run it as yourself, NOT with sudo -- it calls sudo only for the postgres
# steps. Running the whole thing as root leaves .env owned by root, which then
# fails to open with EACCES.
#
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
db=${PGDATABASE:-vanity}
user=${PGUSER:-vanity}
pass=${1:-$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)}

echo "==> creating role '$user' and database '$db'"
sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
DO \$\$ BEGIN
  CREATE ROLE $user LOGIN PASSWORD '$pass';
EXCEPTION WHEN duplicate_object THEN
  ALTER ROLE $user LOGIN PASSWORD '$pass';
END \$\$;
SQL
# CREATE DATABASE cannot run inside a transaction block, hence the separate call.
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$db'" \
  | grep -q 1 || sudo -u postgres createdb -O "$user" "$db"

if [ -f "$root/.env" ] && grep -q '^PGPASSWORD=' "$root/.env"; then
    echo "==> .env already has PGPASSWORD, leaving it alone"
else
    cat > "$root/.env" <<ENV
# Local postgres. Created by scripts/create-db.sh.
PGHOST=127.0.0.1
PGPORT=5432
PGDATABASE=$db
PGUSER=$user
PGPASSWORD=$pass
ENV
    chmod 600 "$root/.env"
    # If someone ran the whole script under sudo anyway, hand .env back.
    [ -n "${SUDO_USER:-}" ] && chown "$SUDO_USER" "$root/.env"
    echo "==> wrote $root/.env (mode 600)"
fi

echo
echo "done. next:  npm run init-db"
