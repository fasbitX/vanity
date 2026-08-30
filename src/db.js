'use strict';
/**
 * Postgres, on this machine.
 *
 * One pool, one database, always local. There is nothing distributed about
 * vanity search: a run happens here and its results belong here.
 */
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

// Minimal .env loader -- five variables do not justify a dependency.
const envPath = path.join(__dirname, '..', '.env');
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
}

const CONFIG = {
  host: process.env.PGHOST || '127.0.0.1',
  port: Number(process.env.PGPORT || 5432),
  database: process.env.PGDATABASE || 'vanity',
  user: process.env.PGUSER || 'vanity',
  password: process.env.PGPASSWORD,
};

const pool = new Pool({ ...CONFIG, max: 4 });

/**
 * A clearer failure than "password authentication failed" for the one thing
 * that actually goes wrong on a fresh checkout: the database does not exist yet.
 */
async function check() {
  try {
    await pool.query('SELECT 1');
  } catch (e) {
    throw new Error(
      `cannot reach postgres at ${CONFIG.host}:${CONFIG.port}/${CONFIG.database} ` +
      `as ${CONFIG.user}\n  ${e.message}\n` +
      '  first time here?  ./scripts/create-db.sh   then   npm run init-db');
  }
}

module.exports = { pool, check, CONFIG };
