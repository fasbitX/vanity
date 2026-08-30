'use strict';
/** Apply schema.sql. Safe to re-run. */
const fs = require('fs');
const path = require('path');
const { pool, check, CONFIG } = require('../src/db');

(async () => {
  await check();
  await pool.query(fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8'));
  const { rows } = await pool.query(
    "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1");
  console.log(`schema applied to ${CONFIG.database} on ${CONFIG.host}:${CONFIG.port}`);
  console.log(`tables: ${rows.map((r) => r.tablename).join(', ')}`);
  await pool.end();
})().catch((e) => { console.error(e.message); process.exit(1); });
