#!/usr/bin/env node
'use strict';
/** What has been found. `node scripts/matches.js [pattern]` */
const { pool, check, CONFIG } = require('../src/db');

(async () => {
  await check();
  const filter = process.argv[2];
  const { rows } = await pool.query(
    `SELECT id, pattern, address, form, engine, difficulty, seconds, found_at
       FROM vanity_matches
      ${filter ? 'WHERE pattern = $1' : ''}
      ORDER BY found_at`, filter ? [filter] : []);

  if (!rows.length) {
    console.log(filter ? `no matches for ${filter}` : 'nothing found yet');
    return pool.end();
  }
  console.log(`\n${CONFIG.database} -- ${rows.length} match(es)\n`);
  for (const r of rows) {
    const rate = r.difficulty && r.seconds
      ? `${(r.difficulty / r.seconds / 1e6).toFixed(0)}M/s effective` : '';
    console.log(`  ${r.address}`);
    console.log(`    ${r.pattern}  ${r.engine}  ${r.form}  ` +
                `${r.seconds ? r.seconds.toFixed(1) + 's' : ''}  ${rate}`);
  }
  // Private keys are deliberately not printed: this is the "what have I got"
  // view, and it gets pasted into terminals and screenshots. VANITY.txt and the
  // wif columns have them when they are actually wanted.
  console.log('\nprivate keys are in VANITY.txt and the wif_* columns\n');
  await pool.end();
})().catch((e) => { console.error(e.message); process.exit(1); });
