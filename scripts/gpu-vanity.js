#!/usr/bin/env node
'use strict';
/**
 * Vanity address search on the GPU.
 *
 *   node scripts/gpu-vanity.js 1Btc
 *   node scripts/gpu-vanity.js --max 5 1Satoshi
 *
 * Same job as scripts/vanity.js, ~200x the addresses per second, and it
 * searches both public-key encodings rather than only the uncompressed one.
 *
 * The kernel reports candidates, not matches: its range test is deliberately
 * widened so it never has to compute a checksum, and it never builds a Base58
 * address at all. src/gpu-vanity.js re-derives every candidate with
 * src/keys.js and only a confirmed address gets here.
 */
const { pool, check } = require('../src/db');
const gv = require('../src/gpu-vanity');
const { difficulty, prefixRanges } = require('../src/vanity-range');
const { validatePrefix } = require('../src/vanitygen');

// The kernel checks BOTH the compressed and the uncompressed address of every
// key, so one key is two chances at a match. Difficulty is quoted per address,
// so estimates use the address rate; the live counter reports keys because that
// is what the kernel counts. Every rate printed says which it is -- reporting a
// key rate and an address rate as if they were the same number is confusing,
// and off by exactly 2x.
const ADDR_PER_KEY = 2;
// Measured on this box: 253.8 Mkey/s = 507.6M addresses/s.
const ADDR_PER_SEC = 507.6e6;

function usage(msg) {
  if (msg) console.error(`\n${msg}`);
  console.error(`
usage: node scripts/gpu-vanity.js [options] <prefix>...

  --max <n>         stop after n matches (default 1)
  --timeout <s>     give up after <s> seconds
  --blocks <n>      thread blocks (default 56, one per SM)
  --no-store        print matches, do not write to the database
  --quiet           no progress line

Prefixes only -- the GPU matches a numeric range, which a regular expression is
not. Use scripts/vanity.js for regex search.

Both public-key encodings are searched, so a match may be a compressed address.
`);
  process.exit(msg ? 2 : 0);
}

function parseArgs(argv) {
  const o = { prefixes: [], maxMatches: 1, store: true, quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--max':      o.maxMatches = Number(argv[++i]); break;
      case '--timeout':  o.timeoutMs = Number(argv[++i]) * 1000; break;
      case '--blocks':   o.blocks = Number(argv[++i]); break;
      case '--no-store': o.store = false; break;
      case '--quiet':    o.quiet = true; break;
      case '-h': case '--help': usage();
      default:
        if (a.startsWith('-')) usage(`unknown option: ${a}`);
        o.prefixes.push(a);
    }
  }
  if (!o.prefixes.length) usage('no prefix given');
  if (!(o.maxMatches > 0)) usage('--max needs a positive number');
  o.prefixes.forEach(validatePrefix);
  return o;
}

async function store(rec, { difficulty: d, seconds }) {
  const k = rec.key;
  const res = await pool.query(
    `INSERT INTO vanity_matches
       (pattern, match_mode, address, private_key_hex, wif_uncompressed,
        wif_compressed, public_key_uncompressed, difficulty, seconds, form, engine)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'gpu')
     ON CONFLICT (private_key_hex) DO NOTHING
     RETURNING id`,
    [rec.prefix, rec.mode, rec.address, k.privateKeyHex, k.wifUncompressed,
     k.wifCompressed, k.publicKeyUncompressed, d, seconds, rec.form]);
  return res.rows[0] ? res.rows[0].id : null;
}

const commas = (n) => Number(n).toLocaleString('en-US');

/**
 * Difficulty spans an absurd range -- 22 for "1B", 2^192 for a whole address --
 * so past a point commas stop helping and start hiding the magnitude.
 */
function fmtDifficulty(d) {
  const n = Number(d);
  if (!isFinite(n)) return String(d);
  if (n < 1e15) return Math.round(n).toLocaleString('en-US');
  return n.toExponential(3);
}

function eta(d) {
  // d is per *address*, and the address rate is what the GPU delivers.
  const s = Number(d) / ADDR_PER_SEC;
  if (s < 1) return { time: 'under a second' };
  if (s < 90) return { time: `~${s.toFixed(1)}s` };
  if (s < 5400) return { time: `~${(s / 60).toFixed(1)} min` };
  if (s < 172800) return { time: `~${(s / 3600).toFixed(1)} hours` };
  const days = s / 86400;
  if (days < 730) return { time: `~${days.toFixed(1)} days` };
  const years = days / 365.25;
  if (years < 1e6) return { time: `~${Math.round(years).toLocaleString('en-US')} years` };
  // Past this point the number stops meaning anything on its own, so give it
  // something to lean against: the universe is about 1.38e10 years old.
  return {
    time: `~${years.toExponential(1)} years`,
    scale: `${(years / 1.38e10).toExponential(1)}x the age of the universe`,
  };
}

async function main() {
  await check();
  const opt = parseArgs(process.argv.slice(2));

  let ranges = 0;
  for (const p of opt.prefixes) {
    const d = difficulty(p);
    ranges += prefixRanges(p).length;
    const e = eta(d);
    console.log(`  ${p}`);
    console.log(`    difficulty   ${fmtDifficulty(d)}`);
    console.log(`    estimate     ${e.time} on the GPU`);
    if (e.scale) console.log(`    for scale    ${e.scale}`);
  }
  console.log(`\nsearching ${ranges} range(s), both key encodings ` +
              `(~254M keys/sec = ~507M addresses/sec)\n`);

  const started = Date.now();
  const stored = [];
  let lastDraw = 0;

  const handle = gv.run({
    prefixes: opt.prefixes,
    blocks: opt.blocks,
    maxMatches: opt.maxMatches,
    timeoutMs: opt.timeoutMs,
    onMatch: (rec) => {
      const secs = (Date.now() - started) / 1000;
      console.log(`\nFOUND  ${rec.address}`);
      console.log(`  prefix    ${rec.prefix}`);
      console.log(`  form      ${rec.form}`);
      console.log(`  privkey   ${rec.form === 'compressed' ? rec.key.wifCompressed : rec.key.wifUncompressed}`);
      console.log(`  verified  src/keys.js re-derived the same address`);
      console.log(`  after     ${secs.toFixed(1)}s`);
      stored.push({ rec, secs });
    },
    onProgress: (keys) => {
      // Only redraw on a terminal: \r means nothing in a pipe or a log file,
      // where it would print one line per launch instead of one line total.
      if (opt.quiet || keys === null || !process.stdout.isTTY) return;
      const now = Date.now();
      if (now - lastDraw < 500) return;
      lastDraw = now;
      const rate = keys / ((now - started) / 1000) / 1e6;
      process.stdout.write(
        `\r  ${commas(keys)} keys, ${rate.toFixed(0)} Mkey/s ` +
        `= ${(rate * ADDR_PER_KEY).toFixed(0)}M addr/s   `);
    },
  });

  process.on('SIGINT', () => { console.log('\nstopping...'); handle.stop(); });

  let result;
  try {
    result = await handle.done;
  } catch (e) {
    console.error(`\n\nCONFIRMATION FAILED\n${e.message}`);
    console.error('\nThe GPU reported a key that does not derive the address it should.');
    console.error('Do not use it. Rebuild with npm run gpu:build and run npm run test:gpu:vanity.');
    await pool.end();
    process.exit(1);
  }

  if (!opt.quiet && process.stdout.isTTY) process.stdout.write('\r' + ' '.repeat(50) + '\r');

  if (opt.store && stored.length) {
    for (const { rec, secs } of stored) {
      const id = await store(rec, { difficulty: Number(difficulty(rec.prefix)), seconds: secs });
      console.log(id ? `  stored as vanity_matches id ${id}` : '  already in vanity_matches');
    }
  } else if (stored.length) {
    console.log('  --no-store: nothing written to the database');
  }

  const secs = (Date.now() - started) / 1000;
  console.log(`\n${stored.length} match(es) in ${secs.toFixed(1)}s, ` +
              `${commas(result.keys)} keys = ${commas(result.keys * ADDR_PER_KEY)} addresses ` +
              `(${(result.keys / secs / 1e6).toFixed(0)} Mkey/s = ` +
              `${(result.keys * ADDR_PER_KEY / secs / 1e6).toFixed(0)}M addr/s)`);
  // Candidates the widened range admitted whose real address missed. A handful
  // is normal; a torrent would mean the range math is wrong.
  if (result.near) console.log(`${result.near} boundary candidate(s) rejected on the real address`);
  if (result.timedOut) console.log(`timed out after ${opt.timeoutMs / 1000}s`);

  await pool.end();
}

main().catch((e) => {
  console.error(e instanceof gv.GpuVanityError ? `\n${e.message}` : e);
  process.exit(1);
});
