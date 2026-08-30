#!/usr/bin/env node
'use strict';
/**
 * Search for a vanity address with vanitygen, verify it with our own
 * arithmetic, and record it.
 *
 *   node scripts/vanity.js 1Btc
 *   node scripts/vanity.js --icase 1sat 1btc
 *   node scripts/vanity.js --regex '^1[Bb]tc.*[0-9]$'
 *
 * Nothing reaches the database on vanitygen's say-so: src/vanitygen.js
 * re-derives every reported key with src/keys.js and refuses anything the two
 * implementations disagree about. See the comment at the top of that file.
 */
const { pool, check } = require('../src/db');
const vg = require('../src/vanitygen');
const { difficulty } = require('../src/vanity-range');

function usage(msg) {
  if (msg) console.error(`\n${msg}`);
  console.error(`
usage: node scripts/vanity.js [options] <pattern>...

  --regex           patterns are regular expressions, not prefixes
  --icase           case-insensitive prefix match
  --keep            keep searching after a pattern is found
  --max <n>         stop after n matches (default 100 with --keep)
  --threads <n>     worker threads (default: one per CPU)
  --timeout <s>     give up after <s> seconds
  --no-store        print matches, do not write to the database
  --quiet           no progress line

A prefix must start with "1" and use only Base58 characters (no 0 O I l).
Each extra character costs roughly 58x more work, so 5-6 is a few seconds and
8+ is a serious wait -- the difficulty is printed before the search starts.
`);
  process.exit(msg ? 2 : 0);
}

function parseArgs(argv) {
  const o = { patterns: [], mode: 'prefix', keep: false, store: true, quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--regex':    o.mode = 'regex'; break;
      case '--icase':    o.mode = 'prefix-ci'; break;
      case '--keep':     o.keep = true; break;
      case '--no-store': o.store = false; break;
      case '--quiet':    o.quiet = true; break;
      case '--max':      o.maxMatches = Number(argv[++i]); break;
      case '--threads':  o.threads = Number(argv[++i]); break;
      case '--timeout':  o.timeoutMs = Number(argv[++i]) * 1000; break;
      case '-h': case '--help': usage();
      default:
        if (a.startsWith('-')) usage(`unknown option: ${a}`);
        o.patterns.push(a);
    }
  }
  if (!o.patterns.length) usage('no pattern given');
  if (o.threads !== undefined && !(o.threads > 0)) usage('--threads needs a positive number');
  if (o.timeoutMs !== undefined && !(o.timeoutMs > 0)) usage('--timeout needs a positive number');
  if (o.maxMatches !== undefined && !(o.maxMatches > 0)) usage('--max needs a positive number');
  // Without --keep each pattern is retired once it hits, so the count is
  // already bounded by the number of patterns. With --keep it is not bounded by
  // anything, and an easy pattern will bury the process -- so cap it.
  if (o.maxMatches === undefined) o.maxMatches = o.keep ? 100 : o.patterns.length;
  return o;
}

/** Store a verified match. The file vanitygen wrote is already the durable copy. */
async function store(rec, { difficulty, seconds }) {
  const k = rec.key;
  const res = await pool.query(
    `INSERT INTO vanity_matches
       (pattern, match_mode, address, private_key_hex, wif_uncompressed,
        wif_compressed, public_key_uncompressed, difficulty, seconds)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     ON CONFLICT (private_key_hex) DO NOTHING
     RETURNING id`,
    [rec.pattern, rec.mode, rec.address, k.privateKeyHex, k.wifUncompressed,
     k.wifCompressed, k.publicKeyUncompressed, difficulty, seconds]);
  return res.rows[0] ? res.rows[0].id : null;
}

const commas = (n) => n.toLocaleString('en-US');

/**
 * Rough wall-clock estimate.
 *
 * vanitygen searches ONE address per key -- the uncompressed one -- so its key
 * rate and its address rate are the same number. (The GPU engine checks both
 * encodings, so there they differ by 2x; every rate printed says which it is.)
 */
const ADDR_PER_SEC = 2.36e6;   // measured: 2.36 Mkey/s on 32 threads of a 9950X

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

  // Cost first, so an 8-character prefix does not quietly turn into an
  // overnight job. This spawns a simulate-only vanitygen per pattern.
  let total = 0;
  for (const p of opt.patterns) {
    // Ours, not vanitygen's: exact, and no process spawn. A regex has no
    // range, so there is nothing to compute for it.
    const d = opt.mode === 'regex' ? null : Number(difficulty(p));
    if (d === null) { console.log(`  ${p}  (regex -- difficulty not computable)`); continue; }
    total += d;
    const e = eta(d);
    console.log(`  ${p}`);
    console.log(`    difficulty   ${fmtDifficulty(d)}`);
    console.log(`    estimate     ${e.time} on the CPU at ~2.4M addr/s`);
    if (e.scale) console.log(`    for scale    ${e.scale}`);
    console.log(`    note         the GPU engine is ~215x faster: npm run gpu`);
  }
  if (opt.patterns.length > 1) console.log(`  total difficulty ${commas(total)}`);
  console.log(`\nsearching (${opt.mode})... results also appended to ${vg.VANITY_FILE}\n`);

  const started = Date.now();
  const stored = [];
  let lastProgress = 0;

  const handle = vg.run({
    patterns: opt.patterns,
    mode: opt.mode,
    keep: opt.keep,
    threads: opt.threads,
    maxMatches: opt.maxMatches,
    timeoutMs: opt.timeoutMs,
    onMatch: (rec) => {
      const secs = (Date.now() - started) / 1000;
      console.log(`\nFOUND  ${rec.address}`);
      console.log(`  pattern   ${rec.pattern}`);
      console.log(`  privkey   ${rec.key.wifUncompressed}`);
      console.log(`  verified  src/keys.js re-derived the same address`);
      console.log(`  after     ${secs.toFixed(1)}s`);
      stored.push({ rec, secs });
    },
    onProgress: (d) => {
      // Same reason as gpu-vanity.js: \r only makes sense on a terminal.
      if (opt.quiet || !process.stdout.isTTY) return;
      // vanitygen redraws its own progress with \r; pass the last one through
      // at a readable rate rather than every update.
      const now = Date.now();
      if (now - lastProgress < 1000) return;
      const m = d.match(/\[([\d.]+ [KM]?key\/s)\][^\r\n]*/g);
      if (m) { process.stdout.write(`\r  ${m[m.length - 1]}   `); lastProgress = now; }
    },
  });

  process.on('SIGINT', () => { console.log('\nstopping...'); handle.stop(); });

  let result;
  try {
    result = await handle.done;
  } catch (e) {
    // A verification failure lands here. It is a bug in the toolchain, not a
    // missed match, so say so plainly and exit non-zero.
    console.error(`\n\nVERIFICATION FAILED\n${e.message}`);
    console.error('\nThe key vanitygen produced does not derive the address it reported.');
    console.error('Do not use it. Re-run ./scripts/build-vanitygen.sh and npm run test:vanity.');
    await pool.end();
    process.exit(1);
  }

  if (!opt.quiet && process.stdout.isTTY) process.stdout.write('\r' + ' '.repeat(40) + '\r');

  if (opt.store && stored.length) {
    for (const { rec, secs } of stored) {
      const id = await store(rec, { difficulty: result.difficulty, seconds: secs });
      console.log(id ? `  stored as vanity_matches id ${id}` : '  already in vanity_matches');
    }
  } else if (stored.length) {
    console.log('  --no-store: nothing written to the database');
  }

  if (result.timedOut) console.log(`\ntimed out after ${opt.timeoutMs / 1000}s with ${stored.length} match(es)`);
  else if (result.hitMax) console.log(`\nstopped at the --max limit of ${opt.maxMatches} match(es)`);
  else console.log(`\ndone: ${stored.length} match(es) in ${((Date.now() - started) / 1000).toFixed(1)}s`);

  await pool.end();
}

main().catch((e) => {
  console.error(e instanceof vg.VanitygenError ? `\n${e.message}` : e);
  process.exit(1);
});
