'use strict';
/**
 * The gate on the CUDA kernel.
 *
 * 200 lines of hand-written field arithmetic, hashing and a 160-bit compare.
 * Get it wrong and it reports private keys that do not derive the address
 * claimed for them -- which is the worst possible failure for this program,
 * because the output looks exactly like success.
 *
 * So: plant a key whose address is a *published constant*, require the GPU to
 * find it, and then require that same test to fail when it should. A detection
 * test that cannot fail proves nothing.
 *
 * The range maths this depends on is checked separately, in test/range.js.
 */
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const gv = require('../src/gpu-vanity');
const { buildSeeds } = require('../scripts/seed');

let passed = 0;
const checkAsync = async (name, fn) => {
  try { await fn(); passed++; console.log(`  ok   ${name}`); }
  catch (e) { console.error(`  FAIL ${name}\n       ${e.message}`); process.exitCode = 1; }
};

// The Bitcoin wiki's worked example: a published key and its published address.
// Nothing in this repo produced either value.
const WIKI = {
  privHex: '18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725',
  address: '16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM',
};

(async () => {
  if (!fs.existsSync(gv.BIN)) {
    console.log('\nGPU\n  SKIP gpu-vanity is not built (npm run build:gpu)');
    return summary();
  }

  console.log('\nGPU, with a planted key');

  await checkAsync('finds a planted key and derives its published address', async () => {
    const prefix = WIKI.address.slice(0, 8);
    const r = await runPlanted(prefix, WIKI.privHex, 40000);
    const hit = r.found.find((m) => m.key.privateKeyHex === WIKI.privHex.padStart(64, '0'));
    assert.ok(hit, `planted key was not reported (found ${r.found.length} other matches)`);
    assert.strictEqual(hit.address, WIKI.address, 'reported the wrong address for the planted key');
    assert.strictEqual(hit.form, 'uncompressed');
  });

  await checkAsync('the planted test can fail: a wrong prefix finds nothing', async () => {
    // Mutation check. If this still "passes", the test above proves nothing --
    // it would be reporting a key it was going to report regardless.
    const bad = '1' + WIKI.address.slice(1, 8).split('').reverse().join('');
    const r = await runPlanted(bad, WIKI.privHex, 4000);
    const hit = r.found.find((m) => m.key.privateKeyHex === WIKI.privHex.padStart(64, '0'));
    assert.ok(!hit, `the planted key was reported for prefix ${bad}, which it does not match`);
  });

  await checkAsync('every reported address really carries the prefix', async () => {
    const r = await runPlanted('1Btc', null, 20000, 25);
    assert.ok(r.found.length > 0, 'no matches at all for an easy prefix -- range math suspect');
    for (const m of r.found) {
      assert.ok(m.address.startsWith('1Btc'), `${m.address} lacks the prefix`);
    }
  });

  summary();
})();

/**
 * One GPU run against a temporary seed file, optionally with a key planted at
 * thread 0. Seeds live in a temp directory and go away with the run.
 */
async function runPlanted(prefix, plantHex, timeoutMs, maxMatches = 1) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gpu-vanity-test-'));
  const start = path.join(dir, 'start.bin');
  const ranges = path.join(dir, 'ranges.bin');
  try {
    const blocks = 56, threads = 256;
    buildSeeds(blocks * threads, start, { plantHex });
    gv.writeRanges([prefix], ranges);
    return await gv.runWith({
      prefixes: [prefix], startFile: start, rangeFile: ranges,
      blocks, threads, maxMatches, timeoutMs, resultFile: null,
    }).done;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function summary() {
  console.log(`\n${passed} checks passed${process.exitCode ? ', SOME FAILED' : ''}\n`);
}
