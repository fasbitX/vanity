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
const { deriveKeyPair } = require('../src/keys');

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

  // The same trap that cost an hour of confused benchmarking: another process
  // on the card halves everything silently. It does not make these checks
  // wrong, but it does make the timeouts tighter than they look.
  const busy = gv.gpuTenants();
  if (busy.length) {
    console.log(`\n  NOTE: ${busy.length} other process(es) are using the GPU ` +
                `(${busy.map((t) => t.pid).join(', ')}).`);
    console.log('        The card is shared, so these checks run slower than usual.');
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

  // --- the endomorphism ------------------------------------------------------
  //
  // The kernel searches six related points per curve step -- P, -P, and the two
  // endomorphism images of each -- because they cost a field multiply rather
  // than an inversion. It reports which one matched and the host turns that
  // back into a private key. If that mapping is wrong the kernel still finds
  // things; it just reports keys that do not own the addresses found, which is
  // the worst failure this program has. So each of the six is exercised
  // separately, against a published key.

  console.log('\nGPU, each endomorphism variant');

  for (let v = 0; v < 6; v++) {
    await checkAsync(`variant ${v} is found and attributed to the right key`, async () => {
      const expectKey = gv.variantKey(BigInt('0x' + WIKI.privHex), v);
      const expect = deriveKeyPair(expectKey);
      // Search for the address this variant produces, and plant the BASE key.
      // The kernel only ever walks to the base point; everything else has to
      // come out of the endomorphism.
      const prefix = expect.addressUncompressed.slice(0, 8);
      const r = await runPlanted(prefix, WIKI.privHex, 60000);

      const hit = r.found.find((m) => m.address === expect.addressUncompressed);
      assert.ok(hit, `variant ${v}: ${expect.addressUncompressed} was not found ` +
                     `(got ${r.found.length} other matches)`);
      assert.strictEqual(hit.key.privateKeyHex, expect.privateKeyHex,
        `variant ${v}: reported a key that does not own the address`);
      assert.strictEqual(hit.variant, v, `variant ${v}: attributed to variant ${hit.variant}`);
    });
  }

  await checkAsync('the six variants really are six different addresses', async () => {
    // If two variants collided the speed-up would be a lie -- twelve addresses
    // per curve step is only worth anything if they are distinct.
    const seen = new Set();
    for (let v = 0; v < 6; v++) {
      const d = deriveKeyPair(gv.variantKey(BigInt('0x' + WIKI.privHex), v));
      seen.add(d.addressUncompressed);
      seen.add(d.addressCompressed);
    }
    assert.strictEqual(seen.size, 12, `expected 12 distinct addresses, got ${seen.size}`);
  });

  // --- many patterns at once -------------------------------------------------

  console.log('\nGPU, several patterns in one run');

  await checkAsync('finds each of several prefixes, and attributes them right', async () => {
    // Sorting the ranges to allow bisection permutes them, so the range index
    // the kernel reports no longer lines up with the order the prefixes were
    // given. If that mapping slipped, matches would come back labelled with
    // somebody else's pattern.
    const prefixes = ['1Btcz', '1Satz', '1zzQ'];
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gpu-vanity-multi-'));
    try {
      const start = path.join(dir, 'start.bin');
      const ranges = path.join(dir, 'ranges.bin');
      buildSeeds(56 * 256, start);
      gv.writeRanges(prefixes, ranges);
      const { found } = await gv.runWith({
        prefixes, startFile: start, rangeFile: ranges,
        blocks: 56, threads: 256, maxMatches: 12, timeoutMs: 120000, resultFile: null,
      }).done;

      assert.ok(found.length > 0, 'no matches for three easy prefixes');
      for (const m of found) {
        assert.ok(prefixes.includes(m.prefix), `unknown prefix ${m.prefix}`);
        assert.ok(m.address.startsWith(m.prefix),
          `${m.address} was reported for ${m.prefix}, which it does not start with`);
      }
      // and each prefix should turn up, given twelve matches over three easy ones
      const seen = new Set(found.map((m) => m.prefix));
      assert.ok(seen.size >= 2, `only ${seen.size} of 3 prefixes matched in 12 hits`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  await checkAsync('nested prefixes still match, on the linear path', async () => {
    // "1Btcz" contains "1Btczz", so the ranges overlap and bisection would be
    // wrong -- the host must have told the kernel to scan linearly. The outer
    // prefix has to keep matching addresses that are not in the inner one.
    const prefixes = ['1Btcz', '1Btczz'];
    assert.strictEqual(gv.buildRanges(prefixes).disjoint, false,
      'these prefixes were expected to overlap');

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gpu-vanity-nest-'));
    try {
      const start = path.join(dir, 'start.bin');
      const ranges = path.join(dir, 'ranges.bin');
      buildSeeds(56 * 256, start);
      gv.writeRanges(prefixes, ranges);
      const { found } = await gv.runWith({
        prefixes, startFile: start, rangeFile: ranges,
        blocks: 56, threads: 256, maxMatches: 20, timeoutMs: 120000, resultFile: null,
      }).done;

      assert.ok(found.length > 0, 'no matches for nested prefixes');
      for (const m of found) {
        assert.ok(m.address.startsWith(m.prefix),
          `${m.address} reported for ${m.prefix}`);
      }
      // The outer prefix is ~58x commoner, so plain "1Btcz" hits must appear;
      // if bisection had been used they would have been swallowed.
      assert.ok(found.some((m) => !m.address.startsWith('1Btczz')),
        'only inner-prefix matches came back -- the outer range was being skipped');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
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
