'use strict';
/**
 * The range maths: a Base58 prefix turned into bounds on a number.
 *
 * This is what makes GPU vanity search possible, and it is the part that can be
 * silently wrong. Get it wrong and the kernel runs at full speed and finds
 * nothing, or finds addresses that do not carry the prefix.
 *
 * Nothing here takes src/vanity-range.js on its own terms. The bounds are
 * checked against Base58 itself -- encode the boundary values and look -- and
 * against vanitygen, which computes the same difficulty by a different route.
 */
const assert = require('assert');
const fs = require('fs');
const crypto = require('crypto');
const b58 = require('../src/base58');
const range = require('../src/vanity-range');
const vg = require('../src/vanitygen');

let passed = 0;
const check = (name, fn) => {
  try { fn(); passed++; console.log(`  ok   ${name}`); }
  catch (e) { console.error(`  FAIL ${name}\n       ${e.message}`); process.exitCode = 1; }
};
const checkAsync = async (name, fn) => {
  try { await fn(); passed++; console.log(`  ok   ${name}`); }
  catch (e) { console.error(`  FAIL ${name}\n       ${e.message}`); process.exitCode = 1; }
};

const encode25 = (A) => b58.encode(Buffer.from(A.toString(16).padStart(50, '0'), 'hex'));
const inAny = (A, rs) => rs.some((r) => A >= r.lo && A < r.hi);

console.log('\nprefix ranges are tight');

check('the bounds are exactly the matching interval', () => {
  for (const p of ['1Btc', '11Bt', '111h', '1z', '1111Q']) {
    const rs = range.prefixRanges(p);
    assert.ok(rs.length >= 1, `${p}: no ranges`);
    for (const r of rs) {
      assert.ok(encode25(r.lo).startsWith(p), `${p}: lo does not match`);
      assert.ok(encode25(r.hi - 1n).startsWith(p), `${p}: hi-1 does not match`);
      // One step outside must miss, unless another range covers it.
      if (!inAny(r.lo - 1n, rs)) {
        assert.ok(!encode25(r.lo - 1n).startsWith(p), `${p}: lo-1 still matches -- not tight`);
      }
      if (!inAny(r.hi, rs)) {
        assert.ok(!encode25(r.hi).startsWith(p), `${p}: hi still matches -- not tight`);
      }
    }
  }
});

check('no match is missed and none is invented', () => {
  // Draw address numbers from the byte window the leading 1s imply, then
  // compare "the encoding starts with the prefix" against "the number is in a
  // range". A disagreement either way is a defect.
  //
  // How often a random draw lands on a match varies enormously between
  // prefixes -- "111h" hits about 1 in 70, "11Bt" about 1 in 25,000 -- so
  // requiring every prefix to produce a hit made this fail at random roughly
  // one run in five. Whether a *particular* prefix produced hits is not the
  // point; whether the sample as a whole exercised the predicate is. So the
  // expected count is computed from the range widths and only asserted where
  // it is high enough to mean something.
  const SAMPLES = 40000;
  let exercised = 0;
  for (const p of ['111h', '11Bt', '1111Q', '1z']) {
    const rs = range.prefixRanges(p);
    let z = 0; while (z < p.length && p[z] === '1') z++;
    const lo = 256n ** BigInt(24 - z), hi = 256n ** BigInt(25 - z);
    const width = rs.reduce((t, r) => t + (r.hi - r.lo), 0n);
    // Expected hits = samples * (matching values / values in the window).
    const expected = SAMPLES * Number((width * 1000000n) / (hi - lo)) / 1e6;

    let hits = 0, invented = 0, missed = 0;
    for (let i = 0; i < SAMPLES; i++) {
      const A = lo + (BigInt('0x' + crypto.randomBytes(24).toString('hex')) % (hi - lo));
      const m = encode25(A).startsWith(p), q = inAny(A, rs);
      if (m && q) hits++; else if (q) invented++; else if (m) missed++;
    }
    assert.strictEqual(invented, 0, `${p}: ${invented} numbers accepted that do not match`);
    assert.strictEqual(missed, 0, `${p}: ${missed} matching numbers not in any range`);
    if (expected >= 10) {
      assert.ok(hits > 0,
        `${p}: expected ~${expected.toFixed(0)} matches in the sample and got none`);
      exercised++;
    }
  }
  // Without this the whole check could pass by never drawing a matching number.
  assert.ok(exercised > 0, 'no prefix had a high enough hit rate to prove anything');
});

check('the sampling check can actually fail', () => {
  // Mutation: double each range and the sampler must notice. It has to be a
  // proportional widening -- these ranges hold ~2^145 values, so adding a few
  // thousand bad ones is invisible to sampling and would make this look like a
  // passing check that never fires.
  const p = '111h';
  const rs = range.prefixRanges(p).map((r) => ({ lo: r.lo, hi: r.hi + (r.hi - r.lo) }));
  let z = 0; while (z < p.length && p[z] === '1') z++;
  const lo = 256n ** BigInt(24 - z), hi = 256n ** BigInt(25 - z);
  let invented = 0;
  for (let i = 0; i < 200000 && !invented; i++) {
    const A = lo + (BigInt('0x' + crypto.randomBytes(24).toString('hex')) % (hi - lo));
    if (inAny(A, rs) && !encode25(A).startsWith(p)) invented++;
  }
  assert.ok(invented > 0, 'a deliberately widened range was not detected');
});

console.log('\nhash160 bounds');

check('dropping the checksum shifts the bounds and nothing else', () => {
  for (const p of ['1Btc', '111h', '1z']) {
    const rs = range.prefixRanges(p);
    const bs = range.hash160Bounds(p);
    assert.strictEqual(bs.length, rs.length);
    const words = (w) => Array.from(w).reduce((a, x) => (a << 32n) | BigInt(x), 0n);
    rs.forEach((r, i) => {
      assert.strictEqual(words(bs[i].lo), r.lo >> 32n, `${p}: lo bound wrong`);
      assert.strictEqual(words(bs[i].hi), (r.hi - 1n) >> 32n, `${p}: hi bound wrong`);
    });
  }
});

(async () => {
  if (fs.existsSync(vg.BIN)) {
    console.log('\nagainst vanitygen');

    await checkAsync('difficulty agrees, including three leading ones', async () => {
      // Three leading "1"s was a real defect in vanitygen: the eight-bit byte
      // window straddles two Base58 rendering lengths, so the matching set is
      // two intervals and it only ever built one. Fixed in vendor/patches --
      // if this fails, the patch did not apply.
      //
      // Compared as doubles above 2^53, because vg_prefix_get_difficulty()
      // returns a C double and rounds there. Ours is exact; that ceiling is
      // vanitygen's reporting, not its ranges.
      for (const p of ['1Btc', '1Sat', '11Bt', '1z', '1BBBB', '11zQ',
                       '111h', '111K', '111Q', '111hh', '1112', '1111Q', '11111h']) {
        const mine = range.difficulty(p);
        const theirs = BigInt(await vg.estimateDifficulty(p));
        if (mine <= (1n << 53n)) {
          assert.strictEqual(mine, theirs, `${p}: ours ${mine}, vanitygen ${theirs}`);
        } else {
          assert.strictEqual(Number(mine), Number(theirs),
            `${p}: ours ${mine}, vanitygen ${theirs} (differ even as doubles)`);
        }
      }
    });

    await checkAsync('difficulty is counted over reachable addresses', async () => {
      // vanitygen divides the 2^192 space of 25-byte values. Only 2^160 of
      // those are addresses anyone can reach -- the checksum is determined by
      // the hash160, not free -- so we divide that instead. For any prefix
      // short enough to search the two agree, which the check above holds us
      // to; the difference only appears once a prefix pins the address to
      // fewer than 2^32 values.
      //
      // A complete address is the extreme case: exactly one key produces it,
      // so the answer is 2^160. Reporting 2^192 there overstated the work by a
      // factor of four billion.
      const whole = '1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo';
      assert.strictEqual(range.difficulty(whole), 1n << 160n,
        'a full address should cost exactly 2^160, one key per address');
      assert.ok(range.difficulty(whole) < (1n << 192n) / 1000000n,
        'still counting the unreachable 25-byte values');

      // and a 33-character prefix is 58x easier than the whole thing
      assert.ok(range.difficulty(whole.slice(0, 33)) < range.difficulty(whole));
    });

    await checkAsync('three leading ones really is two intervals', async () => {
      // The shape of the thing the patch fixes, asserted directly so a
      // regression names itself rather than showing up as a number.
      for (const p of ['111h', '111K', '111hh']) {
        assert.strictEqual(range.prefixRanges(p).length, 2, `${p}: expected two intervals`);
      }
    });
  } else {
    console.log('\nagainst vanitygen\n  SKIP vanitygen is not built (npm run build:vanitygen)');
  }

  console.log(`\n${passed} checks passed${process.exitCode ? ', SOME FAILED' : ''}\n`);
})();
