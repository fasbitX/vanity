'use strict';
/**
 * The gate on the vanitygen integration.
 *
 * vanitygen is a third-party program, built here from a hand-applied OpenSSL 3
 * port of 2013 source. The only reason to trust anything it prints is that
 * src/keys.js re-derives it independently -- so this test has to prove two
 * separate things:
 *
 *   1. the verifier ACCEPTS a correct key/address pair, and
 *   2. the verifier REJECTS a wrong one.
 *
 * (2) is the half that is easy to skip and worthless to omit. A check that
 * cannot fail proves nothing about the thing it is checking, and this repo has
 * already been bitten once by a detection test that passed with a deliberately
 * broken hash160.
 *
 * Every constant below is a published Bitcoin test vector, never a value this
 * project produced. Otherwise the test only proves the code agrees with itself.
 */
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
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

/** Rejection is the expected outcome; a pass here is the failure. */
const mustReject = (reported, opts, why) => {
  assert.throws(
    () => vg.verifyMatch(reported, opts),
    vg.VanitygenError,
    `verifier accepted ${why} -- it cannot detect a bad result`);
};

// --- published constants -----------------------------------------------------
// k = 1, the generator point. Public knowledge.
const K1 = {
  wif: '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf',
  address: '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm',
  pubkey: '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
          '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
  privhex: '0000000000000000000000000000000000000000000000000000000000000001',
};
// The Bitcoin wiki's "Technical background of version 1 addresses" example.
// A different key, so its address and public key are wrong for K1's WIF.
const WIKI = {
  address: '16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM',
  pubkey: '0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352' +
          '2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6',
};

console.log('\nverifier accepts a correct pair');

check('published k=1 WIF and address verify', () => {
  const d = vg.verifyMatch({ address: K1.address, privkey: K1.wif });
  assert.strictEqual(d.privateKeyHex, K1.privhex);
  assert.strictEqual(d.wifUncompressed, K1.wif);
});

check('the optional -v fields verify too', () => {
  vg.verifyMatch({
    address: K1.address, privkey: K1.wif,
    pubkeyHex: K1.pubkey, privkeyHex: K1.privhex.toUpperCase(),
  });
});

check('a satisfied prefix passes the pattern check', () => {
  vg.verifyMatch({ address: K1.address, privkey: K1.wif }, { pattern: '1EHNa', mode: 'prefix' });
});

check('accepts the minimal hex form vanitygen actually prints', () => {
  // -v prints the private key with BN_bn2hex, which drops leading zero bytes.
  // k=1 comes out as "01", not 64 digits. Comparing the strings literally
  // rejects roughly one key in 256 for a leading zero byte alone -- which is
  // how this was found: a real search failed verification on a good key.
  vg.verifyMatch({ address: K1.address, privkey: K1.wif, privkeyHex: '01' });
  vg.verifyMatch({ address: K1.address, privkey: K1.wif, privkeyHex: '0001' });
});

check('padding does not make the hex check toothless', () => {
  mustReject({ address: K1.address, privkey: K1.wif, privkeyHex: '02' },
             {}, 'a short hex for a different key');
});

console.log('\nverifier rejects a wrong one (mutation checks)');

check('rejects a valid address belonging to a different key', () => {
  // Both values are published; they simply are not each other's.
  mustReject({ address: WIKI.address, privkey: K1.wif }, {}, 'a mismatched address');
});

check('rejects an address with one character changed', () => {
  const broken = K1.address.slice(0, -1) + (K1.address.endsWith('m') ? 'n' : 'm');
  mustReject({ address: broken, privkey: K1.wif }, {}, 'a corrupted address');
});

check('rejects a public key belonging to a different key', () => {
  mustReject({ address: K1.address, privkey: K1.wif, pubkeyHex: WIKI.pubkey },
             {}, 'a mismatched public key');
});

check('rejects a raw private key that disagrees with the WIF', () => {
  const wrong = '0000000000000000000000000000000000000000000000000000000000000002';
  mustReject({ address: K1.address, privkey: K1.wif, privkeyHex: wrong },
             {}, 'a mismatched private key hex');
});

check('rejects an address that does not satisfy its own pattern', () => {
  mustReject({ address: K1.address, privkey: K1.wif }, { pattern: '1Btc', mode: 'prefix' },
             'an address that does not match the pattern');
});

check('rejects a truncated or absent field', () => {
  mustReject({ address: K1.address }, {}, 'a missing private key');
  mustReject({ privkey: K1.wif }, {}, 'a missing address');
});

console.log('\npattern validation');

check('rejects prefixes that cannot occur', () => {
  assert.throws(() => vg.validatePrefix('3Btc'), vg.VanitygenError); // P2SH, not P2PKH
  assert.throws(() => vg.validatePrefix('1B0tc'), vg.VanitygenError); // 0 not in Base58
  assert.throws(() => vg.validatePrefix('1BOtc'), vg.VanitygenError); // O not in Base58
  assert.throws(() => vg.validatePrefix('1BItc'), vg.VanitygenError); // I not in Base58
  assert.throws(() => vg.validatePrefix('1Bltc'), vg.VanitygenError); // l not in Base58
  assert.strictEqual(vg.validatePrefix('1Btc'), '1Btc');
});

console.log('\noutput parsing');

check('picks triples out of progress-interleaved output', () => {
  // vanitygen redraws progress with \r on the same stream as its results.
  const sample =
    '[1.02 Mkey/s][total 26624][Prob 28.8%][50% in 0.0s]        \r' +
    '[1.07 Mkey/s][total 27648][Prob 29.7%][50% in 0.0s]        \r' +
    `\r${' '.repeat(79)}\rPattern: 1EHNa\n` +
    `Pubkey (hex): ${K1.pubkey}\n` +
    `Privkey (hex): ${K1.privhex.toUpperCase()}\n` +
    `Address: ${K1.address}\n` +
    `Privkey: ${K1.wif}\n`;

  const got = [];
  const feed = vg.createParser((m) => got.push(m));
  // Split mid-field to prove the parser survives chunk boundaries.
  for (let i = 0; i < sample.length; i += 7) feed(sample.slice(i, i + 7));

  assert.strictEqual(got.length, 1);
  assert.strictEqual(got[0].address, K1.address);
  assert.strictEqual(got[0].privkey, K1.wif);
  assert.strictEqual(got[0].pattern, '1EHNa');
  assert.strictEqual(got[0].pubkeyHex, K1.pubkey);
  // and the parsed record must survive verification
  vg.verifyMatch(got[0], { pattern: got[0].pattern, mode: 'prefix' });
});

check('an incomplete record is never emitted', () => {
  const got = [];
  const feed = vg.createParser((m) => got.push(m));
  feed(`Pattern: 1EHNa\nAddress: ${K1.address}\n`); // no Privkey line
  assert.strictEqual(got.length, 0, 'emitted a match with no private key');
});

// --- live run ----------------------------------------------------------------

(async () => {
  if (!fs.existsSync(vg.BIN)) {
    console.log('\nlive run\n  SKIP vanitygen is not built (./scripts/build-vanitygen.sh)');
    return summary();
  }

  console.log('\nlive run against the real binary');

  await checkAsync('vanitygen difficulty agrees for a known prefix', async () => {
    // 111 is all zero bytes: exactly 256^2, with no partial leading digit to
    // complicate it, so this one figure is checkable by hand.
    assert.strictEqual(await vg.estimateDifficulty('111'), 65536);
  });

  // keyconv is the other binary the build produces, and its BIGNUM handling was
  // patched too. Nothing else exercises it, so check it against the same
  // published vector: a WIF in, the matching address out.
  await checkAsync('keyconv converts the published k=1 WIF to its address', async () => {
    const kc = path.join(path.dirname(vg.BIN), 'keyconv');
    if (!fs.existsSync(kc)) throw new Error(`keyconv not built at ${kc}`);
    const out = execFileSync(kc, [K1.wif], { encoding: 'utf8' });
    assert.ok(out.includes(`Address: ${K1.address}`),
      `keyconv did not produce ${K1.address}:\n${out}`);
    assert.ok(out.includes(`Privkey: ${K1.wif}`),
      `keyconv did not round-trip the private key:\n${out}`);
  });

  await checkAsync('keyconv rejects a key with a broken checksum', async () => {
    const kc = path.join(path.dirname(vg.BIN), 'keyconv');
    const bad = K1.wif.slice(0, -1) + (K1.wif.endsWith('f') ? 'g' : 'f');
    assert.throws(
      () => execFileSync(kc, [bad], { encoding: 'utf8', stdio: 'pipe' }),
      'keyconv accepted a corrupted WIF');
  });

  const out = path.join(os.tmpdir(), `vanity-test-${process.pid}.txt`);
  await checkAsync('finds and verifies a real match end to end', async () => {
    const { found } = await vg.run({
      patterns: ['1Ab'],
      timeoutMs: 120000,
      resultFile: out,
    }).done;

    assert.ok(found.length >= 1, 'no match found within 120s for a ~4.5M difficulty prefix');
    const m = found[0];
    assert.ok(m.address.startsWith('1Ab'), `address ${m.address} lacks the prefix`);
    // run() only returns verified matches, but assert it independently here so
    // this test fails if that guarantee is ever quietly dropped.
    vg.verifyMatch({ address: m.address, privkey: m.key.wifUncompressed },
                   { pattern: '1Ab', mode: 'prefix' });

    // The durable file is written by vanitygen itself, before we see anything.
    const text = fs.readFileSync(out, 'utf8');
    assert.ok(text.includes(m.address), 'match is missing from the result file');
    assert.ok(text.includes(m.key.wifUncompressed), 'private key is missing from the result file');
  });
  fs.rmSync(out, { force: true });

  await checkAsync('--keep is bounded by maxMatches, exactly', async () => {
    // Without a cap this is a firehose: a difficulty-1330 prefix produces
    // matches far faster than a BigInt scalar multiplication can verify them,
    // the event loop starves, and even the timeout stops firing on time. A 20s
    // run once banked 6,891 rows and took minutes to drain.
    const t0 = Date.now();
    const r = await vg.run({
      patterns: ['1Ab'],
      keep: true,
      maxMatches: 4,
      timeoutMs: 60000,
      resultFile: out,
    }).done;

    assert.strictEqual(r.found.length, 4,
      `maxMatches:4 produced ${r.found.length} matches -- the cap is not exact`);
    assert.ok(r.hitMax, 'run did not report stopping at the cap');
    assert.ok(!r.timedOut, 'run hit the timeout instead of the cap');
    assert.ok(Date.now() - t0 < 30000, 'capped run took far longer than it should');
  });
  fs.rmSync(out, { force: true });

  summary();
})();

function summary() {
  console.log(`\n${passed} checks passed${process.exitCode ? ', SOME FAILED' : ''}\n`);
}
