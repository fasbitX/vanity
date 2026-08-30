'use strict';
/**
 * Known-answer tests. Every expected value here comes from published Bitcoin
 * test vectors, not from this implementation -- otherwise the test only proves
 * the code agrees with itself.
 */
const assert = require('assert');
const { N } = require('../src/secp256k1');
const base58 = require('../src/base58');
const keys = require('../src/keys');

let passed = 0;
const check = (name, fn) => {
  try { fn(); passed++; console.log(`  ok   ${name}`); }
  catch (e) { console.error(`  FAIL ${name}\n       ${e.message}`); process.exitCode = 1; }
};

console.log('\nsecp256k1 / address vectors');

// k = 1 -- the generator point itself. Every field is public knowledge.
check('k=1 derives the generator point and its addresses', () => {
  const r = keys.deriveKeyPair(1n);
  assert.strictEqual(r.publicKeyUncompressed,
    '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
    '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8');
  assert.strictEqual(r.publicKeyCompressed,
    '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  assert.strictEqual(r.addressUncompressed, '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm');
  assert.strictEqual(r.addressCompressed,   '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH');
  assert.strictEqual(r.wifUncompressed, '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf');
  assert.strictEqual(r.wifCompressed,   'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn');
});

// The worked example from the Bitcoin wiki's "Technical background of
// version 1 Bitcoin addresses" page.
check('bitcoin wiki worked example', () => {
  const k = 0x18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725n;
  const r = keys.deriveKeyPair(k);
  assert.strictEqual(r.publicKeyUncompressed,
    '0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352' +
    '2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6');
  assert.strictEqual(r.addressUncompressed, '16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM');
});

check('k=2 doubling matches the published point', () => {
  const r = keys.deriveKeyPair(2n);
  assert.strictEqual(r.publicKeyCompressed,
    '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5');
});

check('k=n-1 is the negation of G', () => {
  const r = keys.deriveKeyPair(N - 1n);
  // Same x as G, opposite y parity, so the compressed prefix flips 02 -> 03.
  assert.strictEqual(r.publicKeyCompressed,
    '0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
});

console.log('\nrange enforcement');

check('rejects k=0 and k=n', () => {
  assert.throws(() => keys.deriveKeyPair(0n), RangeError);
  assert.throws(() => keys.deriveKeyPair(N), RangeError);
});

console.log('\nbase58');

// Vectors from the Bitcoin Core base58 test data.
check('base58 encodes leading zero bytes as 1s', () => {
  assert.strictEqual(base58.encode(Buffer.from('00', 'hex')), '1');
  assert.strictEqual(base58.encode(Buffer.from('0000', 'hex')), '11');
  assert.strictEqual(base58.encode(Buffer.from('000000', 'hex')), '111');
});

check('base58 round-trips arbitrary bytes', () => {
  for (const hex of ['61', '626262', '73696d706c792061206c6f6e6720737472696e67', '00010966776006953d5567439e5e39f86a0d273bee']) {
    const buf = Buffer.from(hex, 'hex');
    assert.strictEqual(base58.decode(base58.encode(buf)).toString('hex'), hex);
  }
});

check('base58check rejects a tampered checksum', () => {
  const addr = keys.deriveKeyPair(1n).addressUncompressed;
  const bad = addr.slice(0, -1) + (addr.endsWith('m') ? 'n' : 'm');
  assert.throws(() => base58.decodeCheck(bad), /checksum/);
  assert.strictEqual(keys.validateAddress(bad), false);
  assert.strictEqual(keys.validateAddress(addr), true);
});

console.log('\nWIF');

check('WIF round-trips both compression flags', () => {
  const k = 0x18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725n;
  assert.deepStrictEqual(keys.fromWIF(keys.toWIF(k, false)), { key: k, compressed: false });
  assert.deepStrictEqual(keys.fromWIF(keys.toWIF(k, true)),  { key: k, compressed: true });
});

check('uncompressed WIF starts with 5, compressed with K or L', () => {
  for (let i = 0; i < 20; i++) {
    const r = keys.generateKeyPair();
    assert.match(r.wifUncompressed, /^5/);
    assert.match(r.wifCompressed, /^[KL]/);
  }
});

console.log('\nrandom key properties');

check('1000 random keys are unique, in range, and all start with 1', () => {
  const seen = new Set();
  for (let i = 0; i < 1000; i++) {
    const r = keys.generateKeyPair();
    const k = BigInt('0x' + r.privateKeyHex);
    assert.ok(k >= 1n && k < N, 'private key out of range');
    assert.strictEqual(r.privateKeyHex.length, 64);
    assert.ok(r.addressUncompressed.startsWith('1'), r.addressUncompressed);
    assert.ok(r.addressCompressed.startsWith('1'), r.addressCompressed);
    assert.ok(keys.validateAddress(r.addressUncompressed));
    assert.ok(keys.validateAddress(r.addressCompressed));
    assert.ok(!seen.has(r.privateKeyHex), 'duplicate private key');
    seen.add(r.privateKeyHex);
  }
});

console.log(`\n${passed} checks passed${process.exitCode ? ' (with failures above)' : ''}\n`);
