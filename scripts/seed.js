'use strict';
/**
 * Starting points for the GPU.
 *
 * Each thread walks a sequential range, so it needs a random scalar k and the
 * curve point kG to start from -- plus the shared table of 1G..GRP*G the kernel
 * adds against. Both are produced here rather than in CUDA: it happens once per
 * run, and host code with a checked library is much easier to get right.
 *
 * Seeds are random every run. That matters: a fixed seed file would make two
 * searches for the same prefix walk the same keys and return the same address.
 */
const fs = require('fs');
const crypto = require('crypto');
const native = require('secp256k1');

const GRP = 8;   // must match GRP in cuda/vanity.cu

/** A field element as the kernel reads it: 4 little-endian u64 limbs. */
const feBytes = (hex) => {
  const b = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) {
    b.writeBigUInt64LE(BigInt('0x' + hex.slice((3 - i) * 16, (4 - i) * 16)), i * 8);
  }
  return b;
};

/**
 * Write a seed file: the 1G..GRP*G table, a thread count, then a point and a
 * scalar per thread.
 *
 * `plantHex` starts thread 0 at that key minus one, so the kernel's very first
 * step lands on it. Only the tests use it -- that is how a known key is planted
 * and the GPU required to find it.
 */
function buildSeeds(threads, outPath, { plantHex = null, grp = GRP } = {}) {
  const parts = [];

  const xs = [], ys = [];
  for (let i = 1; i <= grp; i++) {
    const k = Buffer.alloc(32); k.writeUInt32BE(i, 28);
    const p = Buffer.from(native.publicKeyCreate(k, false));
    xs.push(feBytes(p.subarray(1, 33).toString('hex')));
    ys.push(feBytes(p.subarray(33).toString('hex')));
  }
  parts.push(Buffer.concat(xs), Buffer.concat(ys));

  const cnt = Buffer.alloc(4); cnt.writeInt32LE(threads); parts.push(cnt);

  const X = [], Y = [], K = [];
  for (let t = 0; t < threads; t++) {
    let k;
    if (plantHex && t === 0) {
      k = Buffer.from((BigInt('0x' + plantHex) - 1n).toString(16).padStart(64, '0'), 'hex');
    } else {
      do { k = crypto.randomBytes(32); } while (!native.privateKeyVerify(k));
    }
    const p = Buffer.from(native.publicKeyCreate(k, false));
    X.push(feBytes(p.subarray(1, 33).toString('hex')));
    Y.push(feBytes(p.subarray(33).toString('hex')));
    K.push(feBytes(k.toString('hex')));
  }
  parts.push(Buffer.concat(X), Buffer.concat(Y), Buffer.concat(K));

  fs.writeFileSync(outPath, Buffer.concat(parts));
  return { threads, out: outPath };
}

module.exports = { buildSeeds, feBytes, GRP };
