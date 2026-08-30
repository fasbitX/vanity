'use strict';
/**
 * Drives cuda/gpu-vanity, and checks everything it reports.
 *
 * The kernel tests a *widened* range (see src/vanity-range.js: the checksum is
 * shifted off, which rounds both bounds outward), and it never computes a
 * Base58 address at all. So a HIT line is a candidate, in exactly the sense a
 * Bloom hit is a candidate in the funded-address hunt: it is confirmed here by
 * re-deriving the key with src/keys.js and looking at the actual address.
 *
 * That confirmation is not a formality. It is the only thing standing between
 * a bug in 200 lines of hand-written CUDA field arithmetic and a private key
 * being reported as valuable.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, execFileSync } = require('child_process');
const { deriveKeyPair } = require('./keys');
const { N } = require('./secp256k1');

/**
 * secp256k1's endomorphism, host side.
 *
 * The kernel searches six related points per curve step, because each is nearly
 * free once the first is known: lambda*P is (beta*x, y) for one field multiply,
 * and -P is (x, -y) for a subtraction. It reports which one matched; this turns
 * that back into a private key.
 *
 * lambda is a cube root of 1 modulo the group order, so lambda^3 == 1 and the
 * six keys below are k, -k, lambda*k, -lambda*k, lambda^2*k and -lambda^2*k,
 * all modulo n. Nothing rests on this being right: confirm() re-derives the
 * address from whichever key comes out and compares it to the one the kernel
 * matched, so a wrong variant fails loudly rather than producing a bad key.
 */
const LAMBDA = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72n;
const VARIANTS = 6;

function variantKey(k, variant) {
  const neg = (v) => (v === 0n ? 0n : N - v);
  switch (variant) {
    case 0: return k;
    case 1: return neg(k);
    case 2: return (LAMBDA * k) % N;
    case 3: return neg((LAMBDA * k) % N);
    case 4: return (LAMBDA * LAMBDA % N * k) % N;
    case 5: return neg((LAMBDA * LAMBDA % N * k) % N);
    default: throw new GpuVanityError(`kernel reported unknown variant ${variant}`);
  }
}
const { hash160Bounds, difficulty } = require('./vanity-range');
const { matchesPattern } = require('./vanitygen');

const ROOT = path.join(__dirname, '..');
const BIN = process.env.GPU_VANITY_BIN || path.join(ROOT, 'cuda', 'gpu-vanity');
const VANITY_FILE = process.env.VANITY_FILE || path.join(ROOT, 'VANITY.txt');

class GpuVanityError extends Error {}

/**
 * Other processes already computing on the GPU.
 *
 * Two searches on one card do not queue, they interleave, and each gets about
 * half the rate with no indication that anything is wrong. That is genuinely
 * confusing: the run looks healthy, the number is just quietly halved, and it
 * is easy to blame the change you were about to measure. Worth a warning.
 *
 * Returns [] if nvidia-smi is missing or unhappy -- this is a courtesy, not
 * something to fail a search over.
 */
function gpuTenants() {
  let out;
  try {
    out = execFileSync('nvidia-smi',
      ['--query-compute-apps=pid,process_name,used_memory', '--format=csv,noheader'],
      { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    return [];
  }
  return out.split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [pid, name, memory] = l.split(',').map((x) => x.trim());
      return { pid: Number(pid), name, memory };
    })
    // Our own kernel has not been spawned yet when this is called, so anything
    // listed belongs to somebody else.
    .filter((t) => Number.isFinite(t.pid) && t.pid !== process.pid);
}

/** Five big-endian words back to one number, for sorting and overlap checks. */
const wordsToBig = (w) => Array.from(w).reduce((a, x) => (a << 32n) | BigInt(x), 0n);

/**
 * The ranges the kernel will hold, in the order it will hold them.
 *
 * Sorted by lower bound, so the kernel can bisect instead of walking every
 * range for every address. That matters once there is more than one pattern:
 * the test costs 0.9% of the run for a single prefix and 14% for sixteen,
 * because a linear scan is O(ranges) per address and there are 12 addresses per
 * curve step.
 *
 * Bisection is only valid if the ranges are disjoint, and they are not always:
 * "1Btc" and "1Btcoin" nest, since every 1Btcoin address is also a 1Btc
 * address. Overlap is detected here and the kernel is told to fall back to the
 * linear scan, which is correct for any arrangement.
 */
function buildRanges(prefixes) {
  const rows = [];
  prefixes.forEach((p, pi) => {
    for (const b of hash160Bounds(p)) {
      rows.push({ lo: b.lo, hi: b.hi, owner: pi, loN: wordsToBig(b.lo), hiN: wordsToBig(b.hi) });
    }
  });
  rows.sort((a, b) => (a.loN < b.loN ? -1 : a.loN > b.loN ? 1 : 0));

  let disjoint = true;
  for (let i = 1; i < rows.length; i++) {
    if (rows[i].loN <= rows[i - 1].hiN) { disjoint = false; break; }
  }
  return { rows, owners: rows.map((r) => r.owner), disjoint };
}

/**
 * Which prefix each range index belongs to. The kernel reports a range number;
 * a caller wants the pattern. Must agree with the order writeRanges() wrote.
 */
function rangeOwners(prefixes) {
  return buildRanges(prefixes).owners;
}

/**
 * Ranges file: uint32 count, uint32 flags (bit 0 = sorted and disjoint, so the
 * kernel may bisect), then per range five big-endian lo words and five hi words.
 */
function writeRanges(prefixes, file) {
  const { rows, owners, disjoint } = buildRanges(prefixes);
  if (rows.length === 0) throw new GpuVanityError('no searchable ranges');
  if (rows.length > 32) {
    throw new GpuVanityError(
      `${prefixes.length} prefixes need ${rows.length} ranges; the kernel holds 32`);
  }
  const buf = Buffer.alloc(8 + rows.length * 40);
  buf.writeUInt32LE(rows.length, 0);
  buf.writeUInt32LE(disjoint ? 1 : 0, 4);
  rows.forEach((r, i) => {
    const off = 8 + i * 40;
    for (let w = 0; w < 5; w++) buf.writeUInt32LE(r.lo[w], off + w * 4);
    for (let w = 0; w < 5; w++) buf.writeUInt32LE(r.hi[w], off + 20 + w * 4);
  });
  fs.writeFileSync(file, buf);
  return owners;
}

/**
 * Confirm one candidate. Returns the derived key pair, or throws.
 *
 * `form` says which of the two addresses the kernel matched -- a key produces a
 * different address in each encoding, and only one of them may carry the prefix.
 */
function confirm({ privHex, form, h160, prefix, mode = 'prefix', variant = 0 }) {
  const base = BigInt('0x' + privHex);
  if (base <= 0n) throw new GpuVanityError('kernel reported a zero private key');
  const k = variantKey(base, Number(variant));
  if (k <= 0n || k >= N) {
    throw new GpuVanityError(`variant ${variant} of ${privHex} is outside the curve order`);
  }
  const derived = deriveKeyPair(k);
  const address = form === 'compressed' ? derived.addressCompressed : derived.addressUncompressed;

  // The GPU's own hash160 must agree with ours. This is the check that catches
  // a broken field or hash kernel, as opposed to a merely-too-wide range.
  const ourH160 = require('./hash')
    .hash160(Buffer.from(form === 'compressed'
      ? derived.publicKeyCompressed : derived.publicKeyUncompressed, 'hex'))
    .toString('hex');
  if (ourH160 !== h160) {
    throw new GpuVanityError(
      'hash160 mismatch -- the GPU and src/keys.js disagree for the same key\n' +
      `  private key  ${derived.privateKeyHex}\n` +
      `  gpu          ${h160}\n` +
      `  src/keys.js  ${ourH160}`);
  }

  return { key: derived, address, form, prefix, mode, variant: Number(variant) };
}

/**
 * Run a search.
 *
 * `onMatch` only ever sees confirmed matches. `onNear` sees candidates the
 * widened range admitted but the real address does not satisfy -- expected, and
 * worth counting, because a flood of them would mean the range math is wrong.
 */
function run({ prefixes, blocks, threads = 256, ...rest } = {}) {
  if (!Array.isArray(prefixes) || prefixes.length === 0) {
    throw new GpuVanityError('at least one prefix is required');
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gpu-vanity-'));
  const rangeFile = path.join(tmp, 'ranges.bin');
  const startFile = path.join(tmp, 'start.bin');
  writeRanges(prefixes, rangeFile);

  // Fresh random seeds every run. A fixed seed file would make two searches
  // for the same prefix walk the same keys and return the same address.
  const { buildSeeds } = require('../scripts/seed');
  buildSeeds((blocks || 56) * threads, startFile);

  return runWith({ prefixes, blocks, threads, rangeFile, startFile, cleanupDir: tmp, ...rest });
}

/**
 * The same search against seed and range files a caller has already prepared.
 * Exists so a test can plant a known key at thread 0 and require the GPU to
 * find it -- see test/gpu-vanity.js.
 */
function runWith({
  prefixes,
  rangeFile,
  startFile,
  mode = 'prefix',
  blocks,
  threads = 256,
  groups = 256,
  maxMatches = 1,
  timeoutMs,
  resultFile = VANITY_FILE,
  cleanupDir = null,
  onMatch = () => {},
  onProgress = () => {},
  onNear = () => {},
} = {}) {
  if (!fs.existsSync(BIN)) {
    throw new GpuVanityError(`gpu-vanity is not built at ${BIN}\n  run: npm run gpu:build`);
  }
  const owner = rangeOwners(prefixes);

  const args = ['--ranges', rangeFile, '--start', startFile,
                '--threads', String(threads), '--groups', String(groups)];
  if (blocks) args.push('--blocks', String(blocks));

  const child = spawn(BIN, args, { stdio: ['ignore', 'pipe', 'pipe'] });

  const found = [];
  const errors = [];
  let near = 0, overflow = 0, keys = 0, stopping = false;
  let buf = '';

  const stop = () => {
    if (stopping) return;
    stopping = true;
    child.kill('SIGTERM');
  };

  const line = (l) => {
    if (l.startsWith('PROGRESS ')) { keys = Number(l.slice(9)); onProgress(keys); return; }
    if (l.startsWith('OVERFLOW ')) { overflow += Number(l.slice(9)); return; }
    if (!l.startsWith('HIT ')) return;
    if (stopping) return;

    const [, privHex, form, h160, rangeIdx, variant] = l.split(/\s+/);
    const prefix = prefixes[owner[Number(rangeIdx)]];
    let rec;
    try {
      rec = confirm({ privHex, form, h160, prefix, mode, variant: Number(variant || 0) });
    } catch (e) {
      errors.push(e);
      return stop();
    }
    // The widened range admits a couple of hash160 values per bound whose real
    // checksum puts the address just outside the prefix. Not an error.
    if (!matchesPattern(rec.address, prefix, mode)) { near++; onNear(rec); return; }

    // Durable copy first, database second -- same order as MATCHES.txt.
    if (resultFile) {
      fs.appendFileSync(resultFile,
        `Pattern: ${prefix}\nAddress: ${rec.address}\nPrivkey: ` +
        `${form === 'compressed' ? rec.key.wifCompressed : rec.key.wifUncompressed}\n`);
    }
    found.push(rec);
    onMatch(rec);
    if (found.length >= maxMatches) stop();
  };

  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (d) => {
    buf += d;
    const parts = buf.split('\n');
    buf = parts.pop();
    for (const l of parts) line(l.trim());
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (d) => onProgress(null, d));

  let timer = null, timedOut = false;
  if (timeoutMs) timer = setTimeout(() => { timedOut = true; stop(); }, timeoutMs);

  const done = new Promise((resolve, reject) => {
    child.on('error', (e) => {
      if (timer) clearTimeout(timer);
      reject(new GpuVanityError(`could not run ${BIN}: ${e.message}`));
    });
    child.on('close', () => {
      if (timer) clearTimeout(timer);
      if (cleanupDir) fs.rmSync(cleanupDir, { recursive: true, force: true });
      if (errors.length) {
        const e = new GpuVanityError(
          `${errors.length} candidate(s) failed confirmation against src/keys.js:\n` +
          errors.map((x) => x.message).join('\n'));
        e.failures = errors;
        return reject(e);
      }
      resolve({ found, keys, near, overflow, timedOut, hitMax: found.length >= maxMatches });
    });
  });

  return { child, done, stop };
}

module.exports = {
  BIN, VANITY_FILE, GpuVanityError, LAMBDA, VARIANTS, gpuTenants,
  run, runWith, confirm, variantKey, writeRanges, rangeOwners, buildRanges, difficulty,
};
