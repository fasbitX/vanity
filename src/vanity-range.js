'use strict';
/**
 * A Base58 prefix, turned into a numeric range the GPU can test.
 *
 * This is what makes GPU vanity search cheap. Matching "does this address start
 * with 1Btc" looks like it needs the address -- Base58Check, which needs a
 * checksum, which needs two more SHA-256s per candidate. It does not. Base58 is
 * positional, so fixing the leading characters fixes the *value* of the 25-byte
 * address number to a contiguous range, and the test collapses to two
 * comparisons.
 *
 * The 25-byte address buffer is
 *
 *     0x00 || hash160 (20 bytes) || checksum (4 bytes)
 *
 * so as a number it is exactly  A = hash160 * 2^32 + checksum.  The checksum
 * only ever occupies the low 32 bits, which means a range on A becomes a range
 * on hash160 by shifting 32 bits off the end -- and the kernel never has to
 * compute a checksum at all. Rounding outward there widens the accepted set by
 * at most one hash160 value at each end; the host re-derives the real address
 * before anything is reported, so a boundary straggler is caught the same way a
 * Bloom false positive is.
 *
 * The ranges themselves are checked against vanitygen, which computes the same
 * quantity independently: its "Difficulty" is 2^192 divided by the total width.
 * See test/vanity-range.js.
 */
const { ALPHABET } = require('./base58');

const B58 = 58n;
/** 25 bytes = 200 bits. Every bound below lives in this space. */
const ADDR_BYTES = 25n;

/** Base58 digit value, or -1. */
function digit(c) {
  const i = ALPHABET.indexOf(c);
  return i;
}

/**
 * The ranges of the 25-byte address number whose Base58 rendering begins with
 * `prefix`. Returns `[{ lo, hi }]` with `lo` inclusive and `hi` exclusive,
 * usually one entry, occasionally two.
 *
 * Two arise because the address number's *digit count* is not fixed: a 25-byte
 * value spans both 34- and 33-digit renderings, and a prefix can be satisfied
 * at either length. vanitygen has the same case -- it returns up to two pairs.
 */
function prefixRanges(prefix) {
  if (typeof prefix !== 'string' || prefix.length === 0) {
    throw new Error('prefix must be a non-empty string');
  }
  if (prefix[0] !== '1') {
    throw new Error(`prefix '${prefix}': a mainnet P2PKH address starts with 1`);
  }
  for (const c of prefix) {
    if (digit(c) < 0) throw new Error(`prefix '${prefix}': '${c}' is not a Base58 character`);
  }

  // Leading "1"s are not digits: they are zero *bytes* in the buffer. The
  // version byte supplies the first one; each additional one demands another
  // zero byte at the front of the hash160, which is why they cost 256 rather
  // than 58.
  let z = 0;
  while (z < prefix.length && prefix[z] === '1') z++;

  // Exactly z leading zero bytes  <=>  256^(24-z) <= A < 256^(25-z).
  const floor = 256n ** (ADDR_BYTES - 1n - BigInt(z));
  const ceilEx = 256n ** (ADDR_BYTES - BigInt(z));

  // A prefix of nothing but "1"s constrains only the leading zero bytes: any
  // value with *at least* that many is a match, so there is no lower bound.
  if (z === prefix.length) return [{ lo: 0n, hi: ceilEx }];

  const rest = prefix.slice(z);          // first character is a non-zero digit
  let v = 0n;
  for (const c of rest) v = v * B58 + BigInt(digit(c));

  // For a rendering of n digits, the prefix pins A to
  //   v * 58^(n-s)  <=  A  <  (v+1) * 58^(n-s)
  // The digit-count constraint 58^(n-1) <= A < 58^n is implied, because the
  // leading character of `rest` is non-zero. Intersect with the byte-length
  // window and keep whatever survives.
  const s = rest.length;
  const out = [];
  for (let n = s; n <= 40; n++) {
    const scale = B58 ** BigInt(n - s);
    const lo = v * scale;
    const hi = (v + 1n) * scale;
    if (lo >= ceilEx) break;             // renderings only get longer from here
    const clo = lo > floor ? lo : floor;
    const chi = hi < ceilEx ? hi : ceilEx;
    if (clo < chi) out.push({ lo: clo, hi: chi });
  }
  return out;
}

/** Total number of 25-byte values that satisfy the prefix. */
function rangeWidth(ranges) {
  return ranges.reduce((t, r) => t + (r.hi - r.lo), 0n);
}

/**
 * Expected keys per match, computed the way vanitygen does it: the whole
 * 2^192 space of 25-byte values with a zero version byte, divided by how many
 * of them match.
 */
function difficulty(prefix) {
  const w = rangeWidth(prefixRanges(prefix));
  if (w === 0n) return Infinity;
  return (1n << 192n) / w;
}

/**
 * The same ranges, expressed on the 20-byte hash160 the kernel actually holds.
 *
 * A = hash160 * 2^32 + checksum, so dropping the low 32 bits maps a range on A
 * onto a range on hash160. Both ends round outward, which can admit a hash160
 * whose real checksum puts it just outside -- at most one value at each end of
 * each range. That is a candidate, not a match, exactly like a Bloom hit.
 *
 * Bounds come back as 5 big-endian uint32 words, `hi` inclusive, because that
 * is what a 160-bit compare in CUDA wants.
 */
function hash160Bounds(prefix) {
  return prefixRanges(prefix).map(({ lo, hi }) => ({
    lo: toWords(lo >> 32n),
    hi: toWords((hi - 1n) >> 32n),
  }));
}

/** A 160-bit value as 5 big-endian uint32 words (word 0 = most significant). */
function toWords(v) {
  if (v < 0n) v = 0n;
  const max = (1n << 160n) - 1n;
  if (v > max) v = max;
  const w = new Uint32Array(5);
  for (let i = 4; i >= 0; i--) { w[i] = Number(v & 0xffffffffn); v >>= 32n; }
  return w;
}

module.exports = { prefixRanges, rangeWidth, difficulty, hash160Bounds, toWords };
