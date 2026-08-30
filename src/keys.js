'use strict';
/**
 * The original Bitcoin key pipeline, end to end:
 *
 *   32 random bytes  ->  private key (a number 1..n-1)
 *          |  k * G on secp256k1
 *          v
 *     public key  ->  SHA256  ->  RIPEMD160  ->  20-byte hash160
 *          |  prepend version byte 0x00, append SHA256d checksum
 *          v
 *     Base58Check  ->  address beginning with "1"
 */
const crypto = require('crypto');
const { N, derivePublicPoint, isOnCurve } = require('./secp256k1');
const { hash160 } = require('./hash');
const base58 = require('./base58');

const VERSION_P2PKH = 0x00; // mainnet pay-to-pubkey-hash -> "1..."
const VERSION_WIF = 0x80;   // mainnet private key export

const toHex32 = (n) => n.toString(16).padStart(64, '0');

/**
 * A private key is just a uniformly random integer in [1, n-1].
 *
 * Draw 32 bytes from the OS CSPRNG and reject anything outside the range.
 * Rejection keeps the distribution exactly uniform -- reducing mod n would
 * bias the low end. The reject probability is about 2^-128, so in practice
 * this loop never runs twice.
 */
function generatePrivateKey() {
  for (;;) {
    const k = BigInt('0x' + crypto.randomBytes(32).toString('hex'));
    if (k >= 1n && k < N) return k;
  }
}

/** Serialize a curve point in both of Bitcoin's public key encodings. */
function serializePublicKey({ x, y }) {
  const xb = Buffer.from(toHex32(x), 'hex');
  const yb = Buffer.from(toHex32(y), 'hex');
  return {
    // 65 bytes: 0x04 || x || y. The only format Bitcoin had in 2009.
    uncompressed: Buffer.concat([Buffer.from([0x04]), xb, yb]),
    // 33 bytes: parity prefix || x. y is recovered from the curve equation.
    compressed: Buffer.concat([Buffer.from([y % 2n === 0n ? 0x02 : 0x03]), xb]),
  };
}

/** hash160 the public key, prefix the version byte, Base58Check it. */
function publicKeyToAddress(pubkey, version = VERSION_P2PKH) {
  const payload = Buffer.concat([Buffer.from([version]), hash160(pubkey)]);
  return base58.encodeCheck(payload);
}

/** Wallet Import Format: the private key in a checksummed, portable form. */
function toWIF(k, compressed) {
  const parts = [Buffer.from([VERSION_WIF]), Buffer.from(toHex32(k), 'hex')];
  // The trailing 0x01 tells a wallet to derive the compressed pubkey.
  if (compressed) parts.push(Buffer.from([0x01]));
  return base58.encodeCheck(Buffer.concat(parts));
}

function fromWIF(wif) {
  const payload = base58.decodeCheck(wif);
  if (payload[0] !== VERSION_WIF) throw new Error('not a mainnet WIF');
  if (payload.length === 34) {
    if (payload[33] !== 0x01) throw new Error('bad WIF compression flag');
    return { key: BigInt('0x' + payload.subarray(1, 33).toString('hex')), compressed: true };
  }
  if (payload.length !== 33) throw new Error('bad WIF length');
  return { key: BigInt('0x' + payload.subarray(1).toString('hex')), compressed: false };
}

/** Run one private key all the way through to both address forms. */
function deriveKeyPair(k) {
  const point = derivePublicPoint(k);
  if (!isOnCurve(point)) throw new Error('derived point is not on the curve');
  const pub = serializePublicKey(point);
  return {
    privateKeyHex: toHex32(k),
    wifUncompressed: toWIF(k, false),
    wifCompressed: toWIF(k, true),
    publicKeyUncompressed: pub.uncompressed.toString('hex'),
    publicKeyCompressed: pub.compressed.toString('hex'),
    addressUncompressed: publicKeyToAddress(pub.uncompressed),
    addressCompressed: publicKeyToAddress(pub.compressed),
  };
}

/** Generate a fresh random key pair. */
const generateKeyPair = () => deriveKeyPair(generatePrivateKey());

/** Verify an address is well formed and its checksum holds. */
function validateAddress(address) {
  try {
    const payload = base58.decodeCheck(address);
    return payload.length === 21 && payload[0] === VERSION_P2PKH;
  } catch {
    return false;
  }
}

module.exports = {
  VERSION_P2PKH, VERSION_WIF, generatePrivateKey, serializePublicKey,
  publicKeyToAddress, toWIF, fromWIF, deriveKeyPair, generateKeyPair, validateAddress,
};
