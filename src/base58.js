'use strict';
const { checksum } = require('./hash');

// Satoshi's alphabet: no 0, O, I or l, so the characters can't be confused.
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE = 58n;
const INDEX = new Map([...ALPHABET].map((c, i) => [c, BigInt(i)]));

function encode(buf) {
  let num = buf.length ? BigInt('0x' + buf.toString('hex')) : 0n;
  let out = '';
  while (num > 0n) {
    out = ALPHABET[Number(num % BASE)] + out;
    num /= BASE;
  }
  // Each leading zero byte is preserved as a literal '1'. This is why every
  // mainnet P2PKH address -- version byte 0x00 -- begins with a 1.
  for (const byte of buf) {
    if (byte !== 0) break;
    out = '1' + out;
  }
  return out;
}

function decode(str) {
  let num = 0n;
  for (const ch of str) {
    const val = INDEX.get(ch);
    if (val === undefined) throw new Error(`invalid base58 character: ${ch}`);
    num = num * BASE + val;
  }
  let hex = num.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const body = num === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex');
  let leading = 0;
  for (const ch of str) {
    if (ch !== '1') break;
    leading++;
  }
  return Buffer.concat([Buffer.alloc(leading), body]);
}

/** Append the 4-byte SHA256d checksum, then Base58-encode. */
const encodeCheck = (payload) => encode(Buffer.concat([payload, checksum(payload)]));

function decodeCheck(str) {
  const buf = decode(str);
  if (buf.length < 5) throw new Error('base58check payload too short');
  const payload = buf.subarray(0, -4);
  const found = buf.subarray(-4);
  if (!found.equals(checksum(payload))) throw new Error('bad base58check checksum');
  return payload;
}

module.exports = { ALPHABET, encode, decode, encodeCheck, decodeCheck };
