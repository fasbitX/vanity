'use strict';
const crypto = require('crypto');

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest();
const ripemd160 = (buf) => crypto.createHash('ripemd160').update(buf).digest();

/** HASH160 = RIPEMD160(SHA256(x)) -- how Bitcoin shortens a pubkey to 20 bytes. */
const hash160 = (buf) => ripemd160(sha256(buf));

/** The 4-byte checksum appended by Base58Check: first 4 bytes of SHA256d. */
const checksum = (buf) => sha256(sha256(buf)).subarray(0, 4);

module.exports = { sha256, ripemd160, hash160, checksum };
