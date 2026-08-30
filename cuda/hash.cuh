// SHA-256 and RIPEMD-160 on device, specialised for the one thing this kernel
// does: hash160 of a serialized public key.
//
// Inputs are fixed-size (33 or 65 bytes into SHA-256, always 32 bytes into
// RIPEMD-160), so padding is built in rather than handled generally.
#pragma once
#include <stdint.h>

// ------------------------------------------------------------- SHA-256 ------

__device__ __constant__ uint32_t SHA_K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA_S0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define SHA_S1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SHA_s0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define SHA_s1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

__device__ __forceinline__ void sha256_block(uint32_t st[8], const uint32_t m[16]) {
  uint32_t w[64];
  #pragma unroll
  for (int i = 0; i < 16; i++) w[i] = m[i];
  #pragma unroll
  for (int i = 16; i < 64; i++)
    w[i] = SHA_s1(w[i-2]) + w[i-7] + SHA_s0(w[i-15]) + w[i-16];

  uint32_t a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
  #pragma unroll
  for (int i = 0; i < 64; i++) {
    uint32_t t1 = h + SHA_S1(e) + ((e & f) ^ (~e & g)) + SHA_K[i] + w[i];
    uint32_t t2 = SHA_S0(a) + ((a & b) ^ (a & c) ^ (b & c));
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }
  st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

/** SHA-256 of `len` bytes (len < 56 or 56..119: one or two blocks). */
__device__ void sha256(const uint8_t *data, int len, uint32_t out[8]) {
  uint32_t st[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  uint8_t buf[128];
  int total = ((len + 9 + 63) / 64) * 64;   // padded length: 64 or 128 here
  #pragma unroll 1
  for (int i = 0; i < total; i++) buf[i] = (i < len) ? data[i] : 0;
  buf[len] = 0x80;
  uint64_t bits = (uint64_t)len * 8;
  #pragma unroll
  for (int i = 0; i < 8; i++) buf[total - 1 - i] = (uint8_t)(bits >> (8 * i));

  for (int b = 0; b < total; b += 64) {
    uint32_t m[16];
    #pragma unroll
    for (int i = 0; i < 16; i++)
      m[i] = ((uint32_t)buf[b+i*4] << 24) | ((uint32_t)buf[b+i*4+1] << 16) |
             ((uint32_t)buf[b+i*4+2] << 8) | (uint32_t)buf[b+i*4+3];
    sha256_block(st, m);
  }
  #pragma unroll
  for (int i = 0; i < 8; i++) out[i] = st[i];
}

// ---------------------------------------------------------- RIPEMD-160 -----

#define ROTL(x,n) (((x) << (n)) | ((x) >> (32 - (n))))
#define RF1(x,y,z) ((x) ^ (y) ^ (z))
#define RF2(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define RF3(x,y,z) (((x) | ~(y)) ^ (z))
#define RF4(x,y,z) (((x) & (z)) | ((y) & ~(z)))
#define RF5(x,y,z) ((x) ^ ((y) | ~(z)))

__device__ __constant__ uint8_t RL[80] = {
0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
__device__ __constant__ uint8_t RR[80] = {
5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};
__device__ __constant__ uint8_t SL[80] = {
11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};
__device__ __constant__ uint8_t SR[80] = {
8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};
__device__ __constant__ uint32_t KL[5] = {0x00000000,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e};
__device__ __constant__ uint32_t KR[5] = {0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0x00000000};

/** RIPEMD-160 of exactly 32 bytes (one padded block). */
__device__ void ripemd160_32(const uint8_t *data, uint8_t out[20]) {
  uint32_t X[16];
  #pragma unroll
  for (int i = 0; i < 8; i++)
    X[i] = (uint32_t)data[i*4] | ((uint32_t)data[i*4+1] << 8) |
           ((uint32_t)data[i*4+2] << 16) | ((uint32_t)data[i*4+3] << 24);
  X[8] = 0x00000080;   // 0x80 padding byte right after 32 bytes
  #pragma unroll
  for (int i = 9; i < 14; i++) X[i] = 0;
  X[14] = 256;         // bit length, little-endian
  X[15] = 0;

  uint32_t h0=0x67452301,h1=0xefcdab89,h2=0x98badcfe,h3=0x10325476,h4=0xc3d2e1f0;
  uint32_t al=h0,bl=h1,cl=h2,dl=h3,el=h4;
  uint32_t ar=h0,br=h1,cr=h2,dr=h3,er=h4;

  #pragma unroll
  for (int j = 0; j < 80; j++) {
    int r = j / 16;
    uint32_t t;
    // left line
    switch (r) {
      case 0: t = RF1(bl,cl,dl); break; case 1: t = RF2(bl,cl,dl); break;
      case 2: t = RF3(bl,cl,dl); break; case 3: t = RF4(bl,cl,dl); break;
      default: t = RF5(bl,cl,dl);
    }
    t = ROTL(al + t + X[RL[j]] + KL[r], SL[j]) + el;
    al = el; el = dl; dl = ROTL(cl, 10); cl = bl; bl = t;
    // right line
    switch (r) {
      case 0: t = RF5(br,cr,dr); break; case 1: t = RF4(br,cr,dr); break;
      case 2: t = RF3(br,cr,dr); break; case 3: t = RF2(br,cr,dr); break;
      default: t = RF1(br,cr,dr);
    }
    t = ROTL(ar + t + X[RR[j]] + KR[r], SR[j]) + er;
    ar = er; er = dr; dr = ROTL(cr, 10); cr = br; br = t;
  }

  uint32_t o0 = h1 + cl + dr, o1 = h2 + dl + er, o2 = h3 + el + ar,
           o3 = h4 + al + br, o4 = h0 + bl + cr;
  uint32_t o[5] = {o0, o1, o2, o3, o4};
  #pragma unroll
  for (int i = 0; i < 5; i++) {
    out[i*4]   = (uint8_t)(o[i]);
    out[i*4+1] = (uint8_t)(o[i] >> 8);
    out[i*4+2] = (uint8_t)(o[i] >> 16);
    out[i*4+3] = (uint8_t)(o[i] >> 24);
  }
}

/** hash160 = RIPEMD160(SHA256(data)). */
__device__ void hash160(const uint8_t *data, int len, uint8_t out[20]) {
  uint32_t sh[8];
  sha256(data, len, sh);
  uint8_t sb[32];
  #pragma unroll
  for (int i = 0; i < 8; i++) {
    sb[i*4]   = (uint8_t)(sh[i] >> 24);
    sb[i*4+1] = (uint8_t)(sh[i] >> 16);
    sb[i*4+2] = (uint8_t)(sh[i] >> 8);
    sb[i*4+3] = (uint8_t)(sh[i]);
  }
  ripemd160_32(sb, out);
}

/* ------------------------------------------ direct-from-limb hash160 ------ */
//
// The generic path above marshals a point through a byte buffer: limbs ->
// bytes -> words, twice, plus a 128-byte padding copy. That is ~450 byte-level
// operations per key before any actual compression happens.
//
// The coordinates are already 64-bit limbs in registers, and both message
// lengths are fixed (65 and 33 bytes), so the SHA-256 message schedule can be
// built directly with funnel shifts -- 2 operations per word. Padding and
// length are compile-time constants.

/** Big-endian 32-bit words of a field element: w[0] is the most significant. */
__device__ __forceinline__ void fe_be32(const fe &a, uint32_t w[8]) {
#if FIELD32
  // Already 32-bit limbs, just reversed: l[7] is the most significant.
  #pragma unroll
  for (int i = 0; i < 8; i++) w[i] = a.l[7 - i];
#else
  #pragma unroll
  for (int i = 0; i < 4; i++) {
    uint64_t v = a.l[3 - i];
    w[i * 2]     = (uint32_t)(v >> 32);
    w[i * 2 + 1] = (uint32_t)v;
  }
#endif
}

__device__ __forceinline__ uint32_t bswap32_(uint32_t v) {
  return ((v >> 24) & 0xffu) | ((v >> 8) & 0xff00u) |
         ((v << 8) & 0xff0000u) | (v << 24);
}

/** RIPEMD-160 over 8 little-endian words (a SHA-256 digest), no byte buffer. */
/**
 * RIPEMD-160 of one 32-byte input, left as five 32-bit words.
 *
 * Split out from ripemd160_words() so a caller that wants to compare the digest
 * numerically never has to take it apart into bytes and put it back together.
 */
__device__ __forceinline__ void ripemd160_core(const uint32_t in[8], uint32_t o[5]) {
  uint32_t X[16];
  #pragma unroll
  for (int i = 0; i < 8; i++) X[i] = in[i];
  X[8] = 0x00000080;                 // padding right after 32 bytes
  #pragma unroll
  for (int i = 9; i < 14; i++) X[i] = 0;
  X[14] = 256; X[15] = 0;            // bit length, little-endian

  uint32_t h0=0x67452301,h1=0xefcdab89,h2=0x98badcfe,h3=0x10325476,h4=0xc3d2e1f0;
  uint32_t al=h0,bl=h1,cl=h2,dl=h3,el=h4;
  uint32_t ar=h0,br=h1,cr=h2,dr=h3,er=h4;

  #pragma unroll
  for (int j = 0; j < 80; j++) {
    int r = j / 16;
    uint32_t t;
    switch (r) {
      case 0: t = RF1(bl,cl,dl); break; case 1: t = RF2(bl,cl,dl); break;
      case 2: t = RF3(bl,cl,dl); break; case 3: t = RF4(bl,cl,dl); break;
      default: t = RF5(bl,cl,dl);
    }
    t = ROTL(al + t + X[RL[j]] + KL[r], SL[j]) + el;
    al = el; el = dl; dl = ROTL(cl, 10); cl = bl; bl = t;
    switch (r) {
      case 0: t = RF5(br,cr,dr); break; case 1: t = RF4(br,cr,dr); break;
      case 2: t = RF3(br,cr,dr); break; case 3: t = RF2(br,cr,dr); break;
      default: t = RF1(br,cr,dr);
    }
    t = ROTL(ar + t + X[RR[j]] + KR[r], SR[j]) + er;
    ar = er; er = dr; dr = ROTL(cr, 10); cr = br; br = t;
  }

  o[0] = h1 + cl + dr; o[1] = h2 + dl + er; o[2] = h3 + el + ar;
  o[3] = h4 + al + br; o[4] = h0 + bl + cr;
}

/** The same digest as twenty little-endian bytes. */
__device__ __forceinline__ void ripemd160_words(const uint32_t in[8], uint8_t out[20]) {
  uint32_t o[5];
  ripemd160_core(in, o);
  #pragma unroll
  for (int i = 0; i < 5; i++) {
    out[i*4]   = (uint8_t)(o[i]);
    out[i*4+1] = (uint8_t)(o[i] >> 8);
    out[i*4+2] = (uint8_t)(o[i] >> 16);
    out[i*4+3] = (uint8_t)(o[i] >> 24);
  }
}

/** hash160 of a serialized public key, built straight from the coordinates. */
/**
 * hash160 of a point, delivered as five big-endian 32-bit words.
 *
 * The bytes of a hash160 are the RIPEMD state written little-endian, and a
 * numeric comparison wants them big-endian, so the byte form was being built
 * one byte at a time and immediately taken apart again one byte at a time.
 * bswap32 does the whole job in one instruction per word.
 *
 * It also keeps the digest in registers. Handing a `uint8_t[20]` to a function
 * that is not inlined forces the array into local memory, which is off-chip:
 * the kernel was carrying 64 bytes of stack per thread for two digests it only
 * ever wanted to compare.
 */
__device__ __forceinline__ void hash160_point_be(const fe &x, const fe &y,
                                                 bool compressed, uint32_t out[5]) {
  uint32_t st[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  uint32_t x32[8], w[16];
  fe_be32(x, x32);

  if (compressed) {
    // 33 bytes: prefix || x, then padding -- one block.
    uint32_t prefix = (y.l[0] & 1u) ? 0x03u : 0x02u;
    w[0] = (prefix << 24) | (x32[0] >> 8);
    #pragma unroll
    for (int k = 1; k < 8; k++) w[k] = (x32[k-1] << 24) | (x32[k] >> 8);
    w[8] = (x32[7] << 24) | 0x00800000u;
    #pragma unroll
    for (int k = 9; k < 15; k++) w[k] = 0;
    w[15] = 264;                       // 33 bytes in bits
    sha256_block(st, w);
  } else {
    // 65 bytes: 0x04 || x || y -- two blocks, the second almost all padding.
    uint32_t y32[8];
    fe_be32(y, y32);
    w[0] = 0x04000000u | (x32[0] >> 8);
    #pragma unroll
    for (int k = 1; k < 8; k++) w[k] = (x32[k-1] << 24) | (x32[k] >> 8);
    w[8] = (x32[7] << 24) | (y32[0] >> 8);
    #pragma unroll
    for (int k = 9; k < 16; k++) w[k] = (y32[k-9] << 24) | (y32[k-8] >> 8);
    sha256_block(st, w);

#ifndef SKIP_PAD_BLOCK
    w[0] = (y32[7] << 24) | 0x00800000u;   // last y byte, then padding
    #pragma unroll
    for (int k = 1; k < 15; k++) w[k] = 0;
    w[15] = 520;                           // 65 bytes in bits
    sha256_block(st, w);
#endif   // measurement only: skipping this gives a wrong digest, but prices
         // the second block, which carries one data byte and 63 of padding
  }

  // The digest is big-endian words; RIPEMD wants little-endian.
  uint32_t d[8];
  #pragma unroll
  for (int i = 0; i < 8; i++) d[i] = bswap32_(st[i]);
#ifdef SKIP_RIPEMD
  // Measurement only: stop after SHA-256 and consume its output, so the two
  // halves of hash160 can be priced separately.
  #pragma unroll
  for (int i = 0; i < 5; i++) out[i] = d[i];
#else
  uint32_t o[5];
  ripemd160_core(d, o);
  #pragma unroll
  for (int i = 0; i < 5; i++) out[i] = bswap32_(o[i]);
#endif
}

/** The byte form, for callers that want the digest rather than a comparison. */
__device__ __forceinline__ void hash160_point(const fe &x, const fe &y,
                                              bool compressed, uint8_t out[20]) {
  uint32_t w[5];
  hash160_point_be(x, y, compressed, w);
  #pragma unroll
  for (int i = 0; i < 5; i++) {
    out[i*4]   = (uint8_t)(w[i] >> 24);
    out[i*4+1] = (uint8_t)(w[i] >> 16);
    out[i*4+2] = (uint8_t)(w[i] >> 8);
    out[i*4+3] = (uint8_t)(w[i]);
  }
}
