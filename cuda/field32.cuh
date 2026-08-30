// secp256k1 field arithmetic on 32-bit limbs.
//
// NVIDIA has no native 64-bit integer multiply -- it is emulated in several
// 32-bit IMADs -- so eight 32-bit limbs can beat four 64-bit ones despite doing
// four times as many partial products.
//
// The reduction also gets cheaper. p = 2^256 - 2^32 - 977, so
// 2^256 == 2^32 + 977 (mod p). In 32-bit words that fold is "shift up one word,
// plus a multiply by the small constant 977" rather than a full-width multiply
// by 0x1000003D1.
#pragma once
#include <stdint.h>

#define C977 977u

typedef struct { uint32_t l[8]; } fe32;   // l[0] least significant

__device__ __constant__ uint32_t P32[8] = {
  0xFFFFFC2Fu, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
  0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu };

__device__ __forceinline__ uint32_t adc32(uint32_t a, uint32_t b, uint32_t *carry) {
  uint32_t s = a + b;
  uint32_t c = (s < a) ? 1u : 0u;
  uint32_t s2 = s + *carry;
  c += (s2 < s) ? 1u : 0u;
  *carry = c;
  return s2;
}

__device__ __forceinline__ uint32_t sbb32(uint32_t a, uint32_t b, uint32_t *borrow) {
  uint32_t d = a - b;
  uint32_t br = (a < b) ? 1u : 0u;
  uint32_t d2 = d - *borrow;
  br += (d < *borrow) ? 1u : 0u;
  *borrow = br;
  return d2;
}

__device__ __forceinline__ bool fe32_is_zero(const fe32 &a) {
  uint32_t o = 0;
  #pragma unroll
  for (int i = 0; i < 8; i++) o |= a.l[i];
  return o == 0;
}

__device__ __forceinline__ bool fe32_eq(const fe32 &a, const fe32 &b) {
  uint32_t d = 0;
  #pragma unroll
  for (int i = 0; i < 8; i++) d |= (a.l[i] ^ b.l[i]);
  return d == 0;
}

__device__ __forceinline__ bool fe32_ge_p(const fe32 &a) {
  #pragma unroll
  for (int i = 7; i >= 0; i--) {
    if (a.l[i] != P32[i]) return a.l[i] > P32[i];
  }
  return true;   // exactly p
}

__device__ __forceinline__ void fe32_normalize(fe32 &a) {
  if (fe32_ge_p(a)) {
    uint32_t br = 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) a.l[i] = sbb32(a.l[i], P32[i], &br);
  }
}

__device__ __forceinline__ void fe32_add(fe32 &r, const fe32 &a, const fe32 &b) {
  uint32_t c = 0;
  #pragma unroll
  for (int i = 0; i < 8; i++) r.l[i] = adc32(a.l[i], b.l[i], &c);
  // Carry out of 2^256 folds back in as 2^32 + 977.
  while (c) {
    uint32_t k = c;
    c = 0;
    uint32_t c2 = 0;
    r.l[0] = adc32(r.l[0], k * C977, &c2);
    r.l[1] = adc32(r.l[1], k, &c2);
    #pragma unroll
    for (int i = 2; i < 8; i++) r.l[i] = adc32(r.l[i], 0, &c2);
    c = c2;
  }
  fe32_normalize(r);
}

__device__ __forceinline__ void fe32_sub(fe32 &r, const fe32 &a, const fe32 &b) {
  uint32_t br = 0;
  #pragma unroll
  for (int i = 0; i < 8; i++) r.l[i] = sbb32(a.l[i], b.l[i], &br);
  if (br) {   // went negative: add p back
    uint32_t c = 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) r.l[i] = adc32(r.l[i], P32[i], &c);
  }
}

/** Reduce a 16-word product modulo p. */
__device__ __forceinline__ void fe32_reduce(fe32 &r, const uint32_t t[16]) {
  // T = lo + hi * 2^256 == lo + (hi << 32) + hi * 977   (mod p)
  uint32_t acc[10];
  #pragma unroll
  for (int i = 0; i < 8; i++) acc[i] = t[i];
  acc[8] = 0; acc[9] = 0;

  // + hi * 977
  uint32_t carry = 0;
  #pragma unroll
  for (int i = 0; i < 8; i++) {
    uint64_t prod = (uint64_t)t[8 + i] * C977 + acc[i] + carry;
    acc[i] = (uint32_t)prod;
    carry = (uint32_t)(prod >> 32);
  }
  acc[8] += carry;

  // + (hi << one word)
  carry = 0;
  #pragma unroll
  for (int i = 0; i < 8; i++) acc[i + 1] = adc32(acc[i + 1], t[8 + i], &carry);
  acc[9] += carry;

  // Fold whatever landed at or above 2^256 (acc[8], acc[9]) back down.
  uint32_t h0 = acc[8], h1 = acc[9];
  acc[8] = 0; acc[9] = 0;
  if (h0 | h1) {
    uint32_t c = 0;
    uint64_t p0 = (uint64_t)h0 * C977 + acc[0];
    acc[0] = (uint32_t)p0;
    uint32_t hi0 = (uint32_t)(p0 >> 32);
    uint64_t p1 = (uint64_t)h1 * C977 + acc[1] + hi0 + h0;
    acc[1] = (uint32_t)p1;
    c = (uint32_t)(p1 >> 32);
    uint32_t c2 = c;
    acc[2] = adc32(acc[2], h1, &c2);
    #pragma unroll
    for (int i = 3; i < 8; i++) acc[i] = adc32(acc[i], 0, &c2);
    // One more tiny fold if that overflowed again.
    if (c2) {
      uint32_t c3 = 0;
      acc[0] = adc32(acc[0], c2 * C977, &c3);
      acc[1] = adc32(acc[1], c2, &c3);
      #pragma unroll
      for (int i = 2; i < 8; i++) acc[i] = adc32(acc[i], 0, &c3);
    }
  }

  #pragma unroll
  for (int i = 0; i < 8; i++) r.l[i] = acc[i];
  fe32_normalize(r);
}

__device__ __forceinline__ void fe32_mul(fe32 &r, const fe32 &a, const fe32 &b) {
  uint32_t t[16];
  #pragma unroll
  for (int i = 0; i < 16; i++) t[i] = 0;

  #pragma unroll
  for (int i = 0; i < 8; i++) {
    uint32_t carry = 0;
    #pragma unroll
    for (int j = 0; j < 8; j++) {
      // 32x32 -> 64 is two native instructions here, versus a multi-instruction
      // emulation for the 64-bit equivalent.
      uint64_t prod = (uint64_t)a.l[i] * b.l[j] + t[i + j] + carry;
      t[i + j] = (uint32_t)prod;
      carry = (uint32_t)(prod >> 32);
    }
    t[i + 8] = carry;
  }
  fe32_reduce(r, t);
}

__device__ __forceinline__ void fe32_sqr(fe32 &r, const fe32 &a) { fe32_mul(r, a, a); }

/** a^(p-2) mod p, same addition chain as the 64-bit build. */
__device__ void fe32_inv(fe32 &r, const fe32 &a) {
  fe32 x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t;
  fe32_sqr(x2, a);   fe32_mul(x2, x2, a);
  fe32_sqr(x3, x2);  fe32_mul(x3, x3, a);

  t = x3;   for (int i = 0; i < 3; i++)  fe32_sqr(t, t); fe32_mul(x6, t, x3);
  t = x6;   for (int i = 0; i < 3; i++)  fe32_sqr(t, t); fe32_mul(x9, t, x3);
  t = x9;   for (int i = 0; i < 2; i++)  fe32_sqr(t, t); fe32_mul(x11, t, x2);
  t = x11;  for (int i = 0; i < 11; i++) fe32_sqr(t, t); fe32_mul(x22, t, x11);
  t = x22;  for (int i = 0; i < 22; i++) fe32_sqr(t, t); fe32_mul(x44, t, x22);
  t = x44;  for (int i = 0; i < 44; i++) fe32_sqr(t, t); fe32_mul(x88, t, x44);
  t = x88;  for (int i = 0; i < 88; i++) fe32_sqr(t, t); fe32_mul(x176, t, x88);
  t = x176; for (int i = 0; i < 44; i++) fe32_sqr(t, t); fe32_mul(x220, t, x44);
  t = x220; for (int i = 0; i < 3; i++)  fe32_sqr(t, t); fe32_mul(x223, t, x3);

  t = x223;
  for (int i = 0; i < 23; i++) fe32_sqr(t, t); fe32_mul(t, t, x22);
  for (int i = 0; i < 5; i++)  fe32_sqr(t, t); fe32_mul(t, t, a);
  for (int i = 0; i < 3; i++)  fe32_sqr(t, t); fe32_mul(t, t, x2);
  for (int i = 0; i < 2; i++)  fe32_sqr(t, t); fe32_mul(r, t, a);
  fe32_normalize(r);
}

/* ------------------------------------------------------------ FIELD32 ---- */
// Selected with -DFIELD32=1. The 64-bit build in field.cuh stays as the
// verification oracle -- both are checked against Python independently.
#if FIELD32
#define fe            fe32
#define fe_add        fe32_add
#define fe_sub        fe32_sub
#define fe_mul        fe32_mul
#define fe_sqr        fe32_sqr
#define fe_inv        fe32_inv
#define fe_normalize  fe32_normalize
#define fe_is_zero    fe32_is_zero
#define fe_eq         fe32_eq
#define FE_LIMBS 8

/** Load from the host's 4x uint64 layout (start.bin, the 1G..8G table). */
__device__ __forceinline__ void fe_from_u64(fe32 &r, const uint64_t s[4]) {
  #pragma unroll
  for (int i = 0; i < 4; i++) { r.l[i*2] = (uint32_t)s[i]; r.l[i*2+1] = (uint32_t)(s[i] >> 32); }
}
__device__ __forceinline__ void fe_to_u64(uint64_t d[4], const fe32 &a) {
  #pragma unroll
  for (int i = 0; i < 4; i++) d[i] = (uint64_t)a.l[i*2] | ((uint64_t)a.l[i*2+1] << 32);
}
__device__ __forceinline__ void fe_set_zero(fe32 &r) {
  #pragma unroll
  for (int i = 0; i < 8; i++) r.l[i] = 0;
}
__device__ __forceinline__ bool fe_is_odd(const fe32 &a) { return a.l[0] & 1u; }
#endif
