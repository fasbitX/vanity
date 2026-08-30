// secp256k1 base-field arithmetic, mod p = 2^256 - 2^32 - 977.
//
// Elements are four 64-bit limbs, little-endian (l[0] least significant).
// Reduction exploits the shape of p: 2^256 == 2^32 + 977 (mod p), so folding a
// 512-bit product back to 256 bits is two short multiply-accumulates rather
// than a division.
//
// Written in plain C rather than inline PTX: nvcc emits add.cc/madc chains for
// this anyway, and hand-written asm here cost more in debugging than it saved.
#pragma once
#include <stdint.h>

typedef struct { uint64_t l[4]; } fe;

__device__ __constant__ uint64_t P[4] = {
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};
#define FOLD 0x1000003D1ULL  // 2^32 + 977

// ----------------------------------------------------------- carry helpers --

// a + b + carry_in, returning the sum and setting carry_out.
__device__ __forceinline__ uint64_t adc(uint64_t a, uint64_t b, uint64_t &carry) {
  uint64_t s = a + b;
  uint64_t c = (s < a) ? 1 : 0;
  uint64_t s2 = s + carry;
  c += (s2 < s) ? 1 : 0;
  carry = c;
  return s2;
}

// a - b - borrow_in, returning the difference and setting borrow_out.
__device__ __forceinline__ uint64_t sbb(uint64_t a, uint64_t b, uint64_t &borrow) {
  uint64_t d = a - b;
  uint64_t br = (a < b) ? 1 : 0;
  uint64_t d2 = d - borrow;
  br += (d < borrow) ? 1 : 0;
  borrow = br;
  return d2;
}

__device__ __forceinline__ void fe_set_zero(fe &r) { r.l[0] = r.l[1] = r.l[2] = r.l[3] = 0; }
__device__ __forceinline__ bool fe_is_zero(const fe &a) { return (a.l[0] | a.l[1] | a.l[2] | a.l[3]) == 0; }
__device__ __forceinline__ bool fe_eq(const fe &a, const fe &b) {
  return a.l[0] == b.l[0] && a.l[1] == b.l[1] && a.l[2] == b.l[2] && a.l[3] == b.l[3];
}

__device__ __forceinline__ bool fe_ge_p(const fe &a) {
  if (a.l[3] != P[3]) return a.l[3] > P[3];
  if (a.l[2] != P[2]) return a.l[2] > P[2];
  if (a.l[1] != P[1]) return a.l[1] > P[1];
  return a.l[0] >= P[0];
}

// Bring a value in [0, 2p) down to [0, p).
__device__ __forceinline__ void fe_normalize(fe &a) {
  if (fe_ge_p(a)) {
    uint64_t br = 0;
    a.l[0] = sbb(a.l[0], P[0], br);
    a.l[1] = sbb(a.l[1], P[1], br);
    a.l[2] = sbb(a.l[2], P[2], br);
    a.l[3] = sbb(a.l[3], P[3], br);
  }
}

// ------------------------------------------------------------ add / sub -----

__device__ __forceinline__ void fe_add(fe &r, const fe &a, const fe &b) {
  uint64_t c = 0;
  r.l[0] = adc(a.l[0], b.l[0], c);
  r.l[1] = adc(a.l[1], b.l[1], c);
  r.l[2] = adc(a.l[2], b.l[2], c);
  r.l[3] = adc(a.l[3], b.l[3], c);
  // Anything past 2^256 folds back in as FOLD.
  if (c) {
    uint64_t c2 = 0;
    r.l[0] = adc(r.l[0], FOLD, c2);
    r.l[1] = adc(r.l[1], 0, c2);
    r.l[2] = adc(r.l[2], 0, c2);
    r.l[3] = adc(r.l[3], 0, c2);
    if (c2) r.l[0] += FOLD;  // cannot cascade further
  }
  fe_normalize(r);
}

__device__ __forceinline__ void fe_sub(fe &r, const fe &a, const fe &b) {
  uint64_t br = 0;
  r.l[0] = sbb(a.l[0], b.l[0], br);
  r.l[1] = sbb(a.l[1], b.l[1], br);
  r.l[2] = sbb(a.l[2], b.l[2], br);
  r.l[3] = sbb(a.l[3], b.l[3], br);
  if (br) {  // went negative: add p back
    uint64_t c = 0;
    r.l[0] = adc(r.l[0], P[0], c);
    r.l[1] = adc(r.l[1], P[1], c);
    r.l[2] = adc(r.l[2], P[2], c);
    r.l[3] = adc(r.l[3], P[3], c);
  }
}

// ----------------------------------------------------------- multiply -------

__device__ __forceinline__ void fe_mul(fe &r, const fe &a, const fe &b) {
  uint64_t t[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  // Schoolbook 4x4 -> 8 limbs.
  #pragma unroll
  for (int i = 0; i < 4; i++) {
    uint64_t carry = 0;
    #pragma unroll
    for (int j = 0; j < 4; j++) {
      uint64_t lo = a.l[i] * b.l[j];
      uint64_t hi = __umul64hi(a.l[i], b.l[j]);
      // t[i+j] += lo + carry, propagating into hi.
      uint64_t c1 = 0;
      uint64_t s = adc(t[i + j], lo, c1);
      uint64_t c2 = 0;
      s = adc(s, carry, c2);
      t[i + j] = s;
      carry = hi + c1 + c2;   // cannot overflow: hi <= 2^64-2
    }
    t[i + 4] += carry;
  }

  // Fold the top 256 bits down: t_hi * 2^256 == t_hi * FOLD (mod p).
  uint64_t acc[5] = {t[0], t[1], t[2], t[3], 0};
  uint64_t carry = 0;
  #pragma unroll
  for (int i = 0; i < 4; i++) {
    uint64_t lo = t[4 + i] * FOLD;
    uint64_t hi = __umul64hi(t[4 + i], FOLD);
    uint64_t c1 = 0;
    uint64_t s = adc(acc[i], lo, c1);
    uint64_t c2 = 0;
    s = adc(s, carry, c2);
    acc[i] = s;
    carry = hi + c1 + c2;
  }
  acc[4] = carry;

  // Second, much smaller fold for whatever spilled past 2^256 again.
  uint64_t lo = acc[4] * FOLD;
  uint64_t hi = __umul64hi(acc[4], FOLD);
  uint64_t c = 0;
  r.l[0] = adc(acc[0], lo, c);
  r.l[1] = adc(acc[1], hi, c);
  r.l[2] = adc(acc[2], 0, c);
  r.l[3] = adc(acc[3], 0, c);
  if (c) {  // one final tiny fold
    uint64_t c2 = 0;
    r.l[0] = adc(r.l[0], FOLD, c2);
    r.l[1] = adc(r.l[1], 0, c2);
    r.l[2] = adc(r.l[2], 0, c2);
    r.l[3] = adc(r.l[3], 0, c2);
  }
  fe_normalize(r);
}

__device__ __forceinline__ void fe_sqr(fe &r, const fe &a) { fe_mul(r, a, a); }

// ------------------------------------------------------------- inverse ------

// a^(p-2) mod p by Fermat. The addition chain is the standard libsecp256k1
// sequence, which is why the step counts look arbitrary.
__device__ void fe_inv(fe &r, const fe &a) {
  fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t;

  fe_sqr(x2, a);  fe_mul(x2, x2, a);          // a^3
  fe_sqr(x3, x2); fe_mul(x3, x3, a);          // a^7

  t = x3;  for (int i = 0; i < 3; i++) fe_sqr(t, t);   fe_mul(x6, t, x3);
  t = x6;  for (int i = 0; i < 3; i++) fe_sqr(t, t);   fe_mul(x9, t, x3);
  t = x9;  for (int i = 0; i < 2; i++) fe_sqr(t, t);   fe_mul(x11, t, x2);
  t = x11; for (int i = 0; i < 11; i++) fe_sqr(t, t);  fe_mul(x22, t, x11);
  t = x22; for (int i = 0; i < 22; i++) fe_sqr(t, t);  fe_mul(x44, t, x22);
  t = x44; for (int i = 0; i < 44; i++) fe_sqr(t, t);  fe_mul(x88, t, x44);
  t = x88; for (int i = 0; i < 88; i++) fe_sqr(t, t);  fe_mul(x176, t, x88);
  t = x176;for (int i = 0; i < 44; i++) fe_sqr(t, t);  fe_mul(x220, t, x44);
  t = x220;for (int i = 0; i < 3; i++) fe_sqr(t, t);   fe_mul(x223, t, x3);

  t = x223;
  for (int i = 0; i < 23; i++) fe_sqr(t, t);  fe_mul(t, t, x22);
  for (int i = 0; i < 5; i++)  fe_sqr(t, t);  fe_mul(t, t, a);
  for (int i = 0; i < 3; i++)  fe_sqr(t, t);  fe_mul(t, t, x2);
  for (int i = 0; i < 2; i++)  fe_sqr(t, t);  fe_mul(r, t, a);
  fe_normalize(r);
}
