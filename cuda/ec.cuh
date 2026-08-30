// secp256k1 point arithmetic: y^2 = x^3 + 7.
//
// Jacobian coordinates for the ladder (affine (x,y) == (X/Z^2, Y/Z^3)), so only
// one modular inverse is needed, at the very end.
#pragma once
#include "field.cuh"
#include "field32.cuh"

typedef struct { fe x, y; } pt_affine;
typedef struct { fe X, Y, Z; } pt_jac;   // Z == 0 means the point at infinity

// Generator G.
__device__ __constant__ uint64_t GX[4] = {
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
    0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL};
__device__ __constant__ uint64_t GY[4] = {
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
    0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL};

#if FIELD32
__device__ __constant__ uint32_t GX32[8] = {
  0x16F81798u, 0x59F2815Bu, 0x2DCE28D9u, 0x029BFCDBu,
  0xCE870B07u, 0x55A06295u, 0xF9DCBBACu, 0x79BE667Eu};
__device__ __constant__ uint32_t GY32[8] = {
  0xFB10D4B8u, 0x9C47D08Fu, 0xA6855419u, 0xFD17B448u,
  0x0E1108A8u, 0x5DA4FBFCu, 0x26A3C465u, 0x483ADA77u};
#endif

__device__ __forceinline__ void pt_set_infinity(pt_jac &r) {
  fe_set_zero(r.X); fe_set_zero(r.Y); fe_set_zero(r.Z);
  r.X.l[0] = 1; r.Y.l[0] = 1;   // (1, 1, 0)
}
__device__ __forceinline__ bool pt_is_infinity(const pt_jac &a) { return fe_is_zero(a.Z); }

// r = 2a. Standard "dbl-2009-l" for curves with a == 0.
__device__ void pt_double(pt_jac &r, const pt_jac &a) {
  if (pt_is_infinity(a) || fe_is_zero(a.Y)) { pt_set_infinity(r); return; }
  fe A, B, C, D, t1, t2;
  fe_sqr(A, a.Y);                      // A = Y^2
  fe_mul(B, a.X, A); fe_add(B, B, B); fe_add(B, B, B);   // B = 4XY^2
  fe_sqr(C, A); fe_add(C, C, C); fe_add(C, C, C); fe_add(C, C, C); // C = 8Y^4
  fe_sqr(D, a.X); fe_add(t1, D, D); fe_add(D, t1, D);    // D = 3X^2  (a == 0)
  fe_sqr(r.X, D); fe_sub(r.X, r.X, B); fe_sub(r.X, r.X, B);
  fe_sub(t2, B, r.X); fe_mul(r.Y, D, t2); fe_sub(r.Y, r.Y, C);
  fe_mul(r.Z, a.Y, a.Z); fe_add(r.Z, r.Z, r.Z);
}

// r = a + b, both Jacobian. "add-2007-bl".
__device__ void pt_add(pt_jac &r, const pt_jac &a, const pt_jac &b) {
  if (pt_is_infinity(a)) { r = b; return; }
  if (pt_is_infinity(b)) { r = a; return; }

  fe Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, rr, V, t;
  fe_sqr(Z1Z1, a.Z);
  fe_sqr(Z2Z2, b.Z);
  fe_mul(U1, a.X, Z2Z2);
  fe_mul(U2, b.X, Z1Z1);
  fe_mul(S1, a.Y, b.Z); fe_mul(S1, S1, Z2Z2);
  fe_mul(S2, b.Y, a.Z); fe_mul(S2, S2, Z1Z1);

  if (fe_eq(U1, U2)) {
    if (fe_eq(S1, S2)) { pt_double(r, a); return; }
    pt_set_infinity(r); return;          // a == -b
  }

  fe_sub(H, U2, U1);
  fe_add(I, H, H); fe_sqr(I, I);          // I = (2H)^2
  fe_mul(J, H, I);
  fe_sub(rr, S2, S1); fe_add(rr, rr, rr); // r = 2(S2 - S1)
  fe_mul(V, U1, I);

  fe_sqr(r.X, rr); fe_sub(r.X, r.X, J); fe_sub(r.X, r.X, V); fe_sub(r.X, r.X, V);
  fe_sub(t, V, r.X); fe_mul(r.Y, rr, t);
  fe_mul(t, S1, J); fe_add(t, t, t); fe_sub(r.Y, r.Y, t);
  fe_add(t, a.Z, b.Z); fe_sqr(t, t); fe_sub(t, t, Z1Z1); fe_sub(t, t, Z2Z2);
  fe_mul(r.Z, t, H);
}

__device__ void pt_to_affine(pt_affine &r, const pt_jac &a) {
  fe zinv, z2, z3;
  fe_inv(zinv, a.Z);
  fe_sqr(z2, zinv);
  fe_mul(z3, z2, zinv);
  fe_mul(r.x, a.X, z2);
  fe_mul(r.y, a.Y, z3);
  fe_normalize(r.x);
  fe_normalize(r.y);
}

// r = k * G, by binary double-and-add over the 256 bits of k.
__device__ void ec_pubkey(pt_affine &r, const uint64_t k[4]) {
  pt_jac acc, g;
  pt_set_infinity(acc);
#if FIELD32
  #pragma unroll
  for (int i = 0; i < 8; i++) { g.X.l[i] = GX32[i]; g.Y.l[i] = GY32[i]; g.Z.l[i] = 0; }
#else
  #pragma unroll
  for (int i = 0; i < 4; i++) { g.X.l[i] = GX[i]; g.Y.l[i] = GY[i]; g.Z.l[i] = 0; }
#endif
  g.Z.l[0] = 1;

  for (int limb = 3; limb >= 0; limb--) {
    for (int bit = 63; bit >= 0; bit--) {
      pt_jac t;
      pt_double(t, acc);
      acc = t;
      if ((k[limb] >> bit) & 1ULL) { pt_add(t, acc, g); acc = t; }
    }
  }
  pt_to_affine(r, acc);
}
