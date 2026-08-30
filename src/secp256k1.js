'use strict';
/**
 * secp256k1 elliptic curve math, from first principles.
 *
 * Curve:  y^2 = x^3 + 7   (mod p)
 * This is the exact curve Bitcoin has used since 2009.
 *
 * Scalar multiplication runs in Jacobian coordinates so the whole ladder
 * needs a single modular inversion at the end instead of one per step.
 */

// Field prime: 2^256 - 2^32 - 977
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

// Order of G -- the number of distinct points G generates. Valid private
// keys are 1 .. N-1.
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

// Generator point, fixed by the standard.
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

const mod = (a, m = P) => ((a % m) + m) % m;

// Modular inverse via the extended Euclidean algorithm.
function inv(a, m = P) {
  a = mod(a, m);
  if (a === 0n) throw new Error('inverse of zero');
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, m);
}

// Jacobian point: affine (x, y) == (X/Z^2, Y/Z^3). Z === 0n is infinity.
const INFINITY = { X: 0n, Y: 1n, Z: 0n };

function double(p1) {
  const { X, Y, Z } = p1;
  if (Z === 0n || Y === 0n) return INFINITY;
  const A = mod(Y * Y);
  const B = mod(4n * X * A);
  const C = mod(8n * A * A);
  const D = mod(3n * X * X); // curve parameter a is 0, so no aZ^4 term
  const X3 = mod(D * D - 2n * B);
  const Y3 = mod(D * (B - X3) - C);
  const Z3 = mod(2n * Y * Z);
  return { X: X3, Y: Y3, Z: Z3 };
}

function add(p1, p2) {
  if (p1.Z === 0n) return p2;
  if (p2.Z === 0n) return p1;
  const Z1Z1 = mod(p1.Z * p1.Z);
  const Z2Z2 = mod(p2.Z * p2.Z);
  const U1 = mod(p1.X * Z2Z2);
  const U2 = mod(p2.X * Z1Z1);
  const S1 = mod(p1.Y * p2.Z * Z2Z2);
  const S2 = mod(p2.Y * p1.Z * Z1Z1);
  if (U1 === U2) {
    // Same x: either the same point (double) or P + (-P) (infinity).
    return S1 === S2 ? double(p1) : INFINITY;
  }
  const H = mod(U2 - U1);
  const I = mod(4n * H * H);
  const J = mod(H * I);
  const r = mod(2n * (S2 - S1));
  const V = mod(U1 * I);
  const X3 = mod(r * r - J - 2n * V);
  const Y3 = mod(r * (V - X3) - 2n * S1 * J);
  const Z3 = mod((mod(p1.Z + p2.Z) ** 2n - Z1Z1 - Z2Z2) * H);
  return { X: X3, Y: Y3, Z: Z3 };
}

function toAffine(p1) {
  if (p1.Z === 0n) throw new Error('point at infinity has no affine form');
  const zInv = inv(p1.Z);
  const zInv2 = mod(zInv * zInv);
  return { x: mod(p1.X * zInv2), y: mod(p1.Y * zInv2 * zInv) };
}

/** Scalar multiply: k * point. Left-to-right double-and-add. */
function multiply(k, point = { X: Gx, Y: Gy, Z: 1n }) {
  if (k <= 0n || k >= N) throw new RangeError('scalar out of range 1..n-1');
  let result = INFINITY;
  // Start at the highest set bit so we skip leading zeros.
  for (let i = BigInt(k.toString(2).length) - 1n; i >= 0n; i--) {
    result = double(result);
    if ((k >> i) & 1n) result = add(result, point);
  }
  return result;
}

/** k * G, returned in affine coordinates. This is the public key. */
function derivePublicPoint(k) {
  return toAffine(multiply(k));
}

/** Sanity check that a point actually satisfies y^2 = x^3 + 7. */
function isOnCurve({ x, y }) {
  return mod(y * y) === mod(x * x * x + 7n);
}

module.exports = { P, N, Gx, Gy, mod, inv, add, double, multiply, toAffine, derivePublicPoint, isOnCurve };
