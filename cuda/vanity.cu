// GPU vanity address search.
//
// Structurally the same walk as hunt.cu -- each thread holds a point and adds
// G, GRP additions at a time sharing one modular inverse via Montgomery's
// trick -- with one thing swapped out: instead of testing each hash160 against
// a Bloom filter of funded addresses, it tests whether the address *starts with
// a chosen prefix*.
//
// The interesting part is that this needs no Base58 and no checksum on the GPU.
// The 25-byte address buffer is
//
//     0x00 || hash160 (20 bytes) || checksum (4 bytes)
//
// so as a number it is exactly  A = hash160 * 2^32 + checksum.  Base58 is
// positional, so fixing the leading characters fixes A to a contiguous range,
// and because the checksum only occupies the low 32 bits, that range maps onto
// a range on the hash160 the kernel is already holding. Prefix matching is
// therefore a 160-bit comparison against precomputed bounds -- cheaper than the
// eight Bloom probes hunt.cu runs, and it early-exits on the first word almost
// every time.
//
// The bounds are widened outward by at most one hash160 value at each end
// (see src/vanity-range.js), so a reported key is a *candidate*, exactly like a
// Bloom hit. scripts/gpu-vanity.js re-derives the real address with src/keys.js
// before anything is reported. Nothing here is trusted on its own.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ec.cuh"
#include "hash.cuh"

#ifndef GRP
#define GRP 8
#endif

// Measurement only: 2 = both public-key encodings (what the search does),
// 1 = compressed only, which halves the addresses per curve step but skips the
// 65-byte form's second SHA-256 block.
#ifndef FORMS
#define FORMS 2
#endif

// Profiling levels: 1 = curve only, 2 = + hash160, 3 = full pipeline.
// Each stage still consumes its result so the compiler cannot delete the work
// that produced it.
#ifndef PROFILE_STAGE
#define PROFILE_STAGE 3
#endif

#if FIELD32
#define FE_LIMBS_N 8
#else
#define FE_LIMBS_N 4
#endif
#define MAX_HITS 256
#define MAX_RANGES 32

__device__ __constant__ uint64_t TBL_X[GRP][4];   // x of 1G .. GRP*G
__device__ __constant__ uint64_t TBL_Y[GRP][4];

/**
 * secp256k1's endomorphism, and why a curve step is worth six points.
 *
 * beta is a cube root of 1 mod p, lambda a cube root of 1 mod n, and they are
 * linked: lambda*P is exactly (beta*x, y). So multiplying the x coordinate by a
 * constant -- ONE field multiply -- produces another valid point on the curve,
 * whose private key is lambda*k mod n. Doing it again with beta^2 produces a
 * third. Negation is cheaper still: -P = (x, -y), private key n-k.
 *
 * That gives P, -P, lambda*P, -lambda*P, lambda^2*P and -lambda^2*P -- six
 * points and twelve addresses -- from one affine addition and one modular
 * inverse, instead of six of each. The curve was 46% of the run time when it
 * paid for two addresses; here it pays for twelve.
 *
 * The host reconstructs the private key from the variant number, and then
 * re-derives the address from it, so a mistake in any of this is caught rather
 * than reported as a find. Verified against src/secp256k1.js in test/gpu.js.
 */
__device__ __constant__ uint64_t BETA_[4]  =
  { 0xc1396c28719501eeULL, 0x9cf0497512f58995ULL,
    0x6e64479eac3434e9ULL, 0x7ae96a2b657c0710ULL };
__device__ __constant__ uint64_t BETA2_[4] =
  { 0x3ec693d68e6afa40ULL, 0x630fb68aed0a766aULL,
    0x919bb86153cbcb16ULL, 0x851695d49a83f8efULL };

// How many of the six related points to search. 1 = the point only (what this
// kernel did before), 2 = plus its negation, 6 = plus both endomorphisms.
#ifndef VARIANTS
#define VARIANTS 6
#endif

// Prefix bounds, big-endian 32-bit words, word 0 most significant. Both ends
// inclusive. Constant memory: every thread reads the same few words, which is
// the access pattern the constant cache is built for.
__device__ __constant__ uint32_t R_LO[MAX_RANGES][5];
__device__ __constant__ uint32_t R_HI[MAX_RANGES][5];

/** The i-th 64-bit limb, whichever limb width the field uses. */
__device__ __forceinline__ uint64_t fe_limb64(const fe &a, int i) {
#if FIELD32
  return (uint64_t)a.l[i*2] | ((uint64_t)a.l[i*2+1] << 32);
#else
  return a.l[i];
#endif
}

struct Hit {
  uint64_t k[4];       // private key that produced it
  uint8_t  h160[20];
  uint32_t form;       // 0 = uncompressed, 1 = compressed
  uint32_t range;      // which prefix range matched
  uint32_t variant;    // which of the six related points (see BETA_ above)
};

/** Three-way compare of two 160-bit values held as five big-endian words. */
__device__ __forceinline__ int cmp160(const uint32_t a[5], const uint32_t b[5]) {
  for (int i = 0; i < 5; i++) {
    if (a[i] != b[i]) return a[i] > b[i] ? 1 : -1;
  }
  return 0;
}

/**
 * Which range contains this hash160, or -1. Correct for any arrangement of
 * ranges, including nested ones ("1Btc" contains "1Btcoin").
 *
 * O(ranges) per address, and there are twelve addresses per curve step, so this
 * is what makes many patterns expensive: measured at 0.9% of the run for one
 * prefix and 14% for sixteen.
 */
__device__ __forceinline__ int range_of_linear(const uint32_t w[5], uint32_t nRanges) {
  for (uint32_t r = 0; r < nRanges; r++) {
    if (cmp160(w, R_LO[r]) >= 0 && cmp160(w, R_HI[r]) <= 0) return (int)r;
  }
  return -1;
}

/**
 * The same answer by bisection, valid when the ranges are sorted by lower bound
 * and do not overlap.
 *
 * Disjoint and sorted means there is only ever one candidate: the last range
 * whose lower bound is at or below the value. Find it in log2(n) comparisons
 * and check its upper bound, rather than walking all n. The host decides which
 * of these two the kernel gets -- see buildRanges() in src/gpu-vanity.js.
 */
__device__ __forceinline__ int range_of_sorted(const uint32_t w[5], uint32_t nRanges) {
  uint32_t lo = 0, hi = nRanges;          // hi exclusive
  while (lo < hi) {
    uint32_t mid = (lo + hi) >> 1;
    if (cmp160(w, R_LO[mid]) >= 0) lo = mid + 1; else hi = mid;
  }
  if (lo == 0) return -1;                 // below every range
  uint32_t r = lo - 1;
  return cmp160(w, R_HI[r]) <= 0 ? (int)r : -1;
}

/**
 * Bisection wins from about four ranges up; below that its setup costs more
 * than the comparisons it saves, and a single prefix -- the common case -- was
 * measurably (0.7%) worse for it. So take the scan when the list is short.
 */
#define BISECT_FROM 5

__device__ __forceinline__ int range_of(const uint32_t w[5], uint32_t nRanges,
                                        uint32_t sorted) {
  if (sorted && nRanges >= BISECT_FROM) return range_of_sorted(w, nRanges);
  return range_of_linear(w, nRanges);
}

/**
 * Write out a hit. Takes the digest as words and unpacks to bytes here, because
 * this runs once per match rather than twice per key: the byte form costs
 * nothing where it is actually needed, and forcing it on the hot path cost a
 * local-memory round trip for every key that was never going to match.
 */
__device__ __forceinline__ void record(Hit *hits, uint32_t *nHits, const uint64_t kk[4],
                                       const uint32_t w[5], uint32_t form, int range,
                                       uint32_t variant) {
  uint32_t slot = atomicAdd(nHits, 1u);
  if (slot >= MAX_HITS) return;
  #pragma unroll
  for (int j = 0; j < 4; j++) hits[slot].k[j] = kk[j];
  #pragma unroll
  for (int i = 0; i < 5; i++) {
    hits[slot].h160[i*4]     = (uint8_t)(w[i] >> 24);
    hits[slot].h160[i*4 + 1] = (uint8_t)(w[i] >> 16);
    hits[slot].h160[i*4 + 2] = (uint8_t)(w[i] >> 8);
    hits[slot].h160[i*4 + 3] = (uint8_t)(w[i]);
  }
  hits[slot].form = form;
  hits[slot].range = (uint32_t)range;
  hits[slot].variant = variant;
}

__global__ void vanity_kernel(uint64_t *startX, uint64_t *startY,
                              uint64_t *startK, uint32_t groups, uint32_t nRanges,
                              uint32_t sorted, Hit *hits, uint32_t *nHits,
                              uint64_t *keysDone) {
  int tid = blockIdx.x * blockDim.x + threadIdx.x;

  fe px, py;
#if FIELD32
  fe_from_u64(px, &startX[tid * 4]);
  fe_from_u64(py, &startY[tid * 4]);
#else
  #pragma unroll
  for (int i = 0; i < 4; i++) { px.l[i] = startX[tid * 4 + i]; py.l[i] = startY[tid * 4 + i]; }
#endif
  uint64_t k[4];
  #pragma unroll
  for (int i = 0; i < 4; i++) k[i] = startK[tid * 4 + i];

  uint64_t localKeys = 0;

  for (uint32_t g = 0; g < groups; g++) {
    fe dx[GRP], acc[GRP];

    #pragma unroll
    for (int i = 0; i < GRP; i++) {
      fe gx;
#if FIELD32
      fe_from_u64(gx, TBL_X[i]);
#else
      #pragma unroll
      for (int j = 0; j < 4; j++) gx.l[j] = TBL_X[i][j];
#endif
      fe_sub(dx[i], gx, px);
    }

    // Montgomery's trick: prefix products, one inverse, then unwind.
    acc[0] = dx[0];
    #pragma unroll
    for (int i = 1; i < GRP; i++) fe_mul(acc[i], acc[i - 1], dx[i]);

    fe inv;
    fe_inv(inv, acc[GRP - 1]);

    fe dxi[GRP];
    #pragma unroll
    for (int i = GRP - 1; i > 0; i--) {
      fe_mul(dxi[i], inv, acc[i - 1]);
      fe_mul(inv, inv, dx[i]);
    }
    dxi[0] = inv;

    fe nx, ny;
    #pragma unroll
    for (int i = 0; i < GRP; i++) {
      fe gx, gy, lam, t;
#if FIELD32
      fe_from_u64(gx, TBL_X[i]);
      fe_from_u64(gy, TBL_Y[i]);
#else
      #pragma unroll
      for (int j = 0; j < 4; j++) { gx.l[j] = TBL_X[i][j]; gy.l[j] = TBL_Y[i][j]; }
#endif

      fe_sub(t, gy, py);
      fe_mul(lam, t, dxi[i]);          // lambda = (yG - yP)/(xG - xP)
      fe_sqr(nx, lam);
      fe_sub(nx, nx, px);
      fe_sub(nx, nx, gx);              // x3 = lambda^2 - xP - xG
      fe_sub(t, px, nx);
      fe_mul(ny, lam, t);
      fe_sub(ny, ny, py);              // y3 = lambda(xP - x3) - yP
      fe_normalize(nx); fe_normalize(ny);

      // One point in, six out. bx = beta*x and bx2 = beta^2*x are two more
      // valid points at one field multiply each; nyn = -y gives each of them a
      // negation for a subtraction. Twelve addresses from one inversion.
#if PROFILE_STAGE >= 2
      fe nyn;
#if VARIANTS >= 2
      fe zero; fe_set_zero(zero);
      fe_sub(nyn, zero, ny);
#else
      nyn = ny;
#endif
#if VARIANTS >= 6
      fe bx, bx2, bconst;
      fe_from_u64(bconst, BETA_);
      fe_mul(bx, nx, bconst);
      fe_normalize(bx);
      fe_from_u64(bconst, BETA2_);
      fe_mul(bx2, nx, bconst);
      fe_normalize(bx2);
#endif
#endif

      // key for this point is k + (i + 1)
      uint64_t kk[4] = {k[0], k[1], k[2], k[3]};
      {
        uint64_t add = (uint64_t)(i + 1), c = 0;
        kk[0] = adc(kk[0], add, c);
        kk[1] = adc(kk[1], 0, c);
        kk[2] = adc(kk[2], 0, c);
        kk[3] = adc(kk[3], 0, c);
      }

#if PROFILE_STAGE >= 3
      // One digest buffer, reused: keeping twelve of them live would spill.
#define VG_TEST_POINT(XX, YY, VAR)                                    \
      do {                                                            \
        uint32_t h[5];                                                \
        int r;                                                        \
        if (FORMS == 2) {                                             \
          hash160_point_be(XX, YY, false, h);                         \
          r = range_of(h, nRanges, sorted);                           \
          if (r >= 0) record(hits, nHits, kk, h, 0, r, (VAR));        \
        }                                                             \
        hash160_point_be(XX, YY, true, h);                            \
        r = range_of(h, nRanges, sorted);                             \
        if (r >= 0) record(hits, nHits, kk, h, 1, r, (VAR));          \
      } while (0)

      VG_TEST_POINT(nx, ny, 0u);
#if VARIANTS >= 2
      VG_TEST_POINT(nx, nyn, 1u);
#endif
#if VARIANTS >= 6
      VG_TEST_POINT(bx,  ny,  2u);
      VG_TEST_POINT(bx,  nyn, 3u);
      VG_TEST_POINT(bx2, ny,  4u);
      VG_TEST_POINT(bx2, nyn, 5u);
#endif
#undef VG_TEST_POINT
#elif PROFILE_STAGE == 2
      // Hash without testing, so the hashing can be priced on its own.
      uint32_t h[5], acc2 = 0;
      hash160_point_be(nx, ny, false, h); acc2 |= h[0];
      hash160_point_be(nx, ny, true,  h); acc2 |= h[0];
#if VARIANTS >= 2
      hash160_point_be(nx, nyn, false, h); acc2 |= h[0];
      hash160_point_be(nx, nyn, true,  h); acc2 |= h[0];
#endif
#if VARIANTS >= 6
      hash160_point_be(bx,  ny,  false, h); acc2 |= h[0];
      hash160_point_be(bx,  ny,  true,  h); acc2 |= h[0];
      hash160_point_be(bx,  nyn, false, h); acc2 |= h[0];
      hash160_point_be(bx,  nyn, true,  h); acc2 |= h[0];
      hash160_point_be(bx2, ny,  false, h); acc2 |= h[0];
      hash160_point_be(bx2, ny,  true,  h); acc2 |= h[0];
      hash160_point_be(bx2, nyn, false, h); acc2 |= h[0];
      hash160_point_be(bx2, nyn, true,  h); acc2 |= h[0];
#endif
      if (acc2 == 0xffffffffu) atomicAdd(nHits, 0u);
#else
      // Stage 1: no hashing at all. Consume the point so the curve arithmetic
      // that produced it cannot be optimised away.
      if ((uint32_t)nx.l[0] == 0xffffffffu && (uint32_t)ny.l[0] == 0xffffffffu)
        atomicAdd(nHits, 0u);
#endif

      localKeys++;

      if (i == GRP - 1) { px = nx; py = ny; }   // advance base by GRP*G
    }

    uint64_t c = 0;
    k[0] = adc(k[0], (uint64_t)GRP, c);
    k[1] = adc(k[1], 0, c);
    k[2] = adc(k[2], 0, c);
    k[3] = adc(k[3], 0, c);
  }

  // Write the advanced state back, or the next launch restarts the points while
  // the scalars march on and every key it reports after round 1 is wrong.
#if FIELD32
  fe_to_u64(&startX[tid * 4], px);
  fe_to_u64(&startY[tid * 4], py);
  #pragma unroll
  for (int i = 0; i < 4; i++) startK[tid * 4 + i] = k[i];
#else
  #pragma unroll
  for (int i = 0; i < 4; i++) {
    startX[tid * 4 + i] = px.l[i];
    startY[tid * 4 + i] = py.l[i];
    startK[tid * 4 + i] = k[i];
  }
#endif

  atomicAdd((unsigned long long *)keysDone, (unsigned long long)localKeys);
}

// --------------------------------------------------------------- host side --

static void die(const char *what, cudaError_t e) {
  fprintf(stderr, "CUDA error (%s): %s\n", what, cudaGetErrorString(e));
  exit(1);
}
#define CK(call, what) do { cudaError_t _e = (call); if (_e != cudaSuccess) die(what, _e); } while (0)

int main(int argc, char **argv) {
  const char *rangePath = NULL, *startPath = NULL;
  int blocks = 0, threads = 256;
  uint32_t groups = 256;
  long long maxRounds = -1;

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--ranges") && i + 1 < argc) rangePath = argv[++i];
    else if (!strcmp(argv[i], "--start") && i + 1 < argc) startPath = argv[++i];
    else if (!strcmp(argv[i], "--blocks") && i + 1 < argc) blocks = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--groups") && i + 1 < argc) groups = (uint32_t)atoi(argv[++i]);
    else if (!strcmp(argv[i], "--rounds") && i + 1 < argc) maxRounds = atoll(argv[++i]);
  }
  if (!rangePath || !startPath) {
    fprintf(stderr, "usage: %s --ranges <file> --start <file> "
                    "[--blocks N] [--threads N] [--groups N] [--rounds N]\n", argv[0]);
    return 2;
  }

  cudaDeviceProp prop;
  CK(cudaGetDeviceProperties(&prop, 0), "getDeviceProperties");
  // One block per SM: hunt.cu measured throughput flat above that.
  if (blocks <= 0) blocks = prop.multiProcessorCount;
  int nThreads = blocks * threads;

  // Ranges: uint32 count, then count * (5 lo words + 5 hi words), big-endian
  // order within each bound, written by scripts/gpu-vanity.js.
  FILE *f = fopen(rangePath, "rb");
  if (!f) { fprintf(stderr, "cannot open %s\n", rangePath); return 1; }
  uint32_t nRanges = 0, sorted = 0;
  if (fread(&nRanges, sizeof(uint32_t), 1, f) != 1 ||
      fread(&sorted, sizeof(uint32_t), 1, f) != 1) {
    fprintf(stderr, "range file truncated\n"); return 1;
  }
  if (nRanges == 0 || nRanges > MAX_RANGES) {
    fprintf(stderr, "range file has %u ranges, need 1..%d\n", nRanges, MAX_RANGES); return 1;
  }
  uint32_t hLo[MAX_RANGES][5], hHi[MAX_RANGES][5];
  memset(hLo, 0, sizeof(hLo)); memset(hHi, 0, sizeof(hHi));
  for (uint32_t r = 0; r < nRanges; r++) {
    if (fread(hLo[r], sizeof(uint32_t), 5, f) != 5 ||
        fread(hHi[r], sizeof(uint32_t), 5, f) != 5) {
      fprintf(stderr, "range file truncated at range %u\n", r); return 1;
    }
  }
  fclose(f);
  CK(cudaMemcpyToSymbol(R_LO, hLo, sizeof(hLo)), "R_LO");
  CK(cudaMemcpyToSymbol(R_HI, hHi, sizeof(hHi)), "R_HI");

  // Same start-file layout as gpu-hunt: the 1G..GRP*G table, a thread count,
  // then a starting point and scalar per thread.
  f = fopen(startPath, "rb");
  if (!f) { fprintf(stderr, "cannot open %s\n", startPath); return 1; }
  uint64_t tblX[GRP][4], tblY[GRP][4];
  if (fread(tblX, sizeof(tblX), 1, f) != 1 || fread(tblY, sizeof(tblY), 1, f) != 1) {
    fprintf(stderr, "start file too short (table)\n"); return 1;
  }
  int fileThreads = 0;
  if (fread(&fileThreads, sizeof(int), 1, f) != 1) { fprintf(stderr, "start file too short\n"); return 1; }
  if (fileThreads < nThreads) {
    fprintf(stderr, "start file has %d thread seeds, need %d\n", fileThreads, nThreads);
    return 1;
  }
  size_t want = (size_t)fileThreads * 4;
  uint64_t *allX = (uint64_t *)malloc(want * 8), *allY = (uint64_t *)malloc(want * 8),
           *allK = (uint64_t *)malloc(want * 8);
  if (fread(allX, 8, want, f) != want || fread(allY, 8, want, f) != want ||
      fread(allK, 8, want, f) != want) {
    fprintf(stderr, "start file too short (seeds)\n"); return 1;
  }
  fclose(f);

  size_t sz = (size_t)nThreads * 4 * sizeof(uint64_t);
  uint64_t *dX, *dY, *dK, *dKeys; Hit *dHits; uint32_t *dN;
  CK(cudaMemcpyToSymbol(TBL_X, tblX, sizeof(tblX)), "tblX");
  CK(cudaMemcpyToSymbol(TBL_Y, tblY, sizeof(tblY)), "tblY");
  CK(cudaMalloc(&dX, sz), "dX"); CK(cudaMalloc(&dY, sz), "dY"); CK(cudaMalloc(&dK, sz), "dK");
  CK(cudaMemcpy(dX, allX, sz, cudaMemcpyHostToDevice), "cX");
  CK(cudaMemcpy(dY, allY, sz, cudaMemcpyHostToDevice), "cY");
  CK(cudaMemcpy(dK, allK, sz, cudaMemcpyHostToDevice), "cK");
  CK(cudaMalloc(&dHits, MAX_HITS * sizeof(Hit)), "dHits");
  CK(cudaMalloc(&dN, sizeof(uint32_t)), "dN");
  CK(cudaMalloc(&dKeys, sizeof(uint64_t)), "dKeys");
  CK(cudaMemset(dN, 0, sizeof(uint32_t)), "memset dN");

  fprintf(stderr, "gpu: %s, %d SMs, %d blocks x %d threads = %d threads, "
                  "%u range(s), %s lookup\n",
          prop.name, prop.multiProcessorCount, blocks, threads, nThreads, nRanges,
          sorted ? "bisecting" : "linear");
  fflush(stderr);

  Hit hHits[MAX_HITS];
  uint64_t total = 0;
  for (long long round = 0; maxRounds < 0 || round < maxRounds; round++) {
    CK(cudaMemset(dKeys, 0, sizeof(uint64_t)), "memset keys");
    vanity_kernel<<<blocks, threads>>>(dX, dY, dK, groups, nRanges, sorted,
                                      dHits, dN, dKeys);
    CK(cudaGetLastError(), "launch");
    CK(cudaDeviceSynchronize(), "sync");

    uint64_t done = 0; uint32_t n = 0;
    CK(cudaMemcpy(&done, dKeys, sizeof(uint64_t), cudaMemcpyDeviceToHost), "keys back");
    CK(cudaMemcpy(&n, dN, sizeof(uint32_t), cudaMemcpyDeviceToHost), "n back");
    total += done;

    if (n > 0) {
      uint32_t take = n > MAX_HITS ? MAX_HITS : n;
      CK(cudaMemcpy(hHits, dHits, take * sizeof(Hit), cudaMemcpyDeviceToHost), "hits back");
      for (uint32_t i = 0; i < take; i++) {
        printf("HIT ");
        for (int j = 3; j >= 0; j--) printf("%016llx", (unsigned long long)hHits[i].k[j]);
        printf(" %s ", hHits[i].form ? "compressed" : "uncompressed");
        for (int j = 0; j < 20; j++) printf("%02x", hHits[i].h160[j]);
        printf(" %u %u\n", hHits[i].range, hHits[i].variant);
      }
      // Say so rather than silently dropping: an easy prefix can outrun the
      // buffer, and a quiet truncation would look like a slow search.
      if (n > MAX_HITS) printf("OVERFLOW %u\n", n - MAX_HITS);
      fflush(stdout);
      CK(cudaMemset(dN, 0, sizeof(uint32_t)), "reset n");
    }

    printf("PROGRESS %llu\n", (unsigned long long)total);
    fflush(stdout);
  }
  return 0;
}
