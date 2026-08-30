# vanity

Bitcoin vanity address search: CPU via vanitygen, GPU via `cuda/vanity.cu`.
Read README.md first — this file is the traps.

**This is not the `bitcoin-keys` project.** That one hunts funded addresses and
runs Pollard's kangaroo, and it has its own database and its own coordinator.
Nothing here talks to it. The curve/hash/Base58 primitives in `src/` began as
copies of its oracle, but they are this repo's now; do not add a dependency on
that repo, and do not point this one's `.env` anywhere but local Postgres.

## Layout

| path | what |
|---|---|
| `src/secp256k1.js` `hash.js` `base58.js` `keys.js` | the pipeline from first principles — the oracle |
| `src/vanity-range.js` | a Base58 prefix as a numeric range on the hash160 |
| `src/vanitygen.js` | drives vanitygen, re-derives everything it reports |
| `src/gpu-vanity.js` | drives the kernel, confirms every candidate |
| `scripts/seed.js` | random per-thread starting points for the GPU |
| `cuda/vanity.cu` | the kernel |
| `vendor/patches/` | the vanitygen port + two bug fixes (AGPL, not vendored) |

## Commands

```bash
./scripts/create-db.sh    # once. run as YOURSELF, not under sudo
npm run init-db
npm run build             # vanitygen + CUDA
npm run gpu -- 1Btcoin
npm run vanity -- 1Btc
npm run matches
npm run test:all
```

## Rules

- **Nothing is trusted, only checked.** vanitygen and the kernel are both
  independent implementations of what `src/keys.js` does. Every result they
  report is re-derived and compared before it reaches a human or the database.
  Do not "optimise away" that confirmation — it is the product.
- **Every test must be able to fail.** Each gate checks acceptance of a
  published pair *and* rejection of a wrong one. If you add a check, add its
  mutation. A detection test that cannot fail is worthless.
- **Expected values come from published constants**, never from this code.

## Traps

- **One curve step = 12 addresses, and the variant number is load-bearing.**
  The kernel searches six related points -- P, -P, and both endomorphism images
  of each (`λP = (β·x, y)`, one field multiply; `-P = (x, -y)`, one subtraction)
  -- in two encodings apiece. It reports WHICH one matched, and
  `variantKey()` in src/gpu-vanity.js turns that back into a private key
  (`k`, `n-k`, `λk`, `n-λk`, `λ²k`, `n-λ²k` mod n). Get that mapping wrong and
  the kernel still finds things, it just reports keys that do not own the
  addresses found -- the worst failure this program has. confirm() catches it,
  and test/gpu.js exercises all six against a published key. λ³=1, so six is
  all of them; there is no seventh.
- **Rates: 72M curve steps/s, 865M addresses/s.** Those differ by 12x, not 2x.
  Anything reporting a rate must say which it is.
- **The GPU never builds an address, and that is the design.** A 25-byte address
  is `hash160 * 2^32 + checksum`, so a prefix is a range on the hash160 — a
  160-bit compare, no Base58, no checksum. Shifting the checksum off rounds
  outward, so a GPU hit is a CANDIDATE, confirmed on the host.
- **Already measured and rejected** (see README "What the numbers rule out"):
  specialising the uncompressed padding SHA block (≤5%, nvcc already folds it),
  dropping the uncompressed encoding (33% SLOWER per address -- the two hash
  chains hide each other's latency), and returning digests as words instead of
  bytes (no change). The search is hash-bound now; the curve is 14%.
- **Prefix difficulty is not 58 per character.** `1Btc` is 77,178, not 195,112 —
  a prefix pins the address *number* to a range, and the first character after
  the leading `1` is only partly constrained. Leading `1`s cost 256 each, not
  58, because they are zero bytes rather than digits.
- **A prefix can be TWO intervals, not one.** The eight-bit byte window the
  leading `1`s imply spans more than one Base58 rendering length. This is the
  bug that was fixed in vanitygen; do not reintroduce it here by assuming one
  range. At most two can ever intersect — the window is 8 bits and a digit is
  5.86 — which is why the kernel's two-range interface is enough.
- **Use `src/vanity-range.js` for difficulty, not vanitygen.**
  `vg_prefix_get_difficulty()` returns a C double and rounds above 2^53
  (173346595075428786 prints as ...800). `estimateDifficulty()` exists as the
  cross-check, not the source.
- **vanitygen is AGPL-3.0 and this project is MIT.** Cloned and patched at build
  time into `vendor/vanitygen/` (gitignored), driven as a subprocess. Never
  commit it, never link against it.
- **`oclvanitygen` is not built and should not be.** `oclengine.c` reads
  OpenSSL's private `struct ec_point_st`; that layout changed in 1.1 and 3.0.
  `cuda/vanity.cu` replaces it and is far faster.
- **vanitygen crashed after printing a match** until the thread-join fix — it
  never joined its workers, and on OpenSSL 3 a worker still hashing when
  `exit()` runs `OPENSSL_cleanup()` faults. ~1 run in 3, which reads as success.
  If you re-roll the patch, keep the join.
- **`--keep` without `--max` buries the process.** Verification is a BigInt
  scalar multiply (~1ms); an easy prefix hits every few microseconds. The
  backlog starves the event loop so even `--timeout` stops firing. `--max`
  defaults to 100 with `--keep` and the cap is exact.
- **Regenerating the patch: `git add -A` in the clone first.** `git diff HEAD`
  does not include untracked files, and `pcre1compat.h` is a new file — leaving
  it out produces a patch that applies cleanly and then fails to compile.
- **`scripts/create-db.sh` is run as you, not under sudo.** It calls sudo only
  for the postgres steps; running the whole thing as root leaves `.env`
  root-owned and every later command fails with EACCES.
- **`VANITY.txt` and `.env` are gitignored** and hold real private keys.
