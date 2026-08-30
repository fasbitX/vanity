# Changelog

## 1.1.2

**Searching many patterns at once no longer costs 13%.** The range test is run
twelve times per curve step, once per address, and it was a linear scan over
every range. One prefix cost 0.9% of the run; sixteen cost 14%.

Ranges are now sorted by lower bound on the host, so the kernel bisects instead
of walking: the only candidate is the last range whose lower bound is at or
below the value. Measured, interleaved against the previous kernel:

| ranges | before | after |
|---|---|---|
| 2 (one prefix) | 864M addr/s | 859M (−0.6%) |
| 29 (sixteen prefixes) | 752M addr/s | **849M (+12.9%)** |

Bisection is only valid on disjoint ranges, and prefixes can nest — every
`1Btcoin` address is also a `1Btc` address. Overlap is detected on the host and
the kernel is told to fall back to the linear scan, which is correct for any
arrangement. Below five ranges the scan is used anyway, since bisection's setup
costs more than it saves there.

The 0.6% on the single-prefix case is real, not noise, and is the price of the
extra branch. Sixteen patterns getting 12.9% back is worth it.

Two new gates: several prefixes in one run must each be found *and* attributed
to the right pattern (sorting permutes the ranges, so the index the kernel
reports no longer matches the order the prefixes were given), and nested
prefixes must still match on the linear path.

## 1.1.1

**Warn when the GPU is already busy.** Two searches on one card do not queue,
they interleave, and each gets about half the rate with nothing to say so. The
run looks healthy and the number is quietly halved, which is easy to blame on
whatever you were about to measure — it cost an hour of confused benchmarking
here before anyone noticed the card had two tenants.

`npm run gpu` now lists any other process on the device before starting, says
to expect roughly 1/n of the usual rate, and repeats the caveat next to the
final number. `test/gpu.js` prints the same note. Measured on an idle card the
sustained rate is flat: 863–880M addr/s over 100 seconds, 2745 MHz, 148 W,
68 °C, no thermal decay.

## 1.1.0

**Twelve addresses per curve step — 495M → 865M addresses/sec (1.75x).**

The expensive part of the search was never hashing an address, it was getting a
point to hash: an affine addition needs a modular inverse. secp256k1's
endomorphism gives five more points almost free — `λP` is exactly `(β·x, y)`,
one field multiply, and `−P = (x, −y)` is a subtraction. One inversion now buys
six points, each hashed in both encodings.

The curve was 46% of the run time and is now 14%; the search is hash-bound,
which is the floor for this problem. `λ³ = 1`, so six is all of them.

- The kernel reports which of the six matched and the host reconstructs the
  private key from it. `confirm()` re-derives the address from that key and
  compares it against the one that matched, so a wrong variant fails loudly
  rather than reporting a key that does not own its address.
- `test/gpu.js` plants a published key and requires each of the six variants to
  be found *and* correctly attributed, and asserts the twelve addresses really
  are distinct.

**Profiling, and what it rules out.** `-DPROFILE_STAGE=1|2|3`,
`-DHASH_FORMS=1|2|3` and `-DVARIANTS=1|2|6` build instrumented kernels. Three
ideas were measured and rejected: specialising the uncompressed key's padding
SHA-256 block (≤5%, nvcc already folds it), dropping the uncompressed encoding
(33% *slower* per address), and returning digests as words rather than bytes
(no measurable change).

**Output.**

- Rates now say whether they are keys or addresses. They differ by 12x, and the
  summary previously showed one of each without labelling either.
- Difficulty, estimate and the age-of-the-universe comparison are on separate
  lines; difficulty above 1e15 prints in scientific notation; the estimate ladder
  continues past days into years rather than stopping at `1.4e+44 days`.

**Licensing and credit.** Added the `LICENSE` the repo never had (MIT), a
`NOTICE` carrying vanitygen's AGPL-3.0 attribution to samr7, and a Credits
section. The repo is public.

**Fixed** a flaky test of my own making: the range sampling check required every
prefix to produce a hit, but hit rates span 1-in-70 to 1-in-25,000, so it failed
at random about one run in five.

## 1.0.0

Initial release.

- Vanity address search on the CPU with [vanitygen](https://github.com/samr7/vanitygen)
  and on the GPU with `cuda/vanity.cu`.
- A Base58 prefix as a numeric range on the hash160, so the GPU never computes
  Base58 or a checksum — the prefix test costs 1.6% of the run.
- Every result from either engine re-derived with `src/keys.js` before it is
  reported.
- Two bugs fixed in vanitygen, published in `vendor/patches/`: a crash after a
  successful match (unjoined worker threads, fatal under OpenSSL 3), and
  prefixes with exactly three leading `1`s never matching at one of their two
  Base58 rendering lengths.
