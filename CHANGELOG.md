# Changelog

## 1.2.2

**Difficulty is now counted over reachable addresses.** It divided the 2^192
space of 25-byte values, following vanitygen. Only **2^160** of those are
addresses anyone can reach — the four checksum bytes follow from the hash160
rather than being free — so the count is done on the hash160 instead.

For any prefix short enough to be worth searching the two agree exactly, and
`test/range.js` still holds us to vanitygen's figure across 85 prefixes. The
difference appears only once a prefix pins the address to fewer than 2^32
values, and there it is large: a complete 34-character address was reported as
2^192 when the real work is 2^160 — an overstatement by a factor of four
billion, on exactly the input where someone is checking whether it is possible.

Turned up while costing a thousand-card pool against puzzle #140: brute-forcing
one address is 2^160 addresses, 3.6e28 years at a thousand of these cards,
against 109 years for kangaroo on the same hardware — because kangaroo has the
public key and a bounded range and pays the square root, and vanity search has
neither.

**Restores two README sections** deleted by accident in 1.2.0, when a section
replacement spanned further than intended: "Two searches on one card halve each
other" and "Many patterns at once". Adds a Difficulty section, which this
repo's README had never carried.

## 1.2.1

**SHA-256 audited for the same fault as RIPEMD; it does not have it.** Both
loops are fully unrolled, `w[i]` and `SHA_K[i]` are compile-time indices, and
the round loop has no branch. The SASS shows no local-memory traffic from it.

**Corrects an earlier claim.** The uncompressed key's second SHA-256 block —
one data byte and sixty-three of padding — was recorded as cheap "because nvcc
already folds the constant schedule". It does not. Measured by skipping it, the
six of them cost **1.27 ns/step, 13.6% of the run**, and a padding block costs
the same as a full one. The schedule folds; the sixty-four rounds do not, and
they are the bulk. Still not worth specialising, but for the opposite reason.

Two more results recorded:

- Deriving β²x in place from βx cut spilling 40% (264 → 160 bytes) and did not
  move the rate at all. **The kernel is not spill-bound** — reverted.
- Dropping the uncompressed encoding is still a loss, 0.88 ns/address against
  0.78, but the margin narrowed from 33% to 11% once RIPEMD got cheaper.

Adds `-DSKIP_PAD_BLOCK` and `-DFORMS=1` measurement knobs, and removes a
`HASH_FORMS` knob that had become dead code when the inner loop was rewritten
for the endomorphism — it was still accepted on the command line and silently
did nothing, which produced one flatly wrong measurement before it was noticed.

## 1.2.0

**One `#pragma` was worth 44%: 859 → 1287M addresses/sec.**

RIPEMD-160 was 57% of the run. Its 80-round loop carried `#pragma unroll 16`,
and the consequences were invisible in the source:

- `X[RL[j]]` indexes the message block by a table value. Partly unrolled, `j` is
  a runtime value, so `RL[j]` is too, so `X` had to be addressable — it lived in
  **local memory**, off-chip, and all 160 rounds went there for a message word.
- `switch (r)` picking the round function stayed a real branch instead of
  folding, 160 times per hash and twelve hashes per curve step.

Removing the count makes `RL[j]`, `SL[j]` and `KL[r]` compile-time constants:
`X` stays in registers, the switch vanishes, and the tables fold into immediates
(`cmem` 4632 bytes → 16).

| stage | before | after |
|---|---|---|
| RIPEMD-160 | 7.98 ns/step | **3.24** |
| whole kernel | 14.0 ns/step | **9.32** |
| rate | 859M addr/s | **1287M** |

It is faster while *spilling* 164 bytes that the previous build did not — spill
counts are not the thing to optimise, wall-clock is. Partial unrolls are worse
than either extreme: at 20 and 40 the tables stay in constant memory and it runs
at 843M and 758M.

Also **rejected, measured twice**: a rolling 16-word SHA-256 message schedule in
place of `w[64]`. No change — nvcc already does that liveness analysis, and
registers went *up*, 238 to 242.

New profile: SHA-256 42%, RIPEMD-160 35%, curve 22%, prefix test 1.4%.

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
