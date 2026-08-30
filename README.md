# vanity

Bitcoin vanity address search — an address that starts with something you chose,
`1Btcoin…` rather than `1Kx7…`.

**Two separate engines**, not one ported from one place to another:

- **[vanitygen](https://github.com/samr7/vanitygen), on the CPU.** By
  [samr7](https://github.com/samr7), 2011-2013, AGPL-3.0. Third-party and
  OpenSSL-based. It stays on the CPU. What was done to it was make it
  *build* on a current system — it targets OpenSSL 1.0 and PCRE1, neither of
  which exists here — and fix two real bugs found along the way. It is still
  useful beyond searching: because it derives addresses with OpenSSL, it is an
  independent implementation to check our own maths against.
- **`cuda/vanity.cu`, on the GPU.** Written here, from scratch, in CUDA. Does
  the same job **215x faster**. It is not vanitygen compiled for a GPU and
  shares no code with it.

Neither is believed on its own: every result from either is re-derived from
first principles before it is reported.

```bash
npm install
./scripts/create-db.sh        # once: creates the `vanity` role, database and .env
npm run init-db
npm run build                 # vanitygen (cloned + patched) and the CUDA kernel

npm run gpu -- 1Btcoin        # ~13 seconds
npm run vanity -- 1Btc        # the CPU tool
npm run matches               # what has been found
```

## Requirements

- **Linux.** Developed on Ubuntu 24.04.
- **An NVIDIA GPU** for the fast engine — CUDA, built for `sm_89` (Ada / RTX
  40-series) by default. Other architectures: `make -C cuda ARCH=sm_86`. The
  CPU engine needs no GPU at all.
- **Node.js 20+**, **PostgreSQL**, and a C toolchain with `libssl-dev` and
  `libpcre2-dev` to build vanitygen.

Quoted rates are from an RTX 4070 SUPER and a Ryzen 9 9950X. Yours will differ;
the search prints its actual rate as it runs.

### What was *not* done

Two things get assumed, and neither is true here:

- **vanitygen was not moved to the GPU.** Its own GPU engine, `oclvanitygen`,
  is deliberately not built — it reads OpenSSL's private `struct ec_point_st`,
  whose layout changed in 1.1 and again in 3.0, so reproducing it would be
  guesswork that corrupts memory rather than failing loudly. `cuda/vanity.cu`
  exists instead, and is far faster than that engine ever was.
- **Nothing here uses OpenCL.** The upgrade was to **OpenSSL 3.0** — the crypto
  library — not OpenCL, the GPU API. Easy to misread, completely different
  things. The GPU work is CUDA (`nvcc -arch=sm_89`); there is no OpenCL in this
  project at all.

## Rate

| engine | keys/s | addresses/s |
|---|---|---|
| vanitygen, 32 threads of a 9950X | 2.36M | 2.36M |
| `cuda/vanity.cu`, RTX 4070 SUPER | **253.8M** | **507.6M** |

107x the keys, **215x the addresses** — the second factor is larger because the
kernel searches both public-key encodings, while vanitygen only ever searched
the uncompressed one. `1Btcoin` takes 13 seconds on the GPU and about 1.8 hours
on the CPU.

## The trick: no Base58 on the GPU

Matching "does this address start with `1Btc`" looks like it needs the address,
which needs a checksum, which is two more SHA-256s per candidate. It does not.

The 25-byte address buffer is

```
0x00 || hash160 (20 bytes) || checksum (4 bytes)
```

so as a number it is exactly `A = hash160 * 2^32 + checksum`. Base58 is
positional, so fixing the leading characters pins `A` to a contiguous **range** —
and because the checksum only ever occupies the low 32 bits, that range maps
straight onto the hash160 the kernel is already holding.

Prefix matching is therefore a 160-bit comparison against precomputed bounds,
and it settles on the first word almost every time. It is cheaper than a Bloom
probe.

Shifting the checksum off rounds both bounds outward, so the kernel admits at
most one extra hash160 at each end of each range. A reported key is a
**candidate**: `src/gpu-vanity.js` re-derives it with `src/keys.js` and checks
the real address before anything is reported.

## Where the time goes

Measured by differencing instrumented kernels — `-DPROFILE_STAGE=1|2|3` builds
one that stops after the curve, one that stops after hashing, one that does
everything. Each stage still consumes its result so the compiler cannot delete
the work that produced it. 120 launches each, repeated, RTX 4070 SUPER, idle:

| stage | ns/key | share |
|---|---|---|
| elliptic curve — one affine addition + ⅛ of an inverse | 1.82 | **46%** |
| hash160 ×2 — three SHA-256 blocks and two RIPEMD-160 | 2.10 | **53%** |
| prefix range test | 0.06 | **1.6%** |
| **total** | **3.95** | 253 Mkey/s, 507M addr/s |

The prefix test costing 1.6% is the whole argument for the range approach: the
thing that would have been expensive — Base58 and a checksum per candidate — is
not done at all.

`-DHASH_FORMS=1|2|3` prices the two encodings separately:

| what is hashed | ns/key | ns/**address** |
|---|---|---|
| compressed only — one SHA block + RIPEMD | 2.95 | 2.95 |
| uncompressed only — two SHA blocks + RIPEMD | 3.16 | 3.16 |
| **both (what it does)** | 3.95 | **1.97** |

Two things fall out of that. The second SHA-256 block of the uncompressed key —
one data byte and sixty-three bytes of padding — costs only 0.20 ns, so nvcc has
already folded most of the constant schedule away and specialising it by hand is
worth at most 5%. And hashing both encodings costs 2.13 ns where hashing them
separately costs 2.47: the two chains are independent, so they interleave and
hide each other's latency. Dropping the uncompressed form would make the search
**33% slower per address**, not faster.

### Known headroom

The curve is charged to one key but pays for two addresses, and it need not
stop there. secp256k1 has an efficiently computable endomorphism: for
`λ = 0x5363ad4c…` and `β = 0x7ae96a2b…`, the point `λP` is exactly
`(β·x, y)` — a **single field multiplication** produces a second valid point,
whose private key is `λk mod n`. Negation is cheaper still: `−P = (x, −y)`,
private key `n − k`.

So one curve step could yield P, −P, λP, −λP, λ²P and −λ²P — six points, twelve
addresses — for the price of a handful of field operations instead of six
inversions. The curve's 1.82 ns would amortise over twelve addresses rather than
two, leaving the search hash-bound at its floor of about 1.06 ns/address.

That is roughly **1.9x the current address rate**, and it is the only remaining
change on the table worth that much. It is not implemented: every extra point
needs its private key reconstructed on the host, and the identity has been
verified against `src/secp256k1.js` but not yet built into the kernel.

## Nothing is taken on trust

`src/secp256k1.js`, `hash.js`, `base58.js` and `keys.js` implement the key
pipeline from first principles — curve arithmetic in BigInt, SHA-256 and
RIPEMD-160, Base58Check. They are the oracle. Everything else answers to them:

| what it produces | what checks it |
|---|---|
| vanitygen (OpenSSL) | `src/keys.js` re-derives every reported key |
| the CUDA kernel | `src/keys.js` re-derives every candidate |
| `src/vanity-range.js` bounds | Base58 itself, by encoding the boundaries; and vanitygen's difficulty |
| `src/keys.js` | published Bitcoin test vectors (`npm test`) |

That is not ceremony. vanitygen is 2013 code that only builds here because of a
hand-applied OpenSSL 3 port, and the kernel is 200 lines of hand-written field
arithmetic. Either could produce a private key that does not derive the address
claimed for it, and that failure looks exactly like success.

The tests are built to fail. Each one checks that the verifier **accepts** a
published key/address pair *and* **rejects** a wrong one — a mangled address, an
address belonging to a different key, a mismatched public key, a result that
does not satisfy its own pattern. A check that cannot fail proves nothing.

```bash
npm test               # published vectors: the oracle itself
npm run test:range     # the prefix range maths
npm run test:vanitygen # the CPU tool, and that the check can fail
npm run test:gpu       # a planted key the kernel must find, and must not
npm run test:all
```

## Two bugs found in vanitygen

Both are fixed in `vendor/patches/0001-openssl3-pcre2.patch`, alongside the
OpenSSL 3 / PCRE2 port needed to build 2013 code at all.

**It crashed after finding a match.** `start_threads()` never joined its worker
threads, so `main()` returned while they were still hashing. Under OpenSSL 1.0
that was untidy. Under OpenSSL 3, `SHA256()` fetches its digest from the library
context under a lock, so a worker still running when `exit()` triggers
`OPENSSL_cleanup()` dereferences a freed lock and dies with SIGSEGV — *after*
printing the match, about one run in three. Found under AddressSanitizer; gdb
never reproduced it.

**It could not find some addresses at all.** A prefix pins the address number to
`v * 58^e .. (v+1) * 58^e - 1` for whichever rendering length it is read at, and
the eight-bit byte window the leading `1`s imply admits more than one length.
`get_prefix_ranges()` picked a fixed pair; when the longer of the two lay
entirely above the ceiling it dropped that one, returned a single range, and
never looked one length further down. For a prefix with exactly three leading
`1`s that costs about 1.7% of the matching addresses — and because those ranges
are what `vg_prefix_test()` compares against, they were not merely
under-reported, they were never found.

Demonstrated rather than asserted: with the prefix `1112`, where the missing
interval is 8% of the total, a 45-second run now returns 293 addresses of which
**20 lie in the interval vanitygen previously could not reach** and none lie
outside either. Difficulty agreement with our own implementation went from
54/75 prefixes to 113/116; the three that still differ are `double` rounding in
vanitygen's *reporting* above 2^53, not its ranges.

## Layout

| path | what |
|---|---|
| `src/secp256k1.js` `hash.js` `base58.js` `keys.js` | the pipeline from first principles — the oracle |
| `src/vanity-range.js` | a Base58 prefix as a numeric range on the hash160 |
| `src/vanitygen.js` | drives vanitygen and verifies everything it reports |
| `src/gpu-vanity.js` | drives the kernel and confirms every candidate |
| `cuda/vanity.cu` | the search: sequential walk, batched inversion, range test |
| `scripts/build-vanitygen.sh` | clone at a pinned commit, patch, build |
| `scripts/create-db.sh` | the one step that needs postgres superuser |
| `vendor/patches/` | the OpenSSL 3 / PCRE2 port and the two bug fixes |

## Storage

Postgres `vanity` on this machine, one table, `vanity_matches`. Credentials in
`.env` (gitignored, mode 600), written by `scripts/create-db.sh`.

A find is written to `VANITY.txt` **first** and the database second, so the key
material survives a database problem. Both are gitignored: they hold real
private keys.

```sql
SELECT pattern, address, engine, form, seconds FROM vanity_matches ORDER BY found_at;
```

## Credits

The CPU engine is **[vanitygen](https://github.com/samr7/vanitygen)** by
**[samr7](https://github.com/samr7)** — Copyright (C) 2011
`samr7@cs.washington.edu`, AGPL-3.0. It has been the reference vanity address
generator since 2011, it is still fast and still correct thirteen years later,
and the design of the search here owes a lot to reading it. This project would
have been a much longer road without it.

It is used at upstream commit
[`cd1a728`](https://github.com/samr7/vanitygen/commit/cd1a7282431dcf7e522777976aa18728ee5bb7be),
the last one, from 2013.

### The patch, offered back

`vendor/patches/0001-openssl3-pcre2.patch` is a modification of vanitygen and
is therefore AGPL-3.0 itself, as its header says. It is here in the open so
anyone else stuck building 2013 code can take it. It does three things:

1. makes it compile against OpenSSL 3.x and PCRE2, neither of which existed in
   the form it was written for;
2. fixes a crash after a successful match (unjoined worker threads);
3. fixes prefixes with exactly three leading `1`s never matching at one of
   their two possible Base58 rendering lengths.

(2) and (3) are bugs in vanitygen itself, not artefacts of the port. Upstream
has been dormant since 2013, so they are published here rather than filed.

## Licensing

This project is **MIT** (see `LICENSE`; third-party attribution in `NOTICE`).
vanitygen is **AGPL-3.0** and is
deliberately **not vendored**: `scripts/build-vanitygen.sh` clones it from
upstream at a pinned commit into `vendor/vanitygen/` (gitignored), applies the
patch, and builds it. It is executed as a separate process and never linked, so
the two licences stay apart. Only the patch is tracked here, and it carries
vanitygen's licence.

Only `vanitygen` and `keyconv` are built from it — see "What was *not* done"
above for why its OpenCL engine is left alone.

## Security posture

Private keys are stored unencrypted and the BigInt arithmetic is not
constant-time. This is a search tool, not a wallet. An address you intend to
hold funds on should have its key imported into a real wallet and this copy
destroyed.
