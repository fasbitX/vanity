# vendor/

Third-party programs this project drives, but does not contain.

## vanitygen

[samr7/vanitygen](https://github.com/samr7/vanitygen) searches for a Bitcoin
address matching a pattern. It is used here two ways: as a vanity address
generator (`npm run vanity`), and as an **independent implementation** of the
same key pipeline this project builds by hand — an OpenSSL-based second opinion
on our secp256k1, hash160 and Base58Check.

It is **not** committed here. vanitygen is AGPL-3.0 and this project is MIT, so
`scripts/build-vanitygen.sh` clones it into `vendor/vanitygen/` (gitignored) at
a pinned commit, applies the patch below, and builds it. It runs as a separate
process; nothing from it is linked into this project, and the licences stay
apart.

### patches/0001-openssl3-pcre2.patch

vanitygen was last touched in 2013 and does not compile against anything
current. The patch is the minimum to build `vanitygen` and `keyconv` on
OpenSSL 3.x and PCRE2, plus one genuine bug fix. Its header explains each
change; the short version:

| change | why |
|---|---|
| stack/struct `BIGNUM` → heap pointers | `BIGNUM` became opaque in OpenSSL 1.1 |
| `EVP_CIPHER` field access → accessors | same, for `EVP_CIPHER` |
| local `BN_MASK2` | moved into OpenSSL's private headers |
| `pcre1compat.h` | PCRE1 is end-of-life and gone from Ubuntu 24.04 |
| `start_threads()` joins its workers | **crash fix**, see below |
| `get_prefix_ranges()` walks candidate lengths | **matching fix**, see below |

The thread fix is not cosmetic. vanitygen never joined its worker threads, so
`main()` returned while they were still hashing. Under OpenSSL 1.0 that was
merely untidy. Under OpenSSL 3, `SHA256()` fetches its digest from the library
context under a lock, so a worker still running when `exit()` triggers
`OPENSSL_cleanup()` dereferences a freed lock and the process dies — *after*
printing a match, about one run in three on this machine. That is the shape of
bug that gets written off as "it worked, the shell just looked odd".

### It could not find some addresses at all

A prefix pins the address number to `v * 58^e .. (v+1) * 58^e - 1` for whichever
Base58 rendering length it is read at, and the eight-bit byte window the leading
`1`s imply admits more than one length. `get_prefix_ranges()` picked a fixed
pair; when the longer of the two lay entirely above the ceiling it dropped that
one, returned a single range, and never looked one length further down.

With exactly three leading `1`s that loses about 1.7% of the matching addresses.
Those ranges are what `vg_prefix_test()` compares against, so the addresses were
not merely under-counted in the reported difficulty — they were never found.

Demonstrated, not asserted: with the prefix `1112`, where the missing interval
is 8% of the total, a 45-second run now returns 293 addresses of which **20 lie
in the interval vanitygen previously could not reach**, and none lie outside
either. Difficulty agreement with `src/vanity-range.js` went from 54/75 prefixes
to 113/116; the three that still differ are `double` rounding in
`vg_prefix_get_difficulty()` above 2^53, not the ranges.

### What is not patched

`oclvanitygen` and `oclvanityminer` are **not built**. `oclengine.c` declares
its own copy of OpenSSL's private `struct ec_point_st` and reads the
Montgomery-form coordinates straight out of it. That layout changed in OpenSSL
1.1 and again in 3.0, so guessing at it risks silent memory corruption rather
than a clean failure. Porting it properly means going through
`EC_POINT_get_affine_coordinates()` and re-Montgomeryising with a
`BN_MONT_CTX` — a rewrite, not a fix.

There is little reason to want it here. vanitygen's OpenCL engine is 2013-era;
`cuda/vanity.cu` replaces it and is far faster than that engine ever was --
253.8M keys/sec, 507.6M addresses/sec. See the top-level README.
