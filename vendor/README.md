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

The thread fix is not cosmetic. vanitygen never joined its worker threads, so
`main()` returned while they were still hashing. Under OpenSSL 1.0 that was
merely untidy. Under OpenSSL 3, `SHA256()` fetches its digest from the library
context under a lock, so a worker still running when `exit()` triggers
`OPENSSL_cleanup()` dereferences a freed lock and the process dies — *after*
printing a match, about one run in three on this machine. That is the shape of
bug that gets written off as "it worked, the shell just looked odd".

### What is not patched

`oclvanitygen` and `oclvanityminer` are **not built**. `oclengine.c` declares
its own copy of OpenSSL's private `struct ec_point_st` and reads the
Montgomery-form coordinates straight out of it. That layout changed in OpenSSL
1.1 and again in 3.0, so guessing at it risks silent memory corruption rather
than a clean failure. Porting it properly means going through
`EC_POINT_get_affine_coordinates()` and re-Montgomeryising with a
`BN_MONT_CTX` — a rewrite, not a fix.

There is little reason to want it here. vanitygen's OpenCL engine is 2013-era;
this project already has a CUDA pipeline doing 249M keys/sec, and adding prefix
matching to `cuda/hunt.cu` would beat it by a wide margin. See "GPU vanity
search" in the top-level README.
