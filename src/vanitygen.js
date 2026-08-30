'use strict';
/**
 * vanitygen, driven as a subprocess and checked against our own arithmetic.
 *
 * vanitygen searches for an address matching a pattern, using OpenSSL for the
 * curve and the hashing. That makes it an *independent implementation* of the
 * same pipeline this project builds by hand -- which is exactly the kind of
 * oracle the rest of the repo insists on, pointed the other way round.
 *
 * So nothing vanitygen prints is taken at face value. Every reported match is
 * put back through src/keys.js: decode the WIF, multiply by G with our own
 * secp256k1, hash160 it with our own SHA-256 and RIPEMD-160, Base58Check it
 * with our own encoder, and require that the address that falls out is the one
 * vanitygen claimed. A disagreement means one of the two is wrong, and either
 * way the result is not usable.
 *
 * That is not a theoretical concern here: vanitygen is a 2013 program and only
 * builds on this machine because of the OpenSSL 3 port in
 * vendor/patches/. Silent breakage in a hand-applied port to
 * bignum code is precisely the failure this check exists to catch.
 */
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { fromWIF, deriveKeyPair, validateAddress } = require('./keys');

const ROOT = path.join(__dirname, '..');
const BIN = process.env.VANITYGEN_BIN || path.join(ROOT, 'vendor', 'vanitygen', 'vanitygen');

/** Where a find is written before it goes anywhere near the database. */
const VANITY_FILE = process.env.VANITY_FILE || path.join(ROOT, 'VANITY.txt');

/** The Base58 alphabet, minus the characters Bitcoin drops (0 O I l). */
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

class VanitygenError extends Error {}

function binaryPath() {
  if (!fs.existsSync(BIN)) {
    throw new VanitygenError(
      `vanitygen is not built at ${BIN}\n` +
      '  run: ./scripts/build-vanitygen.sh');
  }
  return BIN;
}

/**
 * A prefix is only searchable if every character is in the Base58 alphabet and
 * the address version byte can actually produce it. vanitygen says so itself
 * ("Prefix ... not possible"), but it says so on stderr and then carries on
 * with the remaining patterns, so we check first and fail loudly.
 */
function validatePrefix(pfx) {
  if (!pfx.startsWith('1')) {
    throw new VanitygenError(
      `prefix '${pfx}': mainnet P2PKH addresses start with 1, so the pattern must too`);
  }
  for (const c of pfx.slice(1)) {
    if (!B58.includes(c)) {
      throw new VanitygenError(
        `prefix '${pfx}': '${c}' is not in the Base58 alphabet (0 O I l are excluded)`);
    }
  }
  return pfx;
}

/**
 * Ask vanitygen what a pattern costs.
 *
 * Kept as the *cross-check* on src/vanity-range.js, not as the source of the
 * number. Two reasons to prefer ours for anything that matters:
 *
 *   - vg_prefix_get_difficulty() returns a C double, so any difficulty above
 *     2^53 is rounded on its way to being printed (173346595075428786 comes
 *     out as ...800). Ours is exact BigInt arithmetic.
 *   - it costs a process spawn.
 *
 * They agree otherwise, which is the point: two implementations of the same
 * maths by different routes. They did not always -- see the range fix in
 * vendor/patches -- and test/range.js exists to notice if they stop.
 */
function estimateDifficulty(pattern, { mode = 'prefix' } = {}) {
  return new Promise((resolve, reject) => {
    const args = ['-n'];
    if (mode === 'regex') args.push('-r');
    if (mode === 'prefix-ci') args.push('-i');
    args.push(pattern);

    let child;
    try {
      child = spawn(binaryPath(), args, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      return reject(e);
    }

    let seen = '';
    let settled = false;
    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      child.kill('SIGTERM');
      fn(arg);
    };

    const look = (d) => {
      seen += d;
      const m = seen.match(/Difficulty:\s*(\d+)/);
      if (m) finish(resolve, Number(m[1]));
    };

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', look);
    child.stderr.on('data', look);
    child.on('error', (e) => finish(reject, new VanitygenError(
      `could not run ${BIN}: ${e.message}`)));
    child.on('close', () => finish(reject, new VanitygenError(
      `vanitygen did not report a difficulty for '${pattern}'`)));
  });
}

/**
 * Check one reported match against our own implementation.
 *
 * Returns the fully derived key pair on success. Throws on any disagreement --
 * there is no "close enough" here.
 */
function verifyMatch(reported, { pattern, mode = 'prefix' } = {}) {
  const { address, privkey } = reported;

  if (!address || !privkey) {
    throw new VanitygenError('incomplete match: need both an address and a private key');
  }

  // 1. The address has to be a well-formed mainnet P2PKH address at all.
  //    This is a checksum test, so it catches a mangled line on its own.
  if (!validateAddress(address)) {
    throw new VanitygenError(`address ${address} is not a valid mainnet P2PKH address`);
  }

  // 2. Decode the WIF with our Base58Check decoder. vanitygen 0.22 only emits
  //    uncompressed keys, so anything else means we are parsing the wrong tool.
  let decoded;
  try {
    decoded = fromWIF(privkey);
  } catch (e) {
    throw new VanitygenError(`could not decode private key ${privkey}: ${e.message}`);
  }
  if (decoded.compressed) {
    throw new VanitygenError(
      `private key ${privkey} is in compressed form; vanitygen 0.22 emits uncompressed keys`);
  }

  // 3. Re-derive from scratch: k*G on our secp256k1, our hash160, our Base58.
  const derived = deriveKeyPair(decoded.key);

  // 4. The whole point. If these differ, the port is broken or the parse is.
  if (derived.addressUncompressed !== address) {
    throw new VanitygenError(
      'address mismatch -- vanitygen and src/keys.js disagree on the same private key\n' +
      `  private key   ${derived.privateKeyHex}\n` +
      `  vanitygen     ${address}\n` +
      `  src/keys.js   ${derived.addressUncompressed}`);
  }

  // 5. Optional extra material from -v, checked when present. The public key
  //    is an independent witness: it catches a break in the curve arithmetic
  //    even in the (impossible) case that two different points hashed alike.
  if (reported.pubkeyHex &&
      reported.pubkeyHex.toLowerCase() !== derived.publicKeyUncompressed) {
    throw new VanitygenError(
      'public key mismatch -- the curve arithmetic disagrees\n' +
      `  vanitygen     ${reported.pubkeyHex.toLowerCase()}\n` +
      `  src/keys.js   ${derived.publicKeyUncompressed}`);
  }
  if (reported.privkeyHex) {
    // vanitygen prints this with BN_bn2hex, which emits the *minimal* byte
    // representation: a key with a leading zero byte comes out 62 hex digits,
    // not 64. Left-pad before comparing, or roughly one key in 256 is reported
    // as a mismatch when nothing is wrong.
    const reportedHex = reported.privkeyHex.toLowerCase().padStart(64, '0');
    if (reportedHex !== derived.privateKeyHex) {
      throw new VanitygenError(
        'private key mismatch -- the WIF and the raw hex are not the same key\n' +
        `  vanitygen hex ${reportedHex}\n` +
        `  from the WIF  ${derived.privateKeyHex}`);
    }
  }

  // 6. Finally: is this actually what was asked for? A tool that returns a
  //    valid key for the wrong pattern has still failed.
  if (pattern !== undefined && !matchesPattern(address, pattern, mode)) {
    throw new VanitygenError(
      `address ${address} does not satisfy the ${mode} '${pattern}' it was found for`);
  }

  return derived;
}

function matchesPattern(address, pattern, mode) {
  if (mode === 'regex') return new RegExp(pattern).test(address);
  if (mode === 'prefix-ci') return address.toLowerCase().startsWith(pattern.toLowerCase());
  return address.startsWith(pattern);
}

/**
 * Pull `Pattern:` / `Address:` / `Privkey:` triples out of vanitygen's output.
 *
 * Progress ("[1.2 Mkey/s]...") goes to the same stream, separated by carriage
 * returns rather than newlines, so split on both and ignore anything that is
 * not one of the labelled fields. The parser is a small state machine because
 * the fields arrive on separate lines and a match is only complete once the
 * private key has landed.
 */
function createParser(onMatch) {
  let buf = '';
  let cur = {};

  const flushIfComplete = () => {
    if (cur.pattern !== undefined && cur.address && cur.privkey) {
      onMatch(cur);
      cur = {};
    }
  };

  return (chunk) => {
    buf += chunk;
    const parts = buf.split(/[\r\n]/);
    buf = parts.pop();

    for (const line of parts) {
      const m = line.match(/^\s*(Pattern|Address|Privkey|Pubkey \(hex\)|Privkey \(hex\)):\s*(.+?)\s*$/);
      if (!m) continue;
      switch (m[1]) {
        // A new Pattern line starts a new record; anything half-built before
        // it was never completed and is discarded rather than merged.
        case 'Pattern':        cur = { pattern: m[2] };  break;
        case 'Address':        cur.address = m[2];       break;
        case 'Pubkey (hex)':   cur.pubkeyHex = m[2];     break;
        case 'Privkey (hex)':  cur.privkeyHex = m[2];    break;
        case 'Privkey':        cur.privkey = m[2];       break;
      }
      flushIfComplete();
    }
  };
}

/**
 * Run vanitygen over one or more patterns.
 *
 * Every match is verified before the caller sees it. `onMatch` receives
 * `{ pattern, address, key }` where `key` is the full derived key pair from
 * src/keys.js -- not vanitygen's strings.
 *
 * Resolves when vanitygen exits. `stop()` on the returned handle terminates it.
 */
function run({
  patterns,
  mode = 'prefix',
  keep = false,
  threads,
  timeoutMs,
  // Stop once this many matches have been verified.
  //
  // With `keep`, vanitygen never stops on its own, and on an easy pattern it
  // produces matches far faster than they can be verified: verification is a
  // BigInt scalar multiplication, roughly a millisecond, against a search
  // finding one every few microseconds. The backlog grows without bound, the
  // event loop starves, and `timeoutMs` cannot even fire on schedule -- a 20s
  // run on a difficulty-1330 prefix took minutes and banked 6,891 rows.
  // Bounding the count is the fix; the timer alone is not enough.
  maxMatches = Infinity,
  resultFile = VANITY_FILE,
  onMatch = () => {},
  onProgress = () => {},
} = {}) {
  if (!Array.isArray(patterns) || patterns.length === 0) {
    throw new VanitygenError('at least one pattern is required');
  }
  if (mode === 'prefix' || mode === 'prefix-ci') patterns.forEach(validatePrefix);

  const args = [];
  // -v: also print the public key and the raw private key hex, which gives the
  //     verifier two more independent fields to check.
  args.push('-v');
  if (mode === 'regex') args.push('-r');
  if (mode === 'prefix-ci') args.push('-i');
  if (keep) args.push('-k');
  if (threads) args.push('-t', String(threads));
  // vanitygen appends to the result file and closes it per match, so the key
  // material is on disk before we ever look at it. Same discipline as
  // MATCHES.txt: the durable copy is written first, the database second.
  if (resultFile) args.push('-o', resultFile);
  args.push(...patterns);

  const child = spawn(binaryPath(), args, { stdio: ['ignore', 'pipe', 'pipe'] });

  const found = [];
  const errors = [];
  let stopping = false;

  const handle = (reported) => {
    // SIGTERM is not instant, and whatever vanitygen already wrote into the
    // pipe still arrives. Drop it, so --max means exactly max.
    if (stopping) return;
    try {
      const key = verifyMatch(reported, { pattern: reported.pattern, mode });
      const rec = { pattern: reported.pattern, mode, address: reported.address, key };
      found.push(rec);
      onMatch(rec);
      if (found.length >= maxMatches && !stopping) {
        stopping = true;
        child.kill('SIGTERM');
      }
    } catch (e) {
      // A verification failure is not a match that got away -- it is a bug.
      // Collect it and fail the run rather than dropping it on the floor.
      errors.push(e);
    }
  };

  // vanitygen prints "Difficulty: N" once at startup, so the live run hands us
  // the same figure estimateDifficulty() would have spawned a process to get.
  let difficulty = null;
  const feed = createParser(handle);
  const sink = (d) => {
    feed(d);
    if (difficulty === null) {
      const m = d.match(/Difficulty:\s*(\d+)/);
      if (m) difficulty = Number(m[1]);
    }
    onProgress(d);
  };
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', sink);
  child.stderr.on('data', sink);

  let timer = null;
  let timedOut = false;
  if (timeoutMs) {
    timer = setTimeout(() => { timedOut = true; child.kill('SIGTERM'); }, timeoutMs);
  }

  const done = new Promise((resolve, reject) => {
    child.on('error', (e) => {
      if (timer) clearTimeout(timer);
      reject(new VanitygenError(`could not run ${BIN}: ${e.message}`));
    });
    child.on('close', (code, signal) => {
      if (timer) clearTimeout(timer);
      if (errors.length) {
        const e = new VanitygenError(
          `${errors.length} match(es) failed verification against src/keys.js:\n` +
          errors.map((x) => x.message).join('\n'));
        e.failures = errors;
        return reject(e);
      }
      resolve({ found, difficulty, code, signal, timedOut, hitMax: stopping });
    });
  });

  return { child, done, stop: () => child.kill('SIGTERM') };
}

module.exports = {
  BIN, VANITY_FILE, VanitygenError,
  run, verifyMatch, createParser, estimateDifficulty, validatePrefix, matchesPattern,
};
