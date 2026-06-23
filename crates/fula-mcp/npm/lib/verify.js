'use strict';

const fs = require('fs');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// SECURITY-CRITICAL: SHA-256 verification against the BUNDLED checksums.json.
//
// The trust root is the npm package itself (published via OIDC trusted
// publishing with provenance). `checksums.json` ships INSIDE the package and
// is written at release time, in the SAME workflow run that builds the
// binaries and uploads the Release. We verify a downloaded binary against the
// BUNDLED hash — NOT a hash refetched from the (mutable) GitHub Release, which
// would be circular (an attacker who can swap the Release binary could swap a
// co-located checksum too).
//
// Consequence: if the Release asset is swapped AFTER publish, the bundled hash
// no longer matches and we refuse to exec. (This does not, and cannot, defend
// against a compromise of the CI run that produces both the binary and the
// bundled checksum — that is documented as residual risk in the PR/README.)
// ---------------------------------------------------------------------------

/**
 * Compute the lowercase hex SHA-256 of a file, streaming (constant memory).
 * @param {string} filePath
 * @returns {Promise<string>} lowercase hex digest
 */
function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('error', reject);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

/**
 * Look up the expected SHA-256 for an asset from a parsed checksums object.
 *
 * Accepts EITHER shape:
 *   { "fula-mcp-x86_64-...": "<hex>", ... }                       (flat)
 *   { "checksums": { "fula-mcp-x86_64-...": "<hex>", ... }, ... } (wrapped)
 *
 * The wrapped form lets the workflow add metadata (version, tag) alongside the
 * map without breaking lookups.
 *
 * @param {object} checksums - parsed checksums.json
 * @param {string} assetName - the asset file name (== the map key)
 * @returns {string} lowercase hex expected digest
 * @throws {Error} EBADCHECKSUMS if the entry is missing/malformed.
 */
function expectedHashFor(checksums, assetName) {
  if (!checksums || typeof checksums !== 'object') {
    const err = new Error('[fula-mcp] checksums.json is missing or not an object.');
    err.code = 'EBADCHECKSUMS';
    throw err;
  }
  const map =
    checksums.checksums && typeof checksums.checksums === 'object'
      ? checksums.checksums
      : checksums;
  const raw = map[assetName];
  if (typeof raw !== 'string') {
    const err = new Error(
      `[fula-mcp] No bundled checksum for asset "${assetName}". ` +
        `This npm package is missing checksums for your platform — please ` +
        `report it at https://github.com/functionland/fula-api/issues`
    );
    err.code = 'EBADCHECKSUMS';
    throw err;
  }
  // Normalize: allow an optional "sha256:" prefix and surrounding whitespace,
  // lowercase, and require exactly 64 hex chars.
  const hex = raw.trim().replace(/^sha256:/i, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    const err = new Error(
      `[fula-mcp] Bundled checksum for "${assetName}" is not a valid SHA-256 hex digest.`
    );
    err.code = 'EBADCHECKSUMS';
    throw err;
  }
  return hex;
}

/**
 * Load + parse the bundled checksums.json shipped with the package.
 * @param {string} checksumsPath - absolute path to the bundled checksums.json
 * @returns {object}
 * @throws {Error} EBADCHECKSUMS if absent/unparseable.
 */
function loadChecksums(checksumsPath) {
  let text;
  try {
    text = fs.readFileSync(checksumsPath, 'utf8');
  } catch (e) {
    const err = new Error(
      `[fula-mcp] Could not read bundled checksums.json at ${checksumsPath}: ${e.message}`
    );
    err.code = 'EBADCHECKSUMS';
    throw err;
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    const err = new Error(`[fula-mcp] checksums.json is not valid JSON: ${e.message}`);
    err.code = 'EBADCHECKSUMS';
    throw err;
  }
}

/**
 * Constant-time-ish comparison of two equal-length lowercase hex strings.
 * (Both are already 64-char hex by construction; timing is not a real concern
 * for a public checksum, but we use timingSafeEqual to avoid any doubt.)
 * @param {string} aHex
 * @param {string} bHex
 * @returns {boolean}
 */
function hexEqual(aHex, bHex) {
  if (aHex.length !== bHex.length) return false;
  const a = Buffer.from(aHex, 'hex');
  const b = Buffer.from(bHex, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Verify a file on disk against the bundled expected hash for `assetName`.
 * @param {string} filePath - file to verify
 * @param {string} assetName - the asset key in checksums.json
 * @param {object} checksums - parsed checksums.json
 * @returns {Promise<{ok:boolean, expected:string, actual:string}>}
 *   Resolves with ok=true/false; throws only on bad checksums input or read error.
 */
async function verifyFile(filePath, assetName, checksums) {
  const expected = expectedHashFor(checksums, assetName);
  const actual = await sha256File(filePath);
  return { ok: hexEqual(expected, actual), expected, actual };
}

module.exports = {
  sha256File,
  expectedHashFor,
  loadChecksums,
  hexEqual,
  verifyFile,
};
