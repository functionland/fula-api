'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const { resolveTarget, downloadUrl } = require('./targets');
const { loadChecksums, verifyFile, expectedHashFor, sha256File, hexEqual } = require('./verify');

const MAX_REDIRECTS = 5;

/**
 * Resolve the cache directory for a given version.
 * Prefers an XDG-ish per-user cache; falls back to a private dir under tmp.
 * @param {string} version
 * @param {object} [env] - defaults to process.env
 * @returns {string} absolute cache dir path (NOT yet created)
 */
function cacheDir(version, env) {
  env = env || process.env;
  // Allow an explicit override (useful for tests / locked-down environments).
  if (env.FULA_MCP_CACHE_DIR && env.FULA_MCP_CACHE_DIR.trim()) {
    return path.join(env.FULA_MCP_CACHE_DIR, version);
  }
  let base;
  if (process.platform === 'win32') {
    base = env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    return path.join(base, 'fula-mcp', 'cache', version);
  }
  // XDG on linux; ~/Library/Caches on macOS; ~/.cache fallback.
  if (env.XDG_CACHE_HOME && env.XDG_CACHE_HOME.trim()) {
    base = env.XDG_CACHE_HOME;
  } else if (process.platform === 'darwin') {
    base = path.join(os.homedir(), 'Library', 'Caches');
  } else {
    base = path.join(os.homedir(), '.cache');
  }
  return path.join(base, 'fula-mcp', version);
}

/**
 * Create the cache dir with restrictive permissions (best effort; mode is a
 * no-op on Windows). Symlink components in the parent path are NOT followed for
 * the leaf we create (we always lstat the final binary before trusting it).
 * @param {string} dir
 */
function ensureCacheDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

/**
 * Reject a path that is a symlink (TOCTOU / symlink-attack hardening). Returns
 * fs.Stats if it is a regular file, or null if the path does not exist.
 * @param {string} p
 * @returns {fs.Stats|null}
 * @throws {Error} ESYMLINK if the path exists but is a symlink/non-regular file.
 */
function lstatRegularOrNull(p) {
  let st;
  try {
    st = fs.lstatSync(p);
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
  if (st.isSymbolicLink() || !st.isFile()) {
    const err = new Error(
      `[fula-mcp] Refusing to use cache entry that is not a regular file (possible symlink attack): ${p}`
    );
    err.code = 'ESYMLINK';
    throw err;
  }
  return st;
}

/**
 * GET a URL into a writable stream, following GitHub's redirect to the asset
 * CDN. Rejects on non-200 final status. Streams (constant memory).
 * @param {string} url
 * @param {fs.WriteStream} dest
 * @param {number} [redirectsLeft]
 * @returns {Promise<void>}
 */
function httpsGetTo(url, dest, redirectsLeft) {
  if (redirectsLeft === undefined) redirectsLeft = MAX_REDIRECTS;
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      { headers: { 'User-Agent': 'fula-mcp-npm-installer', Accept: 'application/octet-stream' } },
      (res) => {
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400 && res.headers.location) {
          res.resume(); // drain
          if (redirectsLeft <= 0) {
            reject(new Error('[fula-mcp] Too many redirects while downloading binary.'));
            return;
          }
          const next = new URL(res.headers.location, url).toString();
          resolve(httpsGetTo(next, dest, redirectsLeft - 1));
          return;
        }
        if (status !== 200) {
          res.resume();
          reject(
            new Error(
              `[fula-mcp] Download failed with HTTP ${status} for ${url}. ` +
                `The release asset may not exist yet for this version/platform.`
            )
          );
          return;
        }
        res.pipe(dest);
        dest.on('finish', () => dest.close((err) => (err ? reject(err) : resolve())));
        res.on('error', reject);
        dest.on('error', reject);
      }
    );
    req.on('error', reject);
    req.setTimeout(60_000, () => req.destroy(new Error('[fula-mcp] Download timed out after 60s.')));
  });
}

/**
 * Default byte-fetch: download `url` into the file at `tmpPath` (which is
 * already exclusively created with mode 0o600). Streams over https with
 * redirect handling. Overridable via `opts.download` for tests.
 * @param {string} url
 * @param {string} tmpPath
 * @returns {Promise<void>}
 */
function defaultDownload(url, tmpPath) {
  const dest = fs.createWriteStream(tmpPath, { flags: 'r+' });
  return httpsGetTo(url, dest);
}

/**
 * Ensure the verified binary exists in the cache and return its absolute path.
 *
 * Flow (idempotent + hardened):
 *  1. resolveTarget -> assetName / binName.
 *  2. If cached binary exists, is a regular file (not symlink), and its SHA-256
 *     matches the bundled checksum -> return it (no network).
 *  3. Otherwise download to a freshly-created (wx, random-named) temp file in
 *     the SAME dir, hash it, compare to the bundled checksum.
 *     - mismatch -> delete temp, throw ECHECKSUM (refuse).
 *     - match -> chmod 0o755 (unix), atomic rename into place.
 *  4. Re-lstat the final path and return it. (Caller re-verifies before exec.)
 *
 * @param {object} opts
 * @param {string} opts.version       - package version (no leading 'v')
 * @param {string} opts.checksumsPath - absolute path to bundled checksums.json
 * @param {string} [opts.platform]    - default process.platform
 * @param {string} [opts.arch]        - default process.arch
 * @param {object} [opts.env]         - default process.env
 * @param {(msg:string)=>void} [opts.log] - default writes to process.stderr
 * @param {(url:string,tmpPath:string)=>Promise<void>} [opts.download]
 *        - byte-fetch override (default = real https download). Tests inject
 *          this to drive the verify/exec/refuse branches without a network.
 * @returns {Promise<string>} absolute path to the verified cached binary
 */
async function ensureBinary(opts) {
  const platform = opts.platform || process.platform;
  const arch = opts.arch || process.arch;
  const env = opts.env || process.env;
  const log = opts.log || ((m) => process.stderr.write(m + '\n'));
  const download = opts.download || defaultDownload;

  const { assetName, binName } = resolveTarget(platform, arch);
  const checksums = loadChecksums(opts.checksumsPath);
  // Fail fast if we have no expected hash for this asset (clear error).
  const expected = expectedHashFor(checksums, assetName);

  const dir = cacheDir(opts.version, env);
  const finalPath = path.join(dir, binName);

  // 2. Cached + valid?
  const existing = lstatRegularOrNull(finalPath);
  if (existing) {
    const actual = await sha256File(finalPath);
    if (hexEqual(expected, actual)) {
      return finalPath;
    }
    log(`[fula-mcp] Cached binary failed checksum; re-downloading.`);
    fs.rmSync(finalPath, { force: true });
  }

  ensureCacheDir(dir);

  // 3. Download to a private, exclusively-created temp file in the same dir.
  const url = downloadUrl(opts.version, assetName);
  const tmpPath = path.join(dir, `.${binName}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  log(`[fula-mcp] Downloading ${assetName} (${opts.version}) ...`);

  // 'wx' => fail if it already exists (no clobber of an attacker-planted file).
  // Create+close so the injectable downloader can open it with its own handle.
  try {
    fs.closeSync(fs.openSync(tmpPath, 'wx', 0o600));
  } catch (e) {
    throw new Error(`[fula-mcp] Could not create temp file ${tmpPath}: ${e.message}`);
  }

  try {
    await download(url, tmpPath);
  } catch (e) {
    fs.rmSync(tmpPath, { force: true });
    throw e;
  }

  // 4. Verify the freshly-downloaded bytes against the BUNDLED checksum.
  const result = await verifyFile(tmpPath, assetName, checksums);
  if (!result.ok) {
    fs.rmSync(tmpPath, { force: true });
    const err = new Error(
      `[fula-mcp] SECURITY: checksum mismatch for ${assetName}.\n` +
        `  expected (bundled): ${result.expected}\n` +
        `  actual (downloaded): ${result.actual}\n` +
        `Refusing to execute. The downloaded binary does NOT match the checksum ` +
        `shipped in this npm package. Do not run it. Please report this at ` +
        `https://github.com/functionland/fula-api/issues`
    );
    err.code = 'ECHECKSUM';
    throw err;
  }

  // Make executable on unix (no-op semantics on Windows).
  if (process.platform !== 'win32') {
    fs.chmodSync(tmpPath, 0o755);
  }

  // Atomic rename within the same directory.
  fs.renameSync(tmpPath, finalPath);

  // Re-check it is a regular file post-rename.
  lstatRegularOrNull(finalPath);
  log(`[fula-mcp] Verified and cached at ${finalPath}`);
  return finalPath;
}

module.exports = {
  cacheDir,
  ensureCacheDir,
  lstatRegularOrNull,
  ensureBinary,
};
