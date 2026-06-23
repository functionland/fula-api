'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const { cacheDir, ensureBinary, lstatRegularOrNull } = require('../lib/install');
const { resolveTarget } = require('../lib/targets');

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// Build a self-contained sandbox: a private cache root + a checksums.json whose
// hash matches the bytes we plant, so we can exercise the cache-hit (no network)
// and tamper-reject paths WITHOUT a real download.
function sandbox(genuineBytes) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fula-mcp-install-'));
  const cacheRoot = path.join(root, 'cache');
  const version = '9.9.9';
  const env = { FULA_MCP_CACHE_DIR: cacheRoot };

  // Force a deterministic host so the test does not depend on the runner's OS.
  const platform = 'linux';
  const arch = 'x64';
  const { assetName, binName } = resolveTarget(platform, arch);

  const checksumsPath = path.join(root, 'checksums.json');
  fs.writeFileSync(
    checksumsPath,
    JSON.stringify({ version, checksums: { [assetName]: sha256(genuineBytes) } })
  );

  const dir = cacheDir(version, env);
  fs.mkdirSync(dir, { recursive: true });
  const finalPath = path.join(dir, binName);

  return { root, version, env, platform, arch, assetName, binName, checksumsPath, dir, finalPath };
}

test('ensureBinary returns the cached binary WITHOUT downloading when it matches the bundled checksum', async () => {
  const genuine = Buffer.from('GENUINE prebuilt fula-mcp');
  const sb = sandbox(genuine);
  // Pre-seed a VALID cached binary (simulates a prior verified download).
  fs.writeFileSync(sb.finalPath, genuine);

  const logs = [];
  const result = await ensureBinary({
    version: sb.version,
    checksumsPath: sb.checksumsPath,
    platform: sb.platform,
    arch: sb.arch,
    env: sb.env,
    log: (m) => logs.push(m),
  });

  assert.equal(result, sb.finalPath, 'returns the cached path');
  // No download happened (we never started a server). Assert no "Downloading" log.
  assert.ok(!logs.some((l) => /Downloading/.test(l)), 'must not download on a valid cache hit');
});

test('ensureBinary DELETES a tampered cached binary then attempts re-download (network failure surfaces, tamper not trusted)', async () => {
  const genuine = Buffer.from('GENUINE prebuilt fula-mcp');
  const tampered = Buffer.from('MALICIOUS cache-poisoned binary');
  const sb = sandbox(genuine);
  // Pre-seed a TAMPERED cached binary whose hash != bundled checksum.
  fs.writeFileSync(sb.finalPath, tampered);

  const logs = [];
  // Inject a download that fails (no network), so the test is deterministic.
  // The SECURITY-relevant assertion is that the tampered cache was NOT
  // returned/trusted: it was deleted and a fresh download was attempted.
  let downloadAttempted = false;
  await assert.rejects(
    ensureBinary({
      version: sb.version,
      checksumsPath: sb.checksumsPath,
      platform: sb.platform,
      arch: sb.arch,
      env: sb.env,
      log: (m) => logs.push(m),
      download: async () => {
        downloadAttempted = true;
        throw new Error('[fula-mcp] Download failed (injected, offline test).');
      },
    }),
    (e) => /Download failed/.test(e.message)
  );

  assert.ok(downloadAttempted, 'a fresh download must be attempted (tampered cache not trusted)');
  assert.ok(
    logs.some((l) => /failed checksum/i.test(l)),
    'must log that the cached binary failed checksum'
  );
  // The tampered file must have been removed (not silently kept/executed).
  assert.equal(fs.existsSync(sb.finalPath), false, 'tampered cache entry must be deleted');
});

test('lstatRegularOrNull returns null for a missing path and rejects a symlink', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fula-mcp-lstat-'));
  assert.equal(lstatRegularOrNull(path.join(root, 'nope')), null);

  const real = path.join(root, 'real');
  fs.writeFileSync(real, 'x');
  const link = path.join(root, 'link');
  try {
    fs.symlinkSync(real, link);
  } catch (e) {
    // On Windows without privilege, symlink creation throws EPERM; skip.
    return;
  }
  assert.throws(
    () => lstatRegularOrNull(link),
    (e) => e.code === 'ESYMLINK'
  );
});

test('cacheDir honors FULA_MCP_CACHE_DIR override and namespaces by version', () => {
  const d = cacheDir('1.2.3', { FULA_MCP_CACHE_DIR: '/tmp/custom' });
  assert.equal(d, path.join('/tmp/custom', '1.2.3'));
});

// --- Task-required: drive the DOWNLOAD branch to the exec/refuse decision, ----
// --- with the byte-fetch MOCKED (no network).                              ----

function freshSandbox(genuineBytes) {
  // Like sandbox() but does NOT pre-create the cache dir or pre-seed a binary,
  // so ensureBinary must take the download path.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fula-mcp-dl-'));
  const cacheRoot = path.join(root, 'cache');
  const version = '9.9.9';
  const env = { FULA_MCP_CACHE_DIR: cacheRoot };
  const platform = 'linux';
  const arch = 'x64';
  const { assetName, binName } = resolveTarget(platform, arch);
  const checksumsPath = path.join(root, 'checksums.json');
  fs.writeFileSync(
    checksumsPath,
    JSON.stringify({ version, checksums: { [assetName]: sha256(genuineBytes) } })
  );
  const finalPath = path.join(cacheRoot, version, binName);
  return { root, version, env, platform, arch, assetName, binName, checksumsPath, finalPath };
}

test('ensureBinary: mocked download of GENUINE bytes -> verifies, caches, returns path (the "exec")', async () => {
  const genuine = Buffer.from('GENUINE prebuilt fula-mcp v9.9.9');
  const sb = freshSandbox(genuine);

  let downloadedUrl = null;
  const result = await ensureBinary({
    version: sb.version,
    checksumsPath: sb.checksumsPath,
    platform: sb.platform,
    arch: sb.arch,
    env: sb.env,
    log: () => {},
    // Mock: write the genuine bytes that match the bundled checksum.
    download: async (url, tmpPath) => {
      downloadedUrl = url;
      fs.writeFileSync(tmpPath, genuine);
    },
  });

  // Hit the real release-asset URL shape (proves URL construction is wired in).
  assert.match(
    downloadedUrl,
    /^https:\/\/github\.com\/functionland\/fula-api\/releases\/download\/fula-mcp-v9\.9\.9\/fula-mcp-x86_64-unknown-linux-gnu$/
  );
  assert.equal(result, sb.finalPath, 'returns the cached binary path');
  assert.equal(fs.existsSync(sb.finalPath), true, 'binary is cached on disk');
  assert.equal(fs.readFileSync(sb.finalPath).toString(), genuine.toString(), 'cached bytes are the genuine bytes');
});

test('ensureBinary: mocked download of TAMPERED bytes -> ECHECKSUM, deletes temp, NOTHING cached (the "refuse")', async () => {
  const genuine = Buffer.from('GENUINE prebuilt fula-mcp v9.9.9');
  const tampered = Buffer.from('MALICIOUS swapped release binary');
  const sb = freshSandbox(genuine); // bundled checksum is for the GENUINE bytes

  await assert.rejects(
    ensureBinary({
      version: sb.version,
      checksumsPath: sb.checksumsPath,
      platform: sb.platform,
      arch: sb.arch,
      env: sb.env,
      log: () => {},
      // Mock a malicious-Release swap: bytes do NOT match the bundled checksum.
      download: async (url, tmpPath) => {
        fs.writeFileSync(tmpPath, tampered);
      },
    }),
    (e) => e.code === 'ECHECKSUM' && /checksum mismatch/.test(e.message)
  );

  // The tampered binary must NOT have been cached (would be exec'd otherwise).
  assert.equal(fs.existsSync(sb.finalPath), false, 'tampered binary must not be cached');
  // No leftover temp files in the cache dir either.
  const dir = path.dirname(sb.finalPath);
  const leftovers = fs.existsSync(dir) ? fs.readdirSync(dir) : [];
  assert.deepEqual(leftovers, [], 'no temp/partial files left behind');
});
