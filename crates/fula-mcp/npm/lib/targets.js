'use strict';

// ---------------------------------------------------------------------------
// Single source of truth for the cross-platform distribution.
//
// THREE strings must match byte-for-byte between THIS launcher (which DOWNLOADS)
// and `.github/workflows/fula-mcp-release.yml` (which BUILDS + UPLOADS):
//
//   1. the git tag           -> `fula-mcp-v{version}`         (releaseTag)
//   2. the asset file name   -> `fula-mcp-{target}{ext}`      (assetName)
//   3. the checksums.json key -> the asset file name           (same string)
//
// A drift in any of them is a 404 (download) or a verify-fail that ONLY a real
// tag-push surfaces. So they are all derived here, once, from `TARGETS`.
// ---------------------------------------------------------------------------

// GitHub repo that hosts the Releases. MUST be public (npx users download from
// it, and npm provenance requires a public repo).
const GITHUB_OWNER = 'functionland';
const GITHUB_REPO = 'fula-api';

// The Rust binary's stem (matches `[[bin]] name`/the bin file in the crate).
const BIN_STEM = 'fula-mcp';

// Tag PREFIX. Deliberately `fula-mcp-v` (NOT `v`) so this release train does
// not collide with `flutter-release.yml`, which triggers on `v*`.
const TAG_PREFIX = 'fula-mcp-v';

// Supported platforms: Node `${platform}-${arch}` -> Rust target triple + ext.
// `platform`/`arch` are the values of process.platform / process.arch.
const TARGETS = {
  'win32-x64': { target: 'x86_64-pc-windows-msvc', ext: '.exe' },
  'linux-x64': { target: 'x86_64-unknown-linux-gnu', ext: '' },
  'linux-arm64': { target: 'aarch64-unknown-linux-gnu', ext: '' },
  'darwin-x64': { target: 'x86_64-apple-darwin', ext: '' },
  'darwin-arm64': { target: 'aarch64-apple-darwin', ext: '' },
};

/**
 * Resolve the current host to a distribution descriptor.
 * @param {string} platform - process.platform (e.g. 'linux', 'win32', 'darwin')
 * @param {string} arch     - process.arch (e.g. 'x64', 'arm64')
 * @returns {{key:string,target:string,ext:string,assetName:string,binName:string}}
 * @throws {Error} with a clear, actionable message for an unsupported host.
 */
function resolveTarget(platform, arch) {
  const key = `${platform}-${arch}`;
  const entry = TARGETS[key];
  if (!entry) {
    const supported = Object.keys(TARGETS).sort().join(', ');
    const err = new Error(
      `[fula-mcp] Unsupported platform/arch: ${key}.\n` +
        `Supported: ${supported}.\n` +
        `If you need this platform, please open an issue at ` +
        `https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/issues`
    );
    err.code = 'EUNSUPPORTED';
    throw err;
  }
  return {
    key,
    target: entry.target,
    ext: entry.ext,
    // assetName == the Release asset file name == the checksums.json key.
    assetName: `${BIN_STEM}-${entry.target}${entry.ext}`,
    // binName == the on-disk cached file name (same as the asset).
    binName: `${BIN_STEM}-${entry.target}${entry.ext}`,
  };
}

/**
 * Build the git tag for a given package version.
 * @param {string} version - the npm package version (semver, no leading 'v').
 * @returns {string} e.g. 'fula-mcp-v0.6.16'
 */
function releaseTag(version) {
  return `${TAG_PREFIX}${version}`;
}

/**
 * Build the GitHub Release asset download URL.
 * @param {string} version   - the npm package version.
 * @param {string} assetName - the asset file name (from resolveTarget).
 * @returns {string} the absolute https download URL.
 */
function downloadUrl(version, assetName) {
  return (
    `https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/releases/download/` +
    `${releaseTag(version)}/${assetName}`
  );
}

module.exports = {
  GITHUB_OWNER,
  GITHUB_REPO,
  BIN_STEM,
  TAG_PREFIX,
  TARGETS,
  resolveTarget,
  releaseTag,
  downloadUrl,
};
