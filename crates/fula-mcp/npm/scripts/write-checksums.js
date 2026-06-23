#!/usr/bin/env node
'use strict';

// ---------------------------------------------------------------------------
// Release-time helper (run by .github/workflows/fula-mcp-release.yml).
//
// Given a directory containing the built/collected release binaries (named
// exactly `fula-mcp-{target}{ext}`, the same `assetName` the launcher expects),
// compute each one's SHA-256 and write `<npm>/checksums.json` with the map plus
// version/tag metadata. Also stamps the version into `<npm>/package.json`.
//
// Usage:
//   node scripts/write-checksums.js --assets <dir> --version <semver> [--npm <dir>]
//
// Exits non-zero if ANY expected target's binary is missing (so a partial build
// can never publish a package that claims to support a platform it can't serve).
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const { TARGETS, releaseTag, resolveTarget } = require('../lib/targets');
const { sha256File } = require('../lib/verify');

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--assets') out.assets = argv[++i];
    else if (a === '--version') out.version = argv[++i];
    else if (a === '--npm') out.npm = argv[++i];
    else throw new Error(`Unknown argument: ${a}`);
  }
  if (!out.assets) throw new Error('--assets <dir> is required');
  if (!out.version) throw new Error('--version <semver> is required');
  out.npm = out.npm || path.join(__dirname, '..');
  return out;
}

async function main() {
  const { assets, version, npm } = parseArgs(process.argv);

  // Build the full set of expected asset names from the shared TARGETS map.
  const expectedAssets = Object.keys(TARGETS).map((key) => {
    const [platform, arch] = key.split('-');
    return resolveTarget(platform, arch).assetName;
  });

  const checksums = {};
  const missing = [];
  for (const assetName of expectedAssets) {
    const p = path.join(assets, assetName);
    if (!fs.existsSync(p)) {
      missing.push(assetName);
      continue;
    }
    checksums[assetName] = await sha256File(p);
    process.stdout.write(`  ${checksums[assetName]}  ${assetName}\n`);
  }

  if (missing.length) {
    process.stderr.write(
      `ERROR: missing release binaries for: ${missing.join(', ')}\n` +
        `Refusing to write checksums.json — a published package must serve every ` +
        `platform it advertises.\n`
    );
    process.exit(1);
  }

  const doc = { version, tag: releaseTag(version), checksums };
  const checksumsPath = path.join(npm, 'checksums.json');
  fs.writeFileSync(checksumsPath, JSON.stringify(doc, null, 2) + '\n');
  process.stdout.write(`Wrote ${checksumsPath} (${expectedAssets.length} targets)\n`);

  // Stamp version into package.json.
  const pkgPath = path.join(npm, 'package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  pkg.version = version;
  fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
  process.stdout.write(`Stamped version ${version} into ${pkgPath}\n`);

  // Also emit a plain checksums.txt (sha256sum format) for the Release page.
  const txt = expectedAssets.map((a) => `${checksums[a]}  ${a}`).join('\n') + '\n';
  const txtPath = path.join(assets, 'checksums.txt');
  fs.writeFileSync(txtPath, txt);
  process.stdout.write(`Wrote ${txtPath}\n`);
}

main().catch((e) => {
  process.stderr.write(String(e && e.stack ? e.stack : e) + '\n');
  process.exit(1);
});
