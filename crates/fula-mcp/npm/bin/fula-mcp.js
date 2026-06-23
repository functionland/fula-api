#!/usr/bin/env node
'use strict';

// ---------------------------------------------------------------------------
// `npx @functionland/fula-mcp` entrypoint.
//
// Downloads (once, verified) the prebuilt `fula-mcp` Rust binary matching this
// package's version + the host platform, then execs it as a transparent stdio
// passthrough so it works as a local MCP server for Claude Desktop / Claude
// Code / Codex CLI / Gemini CLI:
//
//   - argv after the launcher is forwarded to the binary.
//   - stdio is inherited (stdin/stdout carry the MCP JSON-RPC frames; stderr
//     carries the binary's logs).
//   - the environment is inherited, so FULA_MCP_CAPABILITY / FULA_MCP_JWT /
//     RUST_LOG etc. reach the binary unchanged.
//   - the binary's exit code becomes this process's exit code.
//
// The binary is verified against the checksum BUNDLED in this package before
// every exec (see lib/verify.js for the trust-model rationale).
// ---------------------------------------------------------------------------

const path = require('path');
const { spawn } = require('child_process');

const pkg = require('../package.json');
const { resolveTarget } = require('../lib/targets');
const { ensureBinary, lstatRegularOrNull } = require('../lib/install');
const { loadChecksums, verifyFile } = require('../lib/verify');

const CHECKSUMS_PATH = path.join(__dirname, '..', 'checksums.json');

function fail(message, code) {
  process.stderr.write(message + '\n');
  process.exit(code || 1);
}

async function main() {
  // 1. Resolve + 2/3. ensure (download+verify or cache hit).
  let binPath;
  try {
    binPath = await ensureBinary({
      version: pkg.version,
      checksumsPath: CHECKSUMS_PATH,
    });
  } catch (e) {
    // resolveTarget / download / checksum errors all land here with a clear,
    // user-facing message already attached.
    return fail(e.message, e.code === 'EUNSUPPORTED' ? 2 : 1);
  }

  // 4. TOCTOU mitigation: re-lstat (reject symlink) + re-verify the exact bytes
  // we are about to exec against the bundled checksum, immediately before spawn.
  try {
    lstatRegularOrNull(binPath);
    const { assetName } = resolveTarget(process.platform, process.arch);
    const checksums = loadChecksums(CHECKSUMS_PATH);
    const result = await verifyFile(binPath, assetName, checksums);
    if (!result.ok) {
      return fail(
        `[fula-mcp] SECURITY: cached binary failed re-verification just before exec ` +
          `(expected ${result.expected}, got ${result.actual}). Refusing to run.`,
        1
      );
    }
  } catch (e) {
    return fail(e.message, 1);
  }

  // 5. Exec the verified binary. Absolute path, shell:false, no PATH lookup.
  const child = spawn(binPath, process.argv.slice(2), {
    stdio: 'inherit',
    env: process.env,
    shell: false,
    windowsHide: true,
  });

  child.on('error', (e) => fail(`[fula-mcp] Failed to launch binary: ${e.message}`, 1));

  // Forward common termination signals so the parent (e.g. Claude Desktop)
  // can cleanly stop the MCP server.
  const forward = (sig) => {
    try {
      child.kill(sig);
    } catch (_) {
      /* child may already be gone */
    }
  };
  process.on('SIGINT', () => forward('SIGINT'));
  process.on('SIGTERM', () => forward('SIGTERM'));

  child.on('exit', (code, signal) => {
    if (signal) {
      // Re-raise the signal so our exit status reflects it.
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code === null ? 1 : code);
  });
}

main().catch((e) => fail(`[fula-mcp] Unexpected error: ${e && e.message ? e.message : e}`, 1));
