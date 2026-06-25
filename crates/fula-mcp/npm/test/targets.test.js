'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  resolveTarget,
  releaseTag,
  downloadUrl,
  TARGETS,
} = require('../lib/targets');

test('resolveTarget maps all five supported hosts to the right triple + ext', () => {
  const cases = [
    ['win32', 'x64', 'x86_64-pc-windows-msvc', '.exe'],
    ['linux', 'x64', 'x86_64-unknown-linux-gnu', ''],
    ['linux', 'arm64', 'aarch64-unknown-linux-gnu', ''],
    ['darwin', 'x64', 'x86_64-apple-darwin', ''],
    ['darwin', 'arm64', 'aarch64-apple-darwin', ''],
  ];
  for (const [platform, arch, triple, ext] of cases) {
    const r = resolveTarget(platform, arch);
    assert.equal(r.target, triple, `${platform}-${arch} triple`);
    assert.equal(r.ext, ext, `${platform}-${arch} ext`);
    assert.equal(r.assetName, `fula-mcp-${triple}${ext}`, `${platform}-${arch} assetName`);
    assert.equal(r.binName, r.assetName, 'binName == assetName');
  }
});

test('resolveTarget covers exactly the documented TARGETS set', () => {
  assert.deepEqual(
    Object.keys(TARGETS).sort(),
    ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'win32-x64']
  );
});

test('resolveTarget throws EUNSUPPORTED for unknown platform/arch', () => {
  assert.throws(
    () => resolveTarget('freebsd', 'x64'),
    (e) => e.code === 'EUNSUPPORTED' && /Unsupported platform/.test(e.message)
  );
  assert.throws(
    () => resolveTarget('win32', 'ia32'),
    (e) => e.code === 'EUNSUPPORTED'
  );
  assert.throws(
    () => resolveTarget('linux', 'arm'),
    (e) => e.code === 'EUNSUPPORTED'
  );
});

test('releaseTag uses the collision-safe fula-mcp-v prefix (NOT bare v)', () => {
  assert.equal(releaseTag('0.6.17'), 'fula-mcp-v0.6.17');
  assert.equal(releaseTag('1.2.3-rc.1'), 'fula-mcp-v1.2.3-rc.1');
});

test('downloadUrl builds the functionland/fula-api release asset URL', () => {
  const { assetName } = resolveTarget('linux', 'x64');
  assert.equal(
    downloadUrl('0.6.17', assetName),
    'https://github.com/functionland/fula-api/releases/download/' +
      'fula-mcp-v0.6.17/fula-mcp-x86_64-unknown-linux-gnu'
  );
  const win = resolveTarget('win32', 'x64');
  assert.equal(
    downloadUrl('0.6.17', win.assetName),
    'https://github.com/functionland/fula-api/releases/download/' +
      'fula-mcp-v0.6.17/fula-mcp-x86_64-pc-windows-msvc.exe'
  );
});
