'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const {
  sha256File,
  expectedHashFor,
  hexEqual,
  verifyFile,
  loadChecksums,
} = require('../lib/verify');

function tmpFile(contents) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fula-mcp-test-'));
  const p = path.join(dir, 'fula-mcp-x86_64-unknown-linux-gnu');
  fs.writeFileSync(p, contents);
  return p;
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

test('sha256File matches crypto digest of the same bytes', async () => {
  const bytes = Buffer.from('hello fula-mcp binary contents');
  const p = tmpFile(bytes);
  assert.equal(await sha256File(p), sha256(bytes));
});

test('expectedHashFor reads flat map', () => {
  const cs = { 'fula-mcp-x86_64-unknown-linux-gnu': 'a'.repeat(64) };
  assert.equal(expectedHashFor(cs, 'fula-mcp-x86_64-unknown-linux-gnu'), 'a'.repeat(64));
});

test('expectedHashFor reads wrapped { checksums: {...} } map', () => {
  const cs = { version: '0.6.17', checksums: { 'fula-mcp-x86_64-apple-darwin': 'B'.repeat(64) } };
  // also normalizes case to lowercase
  assert.equal(expectedHashFor(cs, 'fula-mcp-x86_64-apple-darwin'), 'b'.repeat(64));
});

test('expectedHashFor strips an optional sha256: prefix and whitespace', () => {
  const cs = { 'fula-mcp-x86_64-apple-darwin': '  sha256:' + 'C'.repeat(64) + ' \n' };
  assert.equal(expectedHashFor(cs, 'fula-mcp-x86_64-apple-darwin'), 'c'.repeat(64));
});

test('expectedHashFor throws EBADCHECKSUMS for a missing asset', () => {
  assert.throws(
    () => expectedHashFor({ checksums: {} }, 'fula-mcp-x86_64-unknown-linux-gnu'),
    (e) => e.code === 'EBADCHECKSUMS' && /No bundled checksum/.test(e.message)
  );
});

test('expectedHashFor throws EBADCHECKSUMS for a non-hex / wrong-length value', () => {
  assert.throws(
    () => expectedHashFor({ x: 'not-a-hash' }, 'x'),
    (e) => e.code === 'EBADCHECKSUMS'
  );
  assert.throws(
    () => expectedHashFor({ x: 'abc' }, 'x'),
    (e) => e.code === 'EBADCHECKSUMS'
  );
});

test('hexEqual is true for equal digests, false otherwise', () => {
  assert.equal(hexEqual('a'.repeat(64), 'a'.repeat(64)), true);
  assert.equal(hexEqual('a'.repeat(64), 'b'.repeat(64)), false);
  assert.equal(hexEqual('a'.repeat(64), 'a'.repeat(63)), false);
});

// --- The security-critical good-vs-tampered exec gate ------------------------

test('verifyFile ACCEPTS a binary whose bytes match the bundled checksum', async () => {
  const bytes = Buffer.from('GENUINE fula-mcp binary v1');
  const p = tmpFile(bytes);
  const checksums = { checksums: { 'fula-mcp-x86_64-unknown-linux-gnu': sha256(bytes) } };
  const r = await verifyFile(p, 'fula-mcp-x86_64-unknown-linux-gnu', checksums);
  assert.equal(r.ok, true);
  assert.equal(r.actual, sha256(bytes));
  assert.equal(r.expected, sha256(bytes));
});

test('verifyFile REFUSES a tampered binary (bundled-checksum mismatch)', async () => {
  // The bundled checksum is for the GENUINE bytes; the file on disk is a
  // malicious-Release swap (different bytes). This is the exact attack the
  // bundled-checksum trust root must catch.
  const genuine = Buffer.from('GENUINE fula-mcp binary v1');
  const tampered = Buffer.from('MALICIOUS swapped binary >:)');
  const p = tmpFile(tampered);
  const checksums = { checksums: { 'fula-mcp-x86_64-unknown-linux-gnu': sha256(genuine) } };
  const r = await verifyFile(p, 'fula-mcp-x86_64-unknown-linux-gnu', checksums);
  assert.equal(r.ok, false, 'tampered binary must NOT verify');
  assert.equal(r.actual, sha256(tampered));
  assert.equal(r.expected, sha256(genuine));
  assert.notEqual(r.actual, r.expected);
});

test('loadChecksums parses a real on-disk checksums.json', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fula-mcp-cs-'));
  const p = path.join(dir, 'checksums.json');
  fs.writeFileSync(p, JSON.stringify({ checksums: { foo: 'd'.repeat(64) } }));
  const cs = loadChecksums(p);
  assert.equal(expectedHashFor(cs, 'foo'), 'd'.repeat(64));
});

test('loadChecksums throws EBADCHECKSUMS for a missing file', () => {
  assert.throws(
    () => loadChecksums(path.join(os.tmpdir(), 'definitely-not-here-fula.json')),
    (e) => e.code === 'EBADCHECKSUMS'
  );
});
