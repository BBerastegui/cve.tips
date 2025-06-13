import test from 'node:test';
import assert from 'node:assert/strict';

function extractCVEId(pathname) {
  return pathname.replace(/^\/+|\/+$/g, '').toUpperCase();
}

test('trailing slash trimmed', () => {
  const cveId = extractCVEId('/CVE-2024-1234/');
  assert.equal(cveId, 'CVE-2024-1234');
});
