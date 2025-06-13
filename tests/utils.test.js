import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { getNearbyCVEIds, fetchEPSSBatch } from '../src/index.js';

test('getNearbyCVEIds returns expected list when extra is 4', () => {
  const result = getNearbyCVEIds('CVE-2024-0001', 4);
  assert.deepEqual(result, [
    'CVE-2024-0001',
    'CVE-2024-0002',
    'CVE-2024-0003',
    'CVE-2024-0004',
    'CVE-2024-0005'
  ]);
});

test('fetchEPSSBatch returns empty object for empty array', async (t) => {
  const fetchMock = t.mock.method(globalThis, 'fetch');
  const result = await fetchEPSSBatch([]);
  assert.deepEqual(result, {});
  assert.equal(fetchMock.mock.callCount(), 0);
});

test('fetchEPSSBatch handles network errors gracefully', async (t) => {
  const fetchMock = t.mock.method(globalThis, 'fetch', () => Promise.reject(new Error('network')));
  const result = await fetchEPSSBatch(['CVE-2024-1234']);
  assert.deepEqual(result, {});
  assert.equal(fetchMock.mock.callCount(), 1);
});
