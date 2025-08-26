import test from 'node:test';
import assert from 'node:assert/strict';

import worker from '../dist/src/index.js';

test('/docs serves HTML docs', async () => {
  const res = await worker.fetch(new Request('http://localhost/docs'));
  assert.equal(res.status, 200);
  const contentType = res.headers.get('content-type');
  assert.ok(contentType && contentType.includes('text/html'));
});
