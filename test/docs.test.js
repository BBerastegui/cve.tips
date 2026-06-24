import test from 'node:test';
import assert from 'node:assert/strict';

import worker from '../dist/src/index.js';

test('/docs serves HTML docs', async () => {
  const res = await worker.fetch(new Request('http://localhost/docs'));
  assert.equal(res.status, 200);
  const contentType = res.headers.get('content-type');
  assert.ok(contentType && contentType.includes('text/html'));
});

test('/ serves ASCII API overview', async () => {
  const res = await worker.fetch(new Request('http://localhost/'));
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') ?? '', /text\/plain/);

  const body = await res.text();
  assert.match(body, /CVE intelligence API/);
  assert.match(body, /GET \/CVE-YYYY-NNNN/);
  assert.match(body, /EPSS scores/);
  assert.match(body, /Cloudflare R2/);
});
