# cve.tips

Cloudflare Worker that serves CVE details enriched with EPSS scores, backed by an R2 cache.

## Running tests

Install dependencies once:

```bash
npm install
```

Build the TypeScript sources and run the test suite using Node's built-in runner:

```bash
npm test
```

## API overview

The root path (`/`) serves a plain-text ASCII overview that explains how to call the API. Fetch individual CVEs with:

```bash
curl https://cve.tips/CVE-2024-1234
```

The API returns CVE details enriched with EPSS scores and caches retrieved CVE records in Cloudflare R2.

## Deployment

Deploy the Worker with Wrangler:

```bash
npm run deploy
```

To validate the Cloudflare deploy package without publishing it, run:

```bash
npm run deploy:dry-run
```

## Continuous Integration and Deployment

GitHub Actions runs `npm test` on every pull request and every push to `main`. When a push lands on `main`, the workflow deploys the Worker to Cloudflare after the test job succeeds.

Before enabling autonomous deployments, add this repository secret in GitHub:

- `CLOUDFLARE_API_TOKEN`: a Cloudflare API token with permission to deploy the `cve-tips` Worker for the configured account.

The production Worker and R2 binding are configured in `wrangler.toml`. A `preview` Wrangler environment is also defined for future non-production deploys.
