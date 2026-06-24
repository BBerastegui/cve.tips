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

The repository uses a single GitHub Actions workflow at `.github/workflows/ci-cd.yml` so there is only one authoritative path from Codex changes to production deployment.

On every pull request and every push to `main`, the workflow:

1. Installs dependencies with `npm ci` on Node.js 22.
2. Builds and tests the Worker with `npm test`.
3. Validates the Cloudflare Worker package with `npm run deploy:dry-run`.

When a push lands on `main`, the production deployment job starts only after validation succeeds and publishes the Worker with `npm run deploy`. The deployment job is attached to the `production` GitHub environment, so any required environment secrets or branch protections can be managed in GitHub without changing the workflow.

### Autonomous deployment checklist

To support a fully autonomous Codex-to-deploy flow, keep the following repository settings in place:

- Protect `main` and require the `Build, test, and package` workflow job to pass before merging.
- Enable auto-merge for PRs that have the required checks and approvals satisfied.
- Add the `CLOUDFLARE_API_TOKEN` secret to the `production` environment or repository secrets. The token needs permission to deploy the `cve-tips` Worker for the configured Cloudflare account.
- Avoid mandatory manual reviewers on the `production` environment if the goal is hands-off deployment after merge.

The production Worker and R2 binding are configured in `wrangler.toml`. A `preview` Wrangler environment is also defined for future non-production deploys.
