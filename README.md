# cve.tips

## Running tests

Install dependencies once:

```bash
npm install
```

Build the TypeScript sources and run the test suite using Node's built-in runner:

```bash
npm test
```

## Continuous Integration

A GitHub Actions workflow runs `npm test` on every push and pull request. When
pushing to the `main` branch, the workflow will only deploy if the test job
succeeds.
