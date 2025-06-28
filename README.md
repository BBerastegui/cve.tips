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

This compiles the TypeScript sources and runs Node's test runner over
the compiled tests and any JavaScript tests.

## Continuous Integration

A GitHub Actions workflow runs `npm test` on every push and pull request.
Deployment occurs from the `main` branch only after the test job succeeds.
