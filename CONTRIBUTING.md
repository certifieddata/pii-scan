# Contributing to @certifieddata/pii-scan

## What belongs here

- New PII pattern definitions (with matching tests)
- Parser improvements: NDJSON, TSV, Parquet column metadata
- False positive improvements backed by concrete evidence
- Additional column-name heuristics for under-covered domains
- SARIF or JUnit output formatters for CI/security workflows
- Non-US locale support (country-scoped pattern sets)

## What does not belong here

- Network calls, remote telemetry, or usage reporting of any kind
- Breaking changes to the `ScanResult` or `ColumnFinding` shape without a version bump
- Compliance claims beyond those already disclaimed in the README
- Dependency additions without justification — the zero-runtime-dependency guarantee is intentional

## Development Setup

```bash
# From the pii-scan directory
pnpm install
pnpm build
pnpm test
pnpm lint
pnpm typecheck
```

Node.js 18+ required. pnpm 9+ recommended.

## Adding a New Pattern

1. Add the pattern to `src/patterns.ts` with `name`, `description`, `risk`, and `pattern` fields
2. Add at least one positive-match test and one negative-match test in `src/scanner.test.ts`
3. Update the README "What It Detects" section
4. Run `pnpm test` and `pnpm lint` — both must pass

Pattern guidelines:
- Use the `g` flag on all regexes (the scanner uses `matchAll`)
- Avoid unbounded quantifiers that risk ReDoS (e.g. `(.+)+`)
- Document false-positive risk in the `description` field if high
- Prefer specificity over recall — note exceptions in the README

## PR Checklist

- [ ] New patterns have at least one positive-match test
- [ ] Tests pass: `pnpm test`
- [ ] Lint passes: `pnpm lint`
- [ ] Typecheck passes: `pnpm typecheck`
- [ ] README updated if detection scope or API changes
- [ ] No new runtime dependencies introduced
- [ ] No network calls or file writes beyond the input file

## Testing

```bash
pnpm test          # build + run all tests
pnpm test:unit     # unit tests only (scanner.test.js)
pnpm test:cli      # CLI integration tests (cli.test.js)
```

Tests use Node.js built-in test runner (`node --test`) — no external test framework required.
