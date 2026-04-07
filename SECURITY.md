# Security Policy

## Reporting a Vulnerability

Email: **security@certifieddata.io**

Please do not file public GitHub issues for security vulnerabilities.
Include a description of the issue, reproduction steps, and potential impact.
We aim to respond within 5 business days.

## Scope

| In scope | Notes |
|----------|-------|
| False negative detections that allow PII to pass CI gates undetected | Critical — defeats the purpose of the tool |
| Regex patterns that introduce ReDoS (Regular Expression Denial of Service) risk | Could be triggered by malformed input |
| Any code path that makes a network call | Violates the local-only guarantee |
| Arbitrary file read/write beyond the file path explicitly passed by the caller | Path traversal concerns |

## Out of Scope

- **Intentional false positives** — expected and documented; see README limitations
- **Detection accuracy for non-US locales** — v0.1 is US-centric by design
- **Cases where a CI pipeline runs this tool with untrusted input files** — the calling environment is responsible for input validation

## Privacy Model

`@certifieddata/pii-scan` has **zero runtime dependencies** and makes **no network calls**.

You can verify this by inspecting the source:
- `src/patterns.ts` — only pattern definitions, no imports beyond TypeScript types
- `src/scanner.ts` — imports only from `./patterns.js`
- `src/cli.ts` — imports only from `node:fs`, `node:path`, `node:process`, and `./scanner.js`

No module imports `http`, `https`, `fetch`, `node-fetch`, or any telemetry, analytics,
or remote-reporting SDK. The package will never transmit your data anywhere.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
