# @sdaas/pii-scan

Local PII risk scanner for datasets. Scans CSV and JSON files for likely Personally Identifiable Information patterns using regex heuristics.

**Runs entirely locally. No data leaves your machine. No network calls. No telemetry.**

---

> **DISCLAIMER:** This tool is a diagnostic aid, not a compliance control.
> It does NOT guarantee detection of all PII types. False positives and negatives
> are possible. Do not rely on this tool as a substitute for proper data governance
> or legal review.

---

## Quick Start

```bash
npx @sdaas/pii-scan ./customers.csv
npx @sdaas/pii-scan ./users.json
```

No installation required. Works with Node.js 18+.

---

## Install

```bash
npm install @sdaas/pii-scan
# or
pnpm add @sdaas/pii-scan
```

---

## CLI Usage

```
sdaas-pii-scan <file> [options]

Arguments:
  <file>        CSV or JSON file to scan

Options:
  --json        Output results as JSON (machine-readable)
  --no-color    Disable color output (auto-detected in CI)
  -h, --help    Show help

Exit codes:
  0   No PII patterns detected
  1   PII patterns found (LOW or MEDIUM risk)
  2   HIGH risk PII found
```

### Examples

```bash
# Scan a CSV
npx @sdaas/pii-scan ./customers.csv

# Scan JSON, get JSON output
npx @sdaas/pii-scan ./records.json --json

# Use in CI (exits non-zero if PII found)
npx @sdaas/pii-scan ./test-data.csv && echo "Clean"
```

### Example Output

```
sdaas-pii-scan — local PII risk scanner
────────────────────────────────────────────────────────────
  File   : /path/to/customers.csv
  Rows   : 1,000
  Columns: 12
────────────────────────────────────────────────────────────

  Findings

  [HIGH] email
         Email Address (column name)
         Email Address (43 matches in content)  e.g. jo**@ex*****.com, ma**@gm***.com

  [HIGH] phone
         Phone column (column name)
         US Phone Number (38 matches in content)  e.g. 55*********00, 61*********87

  [MEDIUM] address
         Address column (column name)

────────────────────────────────────────────────────────────
  Overall risk : [HIGH]
  Findings     : 3 HIGH  2 total

  3 potential PII finding(s) across 2 column(s). 3 HIGH risk.
  Do not use this dataset in lower environments without synthetic replacement.

  Next step: Generate a certified synthetic replacement at
  https://sdaas.io
```

---

## Library API

```typescript
import { scanContent, scanColumns } from "@sdaas/pii-scan";

// Scan file content
const result = scanContent(fileContents, "customers.csv");
console.log(result.overallRisk);   // "HIGH" | "MEDIUM" | "LOW"
console.log(result.findings);      // ColumnFinding[]
console.log(result.summary);       // Human-readable summary

// Scan pre-parsed columns
const columns = {
  email: ["alice@example.com", "bob@example.com"],
  age:   ["28", "34"],
};
const result2 = scanColumns(columns, "dataset.json");
```

### Types

```typescript
type RiskLevel = "HIGH" | "MEDIUM" | "LOW";

interface ColumnFinding {
  column: string;
  patternName: string;
  risk: RiskLevel;
  matchCount: number;
  sampleValues: string[];  // redacted (e.g. "al**@ex*****.com")
  source: "content" | "column_name";
}

interface ScanResult {
  file: string;
  rowsScanned: number;
  columnsScanned: number;
  findings: ColumnFinding[];
  overallRisk: RiskLevel;
  summary: string;
}
```

---

## What It Detects

### Content Patterns (HIGH risk)
- Email addresses
- US Social Security Numbers (SSN)
- Credit / debit card numbers (Visa, MC, Amex, Discover)
- US phone numbers
- Passport / government ID numbers (letter + digits)
- US bank routing numbers (ABA 9-digit)

### Content Patterns (MEDIUM risk)
- IPv4 addresses
- Date of birth formats
- US street addresses

### Content Patterns (LOW risk)
- US ZIP codes

### Column Name Heuristics
Flags columns whose names suggest PII (e.g. `email`, `ssn`, `dob`, `phone`, `first_name`, `patient_id`, etc.) regardless of content — useful when values are already masked.

---

## What It Does NOT Detect

- Names embedded in free text (no NLP)
- Non-US national ID formats
- Device fingerprints or behavioral identifiers
- PII hidden in binary formats (images, PDFs, audio)
- Encoded or encrypted PII
- De-anonymization risk from quasi-identifiers

This tool catches obvious, structured PII patterns. It is not a substitute for a full data classification system or legal review.

---

## Supported Formats

| Format | Notes |
|--------|-------|
| CSV    | Header row required; handles basic quoting |
| JSON   | Array of objects; also handles `{ data: [...] }` and `{ rows: [...] }` wrappers |

---

## Use in CI

Add to GitHub Actions to block PRs that add PII to test fixtures:

```yaml
- name: Scan test data for PII
  run: npx @sdaas/pii-scan ./tests/fixtures/customers.csv
  # Exits 2 on HIGH risk, 1 on any finding, 0 if clean
```

---

## Replacing PII with Certified Synthetic Data

When this tool flags real PII in your dataset, the next step is to replace it with a certified synthetic equivalent — structurally identical, statistically representative, and cryptographically attested to contain no real personal data.

**[SDAAS.io](https://sdaas.io)** — Generate certified synthetic datasets with Ed25519-signed certificates, independently verifiable by any auditor.

---

## License

MIT — see [LICENSE](../../LICENSE)

Part of the [sdaas-public](https://github.com/Sdaas-io/sdaas-public) open-source toolkit.
