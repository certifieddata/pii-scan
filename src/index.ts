/**
 * @sdaas/pii-scan
 *
 * Local PII risk scanner for datasets.
 *
 * Runs entirely locally — no data leaves your machine.
 * No network calls. No telemetry.
 *
 * IMPORTANT: This tool is a diagnostic aid only.
 * It does NOT guarantee detection of all PII types.
 * It is NOT a substitute for proper data governance.
 * It does NOT provide regulatory compliance.
 * False positives and false negatives are possible.
 *
 * Quick start:
 *   npx @sdaas/pii-scan ./your-dataset.csv
 */

export { scanContent, scanColumns } from "./scanner.js";
export { PII_PATTERNS, SUSPICIOUS_COLUMN_NAMES } from "./patterns.js";
export type { ScanResult, ColumnFinding } from "./scanner.js";
export type { RiskLevel, PiiPattern } from "./patterns.js";
