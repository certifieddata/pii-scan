#!/usr/bin/env node
/**
 * sdaas-pii-scan CLI
 *
 * Scans CSV or JSON dataset files for likely PII patterns.
 * Runs entirely locally. No data leaves your machine.
 *
 * Usage:
 *   npx @sdaas/pii-scan ./dataset.csv
 *   npx @sdaas/pii-scan ./records.json
 *   npx @sdaas/pii-scan ./data.csv --json        # JSON output
 *   npx @sdaas/pii-scan ./data.csv --no-color    # plain text
 *
 * DISCLAIMER: This tool is a diagnostic aid, not a compliance control.
 * It does NOT guarantee detection of all PII. False positives and
 * negatives are possible. Do not rely on this tool as a substitute
 * for proper data governance or legal review.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { scanContent } from "./scanner.js";
import type { ColumnFinding, ScanResult } from "./scanner.js";
import type { RiskLevel } from "./patterns.js";

const args = process.argv.slice(2);
const filePath = args.find((a) => !a.startsWith("--"));
const jsonOutput = args.includes("--json");
const noColor = args.includes("--no-color") || !process.stdout.isTTY;

if (!filePath || args.includes("--help") || args.includes("-h")) {
  console.log(`
sdaas-pii-scan — Local PII risk scanner for datasets

Usage: npx @sdaas/pii-scan <file> [options]

Arguments:
  <file>        CSV or JSON file to scan

Options:
  --json        Output results as JSON
  --no-color    Disable color output
  -h, --help    Show this help

Examples:
  npx @sdaas/pii-scan ./customers.csv
  npx @sdaas/pii-scan ./users.json --json

Supported formats: CSV, JSON (array of objects)

DISCLAIMER: Diagnostic aid only. Not a compliance control.
No data leaves your machine. No network calls are made.
`.trim());
  process.exit(0);
}

// Color helpers
const c = {
  reset: noColor ? "" : "\x1b[0m",
  bold: noColor ? "" : "\x1b[1m",
  red: noColor ? "" : "\x1b[31m",
  yellow: noColor ? "" : "\x1b[33m",
  green: noColor ? "" : "\x1b[32m",
  cyan: noColor ? "" : "\x1b[36m",
  gray: noColor ? "" : "\x1b[90m",
  white: noColor ? "" : "\x1b[97m",
};

function riskColor(risk: RiskLevel): string {
  if (risk === "HIGH") return c.red;
  if (risk === "MEDIUM") return c.yellow;
  return c.green;
}

function riskBadge(risk: RiskLevel): string {
  return `${riskColor(risk)}${c.bold}[${risk}]${c.reset}`;
}

const absPath = resolve(filePath);
let content: string;

try {
  content = readFileSync(absPath, "utf8");
} catch (err: any) {
  console.error(`Error reading file: ${err.message}`);
  process.exit(1);
}

const result: ScanResult = scanContent(content, absPath);

if (jsonOutput) {
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  process.exit(result.overallRisk === "HIGH" ? 2 : result.findings.length > 0 ? 1 : 0);
}

// Human-readable output
console.log(`
${c.bold}${c.white}sdaas-pii-scan${c.reset} ${c.gray}— local PII risk scanner${c.reset}
${c.gray}${"─".repeat(60)}${c.reset}
  File   : ${absPath}
  Rows   : ${result.rowsScanned.toLocaleString()}
  Columns: ${result.columnsScanned}
${c.gray}${"─".repeat(60)}${c.reset}`);

if (result.findings.length === 0) {
  console.log(`
  ${c.green}${c.bold}No PII patterns detected.${c.reset}

  ${c.gray}Review manually before use. Automated detection has limits.${c.reset}
`);
  process.exit(0);
}

// Group by column
const byColumn = new Map<string, ColumnFinding[]>();
for (const f of result.findings) {
  if (!byColumn.has(f.column)) byColumn.set(f.column, []);
  byColumn.get(f.column)!.push(f);
}

// Sort columns by max risk
const sorted = [...byColumn.entries()].sort(([, a], [, b]) => {
  const riskOrder = { HIGH: 3, MEDIUM: 2, LOW: 1 };
  const maxA = Math.max(...a.map((f) => riskOrder[f.risk]));
  const maxB = Math.max(...b.map((f) => riskOrder[f.risk]));
  return maxB - maxA;
});

console.log(`\n  ${c.bold}Findings${c.reset}\n`);

for (const [column, findings] of sorted) {
  const colRisk = findings.reduce<RiskLevel>(
    (acc, f) => (f.risk === "HIGH" || (acc !== "HIGH" && f.risk === "MEDIUM") ? f.risk : acc),
    "LOW"
  );
  console.log(`  ${riskBadge(colRisk)} ${c.bold}${column}${c.reset}`);
  for (const f of findings) {
    const src = f.source === "column_name" ? `${c.gray}(column name)${c.reset}` : `${c.gray}(${f.matchCount} match${f.matchCount !== 1 ? "es" : ""} in content)${c.reset}`;
    const samples = f.sampleValues.length > 0 ? `  ${c.gray}e.g. ${f.sampleValues.join(", ")}${c.reset}` : "";
    console.log(`         ${f.patternName} ${src}${samples}`);
  }
  console.log();
}

const highCount = result.findings.filter((f) => f.risk === "HIGH").length;
const medCount = result.findings.filter((f) => f.risk === "MEDIUM").length;

console.log(`${c.gray}${"─".repeat(60)}${c.reset}`);
console.log(`  Overall risk : ${riskBadge(result.overallRisk)}`);
console.log(`  Findings     : ${highCount > 0 ? `${c.red}${highCount} HIGH${c.reset}  ` : ""}${medCount > 0 ? `${c.yellow}${medCount} MEDIUM${c.reset}  ` : ""}${result.findings.length} total`);
console.log();
console.log(`  ${c.yellow}${c.bold}${result.summary}${c.reset}`);
console.log();
console.log(`  ${c.gray}Next step: Generate a certified synthetic replacement at${c.reset}`);
console.log(`  ${c.cyan}https://sdaas.io${c.reset}`);
console.log();
console.log(`  ${c.gray}DISCLAIMER: Diagnostic aid only. Not a compliance control.${c.reset}`);
console.log(`  ${c.gray}False positives and negatives are possible.${c.reset}`);
console.log();

process.exit(result.overallRisk === "HIGH" ? 2 : result.findings.length > 0 ? 1 : 0);
