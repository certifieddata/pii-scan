import { PII_PATTERNS, SUSPICIOUS_COLUMN_NAMES, type RiskLevel } from "./patterns.js";

export interface ColumnFinding {
  column: string;
  patternName: string;
  risk: RiskLevel;
  matchCount: number;
  sampleValues: string[]; // redacted
  source: "content" | "column_name";
}

export interface ScanResult {
  file: string;
  rowsScanned: number;
  columnsScanned: number;
  findings: ColumnFinding[];
  overallRisk: RiskLevel;
  summary: string;
}

function redact(value: string): string {
  // Show first 2 and last 2 chars, mask the middle
  if (value.length <= 4) return "****";
  return value.slice(0, 2) + "*".repeat(Math.min(value.length - 4, 8)) + value.slice(-2);
}

function maxRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  const order: RiskLevel[] = ["LOW", "MEDIUM", "HIGH"];
  return order.indexOf(a) >= order.indexOf(b) ? a : b;
}

function parseCSV(content: string): Record<string, string[]> {
  const lines = content.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length === 0) return {};

  // Simple CSV parse — handles basic quoting
  const splitLine = (line: string): string[] => {
    const result: string[] = [];
    let current = "";
    let inQuote = false;
    for (const ch of line) {
      if (ch === '"') { inQuote = !inQuote; }
      else if (ch === "," && !inQuote) { result.push(current.trim()); current = ""; }
      else { current += ch; }
    }
    result.push(current.trim());
    return result;
  };

  const headers = splitLine(lines[0]);
  const columns: Record<string, string[]> = {};
  for (const h of headers) columns[h] = [];

  for (let i = 1; i < lines.length; i++) {
    const values = splitLine(lines[i]);
    headers.forEach((h, idx) => {
      if (values[idx] !== undefined) columns[h].push(values[idx]);
    });
  }
  return columns;
}

function parseJSON(content: string): Record<string, string[]> {
  const data = JSON.parse(content);
  const rows = Array.isArray(data) ? data : data.data ?? data.rows ?? [data];
  if (!rows.length || typeof rows[0] !== "object") return {};

  const columns: Record<string, string[]> = {};
  for (const row of rows) {
    for (const [k, v] of Object.entries(row as Record<string, unknown>)) {
      if (!columns[k]) columns[k] = [];
      columns[k].push(String(v ?? ""));
    }
  }
  return columns;
}

export function scanColumns(
  columns: Record<string, string[]>,
  filePath: string
): ScanResult {
  const findings: ColumnFinding[] = [];
  let totalRows = 0;

  for (const values of Object.values(columns)) {
    totalRows = Math.max(totalRows, values.length);
  }

  for (const [column, values] of Object.entries(columns)) {
    // 1. Column name heuristic
    for (const { pattern, risk, label } of SUSPICIOUS_COLUMN_NAMES) {
      if (pattern.test(column)) {
        findings.push({
          column,
          patternName: label,
          risk,
          matchCount: values.length,
          sampleValues: [],
          source: "column_name",
        });
        break; // one name match per column is enough
      }
    }

    // 2. Content scanning (sample up to 200 rows for speed)
    const sample = values.slice(0, 200).join("\n");
    for (const piiPattern of PII_PATTERNS) {
      const matches = [...sample.matchAll(piiPattern.pattern)];
      if (matches.length > 0) {
        findings.push({
          column,
          patternName: piiPattern.name,
          risk: piiPattern.risk,
          matchCount: matches.length,
          sampleValues: matches.slice(0, 3).map((m) => redact(m[0])),
          source: "content",
        });
      }
    }
  }

  const overallRisk: RiskLevel =
    findings.length === 0
      ? "LOW"
      : findings.reduce<RiskLevel>((acc, f) => maxRisk(acc, f.risk), "LOW");

  const highCount = findings.filter((f) => f.risk === "HIGH").length;
  const summary =
    findings.length === 0
      ? "No PII patterns detected. Review manually before use."
      : `${findings.length} potential PII finding(s) across ${new Set(findings.map((f) => f.column)).size} column(s). ` +
        (highCount > 0 ? `${highCount} HIGH risk. ` : "") +
        "Do not use this dataset in lower environments without synthetic replacement.";

  return {
    file: filePath,
    rowsScanned: totalRows,
    columnsScanned: Object.keys(columns).length,
    findings,
    overallRisk,
    summary,
  };
}

export function scanContent(content: string, filePath: string): ScanResult {
  let columns: Record<string, string[]> = {};

  if (filePath.endsWith(".json")) {
    try {
      columns = parseJSON(content);
    } catch {
      // Treat as plain text if JSON parse fails
      columns = { _text: content.split("\n") };
    }
  } else {
    // Default: CSV
    columns = parseCSV(content);
  }

  return scanColumns(columns, filePath);
}
