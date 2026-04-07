import { type RiskLevel } from "./patterns.js";
export interface ColumnFinding {
    column: string;
    patternName: string;
    risk: RiskLevel;
    matchCount: number;
    sampleValues: string[];
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
export declare function scanColumns(columns: Record<string, string[]>, filePath: string): ScanResult;
export declare function scanContent(content: string, filePath: string): ScanResult;
//# sourceMappingURL=scanner.d.ts.map