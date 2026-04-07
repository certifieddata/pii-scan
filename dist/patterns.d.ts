/**
 * PII detection patterns.
 *
 * All scanning is purely regex-based and runs entirely locally.
 * No data leaves your machine. No network calls are made.
 *
 * These patterns are intentionally broad — they flag LIKELY PII for human review.
 * False positives are expected and preferable to false negatives.
 *
 * This tool does NOT guarantee detection of all PII.
 * It is a diagnostic aid, not a compliance control.
 */
export type RiskLevel = "HIGH" | "MEDIUM" | "LOW";
export interface PiiPattern {
    name: string;
    description: string;
    risk: RiskLevel;
    pattern: RegExp;
}
export declare const PII_PATTERNS: PiiPattern[];
/** Column name patterns that strongly suggest PII fields */
export declare const SUSPICIOUS_COLUMN_NAMES: Array<{
    pattern: RegExp;
    risk: RiskLevel;
    label: string;
}>;
//# sourceMappingURL=patterns.d.ts.map