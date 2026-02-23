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

export const PII_PATTERNS: PiiPattern[] = [
  {
    name: "Email Address",
    description: "Standard email address format",
    risk: "HIGH",
    pattern: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
  },
  {
    name: "SSN (US Social Security Number)",
    description: "9-digit US SSN with or without dashes",
    risk: "HIGH",
    pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
  },
  {
    name: "Credit / Debit Card Number",
    description: "13–19 digit card numbers (Visa, MC, Amex, Discover patterns)",
    risk: "HIGH",
    pattern: /\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12}|\d{13,19})\b/g,
  },
  {
    name: "US Phone Number",
    description: "US phone numbers in common formats",
    risk: "HIGH",
    pattern: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
  },
  {
    name: "IPv4 Address",
    description: "IPv4 addresses (may indicate server logs or tracking data)",
    risk: "MEDIUM",
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
  },
  {
    name: "US ZIP Code",
    description: "5-digit or ZIP+4 format",
    risk: "LOW",
    pattern: /\b\d{5}(?:-\d{4})?\b/g,
  },
  {
    name: "Date of Birth Pattern",
    description: "Common date formats often used in DOB fields",
    risk: "MEDIUM",
    pattern: /\b(?:0?[1-9]|1[0-2])[-\/](?:0?[1-9]|[12]\d|3[01])[-\/](?:19|20)\d{2}\b/g,
  },
  {
    name: "Street Address",
    description: "Common US street address patterns",
    risk: "MEDIUM",
    pattern: /\b\d{1,5}\s+[A-Za-z0-9\s]{3,30}(?:St|Ave|Blvd|Dr|Rd|Ln|Way|Ct|Pl|Ter)\b\.?/gi,
  },
  {
    name: "Passport / ID Number",
    description: "Common passport number formats (letter + digits)",
    risk: "HIGH",
    pattern: /\b[A-Z]{1,2}\d{6,9}\b/g,
  },
  {
    name: "Bank Routing Number (ABA)",
    description: "9-digit US bank routing numbers",
    risk: "HIGH",
    pattern: /\b\d{9}\b/g,
  },
];

/** Column name patterns that strongly suggest PII fields */
export const SUSPICIOUS_COLUMN_NAMES: Array<{ pattern: RegExp; risk: RiskLevel; label: string }> = [
  { pattern: /\b(email|e_mail|email_addr)\b/i, risk: "HIGH", label: "Email column" },
  { pattern: /\b(ssn|social_security|social.security)\b/i, risk: "HIGH", label: "SSN column" },
  { pattern: /\b(phone|mobile|cell|telephone|tel)\b/i, risk: "HIGH", label: "Phone column" },
  { pattern: /\b(dob|date_of_birth|birth_date|birthdate)\b/i, risk: "HIGH", label: "Date of birth column" },
  { pattern: /\b(first.?name|last.?name|full.?name|fname|lname)\b/i, risk: "HIGH", label: "Name column" },
  { pattern: /\b(address|street|city|zip|postal)\b/i, risk: "MEDIUM", label: "Address column" },
  { pattern: /\b(ip.?addr|ip_address|ipv4|ipv6)\b/i, risk: "MEDIUM", label: "IP address column" },
  { pattern: /\b(passport|license|driver.?lic|dl_number)\b/i, risk: "HIGH", label: "ID document column" },
  { pattern: /\b(credit.?card|card.?num|cc_num|cvv|expiry)\b/i, risk: "HIGH", label: "Payment card column" },
  { pattern: /\b(account.?num|bank.?account|routing)\b/i, risk: "HIGH", label: "Bank account column" },
  { pattern: /\b(gender|sex|race|ethnicity|religion|nationality)\b/i, risk: "MEDIUM", label: "Sensitive demographic column" },
  { pattern: /\b(salary|income|wage|compensation)\b/i, risk: "MEDIUM", label: "Financial column" },
  { pattern: /\b(diagnosis|condition|medication|health|medical|patient)\b/i, risk: "HIGH", label: "Health data column" },
];
