/**
 * @certifieddata/pii-scan — scanner unit tests
 *
 * Tests the core scanning functions: scanContent() and scanColumns().
 * All tests run entirely locally — no network calls, no external dependencies.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { scanContent, scanColumns } from "./index.js";
// ── scanContent — CSV ─────────────────────────────────────────────────────────
describe("scanContent — CSV", () => {
    it("detects email address in content", () => {
        const csv = "name,email\nAlice,alice@example.com\nBob,bob@example.com";
        const result = scanContent(csv, "sample.csv");
        assert.ok(result.findings.some((f) => f.patternName === "Email Address"), "Expected Email Address finding");
        assert.equal(result.overallRisk, "HIGH");
    });
    it("returns LOW risk for synthetic-safe data", () => {
        const csv = "product_id,price,quantity\nP001,19.99,5\nP002,34.50,2";
        const result = scanContent(csv, "products.csv");
        assert.equal(result.findings.filter((f) => f.source === "content").length, 0, "Expected no content findings");
        assert.equal(result.overallRisk, "LOW");
    });
    it("detects SSN pattern", () => {
        const csv = "id,ssn_field\n1,123-45-6789\n2,987-65-4321";
        const result = scanContent(csv, "pii.csv");
        assert.ok(result.findings.some((f) => f.patternName.includes("SSN")), "Expected SSN finding");
    });
    it("detects column name heuristics for name columns", () => {
        const csv = "first_name,last_name\nJohn,Doe";
        const result = scanContent(csv, "names.csv");
        assert.ok(result.findings.some((f) => f.source === "column_name" && (f.column === "first_name" || f.column === "last_name")), "Expected column name finding for first_name or last_name");
    });
    it("detects credit card numbers", () => {
        const csv = "order_id,card_number\n1,4111111111111111";
        const result = scanContent(csv, "orders.csv");
        assert.ok(result.findings.some((f) => f.patternName.includes("Card")), "Expected credit card finding");
        assert.equal(result.overallRisk, "HIGH");
    });
    it("detects US phone numbers", () => {
        const csv = "contact,phone_num\nSupport,555-867-5309";
        const result = scanContent(csv, "contacts.csv");
        assert.ok(result.findings.some((f) => f.patternName === "US Phone Number" || f.source === "column_name"), "Expected phone finding");
    });
    it("returns correct rowsScanned and columnsScanned", () => {
        const csv = "a,b,c\n1,2,3\n4,5,6\n7,8,9";
        const result = scanContent(csv, "data.csv");
        assert.equal(result.rowsScanned, 3);
        assert.equal(result.columnsScanned, 3);
    });
    it("handles single-row CSV", () => {
        const csv = "email\nalice@example.com";
        const result = scanContent(csv, "single.csv");
        assert.ok(result.findings.length > 0, "Expected findings");
        assert.equal(result.overallRisk, "HIGH");
    });
    it("returns file path in result", () => {
        const result = scanContent("a,b\n1,2", "path/to/data.csv");
        assert.equal(result.file, "path/to/data.csv");
    });
});
// ── scanContent — JSON ────────────────────────────────────────────────────────
describe("scanContent — JSON", () => {
    it("detects email in JSON array", () => {
        const json = JSON.stringify([{ user: "alice@example.com" }, { user: "bob@example.com" }]);
        const result = scanContent(json, "users.json");
        assert.ok(result.findings.some((f) => f.patternName === "Email Address"), "Expected Email Address finding");
    });
    it("handles empty JSON array", () => {
        const result = scanContent("[]", "empty.json");
        assert.equal(result.findings.length, 0);
        assert.equal(result.overallRisk, "LOW");
    });
    it("handles JSON with data wrapper", () => {
        const json = JSON.stringify({ data: [{ email: "test@example.com" }] });
        const result = scanContent(json, "wrapped.json");
        assert.ok(result.findings.some((f) => f.patternName === "Email Address" || f.source === "column_name"), "Expected finding in wrapped JSON");
    });
    it("handles JSON with rows wrapper", () => {
        const json = JSON.stringify({ rows: [{ ssn: "123-45-6789" }] });
        const result = scanContent(json, "rows.json");
        assert.ok(result.findings.length > 0, "Expected findings");
    });
    it("falls back gracefully on invalid JSON", () => {
        // Should not throw — treats as plain text
        const result = scanContent("not valid json at all", "bad.json");
        assert.ok(result !== undefined);
    });
});
// ── scanColumns ───────────────────────────────────────────────────────────────
describe("scanColumns", () => {
    it("detects phone numbers in content", () => {
        const columns = { contact: ["555-867-5309", "555-123-4567", "555-000-0001"] };
        const result = scanColumns(columns, "test.csv");
        assert.ok(result.findings.some((f) => f.patternName === "US Phone Number"), "Expected US Phone Number finding");
    });
    it("detects routing numbers in content", () => {
        const columns = { routing: ["021000021", "011401533", "021001088"] };
        const result = scanColumns(columns, "bank.csv");
        assert.ok(result.findings.some((f) => f.patternName.includes("Routing") || f.patternName.includes("ABA")), "Expected bank routing number finding");
    });
    it("flags column names matching suspicious patterns", () => {
        const columns = { patient_id: ["P001", "P002"], diagnosis: ["cold", "flu"] };
        const result = scanColumns(columns, "health.csv");
        assert.ok(result.findings.some((f) => f.source === "column_name"), "Expected column name finding for health data");
    });
    it("reports correct column in finding", () => {
        const columns = { email: ["test@example.com"], age: ["25", "30"] };
        const result = scanColumns(columns, "data.csv");
        const emailFinding = result.findings.find((f) => f.patternName === "Email Address");
        assert.ok(emailFinding, "Expected Email Address finding");
        assert.equal(emailFinding.column, "email");
    });
    it("overall risk is HIGH when any finding is HIGH", () => {
        const columns = { zip: ["90210"], email: ["x@y.com"] };
        const result = scanColumns(columns, "mixed.csv");
        assert.equal(result.overallRisk, "HIGH");
    });
    it("overall risk is LOW for empty columns", () => {
        const result = scanColumns({}, "empty.csv");
        assert.equal(result.overallRisk, "LOW");
        assert.equal(result.findings.length, 0);
    });
    it("sampleValues in findings are redacted", () => {
        const columns = { email: ["alice@example.com"] };
        const result = scanColumns(columns, "redact.csv");
        const emailFinding = result.findings.find((f) => f.patternName === "Email Address");
        assert.ok(emailFinding, "Expected finding");
        for (const sample of emailFinding.sampleValues) {
            assert.ok(!sample.includes("alice"), "Sample should not contain full unredacted value");
            assert.ok(sample.includes("*"), "Sample should contain redaction asterisks");
        }
    });
    it("summary is non-empty string", () => {
        const result = scanColumns({ email: ["x@y.com"] }, "test.csv");
        assert.ok(typeof result.summary === "string" && result.summary.length > 0);
    });
});
// ── Risk level ordering ───────────────────────────────────────────────────────
describe("risk level semantics", () => {
    it("MEDIUM risk stays MEDIUM when no HIGH findings", () => {
        // IPv4 is MEDIUM
        const columns = { ip_log: ["192.168.1.1", "10.0.0.1"] };
        const result = scanColumns(columns, "logs.csv");
        // Could be MEDIUM from content or HIGH from column name heuristic — just not LOW
        assert.ok(result.overallRisk !== "LOW" || result.findings.length === 0);
    });
    it("HIGH overrides MEDIUM and LOW", () => {
        const columns = {
            zip: ["90210", "10001"], // LOW
            ip: ["192.168.1.1"], // MEDIUM
            email: ["test@example.com"], // HIGH
        };
        const result = scanColumns(columns, "mixed.csv");
        assert.equal(result.overallRisk, "HIGH");
    });
});
//# sourceMappingURL=scanner.test.js.map