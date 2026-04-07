/**
 * @certifieddata/pii-scan — CLI integration tests
 *
 * Tests CLI exit codes and output format using real temp files.
 * Requires dist/ to be built first: pnpm build
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const CLI = resolve(__dirname, "../dist/cli.js");
function runCli(file, args = []) {
    const result = spawnSync("node", [CLI, file, ...args], { encoding: "utf8" });
    return {
        stdout: result.stdout ?? "",
        stderr: result.stderr ?? "",
        status: result.status ?? 0,
    };
}
function withTempFile(content, ext, fn) {
    const file = join(tmpdir(), `pii-scan-test-${Date.now()}${ext}`);
    writeFileSync(file, content, "utf8");
    try {
        fn(file);
    }
    finally {
        try {
            unlinkSync(file);
        }
        catch { /* ignore cleanup errors */ }
    }
}
// ── Exit codes ────────────────────────────────────────────────────────────────
describe("CLI exit codes", () => {
    it("exits 0 for clean file with no PII", () => {
        withTempFile("product_id,price,quantity\nP001,19.99,5\nP002,34.50,2", ".csv", (file) => {
            const { status } = runCli(file);
            assert.equal(status, 0, "Expected exit 0 for clean CSV");
        });
    });
    it("exits 2 for file with HIGH risk PII", () => {
        withTempFile("name,email\nAlice,alice@example.com\nBob,bob@example.com", ".csv", (file) => {
            const { status } = runCli(file);
            assert.equal(status, 2, "Expected exit 2 for HIGH risk (email found)");
        });
    });
    it("exits 1 for MEDIUM risk findings", () => {
        // IP addresses are MEDIUM; avoid column names that trigger HIGH heuristics
        withTempFile("server_log,request_count\n192.168.1.1,42\n10.0.0.1,7", ".csv", (file) => {
            const { status } = runCli(file);
            // MEDIUM or higher — at minimum exits non-zero
            assert.ok(status >= 1, `Expected exit >= 1 for MEDIUM risk, got ${status}`);
        });
    });
    it("exits non-zero when HIGH risk SSN found", () => {
        withTempFile("record_id,tax_id\n1,123-45-6789\n2,987-65-4321", ".csv", (file) => {
            const { status } = runCli(file);
            assert.equal(status, 2, "Expected exit 2 for SSN (HIGH)");
        });
    });
});
// ── JSON output mode ──────────────────────────────────────────────────────────
describe("CLI --json flag", () => {
    it("outputs valid JSON when --json is passed", () => {
        withTempFile("email\nalice@example.com", ".csv", (file) => {
            const { stdout } = runCli(file, ["--json"]);
            let parsed;
            assert.doesNotThrow(() => {
                parsed = JSON.parse(stdout);
            }, "Output should be parseable JSON");
            assert.ok(typeof parsed.overallRisk === "string", "overallRisk should be a string");
            assert.ok(Array.isArray(parsed.findings), "findings should be an array");
            assert.ok(typeof parsed.file === "string", "file should be a string");
            assert.ok(typeof parsed.rowsScanned === "number", "rowsScanned should be a number");
            assert.ok(typeof parsed.columnsScanned === "number", "columnsScanned should be a number");
        });
    });
    it("JSON output includes summary string", () => {
        withTempFile("email\nalice@example.com", ".csv", (file) => {
            const { stdout } = runCli(file, ["--json"]);
            const parsed = JSON.parse(stdout);
            assert.ok(typeof parsed.summary === "string" && parsed.summary.length > 0);
        });
    });
    it("JSON output has overallRisk HIGH for email column", () => {
        withTempFile("email\nalice@example.com", ".csv", (file) => {
            const { stdout } = runCli(file, ["--json"]);
            const parsed = JSON.parse(stdout);
            assert.equal(parsed.overallRisk, "HIGH");
        });
    });
    it("JSON findings have expected fields", () => {
        withTempFile("email\nalice@example.com\nbob@test.org", ".csv", (file) => {
            const { stdout } = runCli(file, ["--json"]);
            const parsed = JSON.parse(stdout);
            assert.ok(parsed.findings.length > 0);
            const finding = parsed.findings[0];
            assert.ok(typeof finding.column === "string");
            assert.ok(typeof finding.patternName === "string");
            assert.ok(typeof finding.risk === "string");
            assert.ok(["HIGH", "MEDIUM", "LOW"].includes(finding.risk));
            assert.ok(Array.isArray(finding.sampleValues));
            assert.ok(["content", "column_name"].includes(finding.source));
        });
    });
});
// ── JSON file input ───────────────────────────────────────────────────────────
describe("CLI JSON file support", () => {
    it("scans a JSON file", () => {
        const json = JSON.stringify([{ email: "alice@example.com" }, { email: "bob@example.com" }]);
        withTempFile(json, ".json", (file) => {
            const { status } = runCli(file);
            assert.equal(status, 2, "Expected HIGH risk from JSON file with emails");
        });
    });
    it("clean JSON exits 0", () => {
        const json = JSON.stringify([{ product_id: "P001", price: 9.99 }]);
        withTempFile(json, ".json", (file) => {
            const { status } = runCli(file);
            assert.equal(status, 0);
        });
    });
});
// ── Help flag ─────────────────────────────────────────────────────────────────
describe("CLI --help flag", () => {
    it("shows help and exits 0", () => {
        const result = spawnSync("node", [CLI, "--help"], { encoding: "utf8" });
        assert.equal(result.status, 0, "Expected exit 0 for --help");
        assert.ok(result.stdout.includes("pii-scan") || result.stdout.includes("Usage"), "Expected help text in output");
    });
});
//# sourceMappingURL=cli.test.js.map