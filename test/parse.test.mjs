import { test } from "node:test";
import assert from "node:assert/strict";
import { parseResults, ParseError } from "../parse.js";

const rows = [
  { severity: "review", check_id: "RLS-11", object: "bucket pics", finding: "Public bucket: anyone with a file's URL can download it.", fix: "Make it private." },
  { severity: "high", check_id: "RLS-08", object: "public.f(a uuid, b text)", finding: "Runs with full rights, and \"anyone\" can call it.", fix: "revoke execute on function public.f(a uuid, b text) from public, anon;" },
  { severity: "note", check_id: "-", object: "-", finding: "Checked: public plus storage.", fix: "-" },
];

function expectShape(result) {
  assert.equal(result.findings.length, 2);
  assert.equal(result.findings[0].severity, "high", "sorted by severity");
  assert.equal(result.findings[0].object, "public.f(a uuid, b text)");
  assert.equal(result.findings[0].finding, 'Runs with full rights, and "anyone" can call it.');
  assert.equal(result.note, "Checked: public plus storage.");
}

const csvCell = (v) => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
const cols = ["severity", "check_id", "object", "finding", "fix"];

test("JSON array", () => expectShape(parseResults(JSON.stringify(rows))));

test("JSON wrapped in an object", () => expectShape(parseResults(JSON.stringify({ result: rows }))));

test("CSV with quoted commas, quotes and CRLF", () => {
  const csv = [cols.join(","), ...rows.map((r) => cols.map((c) => csvCell(r[c])).join(","))].join("\r\n");
  expectShape(parseResults(csv));
});

test("CSV field containing a newline", () => {
  const csv = `severity,check_id,object,finding,fix\nhigh,RLS-02,t,"line one\nline two",x`;
  assert.equal(parseResults(csv).findings[0].finding, "line one\nline two");
});

test("markdown table, including an escaped pipe", () => {
  const md = [
    "| severity | check_id | object | finding | fix |",
    "| --- | --- | --- | --- | --- |",
    ...rows.map((r) => `| ${cols.map((c) => r[c].replace(/\|/g, "\\|")).join(" | ")} |`),
    "| medium | RLS-06 | t | a \\| b | x |",
  ].join("\n");
  const result = parseResults(md);
  assert.equal(result.findings.length, 3);
  assert.equal(result.findings.find((f) => f.check === "RLS-06").finding, "a | b");
});

test("grid cells copied without a header (tab separated)", () => {
  const tsv = rows.map((r) => cols.map((c) => r[c]).join("\t")).join("\n");
  expectShape(parseResults(tsv));
});

test("clean project: only ok and note rows", () => {
  const result = parseResults(JSON.stringify([
    { severity: "ok", check_id: "-", object: "-", finding: "No configuration problems found by this check.", fix: "-" },
    { severity: "note", check_id: "-", object: "-", finding: "Checked: public.", fix: "-" },
  ]));
  assert.equal(result.findings.length, 0);
});

test("empty input and unrelated data are errors, not empty reports", () => {
  assert.throws(() => parseResults("   "), ParseError);
  assert.throws(() => parseResults("name,email\nx,y"), ParseError);
  assert.throws(() => parseResults("[{\"id\":1}]"), ParseError);
  assert.throws(() => parseResults("{not json"), ParseError);
});

test("markup in pasted text stays text", () => {
  const result = parseResults(JSON.stringify([{ ...rows[1], object: "<img src=x onerror=alert(1)>" }]));
  assert.equal(result.findings[0].object, "<img src=x onerror=alert(1)>");
});
