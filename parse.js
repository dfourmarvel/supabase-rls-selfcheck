// Turns what the Supabase SQL editor gives you (JSON, CSV, markdown, or cells copied
// straight from the grid) into findings. Pure functions so they run under node --test.

export const SEVERITIES = ["critical", "high", "medium", "review"];
const COLUMNS = ["severity", "check_id", "object", "finding", "fix"];

export class ParseError extends Error {}

export function parseResults(text) {
  const t = (text ?? "").trim();
  if (!t) throw new ParseError("Paste the results first.");

  let rows;
  if (t.startsWith("[") || t.startsWith("{")) rows = fromJson(t);
  else if (t.startsWith("|")) rows = fromMarkdown(t);
  else rows = fromDelimited(t, t.split(/\r?\n/)[0].includes("\t") ? "\t" : ",");

  return normalise(rows);
}

function fromJson(t) {
  let data;
  try {
    data = JSON.parse(t);
  } catch {
    throw new ParseError("That looks like JSON but it didn't parse. Copy the results again.");
  }
  if (!Array.isArray(data)) data = data.result ?? data.rows ?? data.data;
  if (!Array.isArray(data)) throw new ParseError("Expected a list of rows in that JSON.");
  return data;
}

function fromMarkdown(t) {
  const lines = t.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.startsWith("|"));
  const cells = (line) =>
    line
      .replace(/^\||\|$/g, "")
      .split(/(?<!\\)\|/)
      .map((c) => c.trim().replace(/\\\|/g, "|"));
  const rows = lines.filter((l) => !/^\|[\s:|-]+\|$/.test(l)).map(cells);
  return toObjects(rows);
}

// RFC 4180-style: quoted fields may hold the delimiter, newlines and "" escapes.
function fromDelimited(t, delim) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < t.length; i++) {
    const ch = t[i];
    if (quoted) {
      if (ch === '"' && t[i + 1] === '"') {
        field += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"' && field === "") quoted = true;
    else if (ch === delim) {
      row.push(field);
      field = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && t[i + 1] === "\n") i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else field += ch;
  }
  row.push(field);
  rows.push(row);
  return toObjects(rows.filter((r) => r.some((c) => c.trim() !== "")));
}

function toObjects(rows) {
  if (rows.length === 0) return [];
  const header = rows[0].map((h) => h.trim().toLowerCase());
  if (!header.includes("severity")) {
    // Cells copied from the grid without the header row: assume the query's column order.
    return rows.map((r) => Object.fromEntries(COLUMNS.map((c, i) => [c, r[i] ?? ""])));
  }
  return rows.slice(1).map((r) => Object.fromEntries(header.map((h, i) => [h, r[i] ?? ""])));
}

function normalise(rows) {
  const clean = rows.map((r) =>
    Object.fromEntries(Object.entries(r).map(([k, v]) => [k.trim().toLowerCase(), String(v ?? "").trim()])),
  );
  const known = clean.filter((r) => [...SEVERITIES, "ok", "note"].includes(r.severity?.toLowerCase()));
  if (known.length === 0) {
    throw new ParseError(
      "These don't look like self-check results. Run the query above and copy its output, with the severity, check_id, object, finding and fix columns.",
    );
  }
  const findings = known
    .filter((r) => SEVERITIES.includes(r.severity.toLowerCase()))
    .map((r) => ({
      severity: r.severity.toLowerCase(),
      check: r.check_id ?? "",
      object: r.object ?? "",
      finding: r.finding ?? "",
      fix: r.fix ?? "",
    }))
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  const note = known.find((r) => r.severity.toLowerCase() === "note")?.finding ?? "";
  return { findings, note };
}
