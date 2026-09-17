import { parseResults, ParseError, SEVERITIES } from "./parse.js";
import { CHECKS, SAMPLE } from "./checks.js";

const $ = (id) => document.getElementById(id);

const LABEL = { critical: "Critical", high: "High", medium: "Medium", review: "Review" };

// Pasted results are untrusted text, so everything below builds nodes with textContent.
function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "text") node.textContent = v;
    else if (k === "class") node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c) node.append(c);
  return node;
}

async function copy(text, button) {
  const label = button.querySelector("span");
  const before = label.textContent;
  try {
    await navigator.clipboard.writeText(text);
    label.textContent = "Copied";
  } catch {
    label.textContent = "Copy failed";
  }
  setTimeout(() => (label.textContent = before), 1800);
}

function findingItem(f, { compact = false, index = 0 } = {}) {
  const check = CHECKS[f.check];
  const li = el("li", { class: `finding sev-${f.severity}` });
  // CSSOM, not a style attribute: the page's CSP blocks inline style attributes.
  li.style.setProperty("--i", String(index));

  li.append(
    el("div", { class: "finding-top" }, [
      el("span", { class: "sev", text: LABEL[f.severity] }),
      el("span", { class: "check-id", text: f.check }),
      check && !compact ? el("span", { class: "check-title", text: check.title }) : null,
    ]),
    el("p", { class: "object", text: f.object }),
    el("p", { class: "finding-text", text: f.finding }),
  );
  if (compact) return li;

  if (check) {
    const details = el("details", { class: "why" }, [
      el("summary", { text: "Why it matters" }),
      el("p", { text: check.why }),
    ]);
    li.append(details);
  }
  if (f.fix && f.fix !== "-") {
    // Only runnable SQL gets a copy button; the other fixes are directions to follow.
    const isSql = /^(alter|revoke|grant|create|drop)\s/i.test(f.fix);
    const btn = isSql
      ? el("button", { class: "btn small", type: "button" }, [
          el("i", { class: "ph ph-copy", "aria-hidden": "true" }),
          el("span", { text: "Copy fix" }),
        ])
      : null;
    btn?.addEventListener("click", () => copy(f.fix, btn));
    li.append(
      el("div", { class: "fix" }, [
        el("div", { class: "fix-head" }, [el("span", { text: isSql ? "Fix" : "How to fix" }), btn]),
        el(isSql ? "code" : "p", { text: f.fix }),
      ]),
    );
  }
  return li;
}

function counts(findings) {
  return Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
}

function renderReport({ findings, note }) {
  const list = $("findings");
  const tally = $("tally");
  list.replaceChildren(...findings.map((f, i) => findingItem(f, { index: Math.min(i, 12) })));
  tally.replaceChildren(
    ...Object.entries(counts(findings))
      .filter(([, n]) => n > 0)
      .map(([s, n]) => el("li", { class: `sev-${s}` }, [el("strong", { text: String(n) }), el("span", { text: ` ${LABEL[s].toLowerCase()}` })])),
  );
  $("report-title").textContent = findings.length
    ? `${findings.length} ${findings.length === 1 ? "thing" : "things"} to look at`
    : "Nothing flagged";
  $("clean").hidden = findings.length > 0;
  $("scope").textContent = note;
  $("scope").hidden = !note;
  $("report").hidden = false;
  $("report").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
  $("report-title").setAttribute("tabindex", "-1");
  $("report-title").focus({ preventScroll: true });
}

function read(text) {
  const error = $("results-error");
  const field = $("results");
  try {
    const result = parseResults(text);
    error.textContent = "";
    field.removeAttribute("aria-invalid");
    renderReport(result);
  } catch (e) {
    if (!(e instanceof ParseError)) throw e;
    error.textContent = e.message;
    field.setAttribute("aria-invalid", "true");
    $("report").hidden = true;
  }
}

function toJson(rows) {
  return JSON.stringify(rows, null, 2);
}

// Hero preview uses the same renderer as the real report.
const sample = parseResults(toJson(SAMPLE));
$("preview").replaceChildren(...sample.findings.slice(0, 3).map((f, i) => findingItem(f, { compact: true, index: i })));
$("preview-counts").textContent = Object.entries(counts(sample.findings))
  .filter(([, n]) => n > 0)
  .map(([s, n]) => `${n} ${s}`)
  .join(", ");

$("check-list").replaceChildren(
  ...Object.entries(CHECKS).flatMap(([id, c]) => [
    el("div", { class: "check-item" }, [
      el("dt", {}, [el("span", { class: "check-id", text: id }), el("span", { text: c.title })]),
      el("dd", { text: c.why }),
    ]),
  ]),
);

$("paste-form").addEventListener("submit", (e) => {
  e.preventDefault();
  read($("results").value);
});

$("use-sample").addEventListener("click", () => {
  $("results").value = toJson(SAMPLE);
  read($("results").value);
});

fetch("rls-selfcheck.sql")
  .then((r) => (r.ok ? r.text() : Promise.reject(new Error(String(r.status)))))
  .then((sql) => {
    $("sql").textContent = sql;
    const btn = $("copy-sql");
    btn.disabled = false;
    btn.addEventListener("click", () => copy(sql, btn));
  })
  .catch(() => {
    $("sql").textContent = "Couldn't load the query here. Get rls-selfcheck.sql from the source repository.";
  });
