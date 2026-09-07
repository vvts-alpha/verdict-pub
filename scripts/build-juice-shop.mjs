// Build benchmarks/juice-shop/ from the Juice Shop assessment run:
//   - regenerate report.html + report.md WITH request/response evidence (current VERDICT branding)
//   - write SVG chart cards (assets/) + a README.md analysis (mirrors benchmarks/xbow-bench)
// Run: node scripts/build-juice-shop.mjs   (set VERDICT_SOURCE_DIR and VERDICT_RUNS_DIR; see scripts/README.md)
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { loadCore, runsDir as configuredRunsDir } from "./verdict-source.mjs";
const { AssessmentStore, buildReportModel, renderReportHtml, renderMarkdown } = await loadCore();

const RUN = "a-mr3eu4zd-e6aw35";
const OUT = "benchmarks/juice-shop";
const ASSETS = `${OUT}/assets`;
mkdirSync(ASSETS, { recursive: true });

function loadEvidenceArtifact(artifactsDir, evId, maxResponseBytes = 16384) {
  if (!existsSync(artifactsDir)) return null;
  let dir = null;
  for (const ent of readdirSync(artifactsDir, { withFileTypes: true })) {
    if (!ent.isDirectory()) continue;
    const cand = join(artifactsDir, ent.name, evId);
    if (existsSync(cand) && statSync(cand).isDirectory()) { dir = cand; break; }
  }
  if (!dir) return null;
  const read = (f) => { try { return readFileSync(join(dir, f), "utf8"); } catch { return null; } };
  const request = read("request.http.txt");
  let response = read("response.http.txt");
  let truncated = false;
  if (response && response.length > maxResponseBytes) { response = response.slice(0, maxResponseBytes); truncated = true; }
  return { request, response, truncated };
}

// ── load + regenerate reports (fixed date → deterministic) ──
const store = AssessmentStore.open(join(configuredRunsDir, RUN, "state.sqlite"));
const state = store.loadAssessment(RUN);
store.close();
if (!state) throw new Error("run not found");
const model = buildReportModel(state, new Date("2026-07-02T12:00:00Z"), { loadEvidence: (evId) => loadEvidenceArtifact(join(configuredRunsDir, RUN, "artifacts"), evId) });
writeFileSync(`${OUT}/report.html`, renderReportHtml(model));
writeFileSync(`${OUT}/report.md`, renderMarkdown(model));

// ── findings from the DB (severity / category / verdict) ──
const db = store; // already closed; re-open read for findings via a fresh store
const s2 = AssessmentStore.open(join(configuredRunsDir, RUN, "state.sqlite"));
const st = s2.loadAssessment(RUN);
s2.close();
const findings = st.findings;
const target = st.target?.url ?? (st.target?.kind === "single_url" ? st.target.url : "OWASP Juice Shop");
const cat = (f) => f.category ?? (String(f.title || "").match(/^\[([a-z0-9-]+)\]/)?.[1]) ?? "other";
const isSuspected = (f) => (f.verdict ?? "confirmed") === "suspected";
const sevOrder = ["critical", "high", "medium", "low", "info"];
const sevRank = (f) => { const i = sevOrder.indexOf(f.severity); return i < 0 ? 9 : i; };
const bySeverity = (a, b) => sevRank(a) - sevRank(b);
const confirmed = findings.filter((f) => !isSuspected(f)).sort(bySeverity); // critical → info, to match the report
const suspected = findings.filter(isSuspected).sort(bySeverity);

const sevCount = {}; for (const k of sevOrder) sevCount[k] = 0;
for (const f of confirmed) sevCount[f.severity] = (sevCount[f.severity] ?? 0) + 1;
const byClass = {};
for (const f of confirmed) { const c = cat(f); byClass[c] = (byClass[c] ?? 0) + 1; }
const classes = new Set([...confirmed, ...suspected].map(cat));

// ── SVG chart cards (dark surface, status palette for severity) ──
const FONT = "ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif", MONO = "ui-monospace,SFMono-Regular,Menlo,monospace";
const xesc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
function barCard(title, items, W = 720) {
  const pad = 20, rowH = 30, top = 58, labelW = 168, valW = 70;
  const H = top + items.length * rowH + 12, tX = pad + labelW, tW = W - pad - labelW - valW;
  const max = Math.max(1, ...items.map((i) => i.value));
  const bars = items.map((it, i) => {
    const y = top + i * rowH, len = Math.max(3, Math.round((it.value / max) * tW)), col = it.color || "#3987e5";
    return `<text x="${pad}" y="${y + 16}" fill="#8b949e" font-size="13" font-family="${FONT}">${xesc(it.label)}</text>` +
      `<rect x="${tX}" y="${y + 3}" width="${tW}" height="18" rx="4" fill="#161b22"/>` +
      `<rect x="${tX}" y="${y + 3}" width="${len}" height="18" rx="4" fill="${col}"/>` +
      `<text x="${tX + tW + 8}" y="${y + 16}" fill="#e6edf3" font-size="12.5" font-family="${MONO}">${xesc(it.value)}</text>`;
  }).join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="${xesc(title)}">` +
    `<rect x="0.5" y="0.5" width="${W - 1}" height="${H - 1}" rx="12" fill="#0d1117" stroke="#21262d"/>` +
    `<text x="${pad}" y="34" fill="#c9d1d9" font-size="15" font-weight="600" font-family="${FONT}">${xesc(title)}</text>${bars}</svg>`;
}
const sevColor = { critical: "#e66767", high: "#d95926", medium: "#c98500", low: "#199e70", info: "#8b949e" };
writeFileSync(`${ASSETS}/by-severity.svg`, barCard("Confirmed findings by severity",
  sevOrder.filter((k) => sevCount[k] > 0).map((k) => ({ label: k, value: sevCount[k], color: sevColor[k] }))));
writeFileSync(`${ASSETS}/by-class.svg`, barCard("Confirmed findings by vulnerability class",
  Object.entries(byClass).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ label: k, value: v, color: "#3987e5" }))));

// ── README ──
const badge = (l, m, c) => `https://img.shields.io/badge/${encodeURIComponent(l)}-${encodeURIComponent(m)}-${c}?style=flat-square`;
const badges = [
  ["confirmed", String(confirmed.length), "2ea043"],
  ["suspected", String(suspected.length), "bb8009"],
  ["vuln classes", String(classes.size), "1f6feb"],
  ["critical", String(sevCount.critical), "c0392b"],
].map(([l, m, c]) => `![${l}](${badge(l, m, c)})`).join(" ");
const img = (f, alt) => `<p align="center"><img src="assets/${f}" alt="${alt}" width="720"></p>`;
const sevLine = sevOrder.filter((k) => sevCount[k] > 0).map((k) => `${sevCount[k]} ${k}`).join(" · ");
const row = (f, i) => `| ${i + 1} | ${f.severity} | ${cat(f)} | ${String(f.title || "").replace(/^\[[a-z0-9-]+\]\s*/, "").replace(/\|/g, "\\|").slice(0, 110)} |`;

const readme = `# VERDICT × OWASP Juice Shop

**One autonomous VERDICT assessment of [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)** — the reference "most modern and sophisticated insecure web application." Every finding below is backed by the agent's recorded request/response evidence (see \`report.html\`).

${badges}

> **${confirmed.length} confirmed findings** across **${classes.size} vulnerability classes** in a single unattended run — from a **critical SQL-injection auth-bypass to admin** down to business-logic fraud (negative-quantity checkout, self-credit wallet top-up) — plus **${suspected.length} suspected** version-based CVE leads. Confirmed = a failing negative control + ≥2 stable positive replays; nothing is a string-match guess.

## Result at a glance

| | |
|---|---|
| Target | OWASP Juice Shop (\`${xescMd(target)}\`) |
| **Confirmed findings** | **${confirmed.length}** (${sevLine}) |
| Suspected (needs manual verification) | ${suspected.length} (version-based CVE leads) |
| Distinct vuln classes | ${classes.size} |

## Confirmed findings by severity

${img("by-severity.svg", "Confirmed findings by severity")}

## Confirmed findings by vulnerability class

${img("by-class.svg", "Confirmed findings by vulnerability class")}

The spread shows breadth *and* depth: broken access control dominates (IDOR / BOLA / mass-assignment / function-level authz), alongside injection (SQLi), server-side attacks (XXE, SSRF, path-traversal), business-logic abuse, and sensitive-data exposure.

## Highlights

- 🔴 **Critical — SQLi auth-bypass to admin.** SQL injection in the login email field yields full authentication bypass as the admin user.
- 🔓 **Broken access control, everywhere.** BOLA on \`/rest/basket/{id}\`, \`/rest/track-order/{id}\`, \`/api/Users/{id}\`; a full user-directory dump (incl. deluxe tokens); IDOR-writes that let any user delete feedback, tamper products, and hijack another user's delivery address.
- 🗄 **Sensitive-data exposure.** \`/rest/memories\` leaks every user's password hash + deluxe token unauthenticated; a **BIP39 crypto-wallet seed phrase** sits in public \`/api/Feedbacks\`.
- 🧩 **Business-logic fraud.** Negative-quantity basket item → negative order total that checkout *accepts*; unvalidated wallet top-up = arbitrary self-credit; deluxe-membership payment bypass.
- 🧨 **Server-side.** XXE file disclosure via the complaint-invoice upload; SSRF with response readback via the profile-image URL; path traversal through **poison null-byte** filter bypass leaking source/config.
- 🧪 **Suspected (${suspected.length}).** Version-based CVE leads from a leaked \`package-lock.json.bak\` — express-jwt CVE-2020-15084 (JWT authz bypass), marsdb RCE, js-yaml RCE, libxmljs XXE — surfaced honestly for manual confirmation, not counted as confirmed.

## All findings

<details><summary><b>${confirmed.length} confirmed + ${suspected.length} suspected</b></summary>

**Confirmed**

| # | Severity | Class | Finding |
|---|---|---|---|
${confirmed.map(row).join("\n")}

**Suspected** (needs manual verification)

| # | Severity | Class | Finding |
|---|---|---|---|
${suspected.map(row).join("\n")}

</details>

## Methodology

- **Evidence discipline** — a finding is \`confirmed\` only with a **negative control that fails + ≥2 positive replays that succeed**; catch-all 200s / unstable responses are auto-refuted. Every finding in \`report.html\` embeds the proving requests and responses.
- **Suspected tier** — version-based CVE leads (from a leaked lockfile) are surfaced as *suspected* — real leads for a human to confirm, deliberately kept out of the confirmed count.
- **Reproduce** — regenerate this folder with \`node scripts/build-juice-shop.mjs\` with a built source checkout and private run directory (see [script setup](../../scripts/README.md)).

## Files

- \`README.md\` — this analysis.
- \`report.html\` / \`report.md\` — the full VERDICT report, **with request/response evidence** for every finding.
- \`assets/*.svg\` — the charts above.
`;
writeFileSync(`${OUT}/README.md`, readme);
console.log(`juice-shop: ${confirmed.length} confirmed + ${suspected.length} suspected · ${classes.size} classes · report.html/md + 2 charts + README`);

function xescMd(s) { return String(s ?? "").replace(/\|/g, "\\|"); }
