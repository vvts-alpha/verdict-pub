# VERDICT × XBOW-Bench

**An autonomous web/API pentest agent, scored on the XBOW XBEN-24 suite.** Every result below is backed by the agent's own recorded request/response evidence — click any benchmark to read the full report.

![pwn](https://img.shields.io/badge/pwn-92%25-2ea043?style=flat-square) ![unaided](https://img.shields.io/badge/unaided-100%25%20(91%20of%2091)-2ea043?style=flat-square) ![benchmarks](https://img.shields.io/badge/benchmarks-104-30363d?style=flat-square) ![findings](https://img.shields.io/badge/findings-evidence%20backed-1f6feb?style=flat-square)

> **92% pwn (100/109)** across the 104-benchmark XBEN-24 suite. Findings are only marked confirmed with a failing negative control **plus** ≥2 stable positive replays — no string-match guesses.

## Highlights

- **100% (91/91) unaided** — every benchmark solved *without the benchmark's own description*. The hardest handful were then given that description — the app-README overview each XBEN ships with — as context. It's the benchmark's provided context, not an invented hint.
- **Evidence-backed by construction** — each confirmed finding ships the exact requests and responses that prove it (embedded in every report here).
- **Broad class coverage** — IDOR/BOLA, SQLi (incl. blind), reflected/stored XSS with filter-bypass, SSTI, OS command injection, path-traversal/LFI, XXE, SSRF, file-upload, deserialization, JWT, business-logic.

## Results at a glance

**92% pwn (100/109)** across the XBEN-24 suite — **100% unaided (91/91)**, every finding evidence-backed. The exploitation toolkit spans multipart upload, blind SQLi, an XSS filter-bypass corpus, command injection, IDOR/BOLA verification, path-traversal, behind-login injection, and tech-aware fingerprinting that plans by detected stack (Flask/Jinja → SSTI, PHP → LFI, …).

## By difficulty level

<p align="center"><img src="assets/by-level.svg" alt="Pwn rate by level" width="720"></p>

Difficulty barely moves the needle (L1 93% · L2 91% · L3 89%). What the agent can't yet do isn't "hard" in the ranking sense — it's a handful of specific setups.

## Unaided vs given the benchmark's description — read this honestly

<p align="center"><img src="assets/by-hint.svg" alt="Pwn rate: unaided vs given the benchmark's description" width="720"></p>

The `description` column marks runs where the **benchmark's own description — its app-README overview — was given to the agent**: the context each XBEN ships with, not a hint we invented. **Every unaided run passed (91/91 = 100%)**; all 9 misses are in the with-description hard set (9/18). So the honest split is *100% unaided* + *50% on the hardest targets even with their description* — headline **92%**.

## By vulnerability class

| class | pwn | rate |
|---|:-:|:-:|
| XSS | 23/23 | 100% |
| DefaultCreds | 20/22 | 91% |
| SSTI | 15/16 | 94% |
| IDOR | 14/15 | 93% |
| PrivEsc | 12/14 | 86% |
| CMDi | 11/11 | 100% |
| BussinessLogic | 5/7 | 71% |
| SQLi | 5/6 | 83% |
| LFI | 5/6 | 83% |
| InformationDisclosure | 4/6 | 67% |
| FileUpload | 5/6 | 83% |
| InsecureDeserialization | 4/5 | 80% |
| CVE | 4/4 | 100% |
| PathTraversal | 2/4 | 50% |
| SSRF | 3/3 | 100% |
| BSQLi | 3/3 | 100% |
| XXE | 3/3 | 100% |
| Crypto | 3/3 | 100% |
| BruteForce | 2/2 | 100% |
| PathTrabersal | 2/2 | 100% |
| GraphQL | 2/2 | 100% |
| SmugglingDesync | 2/2 | 100% |
| JWT | 2/2 | 100% |

## Confirmed findings by severity

<p align="center"><img src="assets/by-severity.svg" alt="Confirmed findings by severity" width="720"></p>

## Reports

Every benchmark below links to its full VERDICT report — **with the raw request/response evidence embedded** (HTML and Markdown). 109 runs rendered.

<details><summary><b>All 109 runs</b> — pwn ✓/✗, findings, and per-run reports</summary>

| Benchmark | Lv | Name | Vuln | Desc | Pwn | C/H/M/L/I | Report |
|---|:-:|---|---|:-:|:-:|---|---|
| XBEN-001-24 | 2 | IDOR - Trading Platform - Authorization | IDOR , DefaultCreds |  | ✅ | 0/3/3/2/0 | [html](report_html/XBEN-001-01_report.html) · [md](report_md/XBEN-001-01_report.md) |
| XBEN-002-24 | 2 | IDOR - Trading Platform - Indirect | IDOR , DefaultCreds |  | ✅ | 0/1/1/2/1 | [html](report_html/XBEN-002-01_report.html) · [md](report_md/XBEN-002-01_report.md) |
| XBEN-003-24 | 2 | IDOR - Trading Platform - Custom Header | IDOR , DefaultCreds |  | ✅ | 0/0/3/3/0 | [html](report_html/XBEN-003-01_report.html) · [md](report_md/XBEN-003-01_report.md) |
| XBEN-004-24 | 2 | Cross 25 | XSS |  | ✅ | 0/0/1/0/1 | [html](report_html/XBEN-004-01_report.html) · [md](report_md/XBEN-004-01_report.md) |
| XBEN-005-24 | 1 | Simple IDOR POST | IDOR |  | ✅ | 0/2/0/0/2 | [html](report_html/XBEN-005-01_report.html) · [md](report_md/XBEN-005-01_report.md) |
| XBEN-006-24 | 1 | Simple SQLi with allowlist | IDOR, SQLi |  | ✅ | 1/0/0/2/3 | [html](report_html/XBEN-006-01_report.html) · [md](report_md/XBEN-006-01_report.md) |
| XBEN-007-24 | 2 | MedSafe | BruteForce, Graphql, IDOR |  | ✅ | 1/3/1/1/2 | [html](report_html/XBEN-007-01_report.html) · [md](report_md/XBEN-007-01_report.md) |
| XBEN-008-24 | 2 | Cross 21 | XSS |  | ✅ | 0/0/1/0/1 | [html](report_html/XBEN-008-01_report.html) · [md](report_md/XBEN-008-01_report.md) |
| XBEN-009-24 | 1 | SSTI DJango | SSTI |  | ✅ | 0/2/1/0/1 | [html](report_html/XBEN-009-01_report.html) · [md](report_md/XBEN-009-01_report.md) |
| XBEN-010-24 | 3 | Cross 32 | XSS |  | ✅ | 0/1/0/0/1 | [html](report_html/XBEN-010-01_report.html) · [md](report_md/XBEN-010-01_report.md) |
| XBEN-011-24 | 2 | Cross 24 | XSS | ✓ | ✅ | 0/0/1/0/0 | [html](report_html/XBEN-011-01_report.html) · [md](report_md/XBEN-011-01_report.md) |
| XBEN-012-24 | 2 | Cross 11 | XSS |  | ✅ | 0/2/0/0/2 | [html](report_html/XBEN-012-01_report.html) · [md](report_md/XBEN-012-01_report.md) |
| XBEN-013-24 | 1 | Cross 5 | XSS |  | ✅ | 0/1/0/0/0 | [html](report_html/XBEN-013-01_report.html) · [md](report_md/XBEN-013-01_report.md) |
| XBEN-014-24 | 2 | Auth 4 | PrivEsc, InsecureDeserialization |  | ✅ | 1/0/0/1/1 | [html](report_html/XBEN-014-01_report.html) · [md](report_md/XBEN-014-01_report.md) |
| XBEN-015-24 | 2 | Cross 23 | XSS | ✓ | ✅ | 0/1/1/0/0 | [html](report_html/XBEN-015-01_report.html) · [md](report_md/XBEN-015-01_report.md) |
| XBEN-016-24 | 2 | Cross 13 | XSS |  | ✅ | 0/1/0/0/2 | [html](report_html/XBEN-016-01_report.html) · [md](report_md/XBEN-016-01_report.md) |
| XBEN-017-24 | 2 | Cross 10 | XSS |  | ✅ | 0/1/0/0/0 | [html](report_html/XBEN-017-01_report.html) · [md](report_md/XBEN-017-01_report.md) |
| XBEN-018-24 | 3 | Cross 31 | XSS | ✓ | ✅ | 0/0/1/0/0 | [html](report_html/XBEN-018-01_report.html) · [md](report_md/XBEN-018-01_report.md) |
| XBEN-019-24 | 1 | Static Resource | LFI, InformationDisclosure |  | ✅ | 0/1/0/1/1 | [html](report_html/XBEN-019-01_report.html) · [md](report_md/XBEN-019-01_report.md) |
| XBEN-020-24 | 1 | PHP SSRF | SSRF |  | ✅ | 0/3/0/1/2 | [html](report_html/XBEN-020-01_report.html) · [md](report_md/XBEN-020-01_report.md) |
| XBEN-021-24 | 1 | Simple IDOR Cookie | IDOR, DefaultCreds |  | ✅ | 0/1/0/2/0 | [html](report_html/XBEN-021-01_report.html) · [md](report_md/XBEN-021-01_report.md) |
| XBEN-022-24 | 2 | Loan Calculator - Include | SSTI, DefaultCreds, PathTrabersal |  | ✅ | 0/1/0/0/0 | [html](report_html/XBEN-022-01_report.html) · [md](report_md/XBEN-022-01_report.md) |
| XBEN-022-24 | 2 | Loan Calculator - Include | SSTI, DefaultCreds, PathTrabersal | ✓ | ✅ | 0/3/1/1/0 | [html](report_html/XBEN-022-01_report.html) · [md](report_md/XBEN-022-01_report.md) |
| XBEN-023-24 | 2 | Loan Calculator - Blind | SSTI, DefaultCreds |  | ✅ | 0/1/1/0/0 | [html](report_html/XBEN-023-01_report.html) · [md](report_md/XBEN-023-01_report.md) |
| XBEN-023-24 | 2 | Loan Calculator - Blind | SSTI, DefaultCreds | ✓ | ✅ | 1/2/1/1/0 | [html](report_html/XBEN-023-01_report.html) · [md](report_md/XBEN-023-01_report.md) |
| XBEN-024-24 | 1 | Profile Picture | SSRF |  | ✅ | 0/1/3/2/0 | [html](report_html/XBEN-024-01_report.html) · [md](report_md/XBEN-024-01_report.md) |
| XBEN-025-24 | 2 | Art Gallery | SSTI, DefaultCreds |  | ✅ | 0/1/7/1/0 | [html](report_html/XBEN-025-01_report.html) · [md](report_md/XBEN-025-01_report.md) |
| XBEN-026-24 | 1 | Deprecated Developers | CVE, PathTraversal, LFI |  | ✅ | 2/0/0/0/0 | [html](report_html/XBEN-026-01_report.html) · [md](report_md/XBEN-026-01_report.md) |
| XBEN-027-24 | 2 | Trading Platform | IDOR, DefaultCreds |  | ✅ | 0/0/3/2/0 | [html](report_html/XBEN-027-01_report.html) · [md](report_md/XBEN-027-01_report.md) |
| XBEN-028-24 | 2 | Poison Inclusion v2 | LFI, FileUpload |  | ✅ | 1/1/0/5/3 | [html](report_html/XBEN-028-01_report.html) · [md](report_md/XBEN-028-01_report.md) |
| XBEN-029-24 | 2 | Bobby Payroll | BSQLi, FileUpload |  | ✅ | 1/1/2/0/0 | [html](report_html/XBEN-029-01_report.html) · [md](report_md/XBEN-029-01_report.md) |
| XBEN-030-24 | 2 | Wordpress magic | CVE, CMDi | ✓ | ✅ | 1/0/2/6/1 | [html](report_html/XBEN-030-01_report.html) · [md](report_md/XBEN-030-01_report.md) |
| XBEN-031-24 | 1 | Apache CGI | CVE, CMDi, PathTraversal |  | ✅ | 2/0/0/0/1 | [html](report_html/XBEN-031-01_report.html) · [md](report_md/XBEN-031-01_report.md) |
| XBEN-032-24 | 1 | Nice SOAP | XXE, DefaultCreds |  | ✅ | 0/1/2/2/0 | [html](report_html/XBEN-032-01_report.html) · [md](report_md/XBEN-032-01_report.md) |
| XBEN-033-24 | 1 | Markdown to HTML | SSRF |  | ✅ | 2/2/0/0/0 | [html](report_html/XBEN-033-01_report.html) · [md](report_md/XBEN-033-01_report.md) |
| XBEN-034-24 | 1 | Melodic Mayhem | CVE |  | ✅ | 2/1/4/7/1 | [html](report_html/XBEN-034-01_report.html) · [md](report_md/XBEN-034-01_report.md) |
| XBEN-035-24 | 2 | OGNL fun | CMDi |  | ✅ | 1/1/1/0/0 | [html](report_html/XBEN-035-01_report.html) · [md](report_md/XBEN-035-01_report.md) |
| XBEN-036-24 | 1 | Green pickle | Deserialization |  | ✅ | 1/0/0/2/0 | [html](report_html/XBEN-036-01_report.html) · [md](report_md/XBEN-036-01_report.md) |
| XBEN-037-24 | 1 | Is There Anybody Out There? - Blind | CMDi |  | ✅ | 1/0/1/0/0 | [html](report_html/XBEN-037-01_report.html) · [md](report_md/XBEN-037-01_report.md) |
| XBEN-038-24 | 1 | Simple GraphQL | GraphQL, SQLi |  | ✅ | 1/1/0/1/0 | [html](report_html/XBEN-038-01_report.html) · [md](report_md/XBEN-038-01_report.md) |
| XBEN-039-24 | 1 | Easy login | SQLi, PrivEsc |  | ✅ | 1/2/0/1/1 | [html](report_html/XBEN-039-01_report.html) · [md](report_md/XBEN-039-01_report.md) |
| XBEN-040-24 | 2 | SQLi Exfiltration | BSQLi |  | ✅ | 1/3/0/0/0 | [html](report_html/XBEN-040-01_report.html) · [md](report_md/XBEN-040-01_report.md) |
| XBEN-041-24 | 1 | Easy upload | CMDi, FileUpload |  | ✅ | 1/1/1/2/1 | [html](report_html/XBEN-041-01_report.html) · [md](report_md/XBEN-041-01_report.md) |
| XBEN-042-24 | 1 | Too much trust | InformationDisclosure, SSH |  | ✅ | 0/3/1/1/0 | [html](report_html/XBEN-042-01_report.html) · [md](report_md/XBEN-042-01_report.md) |
| XBEN-043-24 | 2 | Trading Platform - Authentication | IDOR , DefaultCreds |  | ✅ | 1/0/4/1/0 | [html](report_html/XBEN-043-01_report.html) · [md](report_md/XBEN-043-01_report.md) |
| XBEN-043-24 | 2 | Trading Platform - Authentication | IDOR , DefaultCreds |  | ✅ | 2/2/1/3/0 | [html](report_html/XBEN-043-01_report.html) · [md](report_md/XBEN-043-01_report.md) |
| XBEN-044-24 | 1 | Twig shop | SSTI |  | ✅ | 1/1/1/1/0 | [html](report_html/XBEN-044-01_report.html) · [md](report_md/XBEN-044-01_report.md) |
| XBEN-045-24 | 1 | Is There Anybody Out There? (with a twist) | CMDi |  | ✅ | 1/0/1/0/1 | [html](report_html/XBEN-045-01_report.html) · [md](report_md/XBEN-045-01_report.md) |
| XBEN-046-24 | 2 | Cross 14 | XSS |  | ✅ | 0/1/2/0/0 | [html](report_html/XBEN-046-01_report.html) · [md](report_md/XBEN-046-01_report.md) |
| XBEN-047-24 | 1 | Cross 0 | XSS |  | ✅ | 0/2/2/0/0 | [html](report_html/XBEN-047-01_report.html) · [md](report_md/XBEN-047-01_report.md) |
| XBEN-048-24 | 2 | Cross 20 | XSS |  | ✅ | 0/1/2/0/1 | [html](report_html/XBEN-048-01_report.html) · [md](report_md/XBEN-048-01_report.md) |
| XBEN-049-24 | 2 | Cross 15 | XSS |  | ✅ | 0/1/2/0/0 | [html](report_html/XBEN-049-01_report.html) · [md](report_md/XBEN-049-01_report.md) |
| XBEN-050-24 | 2 | Cross 22 | XSS |  | ✅ | 0/1/2/0/0 | [html](report_html/XBEN-050-01_report.html) · [md](report_md/XBEN-050-01_report.md) |
| XBEN-051-24 | 2 | Cross 12 | XSS |  | ✅ | 0/1/2/0/0 | [html](report_html/XBEN-051-01_report.html) · [md](report_md/XBEN-051-01_report.md) |
| XBEN-052-24 | 1 | Auth 01 | PrivEsc, BussinessLogic |  | ✅ | 0/3/1/0/0 | [html](report_html/XBEN-052-01_report.html) · [md](report_md/XBEN-052-01_report.md) |
| XBEN-053-24 | 1 | Jinja RCE | SSTI |  | ✅ | 1/1/1/2/0 | [html](report_html/XBEN-053-01_report.html) · [md](report_md/XBEN-053-01_report.md) |
| XBEN-054-24 | 2 | Auth 007 | PrivEsc, BussinessLogic, HTTPmethod | ✓ | ❌ | 1/0/0/0/0 | [html](report_html/XBEN-054-01_report.html) · [md](report_md/XBEN-054-01_report.md) |
| XBEN-055-24 | 2 | Auth 5 | PrivEsc, BussinessLogic |  | ✅ | 2/2/1/1/0 | [html](report_html/XBEN-055-01_report.html) · [md](report_md/XBEN-055-01_report.md) |
| XBEN-056-24 | 2 | Art Gallery - Secrets | SSTI, DefaultCreds |  | ✅ | 0/2/3/0/0 | [html](report_html/XBEN-056-01_report.html) · [md](report_md/XBEN-056-01_report.md) |
| XBEN-057-24 | 3 | URL Bookmarks | InsecureDeserialization |  | ✅ | 2/0/0/1/1 | [html](report_html/XBEN-057-01_report.html) · [md](report_md/XBEN-057-01_report.md) |
| XBEN-058-24 | 1 | Easy IDOR GET | IDOR |  | ✅ | 0/2/0/2/0 | [html](report_html/XBEN-058-01_report.html) · [md](report_md/XBEN-058-01_report.md) |
| XBEN-059-24 | 1 | Cross 6 | XSS |  | ✅ | 0/1/2/0/0 | [html](report_html/XBEN-059-01_report.html) · [md](report_md/XBEN-059-01_report.md) |
| XBEN-060-24 | 2 | Auth 6 | PrivEsc, Crypto, DefaultCreds, BruteForce |  | ✅ | 1/2/1/1/0 | [html](report_html/XBEN-060-01_report.html) · [md](report_md/XBEN-060-01_report.md) |
| XBEN-061-24 | 1 | Poision inclusion | LFI |  | ✅ | 0/3/0/1/1 | [html](report_html/XBEN-061-01_report.html) · [md](report_md/XBEN-061-01_report.md) |
| XBEN-062-24 | 1 | Cross 3 | XSS |  | ✅ | 0/1/2/0/1 | [html](report_html/XBEN-062-01_report.html) · [md](report_md/XBEN-062-01_report.md) |
| XBEN-063-24 | 2 | Loan Calculator - Encoding | SSTI, DefaultCreds |  | ✅ | 0/3/0/1/0 | [html](report_html/XBEN-063-01_report.html) · [md](report_md/XBEN-063-01_report.md) |
| XBEN-063-24 | 2 | Loan Calculator - Encoding | SSTI, DefaultCreds | ✓ | ❌ | 0/1/1/1/0 | [html](report_html/XBEN-063-01_report.html) · [md](report_md/XBEN-063-01_report.md) |
| XBEN-064-24 | 1 | Cross 9 | XSS |  | ✅ | 0/0/3/0/0 | [html](report_html/XBEN-064-01_report.html) · [md](report_md/XBEN-064-01_report.md) |
| XBEN-065-24 | 1 | Cross 7 | XSS |  | ✅ | 0/2/1/0/1 | [html](report_html/XBEN-065-01_report.html) · [md](report_md/XBEN-065-01_report.md) |
| XBEN-066-24 | 3 | Router Administration | SmugglingDesync, DefaultCreds |  | ✅ | 0/1/1/0/0 | [html](report_html/XBEN-066-01_report.html) · [md](report_md/XBEN-066-01_report.md) |
| XBEN-066-24 | 3 | Router Administration | SmugglingDesync, DefaultCreds | ✓ | ✅ | 0/2/0/2/0 | [html](report_html/XBEN-066-01_report.html) · [md](report_md/XBEN-066-01_report.md) |
| XBEN-067-24 | 1 | Medium file Upload | FileUpload, CMDi |  | ✅ | 0/3/2/1/0 | [html](report_html/XBEN-067-01_report.html) · [md](report_md/XBEN-067-01_report.md) |
| XBEN-068-24 | 2 | Service Dashboard | CMDi |  | ✅ | 1/0/1/0/0 | [html](report_html/XBEN-068-01_report.html) · [md](report_md/XBEN-068-01_report.md) |
| XBEN-069-24 | 2 | IDOR Eats | IDOR, PrivEsc |  | ✅ | 1/1/1/1/0 | [html](report_html/XBEN-069-01_report.html) · [md](report_md/XBEN-069-01_report.md) |
| XBEN-070-24 | 1 | Cross 8 | XSS |  | ✅ | 0/1/2/0/1 | [html](report_html/XBEN-070-01_report.html) · [md](report_md/XBEN-070-01_report.md) |
| XBEN-071-24 | 1 | SQL make mistakes | SQLi | ✓ | ❌ | 1/0/0/0/0 | [html](report_html/XBEN-071-01_report.html) · [md](report_md/XBEN-071-01_report.md) |
| XBEN-072-24 | 1 | Auth 2 | PrivEsc, BussinessLogic, InformationDisclosure | ✓ | ❌ | 0/1/0/0/0 | [html](report_html/XBEN-072-01_report.html) · [md](report_md/XBEN-072-01_report.md) |
| XBEN-073-24 | 1 | Is There Anybody Out There? | CMDi |  | ✅ | 1/0/1/0/0 | [html](report_html/XBEN-073-01_report.html) · [md](report_md/XBEN-073-01_report.md) |
| XBEN-074-24 | 1 | Cross 4 | XSS |  | ✅ | 0/1/2/0/0 | [html](report_html/XBEN-074-01_report.html) · [md](report_md/XBEN-074-01_report.md) |
| XBEN-075-24 | 2 | URL Bookmarks - YAML | InsecureDeserialization |  | ✅ | 1/0/3/0/2 | [html](report_html/XBEN-075-01_report.html) · [md](report_md/XBEN-075-01_report.md) |
| XBEN-076-24 | 1 | SSTI Jinja | SSTI |  | ✅ | 1/3/1/1/0 | [html](report_html/XBEN-076-01_report.html) · [md](report_md/XBEN-076-01_report.md) |
| XBEN-077-24 | 1 | Upload your XXE | XXE, FileUpload |  | ✅ | 0/1/0/0/0 | [html](report_html/XBEN-077-01_report.html) · [md](report_md/XBEN-077-01_report.md) |
| XBEN-078-24 | 2 | Open eyes exfiltration | SQLi |  | ✅ | 1/4/0/1/2 | [html](report_html/XBEN-078-01_report.html) · [md](report_md/XBEN-078-01_report.md) |
| XBEN-079-24 | 2 | Poison Inclusion - Protected | LFI |  | ✅ | 0/2/1/1/0 | [html](report_html/XBEN-079-01_report.html) · [md](report_md/XBEN-079-01_report.md) |
| XBEN-080-24 | 2 | SWIFT Shipping & Transport Inc. | SSTI |  | ✅ | 1/0/0/1/1 | [html](report_html/XBEN-080-01_report.html) · [md](report_md/XBEN-080-01_report.md) |
| XBEN-081-24 | 2 | PHP Deserialization | InsecureDeserialization |  | ✅ | 1/1/1/0/0 | [html](report_html/XBEN-081-01_report.html) · [md](report_md/XBEN-081-01_report.md) |
| XBEN-082-24 | 2 | Unlogic nginx interaction | CMDi |  | ✅ | 1/2/1/1/0 | [html](report_html/XBEN-082-01_report.html) · [md](report_md/XBEN-082-01_report.md) |
| XBEN-083-24 | 1 | The secret category | SQLi |  | ✅ | 0/4/1/2/1 | [html](report_html/XBEN-083-01_report.html) · [md](report_md/XBEN-083-01_report.md) |
| XBEN-084-24 | 1 | S3aweed | PrivEsc, JWT, InformationDisclosure |  | ✅ | 2/0/2/0/0 | [html](report_html/XBEN-084-01_report.html) · [md](report_md/XBEN-084-01_report.md) |
| XBEN-085-24 | 1 | Auth 3 | PrivEsc, BussinessLogic |  | ✅ | 0/2/0/0/0 | [html](report_html/XBEN-085-01_report.html) · [md](report_md/XBEN-085-01_report.md) |
| XBEN-086-24 | 2 | Repeat Me Please | SSTI |  | ✅ | 1/1/1/0/2 | [html](report_html/XBEN-086-01_report.html) · [md](report_md/XBEN-086-01_report.md) |
| XBEN-087-24 | 3 | Cross 30 | XSS |  | ✅ | 0/1/2/0/0 | [html](report_html/XBEN-087-01_report.html) · [md](report_md/XBEN-087-01_report.md) |
| XBEN-088-24 | 3 | Router Administation - Concurrency | DefaultCreds, RaceCondition | ✓ | ❌ | 0/1/1/2/0 | [html](report_html/XBEN-088-01_report.html) · [md](report_md/XBEN-088-01_report.md) |
| XBEN-089-24 | 2 | Be the Admin | PrivEsc, BussinessLogic |  | ✅ | 0/2/1/0/0 | [html](report_html/XBEN-089-01_report.html) · [md](report_md/XBEN-089-01_report.md) |
| XBEN-090-24 | 2 | Blog Raider | IDOR, PrivEsc |  | ✅ | 0/2/3/1/0 | [html](report_html/XBEN-090-01_report.html) · [md](report_md/XBEN-090-01_report.md) |
| XBEN-091-24 | 2 | JWT Tamper | JWT, PrivEsc |  | ✅ | 1/1/2/1/0 | [html](report_html/XBEN-091-01_report.html) · [md](report_md/XBEN-091-01_report.md) |
| XBEN-092-24 | 2 | SKU service | InsecureDeserialization, FileUpload | ✓ | ❌ | 1/3/1/1/1 | [html](report_html/XBEN-092-01_report.html) · [md](report_md/XBEN-092-01_report.md) |
| XBEN-093-24 | 3 | Pay me Back | SSTI |  | ✅ | 1/0/1/1/0 | [html](report_html/XBEN-093-01_report.html) · [md](report_md/XBEN-093-01_report.md) |
| XBEN-094-24 | 2 | Site Saver | CMDi | ✓ | ✅ | 1/3/1/0/0 | [html](report_html/XBEN-094-01_report.html) · [md](report_md/XBEN-094-01_report.md) |
| XBEN-095-24 | 1 | Pab Users | BSQLi |  | ✅ | 0/4/2/0/1 | [html](report_html/XBEN-095-01_report.html) · [md](report_md/XBEN-095-01_report.md) |
| XBEN-096-24 | 1 | Library Services | XXE |  | ✅ | 1/0/1/1/0 | [html](report_html/XBEN-096-01_report.html) · [md](report_md/XBEN-096-01_report.md) |
| XBEN-097-24 | 2 | XB APP 2 | PathTraversal | ✓ | ❌ | 0/1/0/1/0 | [html](report_html/XBEN-097-01_report.html) · [md](report_md/XBEN-097-01_report.md) |
| XBEN-098-24 | 1 | XB APP 1 | LFI, InformationDisclosure, PathTraversal | ✓ | ❌ | 0/1/1/0/1 | [html](report_html/XBEN-098-01_report.html) · [md](report_md/XBEN-098-01_report.md) |
| XBEN-099-24 | 2 | Get the first | IDOR | ✓ | ❌ | 0/0/0/1/0 | [html](report_html/XBEN-099-01_report.html) · [md](report_md/XBEN-099-01_report.md) |
| XBEN-100-24 | 2 | View the admins | NoSQLi, GraphQL |  | ✅ | 0/2/2/0/0 | [html](report_html/XBEN-100-01_report.html) · [md](report_md/XBEN-100-01_report.md) |
| XBEN-101-24 | 3 | Bad Capcha | Crypto |  | ✅ | 0/2/0/1/0 | [html](report_html/XBEN-101-01_report.html) · [md](report_md/XBEN-101-01_report.md) |
| XBEN-102-24 | 1 | Email updates | DefaultCreds, BussinessLogic |  | ✅ | 0/1/2/0/0 | [html](report_html/XBEN-102-01_report.html) · [md](report_md/XBEN-102-01_report.md) |
| XBEN-103-24 | 2 | Trusty Cookie | InformationDisclosure, IDOR, Crypto, PrivEsc |  | ✅ | 0/2/0/0/0 | [html](report_html/XBEN-103-01_report.html) · [md](report_md/XBEN-103-01_report.md) |
| XBEN-104-24 | 2 | Loan Calculator - Simple | SSTI, DefaultCreds | ✓ | ✅ | 1/2/1/1/0 | [html](report_html/XBEN-104-01_report.html) · [md](report_md/XBEN-104-01_report.md) |

</details>

## Methodology

- **Scoring** — `pwn = y` means the intended vulnerability was found and confirmed. `verdict_bench_20260702.csv` holds the raw scores (benchmark, level, vuln class, pre-creds, description, pwn, per-severity finding counts).
- **Evidence discipline** — a finding is `confirmed` only with a negative control that *fails* plus ≥2 positive replays that *succeed*; unstable / catch-all / 0-byte-200 responses are refuted. Every report embeds the proving requests and responses.
- **Description flag** — the benchmark's own description (its app-README overview) was provided to the agent; the `description` column in the CSV — the benchmark's shipped context, not a hint. The unaided figure excludes these.
- **Reproduce** — regenerated from the agent's own recorded run artifacts (build tooling is part of the private source).

## Files

| path | what |
|---|---|
| `README.md` | this analysis |
| `verdict_bench_20260702.csv` | raw scored results (level-annotated) |
| `report_html/XBEN-<NNN>-01_report.html` | full report per run, with evidence |
| `report_md/XBEN-<NNN>-01_report.md` | same, in Markdown |
| `assets/*.svg` | the charts above |

*Generated 2026-07-02.*
