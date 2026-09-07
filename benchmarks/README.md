# VERDICT — Benchmarks & results analysis

Latest desktop evaluation: [September 2026 review, reports, and model cost](juice-shop/desktop-2026-09.md).

VERDICT is an autonomous web/API pentest agent: you hand it **one top URL** and it runs the whole loop — recon → methodology → diagnosis → evidence → report — with no human in the loop and no seed endpoint list. Measuring that honestly takes **two different axes**, because "find a vulnerability" and "drive an assessment by yourself" are not the same skill.

[![XBOW-Bench](https://img.shields.io/badge/XBOW--Bench-92%25%20(100%2F109)-2ea043?style=flat-square)](xbow-bench) [![Web Security Academy](https://img.shields.io/badge/PortSwigger%20WSA-16%2F20%20detected-2ea043?style=flat-square)](web-security-academy) [![Juice Shop](https://img.shields.io/badge/OWASP%20Juice%20Shop-38%20confirmed-c0392b?style=flat-square)](juice-shop)

## The two axes

| Axis | What it measures | The question | Benchmarks |
|---|---|---|---|
| **① Detection accuracy** | Given a target that *has* a vulnerability, does VERDICT find it and confirm it with evidence? | *"Can it detect the vuln — even through a defense?"* | **XBOW-Bench**, **Web Security Academy** |
| **② Autonomous exploration** | Pointed at one URL of a large, unknown app, how much of the attack surface does it map and exploit **unattended**? | *"How much does it find on its own?"* | **OWASP Juice Shop**, live bug-bounty |

These pull in opposite directions on purpose. Axis ① uses **small, single-purpose targets with a known answer** — you can score hit-rate precisely. Axis ② uses **one big sprawling app with an unknown answer** — you score coverage and self-direction. A tool can be great at one and weak at the other; keeping them separate is what makes the numbers mean something.

---

## ① Detection accuracy

*"There is a vulnerability here. Find it, and prove it."* Narrow targets, known ground truth, measured as a hit-rate. Two benchmarks probe different ends of it — **breadth** and **evasion**.

### [XBOW-Bench (XBEN-24)](xbow-bench) — breadth × hit-rate
**92% pwn (100/109)** across the 104-benchmark XBEN-24 suite; **unaided 91/91 = 100%** (all misses are on the hardest targets, given their own description). Each benchmark is a small app built around one intended vuln class, so this is the cleanest read on *raw detection across the class spectrum* — IDOR/BOLA, SQLi (incl. blind), XSS with filter-bypass, SSTI, CMDi, LFI, XXE, SSRF, deserialization, JWT, business-logic.

### [PortSwigger Web Security Academy](web-security-academy) — evasion / through-a-defense
**16/20 detected** on the two *hardest* tiers (Expert ×10 + Practitioner ×10) — **12 confirmed** (failing negative control + ≥2 positive replays on the exact sink) **+ 4 suspected leads**, only **3 genuine blanks**. Scored on **vulnerability detection, not lab "solved"** (the exploit server is a separate, out-of-scope host). Where XBOW asks *"which classes,"* WSA asks *"can it still find the vuln when the app actively defends"* — a strict cache-ability check, an AngularJS sandbox **and** CSP, an HMAC-signed cookie, OOB-only blind XXE.

---

## ② Autonomous exploration

*"Here is a URL. Go."* No endpoint list, no test plan, no per-vuln prompt — the agent maps the app, decides what to test, and drives itself. This is VERDICT's core differentiator, and it is measured differently: not hit-rate on a known answer, but **breadth of discovery on an unknown surface**.

### [OWASP Juice Shop](juice-shop) — coverage from one URL
**38 confirmed findings across 16 vulnerability classes in a single unattended run** — from a **critical SQLi auth-bypass to admin** down to business-logic fraud (negative-quantity checkout, self-credit wallet top-up), plus 5 suspected CVE leads. Juice Shop is the reference "most sophisticated insecure web app"; nobody told VERDICT where to look. This is the closest public proof that the autonomous loop *covers* a real, sprawling surface rather than just answering a pre-scoped question.

### Live bug-bounty — the real thing
VERDICT has produced confirmed, evidence-backed findings against **live bug-bounty targets** from one URL. Programs and reports are withheld under coordinated disclosure, so this can't be a reproducible number — but it is the same axis as Juice Shop, on real, unscoped, moving targets.

---

## What the benchmarks show

- **Detection is production-grade and evidence-backed.** Nothing is a string-match guess — every `confirmed` carries a failing negative control + ≥2 positive replays, and where the proof falls short VERDICT files a *lead* rather than a fabrication. 129 scored detection targets (XBOW + WSA) stand behind that discipline.
- **The autonomous loop covers real, unknown surface.** Juice Shop (38 confirmed across 16 classes, from one URL) and confirmed live bug-bounty findings show recon → diagnosis → evidence running end-to-end, unattended — the capability the whole design is built around.

## What's next

Both axes keep growing. The near-term focus is **broadening axis ② with more large, auth-gated targets** (Hackazon is up next), scored on coverage and auth-traversal alongside detection — plus faster runs (parallel per-screen diagnosis), a wider injection-bypass corpus, and a scope-gated delivery capability to carry more *leads* through to *confirmed*.

## Shared methodology

- **Evidence discipline (every benchmark).** A finding is `confirmed` only with a **negative control that fails + ≥2 positive replays that succeed**; catch-all 200s, 0-byte-200s, and unstable responses are auto-**refuted**. Every report embeds the proving requests and responses.
- **Suspected / lead tier.** Real leads a human should confirm (version-based CVEs, an anomaly without full confirmation) are surfaced separately and **never counted as confirmed**.
- **Scope gate.** Every network action passes `isInScope`; out-of-scope hosts (e.g. the WSA exploit server) are declined, not attempted.

## The three benchmarks

| Benchmark | Axis | Headline | Details |
|---|---|---|---|
| [XBOW-Bench](xbow-bench) | ① detection (breadth) | 92% · 100/109 | 104 targeted apps, 109 per-run reports |
| [Web Security Academy](web-security-academy) | ① detection (evasion) | 16/20 detected | 20 hardest-tier labs, strict per-lab detection grades |
| [OWASP Juice Shop](juice-shop) | ② autonomous exploration | 38 confirmed / 16 classes | one unattended run, evidence per finding |
