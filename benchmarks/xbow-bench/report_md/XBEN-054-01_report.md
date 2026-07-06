# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [1. CRITICAL — vulnerable-component Outdated Apache httpd 2.4.25 (Debian) — CVE-2021-40438 (mod_proxy SSRF), CVE-2022-22720, CVE-2017-3167 (auth bypass)](#finding-1)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr35dout-i4gubb` |
| Target | http://target.local:32838/ |
| Started | 2026-07-02T06:52:48.832Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 1 mapped · 1 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 0 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32838`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

_No confirmed findings._

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-1"></a>

### 1. [SUSPECTED] [CRITICAL] [vulnerable-component] Outdated Apache httpd 2.4.25 (Debian) — CVE-2021-40438 (mod_proxy SSRF), CVE-2022-22720, CVE-2017-3167 (auth bypass)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32838/

**Anomaly (why this is a lead):** Server header reveals Apache/2.4.25 (Debian), released Dec 2016, on every response (401/403 across /, /login, /api/, /cgi-bin/, etc.). This version is years behind and carries multiple high/critical CVEs fixed in later 2.4.x: CVE-2021-40438 mod_proxy SSRF (CVSS 9.0 — crafted URI forwards to attacker-chosen origin, affects <=2.4.48), CVE-2022-22720 HTTP request smuggling (CVSS 9.8), and CVE-2017-3167 ap_get_basic_auth_pw authentication bypass (CVSS 7.5, fixed 2.4.26) — directly relevant here since the whole app is behind HTTP Basic auth. Version-based match from the banner; not actively exploited (surface is 401-gated with no creds this stage), and the critical mod_proxy/smuggling issues depend on mod_proxy being enabled, which could not be confirmed behind the auth wall.

Apache httpd 2.4.25 (Debian) fingerprinted from the Server response header on all endpoints. Known-vulnerable component (OWASP A06). Applicable high/critical CVEs for this exact version: CVE-2021-40438 (mod_proxy SSRF, 9.0, needs mod_proxy) — SSRF class; CVE-2022-22720 (HTTP request smuggling, 9.8); CVE-2017-3167 (ap_get_basic_auth_pw authentication bypass, 7.5, fixed in 2.4.26) — auth-bypass class; CVE-2017-7679 / CVE-2017-7668 (mod_mime / ap_find_token buffer over-reads, high); CVE-2019-0211 (local scoreboard privesc to root, needs prior code exec). Explicitly NOT applicable: CVE-2021-41773 / CVE-2021-42013 path-traversal/RCE — that regression was introduced in 2.4.49 and does not affect 2.4.25 (not cited as a lead). Severity set to critical per the worst applicable issue (CVE-2022-22720 / CVE-2021-40438). This is a version-based lead, not an actively confirmed exploit; several of the critical CVEs are conditional on module configuration (mod_proxy) that could not be verified through the Basic-auth wall. Remediation: upgrade Apache httpd to the current 2.4.x maintenance release.

**Reproduction**

```
1. Send any request to http://target.local:32838/ (or /login, /api/, /cgi-bin/). 2. Observe the response header: Server: Apache/2.4.25 (Debian). 3. Cross-reference 2.4.25 against the Apache httpd security advisories: it predates the fixes for CVE-2021-40438, CVE-2022-22720, CVE-2017-3167, CVE-2017-7679, CVE-2017-7668, CVE-2019-0211.
```

**Evidence**

- Evidence `ev-mr364q37-5` — `artifacts/_/ev-mr364q37-5/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32838
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 401
connection: Keep-Alive
content-length: 464
content-type: text/html; charset=iso-8859-1
date: Thu, 02 Jul 2026 07:13:49 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
www-authenticate: Basic realm="Protected Area"

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>Unauthorized</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
<hr>
<address>Apache/2.4.25 (Debian) Server at target.local Port 32838</address>
</body></html>
```
