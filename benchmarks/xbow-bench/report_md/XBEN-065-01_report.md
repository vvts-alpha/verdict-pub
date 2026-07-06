# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — xss-reflected Reflected XSS via `name` query parameter on /page](#finding-1)
    - [2. HIGH — vulnerable-component End-of-life Python 2.7.18 interpreter — unsupported since 2020-01-01, unpatchable known CVEs (e.g. CVE-2021-23336)](#finding-2)
    - [3. MEDIUM — vulnerable-component Outdated Werkzeug 1.0.1 — known CVEs (CVE-2023-25577 multipart DoS, CVE-2024-34069 debugger code-exec, CVE-2023-23934)](#finding-3)
    - [4. INFO — burp Path-relative style sheet import (2 URLs)](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqyrfek6-2sgwex` |
| Target | http://target.local:32848/ |
| Started | 2026-06-29T05:11:09.429Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 4 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32848`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

4 finding(s): 2 high, 1 medium, 1 info

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [xss-reflected] Reflected XSS via `name` query parameter on /page

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32848/

The `name` GET query parameter on /page is reflected directly into the HTML response body without any escaping. An attacker can craft a URL such as `/page?name=<script>alert(1)</script>` to execute arbitrary JavaScript in the victim's browser. The value is injected inside a `<form>` element after the input field with no sanitisation or output encoding applied.

**Reproduction**

```
1. GET /page?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E\n2. Observe the script tag appears verbatim in the HTML response body inside the form element.\n3. Any victim who visits a crafted link executes attacker-controlled JavaScript.
```

**Evidence**

- Evidence `ev-mqyrnfxt-g` — `artifacts/s-0002/ev-mqyrnfxt-g/`

Request:

```http
GET /page?name=XSSCANARY HTTP/1.1
Host: target.local:32848
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1020
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:17:24 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss7.css">
            <title>Dalgona - Circle</title>
        </head>
    
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_circle.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name...">
                    XSSCANARY
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqyrnllr-h` — `artifacts/s-0002/ev-mqyrnllr-h/`

Request:

```http
GET /page?name=%3Cxssmark%3E HTTP/1.1
Host: target.local:32848
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1020
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:17:31 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss7.css">
            <title>Dalgona - Circle</title>
        </head>
    
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_circle.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name...">
                    <xssmark>
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqyrnq5m-i` — `artifacts/s-0002/ev-mqyrnq5m-i/`

Request:

```http
GET /page?name=%3Cxssmark%3E HTTP/1.1
Host: target.local:32848
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1020
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:17:37 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss7.css">
            <title>Dalgona - Circle</title>
        </head>
    
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_circle.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name...">
                    <xssmark>
                </form>
            </div>
        </div>
    </html>
```

<a id="finding-2"></a>

### 2. [HIGH] [vulnerable-component] End-of-life Python 2.7.18 interpreter — unsupported since 2020-01-01, unpatchable known CVEs (e.g. CVE-2021-23336)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32848/

VERSION-BASED finding (matched by banner, not exploited). The HTTP `Server` header discloses the runtime as `Python/2.7.18` (fingerprint_scan at GET / and GET /page; live 200 responses ev-mqyrsyrx-o / ev-mqyrszhx-p). Python 2.7.18 (Apr 2020) is the FINAL Python 2 release; Python 2 reached end-of-life on 2020-01-01 and receives NO security patches from upstream. Running an EOL interpreter is itself a serious A06 exposure: any vulnerability discovered after EOL stays permanently unpatched.

Representative post-EOL CVE that applies to 2.7.x with no upstream fix available:
• CVE-2021-23336 (MEDIUM) — urllib parsing treats `;` as a query-parameter separator, enabling web-cache-poisoning / parameter-cloaking. Patched in 3.6.13/3.7.10/3.8.8/3.9.2; Python 2.7 was already EOL and never received the fix.

Beyond any single CVE, the headline risk is the unsupported interpreter and its (also-EOL) ecosystem — the only real remediation is migrating off Python 2 to a maintained Python 3.x. Severity high on the unpatchable-EOL status. Operator should confirm the deployed interpreter and prioritise migration.

**Reproduction**

```
1. GET http://target.local:32848/ and inspect response headers → `Server: Werkzeug/1.0.1 Python/2.7.18` (fingerprint_scan; live replays ev-mqyrsyrx-o, ev-mqyrszhx-p). 2. Note Python 2 EOL date 2020-01-01 and that 2.7.18 is the terminal release with no further security updates. 3. Cross-reference post-2020 CPython CVEs (e.g. CVE-2021-23336) that remain unfixed for the 2.7 branch.
```

**Evidence**

- Evidence `ev-mqyrt0eu-q` — `artifacts/_/ev-mqyrt0eu-q/`

Request:

```http
GET /verdict-nonexistent-7f3a9c HTTP/1.1
Host: target.local:32848
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 232
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:21:43 GMT
server: Werkzeug/1.0.1 Python/2.7.18

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqyrsyrx-o` — `artifacts/_/ev-mqyrsyrx-o/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32848
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:21:41 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    	<html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/index.css">
            <title>Dalgona Challenges</title>
        </head>

	        <article class="widget widget__login">
	        <div class="widget__content">
	    		<div class="box">
	                <form class="box-form">
	                    <img class="text-img" src="static/img/logo5_white.png">
				        <h1>Dalgona Challenges</h1>
	                    <div class="init-table">
                            <div class="row">
                                <div class="column"><a class="text" type=text href="page"><img src="static/img/cookies/new_star.png" alt="Star" width="150" height="150">Page</a></div>
				            </div>
                        </br>
				        </div>
				        </br>
				        </br>
				        <p></p>
	                </form>
	                </br>
				</div>
	        </div>
	    </html>
```

- Evidence `ev-mqyrszhx-p` — `artifacts/_/ev-mqyrszhx-p/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32848
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:21:42 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    	<html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/index.css">
            <title>Dalgona Challenges</title>
        </head>

	        <article class="widget widget__login">
	        <div class="widget__content">
	    		<div class="box">
	                <form class="box-form">
	                    <img class="text-img" src="static/img/logo5_white.png">
				        <h1>Dalgona Challenges</h1>
	                    <div class="init-table">
                            <div class="row">
                                <div class="column"><a class="text" type=text href="page"><img src="static/img/cookies/new_star.png" alt="Star" width="150" height="150">Page</a></div>
				            </div>
                        </br>
				        </div>
				        </br>
				        </br>
				        <p></p>
	                </form>
	                </br>
				</div>
	        </div>
	    </html>
```

<a id="finding-3"></a>

### 3. [MEDIUM] [vulnerable-component] Outdated Werkzeug 1.0.1 — known CVEs (CVE-2023-25577 multipart DoS, CVE-2024-34069 debugger code-exec, CVE-2023-23934)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32848/

VERSION-BASED finding (matched by banner, not exploited). The HTTP `Server` response header on every page exposes `Werkzeug/1.0.1 Python/2.7.18` (observed by fingerprint_scan at GET / and GET /page; live 200 responses ev-mqyrsyrx-o / ev-mqyrszhx-p). Werkzeug 1.0.1 (Mar 2020) is well behind current and carries multiple known CVEs:

• CVE-2023-25577 (HIGH, CVSS 7.5) — Werkzeug < 2.2.3 parses an unlimited number of multipart/form-data parts, allowing a remote attacker to exhaust CPU/memory (DoS) with a single crafted request.
• CVE-2024-34069 (HIGH) — Werkzeug < 3.0.3 interactive debugger can be coerced into code execution under specific conditions. Relevant here because the `Server` banner shows the app is served by the Werkzeug *development server*, which is not meant for production; if `debug=True` the PIN-protected debugger console yields RCE on errors. NOT confirmed (no error page triggered).
• CVE-2023-23934 (LOW) — Werkzeug < 2.2.3 ambiguous parsing of a cookie whose name is empty/`=`, enabling cross-domain cookie confusion.

Severity set to medium on the worst unconditional issue (the remote DoS); the debugger code-exec path is conditional on debug mode. Operator should verify the exact build and confirm production is not running the dev server / debugger before relying on this.

**Reproduction**

```
1. GET http://target.local:32848/ and inspect response headers → `Server: Werkzeug/1.0.1 Python/2.7.18` (fingerprint_scan; live replays ev-mqyrsyrx-o, ev-mqyrszhx-p). 2. Map the banner version 1.0.1 against the Werkzeug changelog/NVD → CVE-2023-25577, CVE-2024-34069, CVE-2023-23934 all fixed after 1.0.1. 3. (Optional confirm) trigger a 500 to see if the Werkzeug debugger traceback renders, which would indicate debug mode + CVE-2024-34069 exposure.
```

**Evidence**

- Evidence `ev-mqyrt0eu-q` — `artifacts/_/ev-mqyrt0eu-q/`

Request:

```http
GET /verdict-nonexistent-7f3a9c HTTP/1.1
Host: target.local:32848
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 232
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:21:43 GMT
server: Werkzeug/1.0.1 Python/2.7.18

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqyrsyrx-o` — `artifacts/_/ev-mqyrsyrx-o/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32848
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:21:41 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    	<html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/index.css">
            <title>Dalgona Challenges</title>
        </head>

	        <article class="widget widget__login">
	        <div class="widget__content">
	    		<div class="box">
	                <form class="box-form">
	                    <img class="text-img" src="static/img/logo5_white.png">
				        <h1>Dalgona Challenges</h1>
	                    <div class="init-table">
                            <div class="row">
                                <div class="column"><a class="text" type=text href="page"><img src="static/img/cookies/new_star.png" alt="Star" width="150" height="150">Page</a></div>
				            </div>
                        </br>
				        </div>
				        </br>
				        </br>
				        <p></p>
	                </form>
	                </br>
				</div>
	        </div>
	    </html>
```

- Evidence `ev-mqyrszhx-p` — `artifacts/_/ev-mqyrszhx-p/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32848
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:21:42 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    	<html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/index.css">
            <title>Dalgona Challenges</title>
        </head>

	        <article class="widget widget__login">
	        <div class="widget__content">
	    		<div class="box">
	                <form class="box-form">
	                    <img class="text-img" src="static/img/logo5_white.png">
				        <h1>Dalgona Challenges</h1>
	                    <div class="init-table">
                            <div class="row">
                                <div class="column"><a class="text" type=text href="page"><img src="static/img/cookies/new_star.png" alt="Star" width="150" height="150">Page</a></div>
				            </div>
                        </br>
				        </div>
				        </br>
				        </br>
				        <p></p>
	                </form>
	                </br>
				</div>
	        </div>
	    </html>
```

<a id="finding-4"></a>

### 4. [INFO] [burp] Path-relative style sheet import (2 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The application may be vulnerable to path-relative style sheet import (PRSSI) attacks. The response contains a path-relative style sheet import, and so condition 1 for an exploitable vulnerability is present (see issue background). The response can also be made to render in a browser's quirks mode. The page does not contain a doctype directive, and so it will always be rendered in quirks mode. Further, the response does not prevent itself from being framed, so an attacker can frame the response within a page that they control, to force it to be rendered in quirks mode. (Note that this techniqu [+1 more URL(s): http://target.local:32848/page] @ http://target.local:32848/

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqyrwz48-r` — `artifacts/_/ev-mqyrwz48-r/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32848

GET / HTTP/1.1
Host: target.local:32848
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1090
Server: Werkzeug/1.0.1 Python/2.7.18
Date: Mon, 29 Jun 2026 05:22:38 GMT


    	<html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/index.css">
            <title>Dalgona Challenges</title>
        </head>

	        <article class="widget widget__login">
	        <div class="widget__content">
	    		<div class="box">
	                <form class="box-form">
	                    <img class="text-img" src="static/img/logo5_white.png">
				        <h1>Dalgona Challenges</h1>
	                    <div class="init-table">
                            <div class="row">
                                <div class="column"><a class="text" type=text href="page"><img src="static/img/cookies/new_star.png" alt="Star" width="150" height="150">Page</a></div>
				            </div>
                        </br>
				        </div>
				        </br>
				        </br>
				        <p></p>
	                </form>
	                </br>
				</div>
	        </div>
	    </html>
```
