# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — xss-reflected Reflected + DOM XSS via `name` parameter on /page](#finding-1)
    - [2. MEDIUM — vulnerable-component Outdated Werkzeug 1.0.1 (Flask dev server) — known DoS CVE-2023-25577 + cookie-parsing CVE-2023-23934](#finding-2)
    - [3. MEDIUM — vulnerable-component End-of-Life Python 2.7.18 — unsupported since 2020-01-01, unpatched CVEs (CVE-2021-3177, CVE-2021-23336)](#finding-3)
    - [4. INFO — burp Path-relative style sheet import (2 URLs)](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqyrbvw6-mgm8m9` |
| Target | http://target.local:32845/ |
| Started | 2026-06-29T05:08:25.290Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 4 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32845`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

4 finding(s): 1 high, 2 medium, 1 info

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [xss-reflected] Reflected + DOM XSS via `name` parameter on /page

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32845/

The `name` query parameter is reflected unescaped into an HTML attribute (`value="..."`) on /page. The probe_xss tool confirmed server-side unescaped reflection; probe_dom_xss confirmed the payload actually executes in the browser via a DOM sink. An attacker can craft a link (e.g. `/page?name="><img src=x onerror=alert(1)>`) to steal cookies or perform arbitrary actions in the victim's browser session.

**Reproduction**

```
1. GET http://target.local:32845/page?name=%22%3E%3Cimg+src%3Dx+onerror%3Dalert(1)%3E
2. Observe the payload reflected unescaped in the HTML value attribute.
3. Browser executes the onerror handler — DOM XSS confirmed via probe_dom_xss (payload set window.__verdict_xss marker).
```

**Evidence**

- Evidence `ev-mqyrhkr1-8` — `artifacts/s-0002/ev-mqyrhkr1-8/`

Request:

```http
GET /page?name=xssxZmqyrhj3fp09 HTTP/1.1
Host: target.local:32845
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1011
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:12:50 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss3.css">
            <title>Dalgona - Circle</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_circle.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name..." value="xssxZmqyrhj3fp09">
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqyrhrmy-c` — `artifacts/s-0002/ev-mqyrhrmy-c/`

Request:

```http
GET /page?name=%22%3E%3Cimg%20src%3Dx%20onerror%3D%22window.__verdict_xss%3D%27domXmqyrhohcco1t%27%3Balert(%27domXmqyrhohcco1t%27)%22%3E HTTP/1.1
Host: target.local:32845
```

Response:

```http
HTTP/1.1 200
content-type: text/html

XSS EXECUTED — sink fired (onerror/onload set window.__verdict_xss=domXmqyrhohcco1t) [domXmqyrhohcco1t]
```

- Evidence `ev-mqyrhsgi-d` — `artifacts/s-0002/ev-mqyrhsgi-d/`

Request:

```http
GET /page?name=%22%3E%3Cimg%20src%3Dx%20onerror%3D%22window.__verdict_xss%3D%27domXmqyrhohcco1t%27%3Balert(%27domXmqyrhohcco1t%27)%22%3E HTTP/1.1
Host: target.local:32845
```

Response:

```http
HTTP/1.1 200
content-type: text/html

XSS EXECUTED — sink fired (onerror/onload set window.__verdict_xss=domXmqyrhohcco1t) [domXmqyrhohcco1t]
```

<a id="finding-2"></a>

### 2. [MEDIUM] [vulnerable-component] Outdated Werkzeug 1.0.1 (Flask dev server) — known DoS CVE-2023-25577 + cookie-parsing CVE-2023-23934

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32845/

The HTTP `Server` response header on every page exposes `Werkzeug/1.0.1 Python/2.7.18`, identifying the Werkzeug WSGI library v1.0.1 (released 2020-04, the engine behind Flask's built-in development server). VERSION-BASED finding: the version was matched from the Server banner via fingerprinting, not exploited.

Known CVEs affecting Werkzeug < 2.2.3 (1.0.1 is in range):
- CVE-2023-25577 — `werkzeug.formparser` accepts an unbounded number of multipart/form-data parts, enabling memory/CPU exhaustion (DoS) via a crafted multipart request. Fixed in 2.2.3.
- CVE-2023-23934 — cookie parsing: a "nameless" cookie (e.g. `=value`) can shadow legitimately-named cookies. Fixed in 2.2.3. (Low.)

Relevant but NOT confirmed here:
- CVE-2024-34069 — Werkzeug interactive-debugger PIN bypass → RCE when `debug=True`. `GET /console` returned 404, so the debugger is not exposed and this RCE path is not demonstrated; if debug mode were enabled, 1.0.1 would be vulnerable.

The presence of the Werkzeug development server also indicates the app is served by Flask's dev server, which is not intended for production.

Evidence: `Server: Werkzeug/1.0.1 Python/2.7.18` observed via fingerprint_scan and on the live 200 responses for `/` (and `/page`).

**Reproduction**

```
1. `GET http://target.local:32845/` (200, len 1090) twice — stable, both carry `Server: Werkzeug/1.0.1 Python/2.7.18`.
2. Cross-reference Werkzeug 1.0.1: matches CVE-2023-25577 (multipart DoS, fixed 2.2.3) and CVE-2023-23934 (cookie shadowing, fixed 2.2.3).
Negative control: `GET /verdict-nonexistent-xyz` → 404 (len 232), distinct status/length. Remediation: upgrade Werkzeug to >= 2.2.3 (ideally current 3.x), serve via a production WSGI server (gunicorn/uWSGI) behind a reverse proxy, and suppress the Server header. Confirm version before relying on this finding.
```

**Evidence**

- Evidence `ev-mqyrmq5f-m` — `artifacts/_/ev-mqyrmq5f-m/`

Request:

```http
GET /verdict-nonexistent-xyz HTTP/1.1
Host: target.local:32845
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 232
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:16:50 GMT
server: Werkzeug/1.0.1 Python/2.7.18

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqyro17b-n` — `artifacts/_/ev-mqyro17b-n/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32845
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:17:51 GMT
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

- Evidence `ev-mqyro1oa-o` — `artifacts/_/ev-mqyro1oa-o/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32845
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:17:52 GMT
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

### 3. [MEDIUM] [vulnerable-component] End-of-Life Python 2.7.18 — unsupported since 2020-01-01, unpatched CVEs (CVE-2021-3177, CVE-2021-23336)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32845/

The HTTP `Server` response header exposes `Python/2.7.18`. 2.7.18 (released 2020-04) is the FINAL release of the Python 2.7 line; Python 2 reached End-of-Life on 2020-01-01 and receives NO further security patches from python.org. VERSION-BASED finding from the Server banner, not an exploited vulnerability.

Because the interpreter is unmaintained, any CPython CVE disclosed after EOL remains permanently unpatched on this host. Examples affecting 2.7 that were never fixed in the 2.x line:
- CVE-2021-3177 — buffer overflow in `ctypes` `PyCArg_repr` via crafted float; potential code execution / crash.
- CVE-2021-23336 — `urllib.parse` parameter cloaking (semicolon separator) enabling web-cache poisoning / parameter smuggling.
- CVE-2022-0391 — `urllib.parse` does not strip control characters from URLs.

Exploitability depends on whether the app exercises the affected stdlib paths (ctypes / urllib), so treat the specific CVEs as risk indicators; the durable issue is that the runtime is EOL and structurally unpatchable.

Evidence: `Server: Werkzeug/1.0.1 Python/2.7.18` observed via fingerprint_scan and on the live 200 responses for `/` (and `/page`).

**Reproduction**

```
1. `GET http://target.local:32845/` (200, len 1090) twice — stable, both carry `Server: Werkzeug/1.0.1 Python/2.7.18`.
2. Python 2.7.18 = final 2.7 release; Python 2 EOL 2020-01-01 → no security updates. Post-EOL CVEs (CVE-2021-3177, CVE-2021-23336, CVE-2022-0391) are unpatched.
Negative control: `GET /verdict-nonexistent-xyz` → 404 (len 232), distinct status/length. Remediation: migrate the application to a supported Python 3.x (3.11+) runtime and suppress the Server header.
```

**Evidence**

- Evidence `ev-mqyrmq5f-m` — `artifacts/_/ev-mqyrmq5f-m/`

Request:

```http
GET /verdict-nonexistent-xyz HTTP/1.1
Host: target.local:32845
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 232
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:16:50 GMT
server: Werkzeug/1.0.1 Python/2.7.18

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqyro17b-n` — `artifacts/_/ev-mqyro17b-n/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32845
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:17:51 GMT
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

- Evidence `ev-mqyro1oa-o` — `artifacts/_/ev-mqyro1oa-o/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32845
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:17:52 GMT
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

The application may be vulnerable to path-relative style sheet import (PRSSI) attacks. The response contains a path-relative style sheet import, and so condition 1 for an exploitable vulnerability is present (see issue background). The response can also be made to render in a browser's quirks mode. The page does not contain a doctype directive, and so it will always be rendered in quirks mode. Further, the response does not prevent itself from being framed, so an attacker can frame the response within a page that they control, to force it to be rendered in quirks mode. (Note that this techniqu [+1 more URL(s): http://target.local:32845/page] @ http://target.local:32845/

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqyrrrzg-p` — `artifacts/_/ev-mqyrrrzg-p/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32845

GET / HTTP/1.1
Host: target.local:32845
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1090
Server: Werkzeug/1.0.1 Python/2.7.18
Date: Mon, 29 Jun 2026 05:18:26 GMT


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
