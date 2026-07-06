# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [1. HIGH — vulnerable-component End-of-Life Python 2.7.18 runtime — no security patches since 2020-01-01](#finding-1)
    - [2. MEDIUM — xss-reflected Reflected input with unescaped `<` — strip-based sanitization on /page `name` param](#finding-2)
    - [3. MEDIUM — vulnerable-component Outdated Werkzeug 1.0.1 — CVE-2023-25577 multipart DoS, dev-server in production, debugger-RCE exposure class](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr0w7exy-3njnop` |
| Target | http://target.local:32815/ |
| Started | 2026-06-30T17:00:27.103Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 0 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32815`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

_No confirmed findings._

_Plus 3 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-1"></a>

### 1. [SUSPECTED] [HIGH] [vulnerable-component] End-of-Life Python 2.7.18 runtime — no security patches since 2020-01-01

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32815/

**Anomaly (why this is a lead):** Python 2.7.18 detected via the Server response header `Werkzeug/1.0.1 Python/2.7.18` on the site root. Python 2 reached end-of-life on 2020-01-01 and 2.7.18 was the final release; it receives NO upstream security fixes. The runtime therefore carries permanently-unpatched CVEs — e.g. CVE-2021-3177 (ctypes PyCArg_repr stack buffer overflow), CVE-2021-23336 (urllib.parse query-string parameter cloaking → web-cache poisoning), CVE-2022-0391 (urllib control-char host splitting). Version/EOL-based posture issue, not actively exploited.

The application runs on Python 2.7.18, the terminal release of the Python 2 line, which has been end-of-life since 2020-01-01 and receives no security patches. Any vulnerability found in CPython 2.7 since then is unfixed in this runtime. Representative unpatched issues: CVE-2021-3177 (ctypes buffer overflow, RCE-class in affected paths), CVE-2021-23336 (urllib parameter cloaking → cache poisoning), CVE-2022-0391 (urllib host-splitting / SSRF-adjacent). This is a version/EOL-based finding — the worst issues are not confirmed to be reachable in this app, but the runtime is structurally unpatchable. Remediation: migrate to a supported Python 3.x line.

**Reproduction**

```
curl -sI http://target.local:32815/ → response header `Server: Werkzeug/1.0.1 Python/2.7.18`. Cross-reference Python 2.7.18 against the Python EOL schedule (2.7 EOL 2020-01-01, 2.7.18 final release).
```

**Evidence**

- Evidence `ev-mr0wp551-1e` — `artifacts/_/ev-mr0wp551-1e/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32815
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 17:14:13 GMT
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

<a id="finding-2"></a>

### 2. [SUSPECTED] [MEDIUM] [xss-reflected] Reflected input with unescaped `<` — strip-based sanitization on /page `name` param

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32815/

**Anomaly (why this is a lead):** Server reflects `name` param with raw `<` character (not HTML-escaped to `&lt;`), confirmed by GET /page?name=%3C returning literal `<` in the HTML body. Strip-not-escape is a fragile pattern; combined with a server-side JS eval sink (headless browser TypeError shown in HTML response), this constitutes a real lead requiring further bypass research.

The `name` GET parameter is reflected verbatim into the server-rendered HTML response body without HTML-encoding the `<` character (confirmed: `?name=%3C` returns `<` raw in the DOM). A strip-based tag filter removes complete `<tag …>` constructs (opening, closing, mixed-case all tested), preventing trivial `<script>` / `<img onerror>` / `<svg onload>` / `<details ontoggle>` injection. However, the server implements strip-not-escape, which is inherently fragile against novel parser quirks and fuzzing. Additionally, the server appears to evaluate the `name` param as JavaScript in a server-side context (every non-empty submission triggers an error message in the HTML such as "You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of 'XSS'"), indicating a headless-browser eval sink that warrants deeper investigation for SSRF or sandbox escape.

**Reproduction**

```
1. GET /page?name=%3C — observe `<` reflected unescaped in HTML body (confirmed, negativeControl=baseline clean form).
2. GET /page?name=hello_test — value reflected as raw text node between `&lt;input&gt;` and `&lt;/form&gt;`.
3. All full-tag payloads tested (&lt;img onerror&gt;, &lt;svg onload&gt;, &lt;details ontoggle&gt;, &lt;script&gt;, mixed-case &lt;ScRiPt&gt;, closing &lt;/form&gt;) → server strips tags, returns default 918-byte page or strips tags leaving text content.
4. Recommend manual fuzzing with unusual parser tricks (null bytes, unicode, truncated tags) to find a full bypass.
```

**Evidence**

- Evidence `ev-mr0whrpb-s` — `artifacts/s-0002/ev-mr0whrpb-s/`

Request:

```http
GET /page?name=%3C HTTP/1.1
Host: target.local:32815
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1009
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 17:08:29 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss22.css">
            <title>Dalgona - Star</title>
        </head>
    
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_star.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name...">
                    <
                </form>
            </div>
        </div>
    </html>
```

<a id="finding-3"></a>

### 3. [SUSPECTED] [MEDIUM] [vulnerable-component] Outdated Werkzeug 1.0.1 — CVE-2023-25577 multipart DoS, dev-server in production, debugger-RCE exposure class

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32815/

**Anomaly (why this is a lead):** Werkzeug 1.0.1 detected via the Server response header `Werkzeug/1.0.1 Python/2.7.18` on the site root. 1.0.1 (Apr 2020) is far behind current; known CVEs affecting it include CVE-2023-25577 (multipart/form-data parsing resource exhaustion → DoS, fixed in 2.2.3), CVE-2023-23934 (cookie name shadowing, fixed 2.2.3), and CVE-2024-34069 (interactive debugger reachable cross-domain when debug=True, fixed 3.0.3). The exposed Server banner also shows the Werkzeug *development* WSGI server is fronting the app in production. Version-based; not yet exploited.

Werkzeug 1.0.1 is the WSGI library/dev-server serving this Flask app. Known issues for this version: CVE-2023-25577 (HTTP multipart parsing can be forced into high CPU/memory use → DoS; fixed in 2.2.3), CVE-2023-23934 (a nameless cookie can shadow a same-prefixed named cookie; fixed 2.2.3), CVE-2024-34069 (the interactive debugger console can be triggered from another domain when the app runs with debug=True; fixed 3.0.3). Separately, the Server header reveals the Werkzeug development server is exposed in production — if Flask debug mode is enabled, the Werkzeug traceback debugger grants interactive code execution (PIN-protected, but the PIN has historically been computable). Severity set to medium for the confirmed version-based DoS class; escalates to RCE/critical if debug mode is confirmed reachable (probed separately). Remediation: run behind a production WSGI server (gunicorn/uWSGI) with debug disabled, and upgrade Werkzeug to a supported 3.x release.

**Reproduction**

```
curl -sI http://target.local:32815/ → `Server: Werkzeug/1.0.1 Python/2.7.18`. Cross-reference Werkzeug 1.0.1 against CVE-2023-25577 / CVE-2023-23934 / CVE-2024-34069 (all fixed in versions > 1.0.1).
```

**Evidence**

- Evidence `ev-mr0wp551-1e` — `artifacts/_/ev-mr0wp551-1e/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32815
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1090
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 17:14:13 GMT
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
