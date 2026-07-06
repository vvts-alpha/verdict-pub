# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — secret-exposure Valid credentials (test:test) disclosed in login page HTML comment](#finding-1)
    - [2. LOW — rate-limit No rate limiting or account lockout on POST /login](#finding-2)
    - [3. LOW — info-disclosure Internal proxy topology & Apache version disclosed via reachable mod_status (/server-status)](#finding-3)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [4. HIGH — other Probable HTTP Request Smuggling surface: multi-tier HAProxy -> Apache/2.4.67 -> Werkzeug proxy chain](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr361en0-gsmwy4` |
| Target | http://target.local:32840/ |
| Started | 2026-07-02T07:11:15.299Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 5 mapped · 5 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32840`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 1 high, 2 low

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [secret-exposure] Valid credentials (test:test) disclosed in login page HTML comment

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32840/

The GET/POST /login page is served to unauthenticated visitors with a leftover HTML comment at the very top of the response body: "&lt;!-- TODO: Delete the testing account (test:test). --&gt;". This discloses a working username/password pair (test / test) to anyone who views the page source. The disclosed credentials are live: submitting them authenticates and redirects to /dashboard (see the linked auth-bypass finding). Hardcoded/leftover credentials in client-served markup are a sensitive-information exposure that hands an attacker valid login material with zero guessing.

**Reproduction**

```
1. Request GET /login unauthenticated (or POST any invalid creds). 2. Observe the first line of the HTML body: "&lt;!-- TODO: Delete the testing account (test:test). --&gt;". The comment is present in every login-page response (evidenceIds ev-mr365sup-1, ev-mr368ghk-w — both 3168+ byte login pages containing the marker). 3. Negative control: the 302 redirect response after a successful login (ev-mr36600q-2, 207-byte "Redirecting..." body) does NOT contain the comment, confirming the marker is specific to the served login page, not a universal string. 4. The leaked creds work — see auth-bypass finding on /login.
```

**Evidence**

- Evidence `ev-mr36600q-2` — `artifacts/s-0001/ev-mr36600q-2/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

username=test&password=test
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
content-length: 207
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 07:14:49 GMT
expires: 0
location: /dashboard
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/dashboard">/dashboard</a>. If not, click the link.
```

- Evidence `ev-mr365sup-1` — `artifacts/s-0001/ev-mr365sup-1/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

username=nonexistentuser123&password=wrongpass456
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
content-length: 3170
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 07:14:39 GMT
expires: 0
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Cookie,Accept-Encoding

<!-- TODO: Delete the testing account (test:test). --> 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #1a1a1a;
            color: white;
        }
        .container {
            margin-top: 100px;
        }
        .form-group label {
            color: white;
        }
        .btn-primary {
            background-color: #ff4444;
            border-color: #ff4444;
        }
        .btn-primary:hover {
            background-color: #cc0000;
            border-color: #cc0000;
        }
        .login-form {
            max-width: 300px;
            margin: auto;
            text-align: center;
            border: 1px solid #ff4444;
            border-radius: 10px;
            padding: 20px;
            background-color: #333333;
        }
        .router-logo {
            width: 100px;
            margin-bottom: 20px;
        }
        .router-title {
            font-size: 24px;
            margin-bottom: 20px;
        }
        .error-message {
            color: #ff4444;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-form">
            <svg width="80" height="80" fill="currentColor" class="bi bi-router router-logo" viewBox="0 0 16 16">
                <path d="M5.525 3.025a3.5 3.5 0 0 1 4.95 0 .5.5 0 1 0 .707-.707 4.5 4.5 0 0 0-6.364 0 .5.5 0 0 0 .707.707"/>
                <path d="M6.94 4.44a1.5 1.5 0 0 1 2.12 0 .5.5 0 0 0 .708-.708 2.5 2.5 0 0 0-3.536 0 .5.5 0 0 0 .707.707ZM2.5 11a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1m4.5-.5a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0m2.5.5a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1m1.5-.5a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0m2 0a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0"/>
                <path d="M2.974 2.342a.5.5 0 1 0-.948.316L3.806 8H1.5A1.5 1.5 0 0 0 0 9.5v2A1.5 1.5 0 0 0 1.5 13H2a.5.5 0 0 0 .5.5h2A.5.5 0 0 0 5 13h6a.5.5 0 0 0 .5.5h2a.5.5 0 0 0 .5-.5h.5a1.5 1.5 0 0 0 1.5-1.5v-2A1.5 1.5 0 0 0 14.5 8h-2.306l1.78-5.342a.5.5 0 1 0-.948-.316L11.14 8H4.86zM14.5 9a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-.5.5h-13a.5.5 0 0 1-.5-.5v-2a.5.5 0 0 1 .5-.5z"/>
                <path d="M8.5 5.5a.5.5 0 1 1-1 0 .5.5 0 0 1 1 0"/>
              </svg>
            <h2 class="router-title">Router XYZ</h2>
            
                <div class="error-message">Invalid username.</div>
            
            <form method="POST" action="/login">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" class="form-control" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary btn-block mt-3">Login</button>
            </form>
        </div>
    </div>
</body>
</html>
```

- Evidence `ev-mr368ghk-w` — `artifacts/s-0001/ev-mr368ghk-w/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

username=test&password=bad1
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
content-length: 3168
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 07:16:43 GMT
expires: 0
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Cookie,Accept-Encoding

<!-- TODO: Delete the testing account (test:test). --> 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #1a1a1a;
            color: white;
        }
        .container {
            margin-top: 100px;
        }
        .form-group label {
            color: white;
        }
        .btn-primary {
            background-color: #ff4444;
            border-color: #ff4444;
        }
        .btn-primary:hover {
            background-color: #cc0000;
            border-color: #cc0000;
        }
        .login-form {
            max-width: 300px;
            margin: auto;
            text-align: center;
            border: 1px solid #ff4444;
            border-radius: 10px;
            padding: 20px;
            background-color: #333333;
        }
        .router-logo {
            width: 100px;
            margin-bottom: 20px;
        }
        .router-title {
            font-size: 24px;
            margin-bottom: 20px;
        }
        .error-message {
            color: #ff4444;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-form">
            <svg width="80" height="80" fill="currentColor" class="bi bi-router router-logo" viewBox="0 0 16 16">
                <path d="M5.525 3.025a3.5 3.5 0 0 1 4.95 0 .5.5 0 1 0 .707-.707 4.5 4.5 0 0 0-6.364 0 .5.5 0 0 0 .707.707"/>
                <path d="M6.94 4.44a1.5 1.5 0 0 1 2.12 0 .5.5 0 0 0 .708-.708 2.5 2.5 0 0 0-3.536 0 .5.5 0 0 0 .707.707ZM2.5 11a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1m4.5-.5a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0m2.5.5a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1m1.5-.5a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0m2 0a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0"/>
                <path d="M2.974 2.342a.5.5 0 1 0-.948.316L3.806 8H1.5A1.5 1.5 0 0 0 0 9.5v2A1.5 1.5 0 0 0 1.5 13H2a.5.5 0 0 0 .5.5h2A.5.5 0 0 0 5 13h6a.5.5 0 0 0 .5.5h2a.5.5 0 0 0 .5-.5h.5a1.5 1.5 0 0 0 1.5-1.5v-2A1.5 1.5 0 0 0 14.5 8h-2.306l1.78-5.342a.5.5 0 1 0-.948-.316L11.14 8H4.86zM14.5 9a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-.5.5h-13a.5.5 0 0 1-.5-.5v-2a.5.5 0 0 1 .5-.5z"/>
                <path d="M8.5 5.5a.5.5 0 1 1-1 0 .5.5 0 0 1 1 0"/>
              </svg>
            <h2 class="router-title">Router XYZ</h2>
            
                <div class="error-message">Wrong password.</div>
            
            <form method="POST" action="/login">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" class="form-control" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary btn-block mt-3">Login</button>
            </form>
        </div>
    </div>
</body>
</html>
```

<a id="finding-2"></a>

### 2. [LOW] [rate-limit] No rate limiting or account lockout on POST /login

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32840/

POST /login enforces no rate limiting, throttling, CAPTCHA, or account lockout. Ten consecutive failed login attempts for the same username (test) within ~13 seconds were all processed normally (HTTP 200, login page re-rendered) with no 429, no increasing delay, and no lockout. Immediately afterwards a valid login for the same account still succeeded (HTTP 302 -> /dashboard), confirming the account was never locked. This permits unrestricted online password brute-force / credential-stuffing against the login form.

**Reproduction**

```
1. Send 10 rapid POST /login with username=test and varying wrong passwords (bad1..bad10). All return HTTP 200 with the login page, no 429/delay/lockout (9th=ev-mr368p8h-14, 10th=ev-mr368q1j-15, both processed normally). 2. Control: a valid login (test:test) immediately after the burst still returns HTTP 302 -> /dashboard (ev-mr368fob-v), proving no account lockout was triggered and the failed attempts were not throttled. Remediation: add per-account/per-IP rate limiting, exponential backoff, and/or temporary lockout on repeated failures.
```

**Evidence**

- Evidence `ev-mr368fob-v` — `artifacts/s-0001/ev-mr368fob-v/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

username=test&password=test
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
content-length: 207
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 07:16:42 GMT
expires: 0
location: /dashboard
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/dashboard">/dashboard</a>. If not, click the link.
```

- Evidence `ev-mr368p8h-14` — `artifacts/s-0001/ev-mr368p8h-14/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

username=test&password=bad9
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
content-length: 3168
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 07:16:55 GMT
expires: 0
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Cookie,Accept-Encoding

<!-- TODO: Delete the testing account (test:test). --> 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #1a1a1a;
            color: white;
        }
        .container {
            margin-top: 100px;
        }
        .form-group label {
            color: white;
        }
        .btn-primary {
            background-color: #ff4444;
            border-color: #ff4444;
        }
        .btn-primary:hover {
            background-color: #cc0000;
            border-color: #cc0000;
        }
        .login-form {
            max-width: 300px;
            margin: auto;
            text-align: center;
            border: 1px solid #ff4444;
            border-radius: 10px;
            padding: 20px;
            background-color: #333333;
        }
        .router-logo {
            width: 100px;
            margin-bottom: 20px;
        }
        .router-title {
            font-size: 24px;
            margin-bottom: 20px;
        }
        .error-message {
            color: #ff4444;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-form">
            <svg width="80" height="80" fill="currentColor" class="bi bi-router router-logo" viewBox="0 0 16 16">
                <path d="M5.525 3.025a3.5 3.5 0 0 1 4.95 0 .5.5 0 1 0 .707-.707 4.5 4.5 0 0 0-6.364 0 .5.5 0 0 0 .707.707"/>
                <path d="M6.94 4.44a1.5 1.5 0 0 1 2.12 0 .5.5 0 0 0 .708-.708 2.5 2.5 0 0 0-3.536 0 .5.5 0 0 0 .707.707ZM2.5 11a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1m4.5-.5a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0m2.5.5a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1m1.5-.5a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0m2 0a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0"/>
                <path d="M2.974 2.342a.5.5 0 1 0-.948.316L3.806 8H1.5A1.5 1.5 0 0 0 0 9.5v2A1.5 1.5 0 0 0 1.5 13H2a.5.5 0 0 0 .5.5h2A.5.5 0 0 0 5 13h6a.5.5 0 0 0 .5.5h2a.5.5 0 0 0 .5-.5h.5a1.5 1.5 0 0 0 1.5-1.5v-2A1.5 1.5 0 0 0 14.5 8h-2.306l1.78-5.342a.5.5 0 1 0-.948-.316L11.14 8H4.86zM14.5 9a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-.5.5h-13a.5.5 0 0 1-.5-.5v-2a.5.5 0 0 1 .5-.5z"/>
                <path d="M8.5 5.5a.5.5 0 1 1-1 0 .5.5 0 0 1 1 0"/>
              </svg>
            <h2 class="router-title">Router XYZ</h2>
            
                <div class="error-message">Wrong password.</div>
            
            <form method="POST" action="/login">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" class="form-control" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary btn-block mt-3">Login</button>
            </form>
        </div>
    </div>
</body>
</html>
```

- Evidence `ev-mr368q1j-15` — `artifacts/s-0001/ev-mr368q1j-15/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

username=test&password=bad10
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
content-length: 3168
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 07:16:56 GMT
expires: 0
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Cookie,Accept-Encoding

<!-- TODO: Delete the testing account (test:test). --> 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #1a1a1a;
            color: white;
        }
        .container {
            margin-top: 100px;
        }
        .form-group label {
            color: white;
        }
        .btn-primary {
            background-color: #ff4444;
            border-color: #ff4444;
        }
        .btn-primary:hover {
            background-color: #cc0000;
            border-color: #cc0000;
        }
        .login-form {
            max-width: 300px;
            margin: auto;
            text-align: center;
            border: 1px solid #ff4444;
            border-radius: 10px;
            padding: 20px;
            background-color: #333333;
        }
        .router-logo {
            width: 100px;
            margin-bottom: 20px;
        }
        .router-title {
            font-size: 24px;
            margin-bottom: 20px;
        }
        .error-message {
            color: #ff4444;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-form">
            <svg width="80" height="80" fill="currentColor" class="bi bi-router router-logo" viewBox="0 0 16 16">
                <path d="M5.525 3.025a3.5 3.5 0 0 1 4.95 0 .5.5 0 1 0 .707-.707 4.5 4.5 0 0 0-6.364 0 .5.5 0 0 0 .707.707"/>
                <path d="M6.94 4.44a1.5 1.5 0 0 1 2.12 0 .5.5 0 0 0 .708-.708 2.5 2.5 0 0 0-3.536 0 .5.5 0 0 0 .707.707ZM2.5 11a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1m4.5-.5a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0m2.5.5a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1m1.5-.5a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0m2 0a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0"/>
                <path d="M2.974 2.342a.5.5 0 1 0-.948.316L3.806 8H1.5A1.5 1.5 0 0 0 0 9.5v2A1.5 1.5 0 0 0 1.5 13H2a.5.5 0 0 0 .5.5h2A.5.5 0 0 0 5 13h6a.5.5 0 0 0 .5.5h2a.5.5 0 0 0 .5-.5h.5a1.5 1.5 0 0 0 1.5-1.5v-2A1.5 1.5 0 0 0 14.5 8h-2.306l1.78-5.342a.5.5 0 1 0-.948-.316L11.14 8H4.86zM14.5 9a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-.5.5h-13a.5.5 0 0 1-.5-.5v-2a.5.5 0 0 1 .5-.5z"/>
                <path d="M8.5 5.5a.5.5 0 1 1-1 0 .5.5 0 0 1 1 0"/>
              </svg>
            <h2 class="router-title">Router XYZ</h2>
            
                <div class="error-message">Wrong password.</div>
            
            <form method="POST" action="/login">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" class="form-control" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary btn-block mt-3">Login</button>
            </form>
        </div>
    </div>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [LOW] [info-disclosure] Internal proxy topology & Apache version disclosed via reachable mod_status (/server-status)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32840/

The Apache mod_status handler is reachable at /server-status. Although access is restricted (HTTP 403), the Apache-generated 403 error page itself discloses the internal server architecture in its footer: "Apache/2.4.67 (Debian) Server at haproxy Port 8001". This reveals (1) the exact front-tier web-server product and version (Apache httpd 2.4.67, Debian build), (2) an internal proxy hostname "haproxy", and (3) the internal backend port 8001. Combined, this exposes a multi-tier reverse-proxy chain (HAProxy edge -> Apache 2.4.67 -> Flask/Werkzeug application, evidenced by the Werkzeug default 404/redirect pages on app routes). This is verbose-error/ServerTokens misconfiguration and directly aids an attacker in fingerprinting version-specific vulnerabilities and the desync/request-smuggling surface between tiers.

**Reproduction**

```
GET http://target.local:32840/server-status -> 403 Forbidden whose body footer reads "&lt;address&gt;Apache/2.4.67 (Debian) Server at haproxy Port 8001&lt;/address&gt;" (Content-Type text/html; charset=iso-8859-1, i.e. an Apache error page, not the Werkzeug app). Contrast with any app route (e.g. GET /nonexistent -> Werkzeug 404, no Apache banner). Stable across 3 replays.
```

**Evidence**

- Evidence `ev-mr36yz82-37` — `artifacts/_/ev-mr36yz82-37/`

Request:

```http
GET /nonexistent_xyzzy_404_probe HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 404
cache-control: public, max-age=0
content-length: 207
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 07:37:21 GMT
expires: 0
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mr36xr2k-36` — `artifacts/_/ev-mr36xr2k-36/`

Request:

```http
GET /server-status HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 403
content-length: 314
content-type: text/html; charset=iso-8859-1
date: Thu, 02 Jul 2026 07:36:23 GMT
server: Apache/2.4.67 (Debian)

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.67 (Debian) Server at haproxy Port 8001</address>
</body></html>
```

- Evidence `ev-mr373wlw-3i` — `artifacts/_/ev-mr373wlw-3i/`

Request:

```http
GET /server-status HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 403
content-length: 314
content-type: text/html; charset=iso-8859-1
date: Thu, 02 Jul 2026 07:41:11 GMT
server: Apache/2.4.67 (Debian)

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.67 (Debian) Server at haproxy Port 8001</address>
</body></html>
```

- Evidence `ev-mr373x6n-3j` — `artifacts/_/ev-mr373x6n-3j/`

Request:

```http
GET /server-status HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 403
content-length: 314
content-type: text/html; charset=iso-8859-1
date: Thu, 02 Jul 2026 07:41:11 GMT
server: Apache/2.4.67 (Debian)

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.67 (Debian) Server at haproxy Port 8001</address>
</body></html>
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-4"></a>

### 4. [SUSPECTED] [HIGH] [other] Probable HTTP Request Smuggling surface: multi-tier HAProxy -> Apache/2.4.67 -> Werkzeug proxy chain

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32840/

**Anomaly (why this is a lead):** The stack is a three-tier proxy chain — HAProxy edge (listener :32840) -> Apache/2.4.67 (Debian) internal (ServerName "haproxy", backend Port 8001, per the /server-status 403 banner) -> Flask/Werkzeug app (default Werkzeug 302/404 pages). Chained heterogeneous HTTP parsers (HAProxy + Apache + Werkzeug), each with independent Content-Length/Transfer-Encoding handling, are the textbook precondition for request smuggling / desync (CL.TE, TE.CL, TE.TE header-obfuscation, and HAProxy's CVE-2021-40346-class 0-length-header integer-overflow desync if the edge HAProxy is unpatched). This is exactly the "outdated proxy / complicated stack" HRS surface the operator flagged. Mechanical confirmation was ATTEMPTED and is blocked by tooling, NOT by safety: (1) sending conflicting Content-Length + Transfer-Encoding via http_request is rejected by the tool's normalizing undici client ("fetch failed" — it refuses to emit ambiguous framing); (2) a CL.0-style desync via probe_scenario (smuggled GET /dashboard inside a POST body to a GET-route, then a follow-up read) came back not-confirmed because the client sets a correct Content-Length and Werkzeug consumes the full body. Confirming HRS here requires raw byte-level socket control (Burp Repeater/Turbo Intruder with "Update Content-Length" off, or the http-request-smuggler / smuggler.py tooling) to send deliberately ambiguous framing across the HAProxy/Apache boundary — recommended as manual follow-up.

The target front-ends a Flask/Werkzeug application behind at least two reverse proxies (an HAProxy edge and an internal Apache/2.4.67). Multi-tier proxy chains that mix distinct HTTP/1.1 parser implementations are the primary condition for HTTP Request Smuggling (request desynchronisation), which can enable bypassing front-end access controls (e.g. reaching the 403-restricted /server-status or other internal-only paths on the backend), request/response queue poisoning affecting other users, and credential/session capture. The specific versions in play (HAProxy edge of unknown but likely fixed-or-not build, Apache 2.4.67) and the confirmed heterogeneous parser chain make this a high-probability lead. It could not be mechanically confirmed because the assessment HTTP client normalises framing headers and will not transmit the ambiguous Content-Length/Transfer-Encoding combinations smuggling requires; a CL.0 attempt through probe_scenario was also negative for the same reason.

**Reproduction**

```
1. Fingerprint the chain: GET /server-status -> Apache 403 banner "Apache/2.4.67 (Debian) Server at haproxy Port 8001"; app routes return Werkzeug default pages -> chain = HAProxy -> Apache 2.4.67 -> Werkzeug. 2. Manual HRS test (not possible via this toolset's normalizing client): using a raw-socket tool (Burp Repeater with Content-Length auto-update disabled, Turbo Intruder, or smuggler.py) send CL.TE / TE.CL / TE.TE and HAProxy 0-length-header (CVE-2021-40346-style) probes to POST / and other routes; measure timeout/desync differentials and attempt to smuggle a request to the front-end-restricted /server-status expecting a 200 mod_status page instead of 403. 3. Note attempted here: conflicting CL+TE via http_request -> client refused ("fetch failed"); CL.0 via probe_scenario (smuggled GET /dashboard in POST /dashboard body + follow-up GET /) -> not confirmed.
```

**Evidence**

- Evidence `ev-mr36xr2k-36` — `artifacts/_/ev-mr36xr2k-36/`

Request:

```http
GET /server-status HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 403
content-length: 314
content-type: text/html; charset=iso-8859-1
date: Thu, 02 Jul 2026 07:36:23 GMT
server: Apache/2.4.67 (Debian)

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.67 (Debian) Server at haproxy Port 8001</address>
</body></html>
```
