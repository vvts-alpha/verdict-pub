# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. MEDIUM — info-disclosure Username enumeration via login response differential](#finding-1)
    - [2. MEDIUM — secret-exposure Working test credentials disclosed in HTML source comment](#finding-2)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [3. MEDIUM — idor Suspected IDOR/BOLA on user-detail API /api/user/{id} (numeric object reference)](#finding-3)
    - [4. LOW — rate-limit No rate limiting on login / username-enumeration endpoint](#finding-4)
    - [5. LOW — secret-exposure Password accepted via HTTP GET query string (credentials in URL/logs) — /password/test](#finding-5)
    - [6. LOW — headers Missing HTTP Security Headers on Login Page](#finding-6)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr0iynzy-fn9ccy` |
| Target | http://target.local:32796/ |
| Started | 2026-06-30T10:49:43.953Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 32 mapped · 32 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 2 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32796`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

2 finding(s): 2 medium

_Plus 4 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [MEDIUM] [info-disclosure] Username enumeration via login response differential

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32796/

The username-only first login step at POST / leaks whether an account exists. A valid username returns 302 redirecting to /password/<username>, while a non-existent username returns 200 with an "User not found" alert. This is a reliable account-existence oracle that an attacker can use to harvest valid usernames. No rate limiting is enforced (see related rate-limit finding), so enumeration can be automated at scale. The leaked redirect target /password/<username> confirms the account exists.

**Reproduction**

```
1. POST / with body `username=test` (Content-Type x-www-form-urlencoded) → HTTP 302, Location: /password/test (account EXISTS). 2. POST / with body `username=zzznotreal999` → HTTP 200, body contains `<div class="alert alert-danger">User not found</div>` (account DOES NOT exist). The two responses are trivially distinguishable, giving a yes/no existence oracle per username.
```

**Evidence**

- Evidence `ev-mr0jvgaw-u` — `artifacts/s-0001/ev-mr0jvgaw-u/`

Request:

```http
POST / HTTP/1.1
Host: target.local:32796
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=nonexistent_zzz999
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1287
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:15:13 GMT
expires: 0
keep-alive: timeout=5, max=99
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<!-- TODO: Delete the testing account (test:test). --> 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Trading Platform</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #2c3e50;
            color: #ffffff;
        }
        .card {
            background-color: #34495e;
            color: #ffffff;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h2 class="text-center mb-4">Trading Platform</h2>
                
                    <div class="alert alert-danger" role="alert">User not found</div>
                
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <button type="submit" class="btn btn-success btn-block">Login</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
```

- Evidence `ev-mr0jvfdi-t` — `artifacts/s-0001/ev-mr0jvfdi-t/`

Request:

```http
POST / HTTP/1.1
Host: target.local:32796
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=test
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 215
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:15:12 GMT
expires: 0
keep-alive: timeout=5, max=100
location: /password/test
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/password/test">/password/test</a>. If not, click the link.
```

- Evidence `ev-mr0jxq8b-15` — `artifacts/s-0001/ev-mr0jxq8b-15/`

Request:

```http
POST / HTTP/1.1
Host: target.local:32796
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=test
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 215
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:16:59 GMT
expires: 0
keep-alive: timeout=5, max=96
location: /password/test
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/password/test">/password/test</a>. If not, click the link.
```

<a id="finding-2"></a>

### 2. [MEDIUM] [secret-exposure] Working test credentials disclosed in HTML source comment

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32796/

The login page (GET /) ships an HTML comment in its source that discloses a live credential pair to any anonymous visitor: `<!-- TODO: Delete the testing account (test:test). -->`. The exposed username `test` is confirmed to be a valid account (login returns 302 -> /password/test), and the comment discloses its password (`test`). The comment is present on both the login page and the post-error page, so it is served to all unauthenticated users. An attacker reading page source obtains ready-to-use credentials for the Trading Platform.

**Reproduction**

```
1. GET / -> response body contains `<!-- TODO: Delete the testing account (test:test). -->` disclosing credentials test/test. 2. Confirm the account is real: POST / with `username=test` -> 302 Location /password/test. By contrast the 302 "Redirecting..." body (negative control) does NOT contain the `test:test` marker, proving the leak originates from the login page source.
```

**Evidence**

- Evidence `ev-mr0jvfdi-t` — `artifacts/s-0001/ev-mr0jvfdi-t/`

Request:

```http
POST / HTTP/1.1
Host: target.local:32796
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=test
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 215
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:15:12 GMT
expires: 0
keep-alive: timeout=5, max=100
location: /password/test
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/password/test">/password/test</a>. If not, click the link.
```

- Evidence `ev-mr0jv5jx-s` — `artifacts/s-0001/ev-mr0jv5jx-s/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32796
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1184
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:14:59 GMT
expires: 0
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<!-- TODO: Delete the testing account (test:test). --> 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Trading Platform</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #2c3e50;
            color: #ffffff;
        }
        .card {
            background-color: #34495e;
            color: #ffffff;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h2 class="text-center mb-4">Trading Platform</h2>
                
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <button type="submit" class="btn btn-success btn-block">Login</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
```

- Evidence `ev-mr0jxlvq-11` — `artifacts/s-0001/ev-mr0jxlvq-11/`

Request:

```http
POST / HTTP/1.1
Host: target.local:32796
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=ratelimit_probe_a
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1287
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:16:53 GMT
expires: 0
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<!-- TODO: Delete the testing account (test:test). --> 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Trading Platform</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #2c3e50;
            color: #ffffff;
        }
        .card {
            background-color: #34495e;
            color: #ffffff;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h2 class="text-center mb-4">Trading Platform</h2>
                
                    <div class="alert alert-danger" role="alert">User not found</div>
                
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <button type="submit" class="btn btn-success btn-block">Login</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-3"></a>

### 3. [SUSPECTED] [MEDIUM] [idor] Suspected IDOR/BOLA on user-detail API /api/user/{id} (numeric object reference)

- Screen: `s-0022`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32796/

**Anomaly (why this is a lead):** User-detail API /api/user/{id} keyed by a guessable numeric id (10032 observed, idor-candidate). Auth is enforced (unauth=404) but no authenticated session could be established this run, so cross-user IDOR/BOLA could not be confirmed or refuted — needs manual auth + differential test of another user's id.

The endpoint /api/user/{id} is a user-detail API keyed directly by a guessable numeric object reference (observed id 10032 during survey, rule-labeled idor-candidate). Such direct-object-reference user APIs are classic BOLA/IDOR surfaces: with a valid session, requesting another user's id may return that user's record. Unauthenticated access returns 404 (auth is enforced on the raw path — no auth-bypass), but no authenticated session could be established this run: role 'test' has no auto-discoverable login form and no session cookie is present, so /api/user/<otherId> could not be exercised to differentially confirm or refute cross-user data access. Surfaced as a lead for manual verification with valid credentials.

**Reproduction**

```
1. Authenticate as a valid user (provide credentials or a captured cookie/Bearer for role 'test'). 2. Identify your own user id (e.g. via /api/user/<self>). 3. Request /api/user/<otherUserId> (e.g. 10031, 10033, or any id != self) with your session, passing victimId=<otherId> and selfId=<self>. 4. Confirm IDOR if the response returns the victim's record (their id/PII present, yours absent) for an id you do not own; negative control = a non-existent id must 404. Inspect returned fields for PII/secrets beyond what the UI exposes.
```

**Evidence**

- Evidence `ev-mr0narkj-8h` — `artifacts/s-0022/ev-mr0narkj-8h/`

Request:

```http
GET /api/user/10032 HTTP/1.1
Host: target.local:32796
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 404
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 207
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 12:51:06 GMT
expires: 0
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

<a id="finding-4"></a>

### 4. [SUSPECTED] [LOW] [rate-limit] No rate limiting on login / username-enumeration endpoint

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32796/

**Anomaly (why this is a lead):** ~20 consecutive POST / login attempts all processed with no 429, no Retry-After, and no lockout — the auth endpoint enforces zero rate limiting, enabling unlimited username enumeration and downstream password brute-force.

The POST / authentication endpoint applies no rate limiting or lockout. Roughly 20 rapid login attempts (mix of valid `test` -> 302 and invalid -> 200) were all processed normally with no HTTP 429, no Retry-After header, and no account/IP lockout. This amplifies the username-enumeration oracle (mass account harvesting) and enables automated password brute-forcing at the downstream /password/<username> step. Recorded as suspected because absence-of-throttling does not fit the negative-control/positive-replay confirmation model, but it was directly observed over ~20 consecutive requests.

**Reproduction**

```
Send ~20 rapid POST / requests with varying `username` values. All return immediately (200 for unknown users, 302 for `test`) with no 429/Retry-After/lockout at any point, e.g. burst request #12 (ev-mr0jxxc2-1c) still returns 302 with no throttling.
```

**Evidence**

- Evidence `ev-mr0jxxc2-1c` — `artifacts/s-0001/ev-mr0jxxc2-1c/`

Request:

```http
POST / HTTP/1.1
Host: target.local:32796
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=test
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 215
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:17:08 GMT
expires: 0
keep-alive: timeout=5, max=89
location: /password/test
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/password/test">/password/test</a>. If not, click the link.
```

<a id="finding-5"></a>

### 5. [SUSPECTED] [LOW] [secret-exposure] Password accepted via HTTP GET query string (credentials in URL/logs) — /password/test

- Screen: `s-0023`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32796/

**Anomaly (why this is a lead):** The password form renders with method=get (no method attribute) and the server accepts /password/test?username=test&user_id=10032&password=<cleartext> returning 200. Any non-JS submission or a shared/direct link therefore places the cleartext password into the URL, landing in server & proxy access logs and browser history (CWE-598). The crawler already captured such a ?password=test GET. Server acceptance is confirmed; full disclosure (the log write) cannot be observed from the client, hence suspected.

/password/test serves a login form whose default method is GET (the rendered form has no method attribute, so it submits via GET to the same path). The backend accepts the password as a GET query parameter (GET /password/test?...&password=test → 200). Credentials transmitted in the query string are exposed in web-server and forward-proxy access logs, browser history, and any Referer headers, even though the normal JS path uses POST. This is a transport/handling weakness (CWE-598), not an injection.

**Reproduction**

```
1) GET http://target.local:32796/password/test?username=test&user_id=10032&password=test → 200 (server accepts password in query string). 2) The rendered <form> has no method attribute → defaults to GET, so a JS failure or native submit sends the typed password in the URL. 3) Such a URL with the cleartext password is then recorded in access/proxy logs and browser history.
```

**Evidence**

- Evidence `ev-mr0nemu7-8r` — `artifacts/s-0023/ev-mr0nemu7-8r/`

Request:

```http
GET /password/test?username=test&user_id=10032&password=test HTTP/1.1
Host: target.local:32796
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 3139
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 12:54:07 GMT
expires: 0
keep-alive: timeout=5, max=99
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password - Trading Platform</title>
    <script src="/static/js/jquery-3.5.1.min.js"></script>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #2c3e50;
            color: #ffffff;
        }
        .card {
            background-color: #34495e;
            color: #ffffff;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h2 class="text-center mb-4">Trading Platform</h2>
                <form>
                    <div class="form-group">
                        <p class="mt-3 text-center">Welcome, John!</p>
                        <label for="password">Password</label>
                        <input type="text" class="form-control" id="username" name="username" value="test" hidden>
                        <input type="text" class="form-control" id="user_id" name="user_id" value="10032" hidden>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <button class="btn btn-success btn-block" id="submitBtn">Login</button>
                </form>
            </div>
        </div>
    </div>


    <script>
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('submitBtn').addEventListener('click', function(event) {
                event.preventDefault(); // Prevent default form submission behavior
                
                var formData = {
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value,
                    user_id: document.getElementById('user_id').value
                };
    
                // AJAX request using fetch API
                fetch('#', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-UserId': '10032'
                    },
                    body: new URLSearchParams(formData),
                    redirect: 'follow' // Follow redirects automatically
                })
                .then(function(response) {
                    // Check if the response contains a redirect
                    if (response.redirected) {
                        // If a redirect is received, navigate to the redirect URL
                        window.location.href = response.url;
                    }
                })
                .then(function(data) {
                    // Handle the response data
                    console.log('Success:', data);
                })
                .catch(function(error) {
                    // Handle error
                    console.error('Error:', error);
                });
            });
        });
    </script>

</body>
</html>
```

<a id="finding-6"></a>

### 6. [SUSPECTED] [LOW] [headers] Missing HTTP Security Headers on Login Page

- Screen: `s-0026`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32796/

**Anomaly (why this is a lead):** Three independent GET / responses return only Content-Type — no X-Content-Type-Options, X-Frame-Options, CSP, HSTS, or Referrer-Policy, exposing users to clickjacking and MIME-sniffing on the login page.

The login page at `/` returns only `Content-Type` in its HTTP response headers. Absent: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, Strict-Transport-Security, and Referrer-Policy. Three independent GET requests (ev-mr0nvpye-9x, ev-mr0nxmzg-a5, ev-mr0ny4v0-a7) all confirm the same minimal header set.

**Reproduction**

```
1. GET http://target.local:32796/\n2. Inspect response headers: only Content-Type is present.\n3. Confirmed across three independent requests.
```

**Evidence**

- Evidence `ev-mr0nvpye-9x` — `artifacts/s-0026/ev-mr0nvpye-9x/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32796
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1184
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 13:07:24 GMT
expires: 0
keep-alive: timeout=5, max=98
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<!-- TODO: Delete the testing account (test:test). --> 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Trading Platform</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #2c3e50;
            color: #ffffff;
        }
        .card {
            background-color: #34495e;
            color: #ffffff;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h2 class="text-center mb-4">Trading Platform</h2>
                
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <button type="submit" class="btn btn-success btn-block">Login</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
```
