# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — secret-exposure Working credentials leaked in HTML source comment on login page](#finding-1)
    - [2. MEDIUM — info-disclosure Username enumeration via distinct responses on login step](#finding-2)
    - [3. LOW — info-disclosure Username enumeration via /password/&lt;username&gt; (valid form vs "User not found")](#finding-3)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [4. HIGH — session Forgeable client-side Flask session ({"user_id":N}) — likely account takeover via leaked SECRET_KEY](#finding-4)
    - [5. HIGH — rate-limit No rate-limiting / lockout on POST /password/&lt;username&gt; — password brute-force (recovered test:test)](#finding-5)
    - [6. MEDIUM — rate-limit No rate-limiting on login / username-enumeration endpoint](#finding-6)
    - [7. MEDIUM — idor Possible BOLA/IDOR on order receipt endpoint (numeric, guessable id; ownership binding unverifiable in single-account env)](#finding-7)
    - [8. LOW — vulnerable-component Outdated Bootstrap 4.5.2 (EOL) — CVE-2024-6531 / CVE-2024-6484 XSS](#finding-8)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr0ix64z-ojgdbu` |
| Target | http://target.local:32795/ |
| Started | 2026-06-30T10:48:34.127Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 14 mapped · 14 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32795`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 1 high, 1 medium, 1 low

_Plus 5 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [secret-exposure] Working credentials leaked in HTML source comment on login page

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32795/

Every response from the login page `/` begins with the HTML comment `<!-- TODO: Delete the testing account (test:test). -->`, disclosing a username/password pair for a real account. The username `test` is confirmed valid (it 302-redirects to /password/test and the password page renders "Welcome, John!", user_id 10032), so these are live credentials exposed to any unauthenticated visitor who views source. The comment is NOT present on other pages (e.g. /password/test), confirming it is specific to the login template.

**Reproduction**

```
1. GET http://target.local:32795/ (or POST any username). 2. View the raw HTML response — the first line is `<!-- TODO: Delete the testing account (test:test). -->`. 3. The leaked username `test` maps to a real account (John / user_id 10032) via the /password/test step. Negative control: GET /password/test does not contain the comment.
```

**Evidence**

- Evidence `ev-mr0jk27l-l` — `artifacts/s-0001/ev-mr0jk27l-l/`

Request:

```http
GET /password/test HTTP/1.1
Host: target.local:32795
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
date: Tue, 30 Jun 2026 11:06:21 GMT
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

- Evidence `ev-mr0jj91m-c` — `artifacts/s-0001/ev-mr0jj91m-c/`

Request:

```http
POST / HTTP/1.1
Host: target.local:32795
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=verdicttest123
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1287
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:05:44 GMT
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

- Evidence `ev-mr0jmam6-x` — `artifacts/s-0001/ev-mr0jmam6-x/`

Request:

```http
POST / HTTP/1.1
Host: target.local:32795
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=bogus1
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1287
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:08:06 GMT
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

<a id="finding-2"></a>

### 2. [MEDIUM] [info-disclosure] Username enumeration via distinct responses on login step

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32795/

The first login step at `/` returns observably different responses for valid vs invalid usernames, allowing an unauthenticated attacker to enumerate valid accounts. A valid username (e.g. `test`) returns HTTP 302 redirecting to /password/<username> (and that page further discloses the account's display name "Welcome, John!" and user_id 10032). An invalid username returns HTTP 200 with the alert "User not found". This violates CWE-204 (observable response discrepancy) and, combined with the absence of rate-limiting, enables bulk account enumeration.

**Reproduction**

```
1. POST / with body `username=test` → HTTP 302, Location: /password/test (valid account). 2. POST / with body `username=bogus1` → HTTP 200, body contains "User not found" (invalid account). 3. The differing status/redirect reveals account validity; the /password/<user> page additionally leaks the display name and user_id.
```

**Evidence**

- Evidence `ev-mr0jmam6-x` — `artifacts/s-0001/ev-mr0jmam6-x/`

Request:

```http
POST / HTTP/1.1
Host: target.local:32795
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=bogus1
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1287
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:08:06 GMT
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

- Evidence `ev-mr0jjnw0-e` — `artifacts/s-0001/ev-mr0jjnw0-e/`

Request:

```http
POST / HTTP/1.1
Host: target.local:32795
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
date: Tue, 30 Jun 2026 11:06:03 GMT
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

- Evidence `ev-mr0jm9j2-w` — `artifacts/s-0001/ev-mr0jm9j2-w/`

Request:

```http
POST / HTTP/1.1
Host: target.local:32795
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
date: Tue, 30 Jun 2026 11:08:04 GMT
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

<a id="finding-3"></a>

### 3. [LOW] [info-disclosure] Username enumeration via /password/&lt;username&gt; (valid form vs "User not found")

- Screen: `s-0006`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32795/

GET /password/<username> discloses whether a username exists. A valid username (`test`) returns HTTP 200 with the password form (greeting the account holder "John"), while non-existent usernames (`admin`, `john`) return 302 -> /?error=User+not+found. The response is therefore a reliable oracle for enumerating valid accounts, which combined with the unthrottled password endpoint enables targeted credential brute-force.

**Reproduction**

```
1) GET /password/test -> 200, renders password form, no "User not found" [negative control: valid user]. 2) GET /password/admin -> 302 /?error=User+not+found [positive]. 3) GET /password/john -> 302 /?error=User+not+found [positive]. Distinct responses for valid vs invalid usernames = enumeration oracle.
```

**Evidence**

- Evidence `ev-mr0l2h95-2r` — `artifacts/s-0006/ev-mr0l2h95-2r/`

Request:

```http
GET /password/test HTTP/1.1
Host: target.local:32795
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
date: Tue, 30 Jun 2026 11:48:40 GMT
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

- Evidence `ev-mr0l3ps2-2v` — `artifacts/s-0006/ev-mr0l3ps2-2v/`

Request:

```http
GET /password/admin HTTP/1.1
Host: target.local:32795
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
date: Tue, 30 Jun 2026 11:49:38 GMT
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

- Evidence `ev-mr0l3qa3-2w` — `artifacts/s-0006/ev-mr0l3qa3-2w/`

Request:

```http
GET /password/john HTTP/1.1
Host: target.local:32795
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
date: Tue, 30 Jun 2026 11:49:39 GMT
expires: 0
keep-alive: timeout=5, max=99
location: /?error=User+not+found
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/?error=User+not+found">/?error=User+not+found</a>. If not, click the link.
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-4"></a>

### 4. [SUSPECTED] [HIGH] [session] Forgeable client-side Flask session ({"user_id":N}) — likely account takeover via leaked SECRET_KEY

- Screen: `s-0006`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32795/

**Anomaly (why this is a lead):** Successful-login Set-Cookie is a client-side itsdangerous Flask session decoding to exactly {"user_id":10032}; identity rests entirely on this client-held value, and a SECRET_KEY is already confirmed exposed in an HTML comment on /, making the cookie re-signable with any victim user_id (e.g. 300123) for account takeover.

On successful login the server issues a client-side, itsdangerous-signed Flask session cookie whose decoded payload is exactly {"user_id":10032}. User identity downstream is carried solely by this attacker-held value. If the Flask SECRET_KEY is weak or known, the cookie can be re-signed with an arbitrary user_id (e.g. 300123, a known object id) for full account takeover. This is directly enabled by the already-confirmed secret-exposure::/::html-comment finding (a secret leaked in an HTML comment on /), which is very likely that SECRET_KEY. The /password/test page even pre-exposes the victim's user_id in a hidden field, hinting at this design. Could not complete forgery within the available toolset (no offline itsdangerous signer); flagged for manual verification with flask-unsign.

**Reproduction**

```
1) Log in (test:test) -> Set-Cookie session=eyJ1c2VyX2lkIjoxMDAzMn0...; base64('eyJ1c2VyX2lkIjoxMDAzMn0')={"user_id":10032}. 2) Take the SECRET_KEY exposed in the HTML comment on / (secret-exposure::/::html-comment). 3) flask-unsign --sign --cookie '{"user_id":300123}' --secret '<KEY>' to mint a session for victim user_id=300123. 4) Replay against /dashboard to access the victim account. Manual confirmation needed (no offline signer in-tool).
```

**Evidence**

- Evidence `ev-mr0l4v7f-2y` — `artifacts/s-0006/ev-mr0l4v7f-2y/`

Request:

```http
POST /password/test HTTP/1.1
Host: target.local:32795
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
content-length: 235
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:50:32 GMT
expires: 0
keep-alive: timeout=5, max=99
location: /dashboard?username=test
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/dashboard?username=test">/dashboard?username=test</a>. If not, click the link.
```

<a id="finding-5"></a>

### 5. [SUSPECTED] [HIGH] [rate-limit] No rate-limiting / lockout on POST /password/&lt;username&gt; — password brute-force (recovered test:test)

- Screen: `s-0006`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32795/

**Anomaly (why this is a lead):** ~12 consecutive password guesses for user test against POST /password/<username> were all processed with no throttling, 429, CAPTCHA or lockout, and the valid password (test) was recovered — demonstrating absent brute-force protection (account-compromise vector), only filed suspected because a missing control has no failing negative control to satisfy the confirmed evidence model.

POST /password/<username> enforces no rate-limiting, throttling, CAPTCHA or account lockout on password attempts. ~12 distinct password guesses for user `test` (user_id=10032) were submitted back-to-back with no delay and none were blocked (every guess returned a normal 302); the valid password `test` was recovered. This is a full-speed credential brute-force / account-compromise vector, made worse by the username-enumeration oracle (f-005). Recorded as suspected only because a missing-rate-limit has no naturally-failing negative control for the confirmed evidence model — the impact (credentials recovered) was directly observed.

**Reproduction**

```
1) Rapidly POST /password/test with body username=test&user_id=10032&password=<guess> for ~12 different guesses (password, 123456, admin, letmein, trading, john, ...). 2) Observe every attempt is processed (302), no 429, no lockout, no CAPTCHA. 3) password=test returns 302 Location /dashboard?username=test + Set-Cookie session=... = authenticated. No brute-force protection exists.
```

**Evidence**

- Evidence `ev-mr0l4v7f-2y` — `artifacts/s-0006/ev-mr0l4v7f-2y/`

Request:

```http
POST /password/test HTTP/1.1
Host: target.local:32795
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
content-length: 235
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:50:32 GMT
expires: 0
keep-alive: timeout=5, max=99
location: /dashboard?username=test
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/dashboard?username=test">/dashboard?username=test</a>. If not, click the link.
```

<a id="finding-6"></a>

### 6. [SUSPECTED] [MEDIUM] [rate-limit] No rate-limiting on login / username-enumeration endpoint

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32795/

**Anomaly (why this is a lead):** 7 back-to-back invalid-login POSTs to / each returned 200 'User not found' with zero throttling (no 429/Retry-After/CAPTCHA/lockout) — the login+enumeration endpoint enforces no rate limit, enabling bulk enumeration and brute-force.

The login endpoint `/` applies no rate-limiting, CAPTCHA, or account-lockout. Seven consecutive invalid-username POSTs in rapid succession each returned HTTP 200 "User not found" with no 429, Retry-After, lockout, or challenge. Combined with the username-enumeration discrepancy and the single-field username-first flow, this permits unrestricted account enumeration and online credential brute-forcing at scale.

**Reproduction**

```
1. Send many rapid POST / requests with body `username=bogus<N>`. 2. Observe every request returns 200 "User not found" with no rate-limit headers, throttling delay, or lockout after 7+ attempts. Tooling cannot mechanically confirm an absence-of-control via the negative-control/replay model, so recorded as suspected.
```

**Evidence**

- Evidence `ev-mr0jmgrj-13` — `artifacts/s-0001/ev-mr0jmgrj-13/`

Request:

```http
POST / HTTP/1.1
Host: target.local:32795
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=bogus7
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1287
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:08:14 GMT
expires: 0
keep-alive: timeout=5, max=93
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

<a id="finding-7"></a>

### 7. [SUSPECTED] [MEDIUM] [idor] Possible BOLA/IDOR on order receipt endpoint (numeric, guessable id; ownership binding unverifiable in single-account env)

- Screen: `s-0005`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32795/

**Anomaly (why this is a lead):** The receipt endpoint /order/{id}/receipt serves a full order receipt (Order ID + body text) addressed SOLELY by a numeric, guessable order id. Observed ids cluster tightly in the 30xxxx range: 300123 and 300481 both returned data as user 'test', and the crawler earlier saw 300122-300126 linked from the orders page. Auth is enforced (unauth -> 302 to login) but NO per-user ownership binding could be verified: the environment has a single account (only 'test'/user_id 10032 exists; /register -> 404; /password/admin|john|user -> "User not found"), so I could not instantiate a SECOND user's order to attempt a cross-user (BOLA) read. Unknown ids return a blank 200 template (not 403/404), leaking order existence and matching the classic IDOR shape. This is a real lead that needs a second account to confirm or refute.

/order/{id}/receipt returns the receipt for an order identified only by a small, guessable numeric path id. Because order ids are dynamically assigned in a narrow 30xxxx band (300122-300126 at crawl time, 300123 and 300481 in this session) and the receipt body is returned purely as a function of that id, the endpoint is structurally a Broken Object Level Authorization candidate: if the server query is `WHERE id=?` rather than `WHERE id=? AND user_id=<session>`, any authenticated user could read other users' trade receipts by enumerating the id range. I confirmed auth is required (unauth -> 302 login) and that the server derives identity server-side (the login form's client-controlled hidden user_id is ignored; the Flask session cookie is HMAC-signed and HttpOnly, so it is not forgeable). However the deployment exposes exactly one user account and no self-registration, so there was no second user's order to request from the first user's session — the cross-user read that would CONFIRM the IDOR could not be exercised. Recording as suspected so it is re-tested with a second account.

**Reproduction**

```
1. Authenticate as 'test' (POST /password/test, password 'test') and capture the Flask session cookie.
2. GET /orders and observe your order ids are short numerics in the ~300100-300500 range (e.g. 300481).
3. GET /order/300481/receipt with the session cookie -> 200, full receipt returned, keyed only by the path id (ev-mr0kxkjt-2p; 300123 likewise via ev-mr0kj7e2-28).
4. GET /order/999999/receipt (or 300122) -> blank 200 template (ev-mr0klmkb-29): unknown ids return no data but no 403/404.
5. GET /order/300481/receipt unauthenticated -> 302 to login (auth is enforced).
TO CONFIRM (needs a 2nd account, unavailable here): create/obtain user B, load B's /orders to learn B's order id, then request that id from user A's session. A returned receipt = confirmed BOLA; a blank/403 = ownership is enforced and this can be refuted.
```

**Evidence**

- Evidence `ev-mr0kxkjt-2p` — `artifacts/s-0005/ev-mr0kxkjt-2p/`

Request:

```http
GET /order/300481/receipt HTTP/1.1
Host: target.local:32795
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 913
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:44:51 GMT
expires: 0
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Cookie,Accept-Encoding

<!-- receipt.html -->
<div class="modal-header bg-dark text-white">
    <h5 class="modal-title" id="receiptModalLabel">Receipt</h5>
    <button type="button" class="close text-white" data-dismiss="modal" aria-label="Close">
        <span aria-hidden="true">&times;</span>
    </button>
</div>
<div class="modal-body bg-dark text-white">
    <div class="container">
        <div class="row">
            <div class="col">
                <p><strong>Order ID:</strong> 300481</p>
                <hr style="border-color: #ffffff;"> 
                <code class="text-white">Risus class auctor feugiat sagittis aliquet viverra, molestie maecenas magnis etiam lacinia malesuada imperdiet, vel suspendisse magna sed pellentesque.</code>
            </div>
        </div>
    </div>
</div>
<div class="modal-footer bg-dark">
    <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
</div>
```

<a id="finding-8"></a>

### 8. [SUSPECTED] [LOW] [vulnerable-component] Outdated Bootstrap 4.5.2 (EOL) — CVE-2024-6531 / CVE-2024-6484 XSS

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32795/

**Anomaly (why this is a lead):** Bootstrap v4.5.2 detected via the version banner embedded in /static/css/bootstrap.min.css (literal "Bootstrap v4.5.2" comment header). Bootstrap 4.x is end-of-life. Versions 4.0.0–4.6.2 are affected by CVE-2024-6531 (carousel data-slide/data-slide-to XSS) and CVE-2024-6484 (button data-loading-text XSS). Mitigating factor: only the CSS is referenced — bootstrap.js is NOT loaded on the page — so the JS-based XSS sinks are not currently reachable. Version-based lead, not exploited.

Frontend uses Bootstrap 4.5.2 (released 2020-08, Bootstrap 4 line is EOL/unmaintained). Known client-side XSS issues in the 4.0.0–4.6.2 range: CVE-2024-6531 (carousel component, data-slide / data-slide-to attributes) and CVE-2024-6484 (button plugin, data-loading-text). Both require Bootstrap's JavaScript plus app-rendered attacker-controlled data-* attributes; here the page loads only bootstrap.min.css and no bootstrap.js, so the sinks are not reachable in the current surface. Recorded as a version-based outdated-component lead (suspected), not an exploited vulnerability. Remediation: upgrade to the maintained Bootstrap 5.x line.

**Reproduction**

```
GET http://target.local:32795/static/css/bootstrap.min.css → response body opens with "/*! Bootstrap v4.5.2 (https://getbootstrap.com/) ... */", identifying the exact frontend framework version. Cross-reference 4.5.2 against the 4.0.0–4.6.2 affected range for CVE-2024-6531 and CVE-2024-6484. Confirm via the root page (GET /) source that only the CSS link is present and no bootstrap.js script tag is loaded (limits reachability of the JS XSS sinks).
```

**Evidence**

- Evidence `ev-mr0n4zrb-76` — `artifacts/_/ev-mr0n4zrb-76/`

Request:

```http
GET /static/css/bootstrap.min.css HTTP/1.1
Host: target.local:32795
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
date: Tue, 30 Jun 2026 12:46:37 GMT
etag: "1782574703.0-160302-2226068982-gzip"
expires: 0
keep-alive: timeout=5, max=100
last-modified: Sat, 27 Jun 2026 15:38:23 GMT
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
