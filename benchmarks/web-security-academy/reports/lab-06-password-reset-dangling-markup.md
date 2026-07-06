# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. LOW — burp Strict transport security not enforced (6 URLs)](#finding-1)
    - [2. INFO — burp TLS certificate](#finding-2)
    - [3. INFO — burp Cross-domain Referer leakage](#finding-3)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [4. HIGH — account-takeover Password reset flow — potential host-header poisoning (account takeover), unconfirmed](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr7i466s-1fycuj` |
| Target | https://0a07008b0333c295819d349400dd001d.web-security-academy.net/ |
| Started | 2026-07-05T08:00:24.383Z |
| Generated | 2026-07-05T11:35:45.714Z |
| Phase | report |
| Screens | 12 mapped · 10 scanned · 2 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `*.web-security-academy.net`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 1 low, 2 info

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [LOW] [burp] Strict transport security not enforced (6 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

(confidence: CERTAIN) [+5 more URL(s): https://0a07008b0333c295819d349400dd001d.web-security-academy.net/post, https://0a07008b0333c295819d349400dd001d.web-security-academy.net/forgot-password, https://0a07008b0333c295819d349400dd001d.web-security-academy.net/my-account, https://0a07008b0333c295819d349400dd001d.web-security-academy.net/post/comment, https://0a07008b0333c295819d349400dd001d.web-security-academy.net/my-account/change-email] @ https://0a07008b0333c295819d349400dd001d.web-security-academy.net/login

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr7prx91-57` — `artifacts/_/ev-mr7prx91-57/`

Request:

```http
GET /login HTTP/1.1
Host: 0a07008b0333c295819d349400dd001d.web-security-academy.net

GET /login HTTP/1.1
Host: 0a07008b0333c295819d349400dd001d.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 4377

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
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a42002f03d4c2248108338001500061.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='TG9nIGluIGFzIHRoZSB1c2VyIDxjb2RlPmNhcmxvczwvY29kZT4u' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2hvc3QtaGVhZGVyL2V4cGxvaXRpbmcvcGFzc3dvcmQtcmVzZXQtcG9pc29uaW5nL2xhYi1ob3N0LWhlYWRlci1wYXNzd29yZC1yZXNldC1wb2lzb25pbmctdmlhLWRhbmdsaW5nLW1hcmt1cA=='>
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
                            <input required type="hidden" name="csrf" value="69iHOmUPQATXOGBYoWiS0gnfqcfd9pAV">
                            <label>Username</label>
                            <input required type=username name="username" autofocus>
                            <label>Password</label>
                            <input required type=password name="password">
                            <a href=/forgot-password>Forgot password?</a>
                            <br/>
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

<a id="finding-2"></a>

### 2. [INFO] [burp] TLS certificate

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The server presented a valid, trusted TLS certificate. This issue is purely informational.<br><br>The server presented the following certificates:<br><br><h4>Server certificate</h4><table><tr><td><b>Issued to:</b>&nbsp;&nbsp;</td><td>*.web-security-academy.net, *.2.web-security-academy.net, *.1.web-security-academy.net, *.3.web-security-academy.net, *.2.h1-web-security-academy.net, *.1.h1-web-security-academy.net, *.h1-web-security-academy.net, *.3.h1-web-security-academy.net</td></tr><tr><td><b>Issued by:</b>&nbsp;&nbsp;</td><td>Amazon RSA 2048 M01</td></tr><tr><td><b>Valid from:</b>&nbsp;&nb @ https://0a07008b0333c295819d349400dd001d.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr7prx8t-56` — `artifacts/_/ev-mr7prx8t-56/`

Request:

```http
GET / HTTP/1.1
Host: 0a07008b0333c295819d349400dd001d.web-security-academy.net
```

Response:

```http
HTTP/1.1 0
```

<a id="finding-3"></a>

### 3. [INFO] [burp] Cross-domain Referer leakage

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The page was loaded from a URL containing a query string:<ul><li>https://0a07008b0333c295819d349400dd001d.web-security-academy.net/post</li></ul>The response contains the following links to other domains:<ul><li>https://exploit-0a42002f03d4c2248108338001500061.exploit-server.net/</li><li>https://portswigger.net/web-security/dashboard</li><li>https://verdict-site-zzq3.example.com/</li></ul> (confidence: CERTAIN) @ https://0a07008b0333c295819d349400dd001d.web-security-academy.net/post

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr7prx97-58` — `artifacts/_/ev-mr7prx97-58/`

Request:

```http
GET /post HTTP/1.1
Host: 0a07008b0333c295819d349400dd001d.web-security-academy.net

GET /post?postId=1 HTTP/1.1
Host: 0a07008b0333c295819d349400dd001d.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 8333

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
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
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a42002f03d4c2248108338001500061.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='TG9nIGluIGFzIHRoZSB1c2VyIDxjb2RlPmNhcmxvczwvY29kZT4u' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2hvc3QtaGVhZGVyL2V4cGxvaXRpbmcvcGFzc3dvcmQtcmVzZXQtcG9pc29uaW5nL2xhYi1ob3N0LWhlYWRlci1wYXNzd29yZC1yZXNldC1wb2lzb25pbmctdmlhLWRhbmdsaW5nLW1hcmt1cA=='>
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
        <div theme="blog">
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
                    <div class="blog-post">
                    <img src="/image/blog/posts/1.jpg">
                    <h1>It&apos;s All in the Game - Football for Dummies</h1>
                    <p><span id=blog-author>Bud Vizer</span> | 19 June 2026</p>
                    <hr>
                    <p>There are two types of people in the world; those who watch soccer, and those who watch people watching soccer. I fall into the latter category. If only they&apos;d leave me in peace to drink my beer and zone out. But, no. I&apos;m going to stick my neck out here, but in my experience, the male of the species feel it is their duty to do some Mansplaining*.</p>
                    <p>It doesn&apos;t matter how many Salt &amp; Pepper pots, beer mats, or random objects they use to explain the offside rule of English football, I&apos;m never going to make the connection between the penalty area and a couple of drinking straws. They have an instant replay for a reason, it&apos;s nice and slow, just point to the television; if you&apos;re at home pause, rewind and fast forward. I&apos;d make better sense of recognizing the players&apos; positions if I could see the players, and not a mishmash of mismatched cutlery.</p>
                    <p>What really annoys me is the way that techies ( you know the ones, nine normal length fingernails and one thumbnail kept obscenely long for a night at home playing Stairway To Heaven on their new turquoise guitar) get away with knowing nothing at all about the game, but somehow wing it with a set of stock phrases they picked up one night after falling asleep watching Silicon Valley, and Match of the Day came on and penetrated their subconscious.</p>
                    <p>And why, oh why, do English men now insist on watching American football? Hours and hours of stopping and starting the game. I try and settle down to watch my favorite show Outnumbered, he tells me he&apos;s just watching the end of a game, but it doesn&apos;t end, not before it&apos;s already time to get up for work the next morning. Just because I&apos;m drifting in and out of the living room (impatiently waiting for it all to be over) doesn&apos;t mean I have any interest and need a new set of rules imparted to me.</p>
                    <p>Soccer, love it or hate it, someone will always want to explain the game to you.</p>
                    <p>*Mansplaining: This is when a man explains something to a woman in a way that suggests the woman is hard of hearing or completely stupid.</p>
                    <div/>
                    <hr>
                    <h1>Comments</h1>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Lee Mealone | 03 July 2026
                        </p>
                        <p>What is the point to any of this?</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="https://verdict-site-ZZQ3.example.com">verdictNameZZQ2</a> | 05 July 2026
                        </p>
                        <p>verdicttest comment body ZZQ1</p>
                        <p></p>
                    </section>
                    <hr>
                    <section class="add-comment">
                        <h2>Leave a comment</h2>
                        <form action="/post/comment" method="POST" enctype="application/x-www-form-urlencoded">
                            <input required type="hidden" name="csrf" value="69iHOmUPQATXOGBYoWiS0gnfqcfd9pAV">
                            <input required type="hidden" name="postId" value="1">
                            <label>Comment:</label>
                            <textarea required rows="12" cols="300" name="comment"></textarea>
                                    <label>Name:</label>
                                    <input required type="text" name="name">
                                    <label>Email:</label>
                                    <input required type="email" name="email">
                                    <label>Website:</label>
                                    <input pattern="(http:|https:).+" type
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-4"></a>

### 4. [SUSPECTED] [HIGH] [account-takeover] Password reset flow — potential host-header poisoning (account takeover), unconfirmed

- Screen: `s-0004`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a07008b0333c295819d349400dd001d.web-security-academy.net/

**Anomaly (why this is a lead):** /forgot-password emails a password-reset link and the lab provisions a dedicated exploit server — the canonical password-reset-poisoning setup. I attempted X-Forwarded-Host poisoning of the reset request but could NOT deliver/confirm it: http_request cannot hold the session-bound anti-CSRF token (reset POSTs are rejected with 400 "session does not contain a CSRF token"), the browser cannot set a custom Host/X-Forwarded-Host header, and the victim inbox (exploit-server /email) is out of scope — so I could not observe whether the emailed reset link carries the injected host. Strong lead for manual verification.

The /forgot-password endpoint accepts a username and (per the classic reset flow) emails a password-reset link to that account. The lab provisions a dedicated exploit server, which is the standard delivery channel for a victim-driven attack such as password reset poisoning. If the reset link is built from an attacker-controllable Host or X-Forwarded-Host header, an attacker can request a reset for a victim, cause the emailed link to point at their own host, and capture the victim's reset token when the victim clicks it — leading to full account takeover.

This could not be confirmed with the available tooling: (1) the reset POST is CSRF-protected with a session-bound token that the http_request client cannot obtain/replay (every scripted POST returns 400 "Invalid CSRF token (session does not contain a CSRF token)"), so the host-header injection cannot be delivered via http_request; (2) the browser can submit the form (it carries the token from the DOM) but cannot set a custom Host/X-Forwarded-Host header; (3) the victim inbox / exploit-server /email endpoint is out of scope, so the poisoned reset link cannot be read back. An OOB probe (X-Forwarded-Host = Collaborator host) produced no callback within the window — consistent with the request being CSRF-blocked and with reset poisoning being victim-driven rather than server-initiated.

Other planned classes on this screen were tested and held: anti-CSRF token is enforced on the reset POST; valid vs invalid usernames produced identical generic responses (no user enumeration); repeated submissions showed no rate limiting (low impact).

**Reproduction**

```
Manual verification (Burp Suite): 1) GET /forgot-password to obtain the session cookie and the form's csrf token. 2) POST /forgot-password with body csrf=<token>&username=wiener AND an added header X-Forwarded-Host: attacker.example (also try Host: attacker.example, and duplicate Host headers) — reusing the same session cookie. 3) Read the victim's reset email via the exploit server's email client and inspect the reset link's host; if it reflects attacker.example, the link is poisoned. 4) Host the poisoned link on the exploit server, deliver to the victim, and capture the reset token from the exploit-server access log when clicked → reset the victim's password = account takeover. Within this assessment steps 2–4 were undeliverable (CSRF token not scriptable, custom Host header not settable in the browser, exploit-server /email out of scope).
```

**Evidence**

- Evidence `ev-mr7kn5zv-1k` — `artifacts/s-0004/ev-mr7kn5zv-1k/`

Request:

```http
POST /forgot-password HTTP/1.1
Host: 0a07008b0333c295819d349400dd001d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
X-Forwarded-Host: verdict-oob-noref-bhwgeq0i.invalid
content-type: application/x-www-form-urlencoded

username=wiener
```

Response:

```http
HTTP/1.1 400
content-length: 26
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

[VERDICT-OOB] control: benign host, no callback expected
```
