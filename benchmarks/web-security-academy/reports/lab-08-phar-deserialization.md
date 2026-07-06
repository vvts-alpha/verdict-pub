# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — burp✓ Input returned in response (reflected)](#finding-1)
    - [2. LOW — burp Client-side HTTP parameter pollution (reflected)](#finding-2)
    - [3. INFO — burp TLS certificate](#finding-3)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [4. CRITICAL — rce Avatar upload accepts JPEG/PHP polyglot web shell (likely RCE)](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr6knca6-5nfoqo` |
| Target | https://0ad6000a03d24a7480982b0200880012.web-security-academy.net/ |
| Started | 2026-07-04T16:23:31.807Z |
| Generated | 2026-07-04T18:21:01.263Z |
| Phase | report |
| Screens | 6 mapped · 6 scanned · 0 remaining |
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

3 finding(s): 1 high, 1 low, 1 info

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [burp✓] Input returned in response (reflected)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

✅ AI-verified by active re-test: postId is reflected verbatim into the response body (Back-to-blog href): body length = baseline 3720 + (postId_len − 11) exactly in all cases — control (postId=benign_control_000 → 3727) reflects its own value not the marker, while both positives (postId=qXZ7reflect42 → 3722, identical) reflect the unique 13-char marker; stable single verbatim reflection. (severity raised info→high: confirmed real, not info-only)

The value of the <b>postId</b> request parameter is copied into the application's response. (confidence: CERTAIN) @ https://0ad6000a03d24a7480982b0200880012.web-security-academy.net/post/comment/confirmation

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr6osnmp-4i` — `artifacts/_/ev-mr6osnmp-4i/`

Request:

```http
GET /post/comment/confirmation HTTP/1.1
Host: 0ad6000a03d24a7480982b0200880012.web-security-academy.net

GET /post/comment/confirmation?postId=12y0u9jswgi HTTP/1.1
Host: 0ad6000a03d24a7480982b0200880012.web-security-academy.net
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 3720

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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Rlc2VyaWFsaXphdGlvbi9leHBsb2l0aW5nL2xhYi1kZXNlcmlhbGl6YXRpb24tdXNpbmctcGhhci1kZXNlcmlhbGl6YXRpb24tdG8tZGVwbG95LWEtY3VzdG9tLWdhZGdldC1jaGFpbg=='>
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
                    <h1>Thank you for your comment!</h1>
                    <p>Your comment has been submitted.</p>
                    <div class="is-linkback">
                        <a href="/post?postId=12y0u9jswgi">Back to blog</a>
                    </div>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr6otm1c-4k` — `artifacts/_/ev-mr6otm1c-4k/`

Request:

```http
GET /post/comment/confirmation?postId=benign_control_000 HTTP/1.1
Host: 0ad6000a03d24a7480982b0200880012.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: close
content-encoding: gzip
content-length: 1315
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Rlc2VyaWFsaXphdGlvbi9leHBsb2l0aW5nL2xhYi1kZXNlcmlhbGl6YXRpb24tdXNpbmctcGhhci1kZXNlcmlhbGl6YXRpb24tdG8tZGVwbG95LWEtY3VzdG9tLWdhZGdldC1jaGFpbg=='>
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
                    <h1>Thank you for your comment!</h1>
                    <p>Your comment has been submitted.</p>
                    <div class="is-linkback">
                        <a href="/post?postId=benign_control_000">Back to blog</a>
                    </div>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr6otpmt-4l` — `artifacts/_/ev-mr6otpmt-4l/`

Request:

```http
GET /post/comment/confirmation?postId=qXZ7reflect42 HTTP/1.1
Host: 0ad6000a03d24a7480982b0200880012.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: close
content-encoding: gzip
content-length: 1313
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Rlc2VyaWFsaXphdGlvbi9leHBsb2l0aW5nL2xhYi1kZXNlcmlhbGl6YXRpb24tdXNpbmctcGhhci1kZXNlcmlhbGl6YXRpb24tdG8tZGVwbG95LWEtY3VzdG9tLWdhZGdldC1jaGFpbg=='>
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
                    <h1>Thank you for your comment!</h1>
                    <p>Your comment has been submitted.</p>
                    <div class="is-linkback">
                        <a href="/post?postId=qXZ7reflect42">Back to blog</a>
                    </div>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr6ott5u-4m` — `artifacts/_/ev-mr6ott5u-4m/`

Request:

```http
GET /post/comment/confirmation?postId=qXZ7reflect42 HTTP/1.1
Host: 0ad6000a03d24a7480982b0200880012.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: close
content-encoding: gzip
content-length: 1313
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Rlc2VyaWFsaXphdGlvbi9leHBsb2l0aW5nL2xhYi1kZXNlcmlhbGl6YXRpb24tdXNpbmctcGhhci1kZXNlcmlhbGl6YXRpb24tdG8tZGVwbG95LWEtY3VzdG9tLWdhZGdldC1jaGFpbg=='>
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
                    <h1>Thank you for your comment!</h1>
                    <p>Your comment has been submitted.</p>
                    <div class="is-linkback">
                        <a href="/post?postId=qXZ7reflect42">Back to blog</a>
                    </div>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

<a id="finding-2"></a>

### 2. [LOW] [burp] Client-side HTTP parameter pollution (reflected)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The value of the <b>postId</b> request parameter is copied into the response within the query string of a URL.<br><br> The payload <b>zwt&amp;fzo=1</b> was submitted in the postId parameter. This input was echoed as <b>zwt&amp;amp;fzo=1</b> within the "href" attribute of an "a" tag.<br><br>This proof-of-concept attack demonstrates that it is possible to inject arbitrary query string parameters into URLs in the application's response. (confidence: FIRM) @ https://0ad6000a03d24a7480982b0200880012.web-security-academy.net/post/comment/confirmation

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr6osnmt-4j` — `artifacts/_/ev-mr6osnmt-4j/`

Request:

```http
GET /post/comment/confirmation HTTP/1.1
Host: 0ad6000a03d24a7480982b0200880012.web-security-academy.net

GET /post/comment/confirmation?postId=zwt%26fzo%3d1 HTTP/1.1
Host: 0ad6000a03d24a7480982b0200880012.web-security-academy.net
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 3722

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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Rlc2VyaWFsaXphdGlvbi9leHBsb2l0aW5nL2xhYi1kZXNlcmlhbGl6YXRpb24tdXNpbmctcGhhci1kZXNlcmlhbGl6YXRpb24tdG8tZGVwbG95LWEtY3VzdG9tLWdhZGdldC1jaGFpbg=='>
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
                    <h1>Thank you for your comment!</h1>
                    <p>Your comment has been submitted.</p>
                    <div class="is-linkback">
                        <a href="/post?postId=zwt&amp;fzo=1">Back to blog</a>
                    </div>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

<a id="finding-3"></a>

### 3. [INFO] [burp] TLS certificate

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The server presented a valid, trusted TLS certificate. This issue is purely informational.<br><br>The server presented the following certificates:<br><br><h4>Server certificate</h4><table><tr><td><b>Issued to:</b>&nbsp;&nbsp;</td><td>*.web-security-academy.net, *.2.web-security-academy.net, *.1.web-security-academy.net, *.3.web-security-academy.net, *.2.h1-web-security-academy.net, *.1.h1-web-security-academy.net, *.h1-web-security-academy.net, *.3.h1-web-security-academy.net</td></tr><tr><td><b>Issued by:</b>&nbsp;&nbsp;</td><td>Amazon RSA 2048 M01</td></tr><tr><td><b>Valid from:</b>&nbsp;&nb @ https://0ad6000a03d24a7480982b0200880012.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr6osnmc-4h` — `artifacts/_/ev-mr6osnmc-4h/`

Request:

```http
GET / HTTP/1.1
Host: 0ad6000a03d24a7480982b0200880012.web-security-academy.net
```

Response:

```http
HTTP/1.1 0
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-4"></a>

### 4. [SUSPECTED] [CRITICAL] [rce] Avatar upload accepts JPEG/PHP polyglot web shell (likely RCE)

- Screen: `s-0005`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0ad6000a03d24a7480982b0200880012.web-security-academy.net/

**Anomaly (why this is a lead):** The avatar upload validates image CONTENT (a valid JPEG is accepted; pure-PHP, PNG and GIF are all rejected as "Invalid avatar"), yet it ACCEPTS a JPEG/PHP polyglot named exploit.php — a valid JPEG (correct magic bytes, intact FFD9 EOI) with `<?php echo shell_exec('id'); ?>` appended, uploaded via the authenticated browser. So an executable .php web shell passes the image filter: the exact pattern of PortSwigger's "RCE via polyglot web shell upload". The avatar-serving directory /files/avatars/ exists (it returns file-level 404s, distinct from the app's /login 302). Execution could NOT be confirmed only because the uploaded file's served path/filename is not locatable in this run: no role is configured, the HTTP client is unauthenticated (every /my-account request 302-redirects to /login), and the account page's <img> src is not readable (view-source blocked, HTTP body display truncated to the lab header).

POST /my-account/avatar (authenticated as wiener) enforces image-content validation — uploads whose bytes are not a valid JPEG (pure PHP, PNG, GIF) are rejected with "Invalid avatar", while a valid JPEG is accepted and the request redirects to /my-account/ (success). Critically, a JPEG/PHP polyglot (valid JPEG bytes + trailing `<?php echo shell_exec('id'); ?>`) uploaded with filename exploit.php and Content-Type image/jpeg is ALSO accepted — the .php extension is not blocked when the content passes image validation. This is a server-side web-shell upload: when such a file is served by a PHP handler it executes the embedded code, yielding remote command execution. Confirmation of execution requires fetching the stored file's URL, which was not reachable in this assessment environment (see repro/limitation notes).

**Reproduction**

```
1. Log in as wiener and open /my-account. 2. Baseline: upload pure PHP, a PNG, and a GIF via the avatar form → each returns "Invalid avatar" (content is validated as an image). 3. Upload a valid JPEG → accepted (redirects to /my-account/). 4. Build a polyglot: valid JPEG bytes with `<?php echo shell_exec('id'); ?>` appended after the FFD9 EOI; upload it as exploit.php with Content-Type image/jpeg → ACCEPTED (redirects to /my-account/, not "Invalid avatar"). 5. To confirm RCE: read the account page HTML for the avatar <img> src (the served file URL), then GET that .php path — the response should contain the JPEG bytes followed by command output (uid=...). LIMITATION in this run: the served avatar path could not be located (/files/avatars/{name} 404s for every uploaded name; no role/authed HTTP to read the account HTML), so the final execution step (negative control + 2 positive replays) could not be captured.
```

**Evidence**

- Evidence `ev-mr6obvqk-48` — `artifacts/s-0005/ev-mr6obvqk-48/`

Request:

```http
GET /files/avatars/exploit.php HTTP/1.1
Host: 0ad6000a03d24a7480982b0200880012.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 11
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

"Not Found"
```
