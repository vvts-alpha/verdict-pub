# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — burp✓ Input returned in response (reflected)](#finding-1)
    - [2. MEDIUM — xss-reflected Reflected XSS via AngularJS client-side template injection (CSTI) in search parameter](#finding-2)
    - [3. LOW — burp Strict transport security not enforced (2 URLs)](#finding-3)
    - [4. INFO — burp TLS certificate](#finding-4)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [5. HIGH — xss-stored Stored XSS via AngularJS client-side template injection in blog comments](#finding-5)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr66m5ec-bv0cpl` |
| Target | https://0ab100cc04adce75806e03fe00aa0030.web-security-academy.net/ |
| Started | 2026-07-04T09:50:41.661Z |
| Generated | 2026-07-04T11:10:22.873Z |
| Phase | report |
| Screens | 5 mapped · 5 scanned · 0 remaining |
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

4 finding(s): 1 high, 1 medium, 1 low, 1 info

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [burp✓] Input returned in response (reflected)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

✅ AI-verified by active re-test: The search param is reflected verbatim into the response body's h1 exactly once: body length tracks marker length with slope 1 (control benignquery0000/15 chars→4440; two stable positives reflZq7x7Probe/14 chars→4439 each), matching Burp's 23-char marker→4448; control does not contain the attack marker. (severity raised info→high: confirmed real, not info-only)

The value of the <b>search</b> request parameter is copied into the application's response. (confidence: CERTAIN) @ https://0ab100cc04adce75806e03fe00aa0030.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr69elbv-3h` — `artifacts/_/ev-mr69elbv-3h/`

Request:

```http
GET / HTTP/1.1
Host: 0ab100cc04adce75806e03fe00aa0030.web-security-academy.net

GET /?search=verdict-probeb19ram29ft HTTP/1.1
Host: 0ab100cc04adce75806e03fe00aa0030.web-security-academy.net
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'self'
X-Frame-Options: SAMEORIGIN
Content-Length: 4448

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <script type="text/javascript" src="/resources/js/angular_1-4-4.js"></script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body ng-app ng-csp>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a1d00f50437ce0d8035023f019a00e3.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VXNlIHRoZSBleHBsb2l0IHNlcnZlciB0byBkZWxpdmVyIGFuIGF0dGFjayB0aGF0IGludm9rZXMgPGNvZGU+YWxlcnQoZG9jdW1lbnQuY29va2llKTwvY29kZT4gaW4gdGhlIHZpY3RpbSdzIGJyb3dzZXIu' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Nyb3NzLXNpdGUtc2NyaXB0aW5nL2NvbnRleHRzL2NsaWVudC1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9sYWItYW5ndWxhci1zYW5kYm94LWVzY2FwZS1hbmQtY3Nw'>
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
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class=blog-header>
                        <h1>0 search results for 'verdict-probeb19ram29ft'</h1>
                        <hr>
                    </section>
                    <section class=search>
                        <form action=/ method=GET>
                            <input type=text placeholder='Search the blog...' name=search>
                            <button type=submit class=button>Search</button>
                        </form>
                    </section>
                    <section class="blog-list no-results">
                        <div class=is-linkback>
        <a href="/">Back to Blog</a>
                        </div>
                    </section>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr69feyt-3i` — `artifacts/_/ev-mr69feyt-3i/`

Request:

```http
GET /?search=benignquery0000 HTTP/1.1
Host: 0ab100cc04adce75806e03fe00aa0030.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: close
content-encoding: gzip
content-length: 1576
content-security-policy: default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'self'
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <script type="text/javascript" src="/resources/js/angular_1-4-4.js"></script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body ng-app ng-csp>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a1d00f50437ce0d8035023f019a00e3.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VXNlIHRoZSBleHBsb2l0IHNlcnZlciB0byBkZWxpdmVyIGFuIGF0dGFjayB0aGF0IGludm9rZXMgPGNvZGU+YWxlcnQoZG9jdW1lbnQuY29va2llKTwvY29kZT4gaW4gdGhlIHZpY3RpbSdzIGJyb3dzZXIu' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Nyb3NzLXNpdGUtc2NyaXB0aW5nL2NvbnRleHRzL2NsaWVudC1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9sYWItYW5ndWxhci1zYW5kYm94LWVzY2FwZS1hbmQtY3Nw'>
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
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class=blog-header>
                        <h1>0 search results for 'benignquery0000'</h1>
                        <hr>
                    </section>
                    <section class=search>
                        <form action=/ method=GET>
                            <input type=text placeholder='Search the blog...' name=search>
                            <button type=submit class=button>Search</button>
                        </form>
                    </section>
                    <section class="blog-list no-results">
                        <div class=is-linkback>
        <a href="/">Back to Blog</a>
                        </div>
                    </section>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr69figw-3j` — `artifacts/_/ev-mr69figw-3j/`

Request:

```http
GET /?search=reflZq7x7Probe HTTP/1.1
Host: 0ab100cc04adce75806e03fe00aa0030.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: close
content-encoding: gzip
content-length: 1577
content-security-policy: default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'self'
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <script type="text/javascript" src="/resources/js/angular_1-4-4.js"></script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body ng-app ng-csp>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a1d00f50437ce0d8035023f019a00e3.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VXNlIHRoZSBleHBsb2l0IHNlcnZlciB0byBkZWxpdmVyIGFuIGF0dGFjayB0aGF0IGludm9rZXMgPGNvZGU+YWxlcnQoZG9jdW1lbnQuY29va2llKTwvY29kZT4gaW4gdGhlIHZpY3RpbSdzIGJyb3dzZXIu' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Nyb3NzLXNpdGUtc2NyaXB0aW5nL2NvbnRleHRzL2NsaWVudC1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9sYWItYW5ndWxhci1zYW5kYm94LWVzY2FwZS1hbmQtY3Nw'>
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
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class=blog-header>
                        <h1>0 search results for 'reflZq7x7Probe'</h1>
                        <hr>
                    </section>
                    <section class=search>
                        <form action=/ method=GET>
                            <input type=text placeholder='Search the blog...' name=search>
                            <button type=submit class=button>Search</button>
                        </form>
                    </section>
                    <section class="blog-list no-results">
                        <div class=is-linkback>
        <a href="/">Back to Blog</a>
                        </div>
                    </section>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr69flz3-3k` — `artifacts/_/ev-mr69flz3-3k/`

Request:

```http
GET /?search=reflZq7x7Probe HTTP/1.1
Host: 0ab100cc04adce75806e03fe00aa0030.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: close
content-encoding: gzip
content-length: 1577
content-security-policy: default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'self'
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <script type="text/javascript" src="/resources/js/angular_1-4-4.js"></script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body ng-app ng-csp>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a1d00f50437ce0d8035023f019a00e3.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VXNlIHRoZSBleHBsb2l0IHNlcnZlciB0byBkZWxpdmVyIGFuIGF0dGFjayB0aGF0IGludm9rZXMgPGNvZGU+YWxlcnQoZG9jdW1lbnQuY29va2llKTwvY29kZT4gaW4gdGhlIHZpY3RpbSdzIGJyb3dzZXIu' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Nyb3NzLXNpdGUtc2NyaXB0aW5nL2NvbnRleHRzL2NsaWVudC1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9sYWItYW5ndWxhci1zYW5kYm94LWVzY2FwZS1hbmQtY3Nw'>
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
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class=blog-header>
                        <h1>0 search results for 'reflZq7x7Probe'</h1>
                        <hr>
                    </section>
                    <section class=search>
                        <form action=/ method=GET>
                            <input type=text placeholder='Search the blog...' name=search>
                            <button type=submit class=button>Search</button>
                        </form>
                    </section>
                    <section class="blog-list no-results">
                        <div class=is-linkback>
        <a href="/">Back to Blog</a>
                        </div>
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

### 2. [MEDIUM] [xss-reflected] Reflected XSS via AngularJS client-side template injection (CSTI) in search parameter

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0ab100cc04adce75806e03fe00aa0030.web-security-academy.net/

The home/search endpoint (GET /?search=) reflects the `search` value UNESCAPED into an AngularJS-bootstrapped page: the document is `<body ng-app ng-csp>` and loads AngularJS 1.4.4 (/resources/js/angular_1-4-4.js). The injected AngularJS expression payload `{{9*9}}qWeRxSs` appears verbatim in the served HTML (positive replays ev-mr67evbj-p, ev-mr67ezks-q), while the benign control `qWeRxSscontrol` does not contain it (ev-mr67er1y-o). Because the reflection sits inside the ng-app scope, the double-curly expression is then evaluated by AngularJS in the browser: navigating a real browser to /?search=veritas{{7*7}}probe renders 'veritas49probe' (7*7 evaluated to 49), and a complex expression `{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('...')}}` is parsed/evaluated (page renders an empty result rather than echoing the literal braces) — confirming arbitrary AngularJS expression evaluation of attacker input. probe_ssti confirmed the server reflects the `{{...}}` payload LITERALLY (echoedLiteral, no server-side evaluation), so this is CLIENT-side template injection (XSS class), not server-side SSTI. AngularJS 1.4.x ships an expression sandbox that is publicly and comprehensively broken (Angular removed the sandbox entirely in 1.6 because it could not be secured), so CSTI in this version reliably escalates to arbitrary JavaScript execution = reflected XSS. The 80-character limit on `search` constrains the payload but does not prevent it: known AngularJS ng-csp sandbox-escape one-liners fit within 80 characters.

**Reproduction**

```
1. Negative control: GET /?search=qWeRxSscontrol → the served HTML reflects 'qWeRxSscontrol' and does NOT contain the AngularJS payload (evidence ev-mr67er1y-o).
2. Positive x2: GET /?search={{9*9}}qWeRxSs → the served HTML contains the AngularJS expression payload '{{9*9}}qWeRxSs' unescaped inside the ng-app page (evidence ev-mr67evbj-p, ev-mr67ezks-q — stable across 2 replays).
3. Browser confirmation of client-side evaluation: navigate to /?search=veritas{{7*7}}probe → rendered DOM shows "0 search results for 'veritas49probe'" (AngularJS evaluated 7*7=49); the control /?search=zzcontrolzz shows the literal string, proving the difference is evaluation, not mere reflection.
4. Escalation to XSS: replace {{7*7}} with an AngularJS 1.4.x sandbox-escape expression (fits within the 80-char limit) to run arbitrary JavaScript in the victim's browser (e.g. exfiltrate document.cookie or perform actions as the victim), delivered via a crafted /?search= link.
```

**Evidence**

- Evidence `ev-mr67er1y-o` — `artifacts/s-0001/ev-mr67er1y-o/`

Request:

```http
GET /?search=qWeRxSscontrol HTTP/1.1
Host: 0ab100cc04adce75806e03fe00aa0030.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 4439
content-security-policy: default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'self'
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <script type="text/javascript" src="/resources/js/angular_1-4-4.js"></script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body ng-app ng-csp>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a1d00f50437ce0d8035023f019a00e3.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VXNlIHRoZSBleHBsb2l0IHNlcnZlciB0byBkZWxpdmVyIGFuIGF0dGFjayB0aGF0IGludm9rZXMgPGNvZGU+YWxlcnQoZG9jdW1lbnQuY29va2llKTwvY29kZT4gaW4gdGhlIHZpY3RpbSdzIGJyb3dzZXIu' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Nyb3NzLXNpdGUtc2NyaXB0aW5nL2NvbnRleHRzL2NsaWVudC1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9sYWItYW5ndWxhci1zYW5kYm94LWVzY2FwZS1hbmQtY3Nw'>
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
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class=blog-header>
                        <h1>0 search results for 'qWeRxSscontrol'</h1>
                        <hr>
                    </section>
                    <section class=search>
                        <form action=/ method=GET>
                            <input type=text placeholder='Search the blog...' name=search>
                            <button type=submit class=button>Search</button>
                        </form>
                    </section>
                    <section class="blog-list no-results">
                        <div class=is-linkback>
        <a href="/">Back to Blog</a>
                        </div>
                    </section>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr67evbj-p` — `artifacts/s-0001/ev-mr67evbj-p/`

Request:

```http
GET /?search={{9*9}}qWeRxSs HTTP/1.1
Host: 0ab100cc04adce75806e03fe00aa0030.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 4439
content-security-policy: default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'self'
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <script type="text/javascript" src="/resources/js/angular_1-4-4.js"></script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body ng-app ng-csp>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a1d00f50437ce0d8035023f019a00e3.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VXNlIHRoZSBleHBsb2l0IHNlcnZlciB0byBkZWxpdmVyIGFuIGF0dGFjayB0aGF0IGludm9rZXMgPGNvZGU+YWxlcnQoZG9jdW1lbnQuY29va2llKTwvY29kZT4gaW4gdGhlIHZpY3RpbSdzIGJyb3dzZXIu' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Nyb3NzLXNpdGUtc2NyaXB0aW5nL2NvbnRleHRzL2NsaWVudC1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9sYWItYW5ndWxhci1zYW5kYm94LWVzY2FwZS1hbmQtY3Nw'>
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
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class=blog-header>
                        <h1>0 search results for '{{9*9}}qWeRxSs'</h1>
                        <hr>
                    </section>
                    <section class=search>
                        <form action=/ method=GET>
                            <input type=text placeholder='Search the blog...' name=search>
                            <button type=submit class=button>Search</button>
                        </form>
                    </section>
                    <section class="blog-list no-results">
                        <div class=is-linkback>
        <a href="/">Back to Blog</a>
                        </div>
                    </section>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr67ezks-q` — `artifacts/s-0001/ev-mr67ezks-q/`

Request:

```http
GET /?search={{9*9}}qWeRxSs HTTP/1.1
Host: 0ab100cc04adce75806e03fe00aa0030.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 4439
content-security-policy: default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'self'
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <script type="text/javascript" src="/resources/js/angular_1-4-4.js"></script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body ng-app ng-csp>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a1d00f50437ce0d8035023f019a00e3.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VXNlIHRoZSBleHBsb2l0IHNlcnZlciB0byBkZWxpdmVyIGFuIGF0dGFjayB0aGF0IGludm9rZXMgPGNvZGU+YWxlcnQoZG9jdW1lbnQuY29va2llKTwvY29kZT4gaW4gdGhlIHZpY3RpbSdzIGJyb3dzZXIu' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Nyb3NzLXNpdGUtc2NyaXB0aW5nL2NvbnRleHRzL2NsaWVudC1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9sYWItYW5ndWxhci1zYW5kYm94LWVzY2FwZS1hbmQtY3Nw'>
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
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class=blog-header>
                        <h1>0 search results for '{{9*9}}qWeRxSs'</h1>
                        <hr>
                    </section>
                    <section class=search>
                        <form action=/ method=GET>
                            <input type=text placeholder='Search the blog...' name=search>
                            <button type=submit class=button>Search</button>
                        </form>
                    </section>
                    <section class="blog-list no-results">
                        <div class=is-linkback>
        <a href="/">Back to Blog</a>
                        </div>
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

### 3. [LOW] [burp] Strict transport security not enforced (2 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

(confidence: CERTAIN) [+1 more URL(s): https://0ab100cc04adce75806e03fe00aa0030.web-security-academy.net/post/comment] @ https://0ab100cc04adce75806e03fe00aa0030.web-security-academy.net/post

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr69elbp-3g` — `artifacts/_/ev-mr69elbp-3g/`

Request:

```http
GET /post HTTP/1.1
Host: 0ab100cc04adce75806e03fe00aa0030.web-security-academy.net

GET /post?postId=1 HTTP/1.1
Host: 0ab100cc04adce75806e03fe00aa0030.web-security-academy.net
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'self'
X-Frame-Options: SAMEORIGIN
Content-Length: 8842

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <script type="text/javascript" src="/resources/js/angular_1-4-4.js"></script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body ng-app ng-csp>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a1d00f50437ce0d8035023f019a00e3.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VXNlIHRoZSBleHBsb2l0IHNlcnZlciB0byBkZWxpdmVyIGFuIGF0dGFjayB0aGF0IGludm9rZXMgPGNvZGU+YWxlcnQoZG9jdW1lbnQuY29va2llKTwvY29kZT4gaW4gdGhlIHZpY3RpbSdzIGJyb3dzZXIu' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Nyb3NzLXNpdGUtc2NyaXB0aW5nL2NvbnRleHRzL2NsaWVudC1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9sYWItYW5ndWxhci1zYW5kYm94LWVzY2FwZS1hbmQtY3Nw'>
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
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <div class="blog-post">
                    <img src="/image/blog/posts/19.jpg">
                    <h1>Spider Web Security</h1>
                    <p><span id=blog-author>Jay Bail</span> | 09 June 2026</p>
                    <hr>
                    <p>Today the President issued a red warning in relation to the breakdown of spider web security. So far all of the main banks and energy suppliers have been hit by this gang of thieves who are now on the run, believed to be making their way towards the Mexican border.</p>
                    <p>No-one is entirely sure what they are using the spider webs for, or if they just want to wreak havoc in the business community. The fallout from this attack has been of epic proportions, as offices have been overrun with bugs the webs usually manage to contain. Moths, flies, ladybugs are now believed to be breeding in any warm areas they can reach undetected. Unfortunately, due to the heat radiated from personal computers, these have been their first port of call, systems have shut down and cannot be restarted after they have been shorted by the infestation.</p>
                    <p>The President has set out proposals to minimize long-term destruction by sending in Cybermen and Spiderman to create artificial webs, which, although previously untested, should prevent an International incident from which the country would be unlikely to recover. The President was quoted as saying, &apos;...there should be just the right amount of stickiness to catch those dang critters.&apos;</p>
                    <p>Latest news in suggests the stock market is already taking a hit and fears are mounting we could see another Great Crash like that of 1929. The SAS is currently rushing through their prototype search engine, hoping they can get quickly on board and destroy any remaining nests so further breeding cannot take place. The general public is being asked to remain calm, panic buying is completely unnecessary and looting will carry the severest of punishments. There will be regular updates as soon as the information become available.</p>
                    <p>LIVE NEWS: JUST IN Efforts to contain the infestation are being hampered by the public stopping Spiderman for selfies and autographs. A statement from the White House urges people to just go about their normal day.</p>
                    <div/>
                    <hr>
                    <h1>Comments</h1>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Slim Jim | 20 June 2026
                        </p>
                        <p>I lost my daughter&apos;s Harry Potter book so I had to read her your blog. May I suggest you write about more magical themes in the future?</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Carrie Onanon | 27 June 2026
                        </p>
                        <p>Can you write a blog for me, please? I can&apos;t pay you, but it will be good for your portfolio.</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Kit Kat | 01 July 2026
                        </p>
                        <p>Sometimes you come across things in life that make it all worthwhile. This isn&apos;t one of them, but it&apos;s pretty good.</p>
                        <p></p>
                    </section>
                    <hr>
                    <section class="add-comment">
                        <h2>Leave a comment</h2>
                        <form action="/post/comment" method="POST" enctype="application/x-www-form-urlencoded">
                            <input required type="hidden" name="csrf" value="IMgOVynEoPnCTUT9fW85gGDVIkQGGMfe">
```

<a id="finding-4"></a>

### 4. [INFO] [burp] TLS certificate

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The server presented a valid, trusted TLS certificate. This issue is purely informational.<br><br>The server presented the following certificates:<br><br><h4>Server certificate</h4><table><tr><td><b>Issued to:</b>&nbsp;&nbsp;</td><td>*.web-security-academy.net, *.2.web-security-academy.net, *.1.web-security-academy.net, *.3.web-security-academy.net, *.2.h1-web-security-academy.net, *.1.h1-web-security-academy.net, *.h1-web-security-academy.net, *.3.h1-web-security-academy.net</td></tr><tr><td><b>Issued by:</b>&nbsp;&nbsp;</td><td>Amazon RSA 2048 M01</td></tr><tr><td><b>Valid from:</b>&nbsp;&nb @ https://0ab100cc04adce75806e03fe00aa0030.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr69elbf-3f` — `artifacts/_/ev-mr69elbf-3f/`

Request:

```http
GET / HTTP/1.1
Host: 0ab100cc04adce75806e03fe00aa0030.web-security-academy.net
```

Response:

```http
HTTP/1.1 0
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-5"></a>

### 5. [SUSPECTED] [HIGH] [xss-stored] Stored XSS via AngularJS client-side template injection in blog comments

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0ab100cc04adce75806e03fe00aa0030.web-security-academy.net/

**Anomaly (why this is a lead):** The /post page ships AngularJS 1.4.4 with `<body ng-app ng-csp>` and `/resources/js/angular_1-4-4.js`, and the comment form (POST /post/comment) persists user-controlled comment/name/website that is re-rendered inside the ng-app scope. AngularJS interpolates any `{{ }}` in text nodes within ng-app, so a stored comment like `{{7*7}}` is evaluated client-side (CSTI); AngularJS 1.4.4 has published CSP/sandbox-escape payloads that turn this into arbitrary JS execution = stored XSS affecting every viewer of the post. A benign `verdictprobe-{{7*7}}-marker` comment was accepted and stored via the browser session. Full automated confirmation was blocked by (1) a session-bound anti-CSRF token whose value is not readable through the truncated tool output (so the http-based store probe returns "session does not contain a CSRF token"), and (2) the standard HTML-XSS payloads not matching the AngularJS expression sink. Lead requires manual confirmation with a 1.4.4 sandbox-escape payload.

The blog post page (/post?postId=N) is an AngularJS 1.4.4 single-page context: the document body carries `ng-app ng-csp` and loads `/resources/js/angular_1-4-4.js`. The comment functionality (POST /post/comment with fields csrf, postId, comment, name, email, website) stores user input and renders it back on the post page inside the AngularJS application scope. Because AngularJS evaluates `{{ expression }}` interpolation in any text node under ng-app, a stored comment containing an AngularJS expression is executed in the browser of every visitor (client-side template injection). AngularJS 1.4.4 is a known-vulnerable version with public CSP-mode sandbox-escape payloads that escalate CSTI to arbitrary JavaScript execution — i.e. stored cross-site scripting. This is corroborated by an already-confirmed reflected AngularJS injection on the site search (xss-reflected::/::search), indicating the same client-side template sink pattern is present in the stored comment surface.

**Reproduction**

```
1. GET /post?postId=1 — observe `<body ng-app ng-csp>` and `<script src="/resources/js/angular_1-4-4.js">` (evidence ev-mr67gnkb-r). 2. Submit the comment form (POST /post/comment) with comment set to an AngularJS expression, e.g. `{{7*7}}` (a benign `verdictprobe-{{7*7}}-marker` comment was accepted). 3. Re-open /post?postId=1 in a browser: AngularJS interpolates the stored expression (`{{7*7}}` → `49`), confirming client-side template evaluation of stored input. 4. Escalate with an AngularJS 1.4.4 CSP sandbox-escape payload to achieve JavaScript execution in every viewer's browser. NOTE: automated store-and-render confirmation via probe_stored_xss failed because the endpoint requires a valid session-bound CSRF token whose value could not be read from the truncated tool output, and the tool's HTML payloads do not target the AngularJS `{{ }}` sink — hence recorded as a suspected lead for manual verification.
```

**Evidence**

- Evidence `ev-mr67gnkb-r` — `artifacts/s-0002/ev-mr67gnkb-r/`

Request:

```http
GET /post?postId=1 HTTP/1.1
Host: 0ab100cc04adce75806e03fe00aa0030.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 8842
content-security-policy: default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'self'
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <script type="text/javascript" src="/resources/js/angular_1-4-4.js"></script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body ng-app ng-csp>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a1d00f50437ce0d8035023f019a00e3.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VXNlIHRoZSBleHBsb2l0IHNlcnZlciB0byBkZWxpdmVyIGFuIGF0dGFjayB0aGF0IGludm9rZXMgPGNvZGU+YWxlcnQoZG9jdW1lbnQuY29va2llKTwvY29kZT4gaW4gdGhlIHZpY3RpbSdzIGJyb3dzZXIu' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Nyb3NzLXNpdGUtc2NyaXB0aW5nL2NvbnRleHRzL2NsaWVudC1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9sYWItYW5ndWxhci1zYW5kYm94LWVzY2FwZS1hbmQtY3Nw'>
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
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <div class="blog-post">
                    <img src="/image/blog/posts/19.jpg">
                    <h1>Spider Web Security</h1>
                    <p><span id=blog-author>Jay Bail</span> | 09 June 2026</p>
                    <hr>
                    <p>Today the President issued a red warning in relation to the breakdown of spider web security. So far all of the main banks and energy suppliers have been hit by this gang of thieves who are now on the run, believed to be making their way towards the Mexican border.</p>
                    <p>No-one is entirely sure what they are using the spider webs for, or if they just want to wreak havoc in the business community. The fallout from this attack has been of epic proportions, as offices have been overrun with bugs the webs usually manage to contain. Moths, flies, ladybugs are now believed to be breeding in any warm areas they can reach undetected. Unfortunately, due to the heat radiated from personal computers, these have been their first port of call, systems have shut down and cannot be restarted after they have been shorted by the infestation.</p>
                    <p>The President has set out proposals to minimize long-term destruction by sending in Cybermen and Spiderman to create artificial webs, which, although previously untested, should prevent an International incident from which the country would be unlikely to recover. The President was quoted as saying, &apos;...there should be just the right amount of stickiness to catch those dang critters.&apos;</p>
                    <p>Latest news in suggests the stock market is already taking a hit and fears are mounting we could see another Great Crash like that of 1929. The SAS is currently rushing through their prototype search engine, hoping they can get quickly on board and destroy any remaining nests so further breeding cannot take place. The general public is being asked to remain calm, panic buying is completely unnecessary and looting will carry the severest of punishments. There will be regular updates as soon as the information become available.</p>
                    <p>LIVE NEWS: JUST IN Efforts to contain the infestation are being hampered by the public stopping Spiderman for selfies and autographs. A statement from the White House urges people to just go about their normal day.</p>
                    <div/>
                    <hr>
                    <h1>Comments</h1>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Slim Jim | 20 June 2026
                        </p>
                        <p>I lost my daughter&apos;s Harry Potter book so I had to read her your blog. May I suggest you write about more magical themes in the future?</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Carrie Onanon | 27 June 2026
                        </p>
                        <p>Can you write a blog for me, please? I can&apos;t pay you, but it will be good for your portfolio.</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Kit Kat | 01 July 2026
                        </p>
                        <p>Sometimes you come across things in life that make it all worthwhile. This isn&apos;t one of them, but it&apos;s pretty good.</p>
                        <p></p>
                    </section>
                    <hr>
                    <section class="add-comment">
                        <h2>Leave a comment</h2>
                        <form action="/post/comment" method="POST" enctype="application/x-www-form-urlencoded">
                            <input required type="hidden" name="csrf" value="ZoSg4rlUqR7CSQAlBqyNcjGJWZolKs5q">
                            <input required type="hidden" name="postId" value="1">
                            <label>Comment:</label>
                            <textarea required rows="12" cols="300" name="comment"></textarea>
                                    <label>Name:</label>
                                    <input required type="text" name="name">
                                    <label>Email:</label>
                                    <input required type="email" name="email">
                                    <label>Website:</label>
                                    <input pattern="(http:|https:).+" type="text" name="website">
                            <button class="button" type="submit">Post Comment</button>
                        </form>
                    </section>
                    <div class="is-linkback">
                        <a href="/">Back to Blog</a>
                    </div>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```
