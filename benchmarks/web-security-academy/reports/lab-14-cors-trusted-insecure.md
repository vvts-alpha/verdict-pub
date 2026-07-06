# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. LOW — info-disclosure Account API (/accountDetails) discloses active session token(s) in the response body](#finding-1)
    - [2. LOW — burp Strict transport security not enforced (7 URLs)](#finding-2)
    - [3. LOW — burp? Cross-origin resource sharing: all subdomains trusted](#finding-3)
    - [4. INFO — burp TLS certificate](#finding-4)
    - [5. INFO — burp Cacheable HTTPS response](#finding-5)
    - [6. INFO — burp Cross-domain Referer leakage](#finding-6)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [7. HIGH — secret-exposure Suspected cross-origin exfiltration of the administrator's API key via credentialed /accountDetails](#finding-7)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr7s6tyf-7c66w3` |
| Target | https://0a0300aa031f841980ff030c008e006a.web-security-academy.net/ |
| Started | 2026-07-05T12:42:24.735Z |
| Generated | 2026-07-05T14:49:50.513Z |
| Phase | report |
| Screens | 6 mapped · 6 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 6 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `*.web-security-academy.net`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

6 finding(s): 3 low, 3 info

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [LOW] [info-disclosure] Account API (/accountDetails) discloses active session token(s) in the response body

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a0300aa031f841980ff030c008e006a.web-security-academy.net/

The authenticated JSON endpoint GET /accountDetails (consumed by client-side JS on /my-account) returns not only the account's username/email/apikey but also the caller's live session identifier(s) in a "sessions" array (e.g. "sessions":["Rx8gLuGSGQH3tm3l5KIBAuMgyAHn9ueB"], which matches the value of the session cookie). Returning session identifiers in a response body is a defence-in-depth failure: the session token becomes readable by any JavaScript that can read the response, so it materially amplifies the impact of any XSS or CORS/cross-origin read on this endpoint from "leak the API key" to "full session hijack / account takeover". Unauthenticated requests return only 401 "Unauthorized" and do NOT expose the token (negative control).

**Reproduction**

```
1. Log in as wiener:peter. 2. GET /accountDetails with the session cookie. 3. Response JSON contains "apikey" AND "sessions":["<your session cookie value>"]. 4. Control: GET /accountDetails with no/invalid session → 401 "Unauthorized", no token disclosed.
```

**Evidence**

- Evidence `ev-mr7uqyr7-2x` — `artifacts/_/ev-mr7uqyr7-2x/`

Request:

```http
GET /accountDetails HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 401
content-length: 14
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

"Unauthorized"
```

- Evidence `ev-mr7vldgq-3z` — `artifacts/_/ev-mr7vldgq-3z/`

Request:

```http
GET /accountDetails HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
access-control-allow-credentials: true
content-length: 149
content-type: application/json; charset=utf-8
x-frame-options: SAMEORIGIN

{
  "username": "wiener",
  "email": "",
  "apikey": "kfzjm1rZ13ebB3RMb3PQ7yafcJuB8MCa",
  "sessions": [
    "Rx8gLuGSGQH3tm3l5KIBAuMgyAHn9ueB"
  ]
}
```

- Evidence `ev-mr7vmbt7-42` — `artifacts/_/ev-mr7vmbt7-42/`

Request:

```http
GET /accountDetails HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
Cookie: <redacted>
Origin: https://evil-attacker.example
```

Response:

```http
HTTP/1.1 200
access-control-allow-credentials: true
content-length: 149
content-type: application/json; charset=utf-8
x-frame-options: SAMEORIGIN

{
  "username": "wiener",
  "email": "",
  "apikey": "kfzjm1rZ13ebB3RMb3PQ7yafcJuB8MCa",
  "sessions": [
    "Rx8gLuGSGQH3tm3l5KIBAuMgyAHn9ueB"
  ]
}
```

<a id="finding-2"></a>

### 2. [LOW] [burp] Strict transport security not enforced (7 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

(confidence: CERTAIN) [+6 more URL(s): https://0a0300aa031f841980ff030c008e006a.web-security-academy.net/login, https://0a0300aa031f841980ff030c008e006a.web-security-academy.net/admin, https://0a0300aa031f841980ff030c008e006a.web-security-academy.net/my-account, https://0a0300aa031f841980ff030c008e006a.web-security-academy.net/accountDetails, https://0a0300aa031f841980ff030c008e006a.web-security-academy.net/product/stock, …] @ https://0a0300aa031f841980ff030c008e006a.web-security-academy.net/product

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr7wodfw-4y` — `artifacts/_/ev-mr7wodfw-4y/`

Request:

```http
GET /product HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net

GET /product?productId=1 HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 6239

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
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
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a0400d603b1845d80450279019c0001.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='T2J0YWluIGFuZCBzdWJtaXQgdGhlIGFkbWluIHVzZXIncyBBUEkga2V5Lg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2NvcnMvbGFiLWJyZWFraW5nLWh0dHBzLWF0dGFjaw=='>
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
        <div theme="ecommerce">
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account?id=wiener">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="product">
                        <h3>High-End Gift Wrapping</h3>
                        <img src="/resources/images/rating1.png">
                        <div id="price">$75.28</div>
                        <img src="/image/productcatalog/products/53.jpg">
                        <label>Description:</label>
                        <p>We offer a completely unique gift wrapping experience - the gift that just keeps on giving. We can crochet any shape and size to order. We also collect worldwide, we do the hard work so you don't have to.</p>
<p>The gift is no longer the only surprise. Your friends and family will be delighted at our bespoke wrapping, each item 100% original, something that will be talked about for many years to come.</p>
<p>Due to the intricacy of this service, you must allow 3 months for your order to be completed. So. organization is paramount, no leaving shopping until the last minute if you want to take advantage of this fabulously wonderful new way to present your gifts.</p>
<p>Get in touch, tell us what you need to be wrapped, and we can give you an estimate within 24 hours. Let your funky originality extend to all areas of your life. We love every project we work on, so don't delay, give us a call today.</p>
                        <form id="stockCheckForm" action="/product/stock" method="POST">
                            <input required type="hidden" name="productId" value="1">
                            <select name="storeId">
                                <option value="1" >London</option>
                                <option value="2" >Paris</option>
                                <option value="3" >Milan</option>
                            </select>
                            <button type="submit" class="button">Check stock</button>
                        </form>
                        <script>
                            const stockCheckForm = document.getElementById("stockCheckForm");
                            stockCheckForm.addEventListener("submit", function(e) {
                                const data = new FormData(stockCheckForm);
                                window.open('http://stock.0a0300aa031f841980ff030c008e006a.web-security-academy.net/?productId=1&storeId=' + data.get('storeId'), 'stock', 'height=10,width=10,left=10,top=10,menubar=no,toolbar=no,location=no,status=no');
                                e.preventDefault();
                            });
                        </script>
                        <div class="is-linkback">
                            <a href="/">Return to list</a>
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

### 3. [LOW] [burp?] Cross-origin resource sharing: all subdomains trusted

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

⚠ AI re-test could not reproduce (severity kept, manual confirmation advised): Could not reproduce: the reflected Access-Control-Allow-Origin only appears on the authenticated 200 response (session cookie redacted). Without credentials, control and both arbitrary-subdomain positives returned identical 401s with no ACAO header, so the effect is absent — automated re-test failed, finding kept for manual review.

The application implements an HTML5 cross-origin resource sharing (CORS) policy for this request that allows access from arbitrary subdomains.<br><br>The application allowed access from the requested origin <strong>https://lvodpnhz.0a0300aa031f841980ff030c008e006a.web-security-academy.net</strong><br><br>Since the Vary: Origin header was not present in the response, reverse proxies and intermediate servers may cache it. This may enable an attacker to carry out cache poisoning attacks. (confidence: CERTAIN) @ https://0a0300aa031f841980ff030c008e006a.web-security-academy.net/accountDetails

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr7wodgd-51` — `artifacts/_/ev-mr7wodgd-51/`

Request:

```http
GET /accountDetails HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net

GET /accountDetails HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: */*
Origin: https://lvodpnhz.0a0300aa031f841980ff030c008e006a.web-security-academy.net
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Access-Control-Allow-Origin: https://lvodpnhz.0a0300aa031f841980ff030c008e006a.web-security-academy.net
Access-Control-Allow-Credentials: true
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 149

{
  "username": "wiener",
  "email": "",
  "apikey": "kfzjm1rZ13ebB3RMb3PQ7yafcJuB8MCa",
  "sessions": [
    "Rx8gLuGSGQH3tm3l5KIBAuMgyAHn9ueB"
  ]
}
```

- Evidence `ev-mr7wpfay-52` — `artifacts/_/ev-mr7wpfay-52/`

Request:

```http
GET /accountDetails HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Origin: https://evil-unrelated-domain.com
```

Response:

```http
HTTP/1.1 401
connection: close
content-encoding: gzip
content-length: 34
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

"Unauthorized"
```

- Evidence `ev-mr7wpit9-53` — `artifacts/_/ev-mr7wpit9-53/`

Request:

```http
GET /accountDetails HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Origin: https://attacker1random.0a0300aa031f841980ff030c008e006a.web-security-academy.net
```

Response:

```http
HTTP/1.1 401
connection: close
content-encoding: gzip
content-length: 34
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

"Unauthorized"
```

- Evidence `ev-mr7wpmbr-54` — `artifacts/_/ev-mr7wpmbr-54/`

Request:

```http
GET /accountDetails HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Origin: https://attacker2different.0a0300aa031f841980ff030c008e006a.web-security-academy.net
```

Response:

```http
HTTP/1.1 401
connection: close
content-encoding: gzip
content-length: 34
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

"Unauthorized"
```

- Evidence `ev-mr7wq9ke-56` — `artifacts/_/ev-mr7wq9ke-56/`

Request:

```http
OPTIONS /accountDetails HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Origin: https://attacker1random.0a0300aa031f841980ff030c008e006a.web-security-academy.net
Access-Control-Request-Method: GET
```

Response:

```http
HTTP/1.1 401
connection: close
content-encoding: gzip
content-length: 34
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

"Unauthorized"
```

<a id="finding-4"></a>

### 4. [INFO] [burp] TLS certificate

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The server presented a valid, trusted TLS certificate. This issue is purely informational.<br><br>The server presented the following certificates:<br><br><h4>Server certificate</h4><table><tr><td><b>Issued to:</b>&nbsp;&nbsp;</td><td>*.web-security-academy.net, *.2.web-security-academy.net, *.1.web-security-academy.net, *.3.web-security-academy.net, *.2.h1-web-security-academy.net, *.1.h1-web-security-academy.net, *.h1-web-security-academy.net, *.3.h1-web-security-academy.net</td></tr><tr><td><b>Issued by:</b>&nbsp;&nbsp;</td><td>Amazon RSA 2048 M01</td></tr><tr><td><b>Valid from:</b>&nbsp;&nb @ https://0a0300aa031f841980ff030c008e006a.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr7wodfh-4x` — `artifacts/_/ev-mr7wodfh-4x/`

Request:

```http
GET / HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net
```

Response:

```http
HTTP/1.1 0
```

<a id="finding-5"></a>

### 5. [INFO] [burp] Cacheable HTTPS response

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

(confidence: CERTAIN) @ https://0a0300aa031f841980ff030c008e006a.web-security-academy.net/accountDetails

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr7wodg1-4z` — `artifacts/_/ev-mr7wodg1-4z/`

Request:

```http
GET /accountDetails HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net

GET /accountDetails HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Access-Control-Allow-Credentials: true
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 149

{
  "username": "wiener",
  "email": "",
  "apikey": "kfzjm1rZ13ebB3RMb3PQ7yafcJuB8MCa",
  "sessions": [
    "Rx8gLuGSGQH3tm3l5KIBAuMgyAHn9ueB"
  ]
}
```

<a id="finding-6"></a>

### 6. [INFO] [burp] Cross-domain Referer leakage

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The page was loaded from a URL containing a query string:<ul><li>https://0a0300aa031f841980ff030c008e006a.web-security-academy.net/my-account</li></ul>The response contains the following links to other domains:<ul><li>https://exploit-0a0400d603b1845d80450279019c0001.exploit-server.net/</li><li>https://portswigger.net/web-security/dashboard</li></ul> (confidence: CERTAIN) @ https://0a0300aa031f841980ff030c008e006a.web-security-academy.net/my-account

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr7wodg7-50` — `artifacts/_/ev-mr7wodg7-50/`

Request:

```http
GET /my-account HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net

GET /my-account?id=wiener HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Content-Length: 4616

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
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a0400d603b1845d80450279019c0001.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='T2J0YWluIGFuZCBzdWJtaXQgdGhlIGFkbWluIHVzZXIncyBBUEkga2V5Lg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2NvcnMvbGFiLWJyZWFraW5nLWh0dHBzLWF0dGFjaw=='>
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
                            <a href="/my-account?id=wiener">My account</a><p>|</p>
                            <a href="/logout">Log out</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <h1>My Account</h1>
                    <div id=account-content>
                        <p>Your username is: wiener</p>
                        <div>Your API Key is: <span id=apikey></span></div>
                        <script>
                            fetch('/accountDetails', {credentials:'include'})
                                .then(r => r.json())
                                .then(j => document.getElementById('apikey').innerText = j.apikey)
                        </script>
                        <form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
                            <label>Email</label>
                            <input required type="email" name="email" value="">
                            <input required type="hidden" name="csrf" value="A2OgYdCk8ZsrrFT5WviKBHL1yMX7W5yJ">
                            <button class='button' type='submit'> Update email </button>
                        </form>
                    </div>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-7"></a>

### 7. [SUSPECTED] [HIGH] [secret-exposure] Suspected cross-origin exfiltration of the administrator's API key via credentialed /accountDetails

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a0300aa031f841980ff030c008e006a.web-security-academy.net/

**Anomaly (why this is a lead):** Authenticated GET /accountDetails returns the full apikey and session token even when the request carries an arbitrary/foreign Origin (evil host AND Origin: null both accepted, 200 with the key), and the lab provides an exploit server plus a cross-user "steal the admin's API key" goal — the exact CORS origin-reflection exfiltration pattern for stealing the admin's secret. ACAO/ACAC reflection could not be observed (tool hides those headers) and the exploit-server delivery channel is out of scope, so it stays unconfirmed.

The lab objective is to obtain the administrator's API key (a secret). That secret is served by the credentialed JSON endpoint GET /accountDetails (which returns apikey + session token for the current user) and the lab ships an exploit server — the canonical setup for a CORS origin-reflection credential-theft attack: attacker JS on the exploit server does fetch('https://LAB/accountDetails',{credentials:'include'}) and posts the response (admin's apikey + session) to the attacker log when the admin bot visits. Evidence I could gather: authenticated GET /accountDetails returns the full apikey even when the request carries an arbitrary/foreign Origin header — both Origin: https://evil-attacker.example and Origin: null returned 200 with the key. What I could NOT do this run: (1) positively confirm the Access-Control-Allow-Origin / Access-Control-Allow-Credentials reflection, because this harness's http client only surfaces a curated header subset (content-type/set-cookie/location) and never CORS headers; (2) complete the end-to-end exfiltration, because the exploit-server host (exploit-*.exploit-server.net) is OUT OF ASSESSMENT SCOPE, so the attacker page can be neither hosted nor delivered to the admin. This is the standing credential-exposure objective and should be manually finished (see repro).

**Reproduction**

```
1. Log in as wiener:peter. 2. In Burp, GET /accountDetails with header Origin: https://evil-attacker.example and a valid session cookie; check response for Access-Control-Allow-Origin: https://evil-attacker.example + Access-Control-Allow-Credentials: true (reflection = confirmed CORS misconfig). 3. Host on the exploit server an HTML page whose JS does fetch('https://LAB/accountDetails',{credentials:'include'}) then exfiltrates the JSON to /log or a collaborator. 4. Deliver to victim (admin bot). 5. Read the administrator's apikey from the exploit-server access log and submit it via POST /submitSolution (param answer).
```

**Evidence**

- Evidence `ev-mr7vmbt7-42` — `artifacts/_/ev-mr7vmbt7-42/`

Request:

```http
GET /accountDetails HTTP/1.1
Host: 0a0300aa031f841980ff030c008e006a.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
Cookie: <redacted>
Origin: https://evil-attacker.example
```

Response:

```http
HTTP/1.1 200
access-control-allow-credentials: true
content-length: 149
content-type: application/json; charset=utf-8
x-frame-options: SAMEORIGIN

{
  "username": "wiener",
  "email": "",
  "apikey": "kfzjm1rZ13ebB3RMb3PQ7yafcJuB8MCa",
  "sessions": [
    "Rx8gLuGSGQH3tm3l5KIBAuMgyAHn9ueB"
  ]
}
```
