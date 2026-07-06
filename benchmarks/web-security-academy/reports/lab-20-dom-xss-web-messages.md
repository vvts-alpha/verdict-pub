# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. LOW — burp Strict transport security not enforced](#finding-1)
    - [2. INFO — burp TLS certificate](#finding-2)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [3. MEDIUM — xss-reflected Suspected client-side (DOM) XSS via web message — "call print()" mystery lab requires exploit-server delivery](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr7y055x-w528ke` |
| Target | https://0a77006f03713321802803c7005f0045.web-security-academy.net/ |
| Started | 2026-07-05T15:25:10.320Z |
| Generated | 2026-07-05T16:16:50.375Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 2 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `*.web-security-academy.net`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

2 finding(s): 1 low, 1 info

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [LOW] [burp] Strict transport security not enforced

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

(confidence: CERTAIN) @ https://0a77006f03713321802803c7005f0045.web-security-academy.net/product

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr7zu7js-1k` — `artifacts/_/ev-mr7zu7js-1k/`

Request:

```http
GET /product HTTP/1.1
Host: 0a77006f03713321802803c7005f0045.web-security-academy.net

GET /product?productId=1 HTTP/1.1
Host: 0a77006f03713321802803c7005f0045.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 4865

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
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a1200860344335580d10228012800fc.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VXNlIHRoZSBleHBsb2l0IHNlcnZlciB0byBkZWxpdmVyIGFuIGF0dGFjayB0aGF0IGNhbGxzIHRoZSA8Y29kZT5wcmludCgpPC9jb2RlPiBmdW5jdGlvbiBpbiB0aGUgdmljdGltJ3MgYnJvd3Nlci4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2RvbS1iYXNlZC9jb250cm9sbGluZy10aGUtd2ViLW1lc3NhZ2Utc291cmNlL2xhYi1kb20teHNzLXVzaW5nLXdlYi1tZXNzYWdlcw=='>
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
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="product">
                        <h3>The Giant Enter Key</h3>
                        <img src="/resources/images/rating2.png">
                        <div id="price">$93.29</div>
                        <img src="/image/productcatalog/products/37.jpg">
                        <label>Description:</label>
                        <p>Made from soft, nylon material and stuffed with cotton, this giant enter key is the ideal office addition. Simply plug it in via a USB port and use it as you're normal enter button! The only difference being is you can smash the living heck out of it whenever you're annoyed. This not only saves your existing keyboard from yet another hammering, but also ensures you won't get billed by your boss for damage to company property.</p>
<p>This is also an ideal gift for that angry co-worker or stressed out secretary that you just fear to walk past. So, whether it's for you or a gift for an agitated friend, this sheer surface size of this button promises you'll never miss when you go to let that anger out.</p>
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

<a id="finding-2"></a>

### 2. [INFO] [burp] TLS certificate

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The server presented a valid, trusted TLS certificate. This issue is purely informational.<br><br>The server presented the following certificates:<br><br><h4>Server certificate</h4><table><tr><td><b>Issued to:</b>&nbsp;&nbsp;</td><td>*.web-security-academy.net, *.2.web-security-academy.net, *.1.web-security-academy.net, *.3.web-security-academy.net, *.2.h1-web-security-academy.net, *.1.h1-web-security-academy.net, *.h1-web-security-academy.net, *.3.h1-web-security-academy.net</td></tr><tr><td><b>Issued by:</b>&nbsp;&nbsp;</td><td>Amazon RSA 2048 M01</td></tr><tr><td><b>Valid from:</b>&nbsp;&nb @ https://0a77006f03713321802803c7005f0045.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr7zu7jf-1j` — `artifacts/_/ev-mr7zu7jf-1j/`

Request:

```http
GET / HTTP/1.1
Host: 0a77006f03713321802803c7005f0045.web-security-academy.net
```

Response:

```http
HTTP/1.1 0
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-3"></a>

### 3. [SUSPECTED] [MEDIUM] [xss-reflected] Suspected client-side (DOM) XSS via web message — "call print()" mystery lab requires exploit-server delivery

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a77006f03713321802803c7005f0045.web-security-academy.net/

**Anomaly (why this is a lead):** This is a "Mystery challenge" lab whose objective is to make the VICTIM's browser call print(), delivered from the exploit server. In-scope testing eliminates every URL/form-driven vector: productId is server-validated (400 on non-numeric), there are no forms, no XHR APIs, no hidden params (probe_params clean), and location.hash/search/storeId DOM injection all failed to execute (probe_dom_xss negative x3). A victim-triggered print() with no lab-side input remaining points to a cross-origin web-message (postMessage) DOM XSS: a message listener on the home page writing event.data into an innerHTML sink. This can only be actuated from the exploit server (exploit-0a12...exploit-server.net), which is OUT OF SCOPE for these tools — so it is a strong lead I cannot mechanically confirm in-scope.

The application is a PortSwigger "Mystery challenge" lab (product-listing home + /product details). The stated objective is to deliver an attack via the exploit server that calls print() in the victim's browser — the canonical DOM-XSS proof-of-concept. All in-scope input vectors were actively ruled out: productId is strictly integer-validated server-side; there are no HTML forms; no XHR/fetch endpoints fire; hidden-parameter fuzzing (probe_params) returns nothing on either page; and DOM execution probes against location.hash (both pages), a storeId query source, and hidden params all came back non-executing. With no lab-side URL/form input capable of producing script execution, a victim-side print() delivered cross-origin is consistent with a web-message (postMessage) DOM XSS: the home page ('/') almost certainly registers a `window.addEventListener('message', e => document.getElementById('ads').innerHTML = e.data)`-style handler that sinks attacker-controlled message data into innerHTML. The specific listener/sink source could not be read directly (response bodies are truncated by the tooling past the lab header), and the vector cannot be exercised from in-scope tools because it requires an attacker page hosted on the out-of-scope exploit server.

**Reproduction**

```
1. Browse the target home page ('/') — it is a static product listing with no forms/params and an (initially empty) DOM container fed by a postMessage listener.
2. Confirm no in-scope vector executes: productId=non-numeric → 400; probe_params clean; probe_dom_xss on '/#{{XSS}}', '/product?productId=1#{{XSS}}', and '/product?productId=1&storeId={{XSS}}' all report no execution.
3. To confirm/exploit (requires the OUT-OF-SCOPE exploit server): open the exploit server, and in the response body host an attacker page such as:
   <iframe src="https://0a77006f03713321802803c7005f0045.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')"></iframe>
   (If the listener validates the message shape, adjust to the expected format, e.g. a JSON payload or a javascript:/URL variant used by the web-message lab family.)
4. Store the exploit and click "Deliver exploit to victim". The victim's browser loads the iframe, receives the cross-origin message, sinks it into innerHTML, and the injected img's onerror fires print() in the victim's session — solving the lab.
NOTE: steps 3–4 could not be executed here because the exploit server host is out of assessment scope (browser_navigate to it returns BLOCKED). This finding is therefore recorded as SUSPECTED and needs manual exploit-server delivery to confirm.
```

**Evidence**

- Evidence `ev-mr7z07cg-s` — `artifacts/_/ev-mr7z07cg-s/`

Request:

```http
GET / HTTP/1.1
Host: 0a77006f03713321802803c7005f0045.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 12034
content-type: text/html; charset=utf-8
set-cookie: <redacted>

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
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0a1200860344335580d10228012800fc.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VXNlIHRoZSBleHBsb2l0IHNlcnZlciB0byBkZWxpdmVyIGFuIGF0dGFjayB0aGF0IGNhbGxzIHRoZSA8Y29kZT5wcmludCgpPC9jb2RlPiBmdW5jdGlvbiBpbiB0aGUgdmljdGltJ3MgYnJvd3Nlci4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2RvbS1iYXNlZC9jb250cm9sbGluZy10aGUtd2ViLW1lc3NhZ2Utc291cmNlL2xhYi1kb20teHNzLXVzaW5nLXdlYi1tZXNzYWdlcw=='>
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
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <!-- Ads to be inserted here -->
                    <div id='ads'>
                    </div>
                    <script>
                        window.addEventListener('message', function(e) {
                            document.getElementById('ads').innerHTML = e.data;
                        })
                    </script>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/37.jpg">
                            <h3>The Giant Enter Key</h3>
                            <img src="/resources/images/rating2.png">
                            $93.29
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/25.jpg">
                            <h3>The Lazy Dog</h3>
                            <img src="/resources/images/rating4.png">
                            $46.28
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating3.png">
                            $42.94
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/30.jpg">
                            <h3>Giant Pillow Thing</h3>
                            <img src="/resources/images/rating2.png">
                            $20.33
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/12.jpg">
                            <h3>Hologram Stand In</h3>
                            <img src="/resources/images/rating1.png">
                            $90.85
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/36.jpg">
                            <h3>Caution Sign</h3>
                            <img src="/resources/images/rating3.png">
                            $98.83
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/22.jpg">
                            <h3>Babbage Web Spray</h3>
                            <img src="/resources/images/rating4.png">
                            $48.83
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating1.png">
                            $34.57
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating2.png">
                            $17.26
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/18.jpg">
                            <h3>Portable Hat</h3>
                            <img src="/resources/images/rating4.png">
                            $86.12
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/6.jpg">
                            <h3>Com-Tool</h3>
                            <img src="/resources/images/rating5.png">
                            $98.07
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/56.jpg">
                            <h3>More Than Just Birdsong</h3>
                            <img src="/resources/images/rating5.png">
                            $27.38
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $72.35
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/45.jpg">
                            <h3>ZZZZZZ Bed - Your New Home Office</h3>
                            <img src="/resources/images/rating4.png">
                            $39.56
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/66.jpg">
                            <h3>Paddling Pool Shoes</h3>
                            <img src="/resources/images/rating1.png">
                            $68.20
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/8.jpg">
                            <h3>Folding Gadgets</h3>
                            <img src="/resources/images/rating2.png">
                            $53.19
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/10.jpg">
                            <h3>Giant Grasshopper</h3>
                            <img src="/resources/images/rating2.png">
                            $20.99
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating2.png">
                            $81.31
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating4.png">
                            $70.03
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/27.jpg">
                            <h3>The Trolley-ON</h3>
                            <img src="/resources/images/rating2.png">
                            $58.36
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
