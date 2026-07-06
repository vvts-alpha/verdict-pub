# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — burp✓ Input returned in response (reflected)](#finding-1)
    - [2. LOW — burp Strict transport security not enforced (4 URLs)](#finding-2)
    - [3. INFO — burp TLS certificate](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr7i5yaw-1bxf9v` |
| Target | https://0abf007503a1883a8009bc45002e00aa.web-security-academy.net/ |
| Started | 2026-07-05T08:01:47.478Z |
| Generated | 2026-07-05T10:07:58.994Z |
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

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [burp✓] Input returned in response (reflected)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

✅ AI-verified by active re-test: Control (no search param) returned the 9545-byte homepage with the marker absent; two stable positives returned an identical 4152-byte "search results" page, and length arithmetic (4161−(23−14)=4152 vs Burp's marker) proves the search value is reflected exactly once in the h1 sink. (severity raised info→high: confirmed real, not info-only)

The value of the <b>search</b> request parameter is copied into the application's response. (confidence: CERTAIN) @ https://0abf007503a1883a8009bc45002e00aa.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr7mmkwf-42` — `artifacts/_/ev-mr7mmkwf-42/`

Request:

```http
GET / HTTP/1.1
Host: 0abf007503a1883a8009bc45002e00aa.web-security-academy.net

GET /?search=verdict-probeyht9p8i2z0 HTTP/1.1
Host: 0abf007503a1883a8009bc45002e00aa.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 4161

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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSB1c2VyIDxjb2RlPmNhcmxvczwvY29kZT4u' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3JlcXVlc3Qtc211Z2dsaW5nL2FkdmFuY2VkL3JlcXVlc3QtdHVubmVsbGluZy9sYWItcmVxdWVzdC1zbXVnZ2xpbmctaDItYnlwYXNzLWFjY2Vzcy1jb250cm9scy12aWEtcmVxdWVzdC10dW5uZWxsaW5n'>
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
                    <section class=blog-header>
                        <h1>0 search results for 'verdict-probeyht9p8i2z0'</h1>
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

- Evidence `ev-mr7mnaov-43` — `artifacts/_/ev-mr7mnaov-43/`

Request:

```http
GET / HTTP/1.1
Host: 0abf007503a1883a8009bc45002e00aa.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 9545
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSB1c2VyIDxjb2RlPmNhcmxvczwvY29kZT4u' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3JlcXVlc3Qtc211Z2dsaW5nL2FkdmFuY2VkL3JlcXVlc3QtdHVubmVsbGluZy9sYWItcmVxdWVzdC1zbXVnZ2xpbmctaDItYnlwYXNzLWFjY2Vzcy1jb250cm9scy12aWEtcmVxdWVzdC10dW5uZWxsaW5n'>
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
                    <section class="blog-header">
                        <img src="/resources/images/blog.svg">
                    </section>
                    <section class=search>
                        <form action=/ method=GET>
                            <input type=text placeholder='Search the blog...' name=search>
                            <button type=submit class=button>Search</button>
                        </form>
                    </section>
                    <section class="blog-list">
                        <div class="blog-post">
                        <a href="/post?postId=2"><img src="/image/blog/posts/8.jpg"></a>
                        <h2>Grandma's on the net</h2>
                        <p>I love old people and technology. I love the language they use, where they have to put the word 'the' in front of everything. The Facebook, The Twitter...the ones I love the most are the ones who show they have...</p>
                        <a class="button is-small" href="/post?postId=2">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=9"><img src="/image/blog/posts/18.jpg"></a>
                        <h2>Protect Your Smart Home Gadgets From Cyber Attacks</h2>
                        <p>While we've been sleeping in beds that don't cook breakfast and having to switch the overhead lights on ourselves, some of the more privileged in our communities have been under attack. A home invasion of a different kind. The attacks...</p>
                        <a class="button is-small" href="/post?postId=9">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=8"><img src="/image/blog/posts/38.jpg"></a>
                        <h2>Don't Believe Everything You Read</h2>
                        <p>Don't believe everything you read is not only a common expression, it's also a pretty obvious one. Although, it's common and obvious because it's an old saying, an old saying rooted in print journalism and their individual biases. But now,...</p>
                        <a class="button is-small" href="/post?postId=8">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=3"><img src="/image/blog/posts/2.jpg"></a>
                        <h2>21st Century Dreaming</h2>
                        <p>Despite the number of differences in lifestyle between us humans, we can all have dreams with similar themes. I have very vivid dreams which appear like full-length movies. I have noticed changes as society and technology evolves.</p>
                        <a class="button is-small" href="/post?postId=3">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=7"><img src="/image/blog/posts/24.jpg"></a>
                        <h2>The Reverse Bucket List</h2>
                        <p>I have yet to create a bucket list, mainly because I'm not very adventurous and don't want to do anything that will scare the pants off me. With my weekends wasting away with a huge dose of apathy and only...</p>
                        <a class="button is-small" href="/post?postId=7">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=5"><img src="/image/blog/posts/67.jpg"></a>
                        <h2>The Lies People Tell</h2>
                        <p>The best kind of lies are the ones you overhear other people telling. You know they are lying because you're standing in a bar when you hear them on the phone saying, 'I'm in the grocery store.' At times like...</p>
                        <a class="button is-small" href="/post?postId=5">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=6"><img src="/image/blog/posts/19.jpg"></a>
                        <h2>Spider Web Security</h2>
                        <p>Today the President issued a red warning in relation to the breakdown of spider web security. So far all of the main banks and energy suppliers have been hit by this gang of thieves who are now on the run,...</p>
                        <a class="button is-small" href="/post?postId=6">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=1"><img src="/image/blog/posts/39.jpg"></a>
                        <h2>The Art Of Communication</h2>
                        <p>I'm a bit of a Francophile, so when I travel to France I love to speak their language. I'm by no means fluent but I give it my best shot. I usually travel with my partner and son, neither of...</p>
                        <a class="button is-small" href="/post?postId=1">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=4"><img src="/image/blog/posts/17.jpg"></a>
                        <h2>Passwords</h2>
                        <p>There are three types of password users in the world; those who remember them, those who don't, and those who write them down.</p>
                        <a class="button is-small" href="/post?postId=4">View post</a>
                        </div>
                        <div class="blog-post">
                        <a href="/post?postId=10"><img src="/image/blog/posts/48.jpg"></a>
                        <h2>Look No Hands - The Game Plays Itself</h2>
                        <p>I was so fed up with my husband always sitting in front of the television playing his silly games, I did something about it. I came up with an idea that would revolutionize game playing in the future. I wrote...</p>
                        <a class="button is-small" href="/post?postId=10">View post</a>
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

- Evidence `ev-mr7mndzx-44` — `artifacts/_/ev-mr7mndzx-44/`

Request:

```http
GET /?search=vReflZ9q7x2mK4 HTTP/1.1
Host: 0abf007503a1883a8009bc45002e00aa.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 4152
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSB1c2VyIDxjb2RlPmNhcmxvczwvY29kZT4u' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3JlcXVlc3Qtc211Z2dsaW5nL2FkdmFuY2VkL3JlcXVlc3QtdHVubmVsbGluZy9sYWItcmVxdWVzdC1zbXVnZ2xpbmctaDItYnlwYXNzLWFjY2Vzcy1jb250cm9scy12aWEtcmVxdWVzdC10dW5uZWxsaW5n'>
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
                    <section class=blog-header>
                        <h1>0 search results for 'vReflZ9q7x2mK4'</h1>
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

- Evidence `ev-mr7mnhir-45` — `artifacts/_/ev-mr7mnhir-45/`

Request:

```http
GET /?search=vReflZ9q7x2mK4 HTTP/1.1
Host: 0abf007503a1883a8009bc45002e00aa.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 4152
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSB1c2VyIDxjb2RlPmNhcmxvczwvY29kZT4u' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3JlcXVlc3Qtc211Z2dsaW5nL2FkdmFuY2VkL3JlcXVlc3QtdHVubmVsbGluZy9sYWItcmVxdWVzdC1zbXVnZ2xpbmctaDItYnlwYXNzLWFjY2Vzcy1jb250cm9scy12aWEtcmVxdWVzdC10dW5uZWxsaW5n'>
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
                    <section class=blog-header>
                        <h1>0 search results for 'vReflZ9q7x2mK4'</h1>
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

### 2. [LOW] [burp] Strict transport security not enforced (4 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

(confidence: CERTAIN) [+3 more URL(s): https://0abf007503a1883a8009bc45002e00aa.web-security-academy.net/admin, https://0abf007503a1883a8009bc45002e00aa.web-security-academy.net/post, https://0abf007503a1883a8009bc45002e00aa.web-security-academy.net/post/comment] @ https://0abf007503a1883a8009bc45002e00aa.web-security-academy.net/login

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr7mmkwb-41` — `artifacts/_/ev-mr7mmkwb-41/`

Request:

```http
GET /login HTTP/1.1
Host: 0abf007503a1883a8009bc45002e00aa.web-security-academy.net

GET /login HTTP/1.1
Host: 0abf007503a1883a8009bc45002e00aa.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 4093

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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='RGVsZXRlIHRoZSB1c2VyIDxjb2RlPmNhcmxvczwvY29kZT4u' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L3JlcXVlc3Qtc211Z2dsaW5nL2FkdmFuY2VkL3JlcXVlc3QtdHVubmVsbGluZy9sYWItcmVxdWVzdC1zbXVnZ2xpbmctaDItYnlwYXNzLWFjY2Vzcy1jb250cm9scy12aWEtcmVxdWVzdC10dW5uZWxsaW5n'>
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
                            <input required type="hidden" name="csrf" value="aIutL2e3waBbOoQhEYjY7549FQ8W7eJo">
                            <label>Username</label>
                            <input required type=username name="username" autofocus>
                            <label>Password</label>
                            <input required type=password name="password">
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

<a id="finding-3"></a>

### 3. [INFO] [burp] TLS certificate

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The server presented a valid, trusted TLS certificate. This issue is purely informational.<br><br>The server presented the following certificates:<br><br><h4>Server certificate</h4><table><tr><td><b>Issued to:</b>&nbsp;&nbsp;</td><td>*.web-security-academy.net, *.2.web-security-academy.net, *.1.web-security-academy.net, *.3.web-security-academy.net, *.2.h1-web-security-academy.net, *.1.h1-web-security-academy.net, *.h1-web-security-academy.net, *.3.h1-web-security-academy.net</td></tr><tr><td><b>Issued by:</b>&nbsp;&nbsp;</td><td>Amazon RSA 2048 M01</td></tr><tr><td><b>Valid from:</b>&nbsp;&nb @ https://0abf007503a1883a8009bc45002e00aa.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr7mmkw1-40` — `artifacts/_/ev-mr7mmkw1-40/`

Request:

```http
GET / HTTP/1.1
Host: 0abf007503a1883a8009bc45002e00aa.web-security-academy.net
```

Response:

```http
HTTP/1.1 0
```
