# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [1. MEDIUM — xss-reflected Reflected XSS filter present on search param — all automated bypasses blocked](#finding-1)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr7xxybb-2pt4se` |
| Target | https://0a49007a0396baa1825c4cf900d200e6.h1-web-security-academy.net/ |
| Started | 2026-07-05T15:23:28.087Z |
| Generated | 2026-07-06T00:05:40.846Z |
| Phase | phase2_scan |
| Screens | 17 mapped · 17 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 0 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `*.h1-web-security-academy.net`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

_No confirmed findings._

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-1"></a>

### 1. [SUSPECTED] [MEDIUM] [xss-reflected] Reflected XSS filter present on search param — all automated bypasses blocked

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target https://0a49007a0396baa1825c4cf900d200e6.h1-web-security-academy.net/

**Anomaly (why this is a lead):** The `search` param on `/?search=` is reflected into the HTML response (probe_xss confirmed reflection). A filter is stripping/escaping all 10 automated tag/handler bypass vectors. probe_dom_xss did not execute in browser. Input reflects but no inert context confirmed — manual targeted bypass warranted.

The `search` query parameter value is reflected into the response HTML. A filter blocks all automated XSS bypasses (10 vectors tried: direct tags, attribute breakout, case-mix, svg/iframe/body/details vectors, event handlers). DOM-based XSS was also probed without execution. The reflection context and filter logic warrant manual investigation for a context-aware bypass (e.g. JS string injection, Unicode/encoding tricks, or browser-specific parser quirks).

**Reproduction**

```
1. Navigate to `/?search=<img src=x onerror=alert(1)>` — observe the tag is filtered/escaped.
2. Try context-aware bypasses: if reflection lands in a JS string context, try `\";alert(1)//`; if in an attribute, try `" autofocus onfocus=alert(1)`.
3. Run probe_xss with a custom bypass corpus targeting the specific reflection context.
```

**Evidence**

- Evidence `ev-mr7zkknb-1r` — `artifacts/s-0003/ev-mr7zkknb-1r/`

Request:

```http
GET /?search=VERDICTMARKER1337 HTTP/1.1
Host: 0a49007a0396baa1825c4cf900d200e6.h1-web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 4098
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
                            <br/><div id=mysteryObjective><a id=mysteryReveal data-hidden-objective='UGVyZm9ybSBhbiBYU1MgYXR0YWNrIHRoYXQgY2F1c2VzIEJ1cnAncyBicm93c2VyIChvciBDaHJvbWUpIHRvIGNhbGwgdGhlIDxjb2RlPmFsZXJ0KCk8L2NvZGU+IGZ1bmN0aW9uLg==' data-hidden-link='aHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQvd2ViLXNlY3VyaXR5L2Nyb3NzLXNpdGUtc2NyaXB0aW5nL2NvbnRleHRzL2xhYi1zb21lLXN2Zy1tYXJrdXAtYWxsb3dlZA=='>
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
                        <h1>0 search results for 'VERDICTMARKER1337'</h1>
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
