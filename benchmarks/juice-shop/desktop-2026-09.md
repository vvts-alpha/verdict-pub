# Testing OWASP Juice Shop with VERDICT Desktop — September 2026

I ran VERDICT Desktop against a local OWASP Juice Shop 20.2.0 instance using **OpenCodeGo / `omen-alpha`**, with one administrator account and two customer accounts. VERDICT mapped and tested **154 screens**. The model usage cost for this run was **US$9.92**.

## Results

| Item | Result |
| --- | --- |
| Assessment | `a-mtoiju1k-ajc469` |
| Started | September 6, 2026, 00:04 JST |
| Original report exported | September 7, 2026, 08:54 JST |
| Provider / model | OpenCodeGo / `omen-alpha` |
| Model usage cost | **US$9.92** |
| Mapped / tested screens | **154 / 154** |
| Reviewed engine output | 54 confirmed-category entries, 5 suspected leads, 1 low-signal note |
| Published report | **23 test cases: 18 observed-result cases and 5 follow-up cases** |

I grouped overlapping findings into test cases and documented the evidence and remaining questions for each one. The engine's finding counts and the report's case counts measure different things. The 154-screen figure measures exploration coverage; it does not mean every vulnerability class was tested on every screen. The timestamps include interruptions and time before export.

## Read the report

[Markdown](desktop-2026-09/report.md) · [PDF](desktop-2026-09/report.pdf) · [HTML](desktop-2026-09/report.html)

The report includes the test setup, controls, observed responses, impact, remediation, and evidence references. I removed credentials, account details, and raw private artifacts from the published files.

Three examples from the assessment:

- **Login SQL injection:** a false-condition control returned HTTP 401; two true-condition requests obtained administrator sessions.
- **DOM XSS:** the benign control did not execute script; two browser probes executed the marker in the search route.
- **Address ownership:** a customer account updated another customer's address, and the updated record appeared in the caller's address list.

## Model cost

I paid **US$9.92** for this assessment. My OpenCodeGo dashboard below shows **US$8.51** for `omen-alpha (go)` on September 6. That screenshot is a daily view with **All models / All Keys** selected; it covers a different scope from the assessment total.

![My OpenCodeGo dashboard: omen-alpha (go), US$8.51 on September 6](assets/model-cost-2026-09.png)

## How I reviewed the results

I reviewed a copy of the saved assessment and its existing evidence. This review did not send new requests to Juice Shop or make additional model calls.

The original output contained overlapping findings for login SQLi, DOM XSS, unsigned JWT acceptance, and address updates. I consolidated six duplicate entries, moved the upload-only XSS claim to suspected, and reduced the negative-wallet-deposit finding from high to medium. The reviewed engine output contains 54 confirmed-category entries, five suspected leads, and one low-signal note.

For the published report, I then grouped those entries into 23 test cases. T01–T18 cover the observed results; T19–T23 cover cases requiring further verification or an access-policy decision. Each case states what the recorded tests establish and what still needs checking.

Upload acceptance alone did not demonstrate browser script execution, so that XSS case remains a lead. The wallet tests showed acceptance of negative amounts; they did not establish theft or an external payout. Burp active scanning did not run because both submissions were rejected with HTTP 401, and blind XXE remains unresolved.
