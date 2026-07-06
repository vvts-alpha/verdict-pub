# VERDICT Security Assessment Report

## Contents

- [Assessment Information](#assessment-information)
- [Scope](#scope)
- [Summary](#summary)
- [Suspected (needs manual verification)](#suspected-needs-manual-verification)
    - [1. CRITICAL — vulnerable-component Outdated Apache httpd 2.4.59 — CVE-2024-38476 / -38474 / -38475 (mod_rewrite/mod_proxy RCE & source disclosure)](#finding-1)

## Assessment Information

| | |
|---|---|
| Assessment ID | `a-mr3638ec-yq4db6` |
| Target | http://target.local:32841/ |
| Started | 2026-07-02T07:12:40.514Z |
| Generated | 2026-07-02T00:00:00.000Z |
| Phase | report |
| Screens | 8 mapped · 8 scanned · 0 remaining |
| Hypotheses | 0 (0 confirmed) |
| Findings | 0 |
| Tooling | VERDICT |

## Scope

- **In-scope hosts**: `target.local:32841`
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

### 1. [SUSPECTED] [CRITICAL] [vulnerable-component] Outdated Apache httpd 2.4.59 — CVE-2024-38476 / -38474 / -38475 (mod_rewrite/mod_proxy RCE & source disclosure)

- Screen: `(cross-screen)`
- Source: validator `claude-pilot`
- Scope basis: authorized target http://target.local:32841/

**Anomaly (why this is a lead):** Apache/2.4.59 (Debian) detected via the Server response header on every page. 2.4.59 predates the 2.4.60 security release (2024-07-01) and is affected by CVE-2024-38476 (CVSS 9.8 — backend/internal-redirect output can invoke a local handler → RCE/SSRF), CVE-2024-38474 (9.8 — mod_rewrite substitution encoding → script execution / source disclosure), CVE-2024-38475 (9.1 — mod_rewrite improper escaping → path traversal / source disclosure) and CVE-2024-38473 (8.1 — mod_proxy encoding → SSRF / request smuggling / auth bypass). Version-based match, not exploited; the mod_rewrite/mod_proxy CVEs are config-dependent.

The Server header advertises Apache/2.4.59 (Debian), released April 2024 and superseded by 2.4.60 (2024-07-01). 2.4.59 is exposed to the 2.4.60 security batch, including exploitable-class issues: CVE-2024-38476 (CVSS 9.8, RCE/SSRF via internal-redirect to a local handler), CVE-2024-38474 (9.8, mod_rewrite substitution-encoding → script execution / source disclosure), CVE-2024-38475 (9.1, mod_rewrite improper escaping → path traversal / source disclosure), CVE-2024-38473 (8.1, mod_proxy encoding → SSRF / request smuggling / potential auth bypass), plus CVE-2024-39884 (source-code disclosure). This is a version-based lead: confirmation depends on the server actually using mod_rewrite/mod_proxy with the relevant rules, which was not verified. Remediation: upgrade to the current 2.4.x (>= 2.4.62, ideally latest).

**Reproduction**

```
1. GET http://target.local:32841/ (or any page). 2. Observe response header: Server: Apache/2.4.59 (Debian). 3. Cross-reference 2.4.59 against the Apache httpd 2.4.60 changelog / CVE list — 2.4.59 is affected by CVE-2024-38476/-38474/-38475/-38473 among others. No active exploit was fired (config-dependent).
```

**Evidence**

- Evidence `ev-mr37f498-5i` — `artifacts/_/ev-mr37f498-5i/`

Request:

```http
GET / HTTP/1.1
Host: target.local:32841
user-agent: verdict-scanner/0.1
x-verdict: assessment
```

Response (truncated):

```http
HTTP/1.1 200
accept-ranges: bytes
connection: Keep-Alive
content-length: 73628
content-type: text/html
date: Thu, 02 Jul 2026 07:49:54 GMT
etag: "11f9c-6553e04418500-gzip"
keep-alive: timeout=5, max=100
last-modified: Sat, 27 Jun 2026 15:38:28 GMT
server: Apache/2.4.59 (Debian)
vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">

<head>
   <meta charset="UTF-8" />
   <meta http-equiv="X-UA-Compatible" content="IE=edge" />
   <meta name="viewport" content="width=device-width, initial-scale=1.0" />
   <title>Welcome!</title>
   <link rel="icon" href="favicon.ico">
   <link href="style.css" rel="stylesheet">
</head>

<body x-data="{ page: 'home', 'darkMode': true, 'stickyMenu': false, 'navigationOpen': false, 'scrollTop': false }"
   x-init="
         darkMode = JSON.parse(localStorage.getItem('darkMode'));
         $watch('darkMode', value => localStorage.setItem('darkMode', JSON.stringify(value)))"
   :class="{'b eh': darkMode === true}">

   <header class="g s r vd ya cj" :class="{ 'hh sm _k dj bl ll' : stickyMenu }"
      @scroll.window="stickyMenu = (window.pageYOffset > 20) ? true : false">
      <div class="bb ze ki xn 2xl:ud-px-0 oo wf yf i">
         <div class="vd to/4 tc wf yf">
            <a href="index.html">
               <img class="om" src="images/logo-light.svg" alt="Logo Light" />
               <img class="xc nm" src="images/logo-dark.svg" alt="Logo Dark" />
            </a>

            <button class="po rc" @click="navigationOpen = !navigationOpen">
               <span class="rc i pf re pd">
                  <span class="du-block h q vd yc">
                     <span class="rc i r s eh um tg te rd eb ml jl dl" :class="{ 'ue el': !navigationOpen }"></span>
                     <span class="rc i r s eh um tg te rd eb ml jl fl" :class="{ 'ue qr': !navigationOpen }"></span>
                     <span class="rc i r s eh um tg te rd eb ml jl gl" :class="{ 'ue hl': !navigationOpen }"></span>
                  </span>
                  <span class="du-block h q vd yc lf">
                     <span class="rc eh um tg ml jl el h na r ve yc" :class="{ 'sd dl': !navigationOpen }"></span>
                     <span class="rc eh um tg ml jl qr h s pa vd rd" :class="{ 'sd rr': !navigationOpen }"></span>
                  </span>
               </span>
            </button>

         </div>
         <div class="vd wo/4 sd qo f ho oo wf yf" :class="{ 'd hh rm sr td ud qg ug jc yh': navigationOpen }">
            <nav>
               <ul class="tc _o sf yo cg ep">
                  <li><a href="index.html" class="xl" :class="{ 'mk': page === 'home' }">Home</a></li>
                  <li><a href="index.html#features" class="xl">Features</a></li>
                  <li><a href="index.html#support" class="xl">Contact Us</a></li>
               </ul>
            </nav>
            <div class="tc wf ig pb no">
               <div class="pc h io pa ra" :class="navigationOpen ? '!-ud-visible' : 'd'">
                  <label class="rc ab i">
                     <input type="checkbox" :value="darkMode" @change="darkMode = !darkMode"
                        class="pf vd yc uk h r za ab" />

                     <svg :class="{ 'wn' : page === 'home', 'xh' : page === 'home' && stickyMenu }" class="th om"
                        width="25" height="25" viewBox="0 0 25 25" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path
                           d="M12.0908 18.6363C10.3549 18.6363 8.69 17.9467 7.46249 16.7192C6.23497 15.4916 5.54537 13.8268 5.54537 12.0908C5.54537 10.3549 6.23497 8.69 7.46249 7.46249C8.69 6.23497 10.3549 5.54537 12.0908 5.54537C13.8268 5.54537 15.4916 6.23497 16.7192 7.46249C17.9467 8.69 18.6363 10.3549 18.6363 12.0908C18.6363 13.8268 17.9467 15.4916 16.7192 16.7192C15.4916 17.9467 13.8268 18.6363 12.0908 18.6363ZM12.0908 16.4545C13.2481 16.4545 14.358 15.9947 15.1764 15.1764C15.9947 14.358 16.4545 13.2481 16.4545 12.0908C16.4545 10.9335 15.9947 9.8236 15.1764 9.00526C14.358 8.18692 13.2481 7.72718 12.0908 7.72718C10.9335 7.72718 9.8236 8.18692 9.00526 9.00526C8.18692 9.8236 7.72718 10.9335 7.72718 12.0908C7.72718 13.2481 8.18692 14.358 9.00526 15.1764C9.8236 15.9947 10.9335 16.4545 12.0908 16.4545ZM10.9999 0.0908203H13.1817V3.36355H10.9999V0.0908203ZM10.9999 20.8181H13.1817V24.0908H10.9999V20.8181ZM2.83446 4.377L4.377 2.83446L6.69082 5.14828L5.14828 6.69082L2.83446 4.37809V4.377ZM17.4908 19.0334L19.0334 17.4908L21.3472 19.8046L19.8046 21.3472L17.4908 19.0334ZM19.8046 2.83337L21.3472 4.377L19.0334 6.69082L17.4908 5.14828L19.8046 2.83446V2.83337ZM5.14828 17.4908L6.69082 19.0334L4.377 21.3472L2.83446 19.8046L5.14828 17.4908ZM24.0908 10.9999V13.1817H20.8181V10.9999H24.0908ZM3.36355 10.9999V13.1817H0.0908203V10.9999H3.36355Z"
                           fill />
                     </svg>

                     <img class="xc nm" src="images/icon-moon.svg" alt="Moon" />
                  </label>
               </div>
               <a href="signin.html" :class="{ 'nk yl' : page === 'home', 'ok' : page === 'home' && stickyMenu }"
                  class="ek pk xl">Sign In</a>
               <a href="signup.html" :class="{ 'hh/[0.15]' : page === 'home', 'sh' : page === 'home' && stickyMenu }"
                  class="lk gh dk rg tc wf xf _l gi hi">Sign Up</a>
            </div>
         </div>
      </div>
   </header>

   <main>

      <section class="gj do ir hj sp jr i pg">

         <div class="xc fn zd/2 2xl:ud-w-187.5 bd 2xl:ud-h-171.5 h q r">
            <img src="images/shape-01.svg" alt="shape" class="xc 2xl:ud-block h t -ud-left-[10%] ua" />
            <img src="images/shape-02.svg" alt="shape" class="xc 2xl:ud-block h u p va" />
            <img src="images/shape-03.svg" alt="shape" class="xc 2xl:ud-block h v w va" />
            <img src="images/shape-04.svg" alt="shape" class="h q r" />
            <img src="images/hero.png" alt="Woman" class="h q r ua" />
         </div>

         <div class="bb ze ki xn 2xl:ud-px-0">
            <div class="tc _o">
               <div class="animate_left jn/2">
                  <h1 class="fk vj zp or kk wm wb">We specialize in UI/UX, Web Development, Digital Marketing.</h1>
                  <p class="fq">
                     Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque fringilla magna mauris. Nulla
                     fermentum viverra sem eu rhoncus consequat varius nisi quis, posuere magna.
                  </p>
                  <div class="tc tf yo zf mb">
                     <a href="index.html#" class="ek jk lk gh gi hi rg ml il vc _d _l">Get Started Now</a>
                     <span class="tc sf">
                        <a href="index.html#" class="inline-block ek xj kk wm"> Call us (0123) 456 – 789 </a>
                        <span class="inline-block">For any question or concern</span>
                     </span>
                  </div>
               </div>
            </div>
         </div>
      </section>


      <section id="features">
         <div class="bb ze ki yn 2xl:ud-px-12.5">
            <div class="tc uf zo xf ap zf bp mq">

               <div class="animate_top kn to/3 tc cg oq">
                  <div class="tc wf xf cf ae cd rg mh">
                     <img src="images/icon-01.svg" alt="Icon" />
                  </div>
                  <div>
                     <h4 class="ek yj go kk wm xb">24/7 Support</h4>
                     <p>Lorem ipsum dolor sit amet conse adipiscing elit.</p>
                  </div>
               </div>

               <div class="animate_top kn to/3 tc cg oq">
                  <div class="tc wf xf cf ae cd rg nh">
                     <img src="images/icon-02.svg" alt="Icon" />
                  </div>
                  <div>
                     <h4 class="ek yj go kk wm xb">Take Ownership</h4>
                     <p>Lorem ipsum dolor sit amet conse adipiscing elit.</p>
                  </div>
               </div>

               <div class="animate_top kn to/3 tc cg oq">
                  <div class="tc wf xf cf ae cd rg oh">
                     <img src="images/icon-03.svg" alt="Icon" />
                  </div>
                  <div>
                     <h4 class="ek yj go kk wm xb">Team Work</h4>
                     <p>Lorem ipsum dolor sit amet conse adipiscing elit.</p>
                  </div>
               </div>
            </div>
         </div>
      </section>


      <section class="ji gp uq 2xl:ud-py-35 pg">
         <div class="bb ze ki xn wq">
            <div class="tc wf gg qq">

               <div class="animate_left xc gn gg jn/2 i">
                  <div>
                     <img src="images/shape-05.svg" alt="Shape" class="h -ud-left-5 x" />
                     <img src="images/about-01.png" alt="About" class="ib" />
                     <img src="images/about-02.png" alt="About" />
                  </div>
                  <div>
                     <img src="images/shape-06.svg" alt="Shape" />
                     <img src="images/about-03.png" alt="About" class="ob gb" />
                     <img src="images/shape-07.svg" alt="Shape" class="bb" />
                  </div>
               </div>

               <div class="animate_right jn/2">
                  <h4 class="ek yj mk gb">Why Choose Us</h4>
                  <h2 class="fk vj zp pr kk wm qb">We Make Our customers happy by giving Best services.</h2>
                  <p class="uo">It is a long established fact that a reader will be distracted by the readable content
                     of a page when looking at its layout. The point of using Lorem Ipsum.</p>
                  <a href="https://www.youtube.com/watch?v=xcJtL7QggTI" data-fslightbox class="vc wf hg mb">
                     <span class="tc wf xf be dd rg i gh ua">
                        <span class="nf h vc yc vd rg gh qk -ud-z-1"></span>
                        <img src="images/icon-play.svg" alt="Play" />
                     </span>
                     <span class="kk">SEE HOW WE WORK</span>
                  </a>
               </div>
            </div>
         </div>
      </section>


      <section class="i pg ji gp uq">

         <span class="rc h s r vd fd/5 fh rm"></span>
         <img src="images/shape-08.svg" alt="Shape Bg" class="h q r" />
         <img src="images/shape-09.svg" alt="Shape" class="of h y z/2" />
         <img src="images/shape-10.svg" alt="Shape" class="h _ aa" />
         <img src="images/shape-11.svg" alt="Shape" class="of h m ba" />

         <div
            x-data="{ sectionTitle: `Meet With Our Creative Dedicated Team`, sectionTitleText: `Lorem ipsum dolor sit amet, consectetur adipiscing elit. In convallis tortor eros. Donec vitae tortor lacus. Phasellus aliquam ante in maximus.`}">
            <div class="animate_top bb ze rj ki xn vq">
               <h2 x-text="sectionTitle" class="fk vj pr kk wm on/5 gq/2 bb _b">
               </h2>
               <p class="bb on/5 wo/5 hq" x-text="sectionTitleText"></p>
            </div>
         </div>

         <div class="bb ze i va ki xn xq jb jo">
            <div class="wc qf pn xo gg cp">

               <div class="animate_top rj">
                  <div class="c i pg z-1">
                     <img class="vd" src="images/team-01.png" alt="Team" />
                     <div class="ef im nl il">
                        <span class="h -ud-left-5 -ud-bottom-21 rc de gd gh if wa"></span>
                        <span class="h s p rc vd hd mh va"></span>
                        <div class="h s p vd ij jj xa">
                           <ul class="tc xf wf gg">
                              <li>
                                 <a href="index.html#">
                                    <svg class="uh vl ml il" width="10" height="18" viewBox="0 0 10 18" fill="none"
                                       xmlns="http://www.w3.org/2000/svg">
                                       <path
                                          d="M6.66634 10.25H8.74968L9.58301 6.91669H6.66634V5.25002C6.66634 4.39169 6.66634 3.58335 8.33301 3.58335H9.58301V0.783354C9.31134 0.74752 8.28551 0.666687 7.20218 0.666687C4.93968 0.666687 3.33301 2.04752 3.33301 4.58335V6.91669H0.833008V10.25H3.33301V17.3334H6.66634V10.25Z"
                                          fill />
                                    </svg>
                                 </a>
                              </li>
                              <li>
                                 <a href="index.html#">
                                    <svg class="uh vl ml il" width="18" height="14" viewBox="0 0 18 14" fill="none"
                                       xmlns="http://www.w3.org/2000/svg">
                                       <path
                                          d="M17.4683 1.71333C16.8321 1.99475 16.1574 2.17956 15.4666 2.26167C16.1947 1.82619 16.7397 1.14085 16.9999 0.333333C16.3166 0.74 15.5674 1.025 14.7866 1.17917C14.2621 0.617982 13.5669 0.245803 12.809 0.120487C12.0512 -0.00482822 11.2732 0.123742 10.596 0.486211C9.91875 0.848679 9.38024 1.42474 9.06418 2.12483C8.74812 2.82492 8.67221 3.60982 8.84825 4.3575C7.46251 4.28805 6.10686 3.92794 4.86933 3.30055C3.63179 2.67317 2.54003 1.79254 1.66492 0.715833C1.35516 1.24788 1.19238 1.85269 1.19326 2.46833C1.19326 3.67667 1.80826 4.74417 2.74326 5.36917C2.18993 5.35175 1.64878 5.20232 1.16492 4.93333V4.97667C1.16509 5.78142 1.44356 6.56135 1.95313 7.18422C2.46269 7.80709 3.17199 8.23456 3.96075 8.39417C3.4471 8.53337 2.90851 8.55388 2.38576 8.45417C2.60814 9.14686 3.04159 9.75267 3.62541 10.1868C4.20924 10.6209 4.9142 10.8615 5.64159 10.875C4.91866 11.4428 4.0909 11.8625 3.20566 12.1101C2.32041 12.3578 1.39503 12.4285 0.482422 12.3183C2.0755 13.3429 3.93 13.8868 5.82409 13.885C12.2349 13.885 15.7408 8.57417 15.7408 3.96833C15.7408 3.81833 15.7366 3.66667 15.7299 3.51833C16.4123 3.02514 17.0013 2.41418 17.4691 1.71417L17.4683 1.71333Z"
                                          fill />
                                    </svg>
                                 </a>
                              </li>
                              <li>
                                 <a href="index.html#">
                                    <svg class="uh vl ml il" width="17" height="16" viewBox="0 0 17 16" fill="none"
                                       xmlns="http://www.w3.org/2000/svg">
                                       <path
                                          d="M3.78353 2.16665C3.78331 2.60867 3.6075 3.03251 3.29478 3.34491C2.98207 3.65732 2.55806 3.8327 2.11603 3.83248C1.674 3.83226 1.25017 3.65645 0.937761 3.34373C0.625357 3.03102 0.449975 2.60701 0.450196 2.16498C0.450417 1.72295 0.626223 1.29912 0.93894 0.986712C1.25166 0.674307 1.67567 0.498925 2.1177 0.499146C2.55972 0.499367 2.98356 0.675173 3.29596 0.98789C3.60837 1.30061 3.78375 1.72462 3.78353 2.16665V2.16665ZM3.83353 5.06665H0.500195V15.5H3.83353V5.06665ZM9.1002 5.06665H5.78353V15.5H9.06686V10.025C9.06686 6.97498 13.0419 6.69165 13.0419 10.025V15.5H16.3335V8.89165C16.3335 3.74998 10.4502 3.94165 9.06686 6.46665L9.1002 5.06665V5.06665Z"
                                          fill />
                                    </svg>
                                 </a>
                              </li>
                           </ul>
                        </div>
                     </div>
                  </div>
                  <h4 class="yj go kk wm ob zb">Olivia Andrium</h4>
                  <p>Product Manager</p>
               </div>

               <div class="animate_top rj">
                  <div class="c i pg z-1">
                     <img class="vd" src="images/team-02.png" alt="Team" />
                     <div class="ef im nl il">
                        <span class="h -ud-left-5 -ud-bottom-21 rc de gd gh if wa"></span>
                        <span class="h s p rc vd hd mh va"></span>
                        <div class="h s p vd ij jj xa">
                           <ul class="tc xf wf gg">
                              <li>
                                 <a href="index.html#">
                                    <svg class="uh vl ml il" width="10" height="18" viewBox="0 0 10 18" fill="none"
                                       xmlns="http://www.w3.org/2000/svg">
                                       <path
                                          d="M6.
```
