// Export a run's WebUI observer view to a SINGLE self-contained HTML (no server).
// Reuses the built webui bundle verbatim; a shim mocks WebSocket/fetch/img so the
// real React app runs offline off inlined data (state view + cited evidence + screenshots).
//   node scripts/export-static-ui.mjs <assessmentId> [runsDir=runs] [outFile]
import { loadCore, runsDir as configuredRunsDir, sourcePath } from "./verdict-source.mjs";
const { AssessmentStore, buildStateView } = await loadCore();
import { readFileSync, writeFileSync, existsSync, statSync, readdirSync } from "node:fs";
import { join } from "node:path";

const id = process.argv[2];
const runsDir = process.argv[3] || configuredRunsDir;
if (!id) { console.error("usage: export-static-ui.mjs <assessmentId> [runsDir] [outFile]"); process.exit(1); }
const runDir = join(runsDir, id);
const outFile = process.argv[4] || join(runDir, "ui-snapshot.html");

// 1. state view (same path the server uses)
const store = AssessmentStore.open(join(runDir, "state.sqlite"));
const state = store.loadAssessment(id);
store.close();
if (!state) throw new Error("assessment not found: " + id);
const view = buildStateView(state);

// 2. evidence — only IDs the UI can reach (cited in the view), read like the /evidence endpoint
const artRoot = join(runDir, "artifacts");
const evIds = [...new Set((JSON.stringify(view).match(/ev-[a-z0-9-]+/gi) || []))];
const rJson = (d, f) => { try { return JSON.parse(readFileSync(join(d, f), "utf8")); } catch { return null; } };
const rText = (d, f) => { try { return readFileSync(join(d, f), "utf8"); } catch { return null; } };
function evDir(evId) {
  if (!existsSync(artRoot)) return null;
  for (const ent of readdirSync(artRoot, { withFileTypes: true })) {
    if (!ent.isDirectory()) continue;
    const c = join(artRoot, ent.name, evId);
    if (existsSync(c) && statSync(c).isDirectory()) return c;
  }
  return null;
}
const evidence = {};
for (const evId of evIds) {
  const d = evDir(evId); if (!d) continue;
  evidence[evId] = {
    request: rJson(d, "request.json"), response: rJson(d, "response.json"), meta: rJson(d, "meta.json"),
    body: (rText(d, "response.body.txt") || "").slice(0, 20000),
    requestRaw: rText(d, "request.http.txt"),
    responseRaw: (rText(d, "response.http.txt") || "").slice(0, 24000) || null,
  };
}

// 3. screenshots -> data URIs keyed by screenId
const shots = {};
const shotDir = join(artRoot, "screens");
if (existsSync(shotDir)) for (const f of readdirSync(shotDir)) {
  if (f.endsWith(".png")) shots[f.slice(0, -4)] = "data:image/png;base64," + readFileSync(join(shotDir, f)).toString("base64");
}

// 4. bundle + static assets from the built webui
const dist = sourcePath("packages/webui/dist");
const indexHtml = readFileSync(join(dist, "index.html"), "utf8");
const jsName = indexHtml.match(/assets\/(index-[^"']+\.js)/)[1];
const cssName = indexHtml.match(/assets\/(index-[^"']+\.css)/)[1];
const js = readFileSync(join(dist, "assets", jsName), "utf8");
const css = readFileSync(join(dist, "assets", cssName), "utf8");
const dataUri = (p, m) => existsSync(p) ? "data:" + m + ";base64," + readFileSync(p).toString("base64") : null;
const assets = { "verdict-title.png": dataUri(join(dist, "verdict-title.png"), "image/png"), "favicon.png": dataUri(join(dist, "favicon.png"), "image/png") };

const snap = { id, view, me: { role: "viewer", authEnabled: false }, sessions: [], evidence, shots, assets };
const snapJson = JSON.stringify(snap).replace(/</g, "\\u003c"); // never break the <script>

const shim = `(function(){
  var SNAP = window.__VERDICT_SNAP__;
  var _get = URLSearchParams.prototype.get;
  URLSearchParams.prototype.get = function(k){ return k==='id' ? SNAP.id : _get.call(this,k); };
  window.WebSocket = function(url){ var s=this; this.readyState=0; this.close=function(){}; this.send=function(){};
    setTimeout(function(){ s.readyState=1; if(s.onopen)s.onopen({});
      if(String(url).indexOf('/ws?')>=0 && s.onmessage) s.onmessage({data:JSON.stringify({type:'snapshot',view:SNAP.view})}); },0); };
  window.WebSocket.prototype={}; window.WebSocket.OPEN=1;
  function J(o,ok,st){ return Promise.resolve({ok:ok!==false,status:st||200,json:function(){return Promise.resolve(o);},text:function(){return Promise.resolve(typeof o==='string'?o:JSON.stringify(o));}}); }
  window.fetch=function(input,init){ var url=typeof input==='string'?input:(input&&input.url)||''; var m=(init&&init.method)||'GET';
    if(m==='POST') return J({ok:true});
    if(/\\/api\\/me(\\?|$)/.test(url)) return J(SNAP.me);
    var e=url.match(/\\/evidence\\/(ev-[a-z0-9_-]+)/i); if(e) return SNAP.evidence[e[1]]?J(SNAP.evidence[e[1]]):J({error:'not found'},false,404);
    if(/\\/sessions(\\?|$)/.test(url)) return J(SNAP.sessions);
    if(/\\/api\\/assessments\\/[^/]+$/.test(url)) return J(SNAP.view);
    if(/\\/api\\/assessments(\\?|$)/.test(url)) return J([{id:SNAP.id}]);
    return J({},false,404); };
  function fix(v){ var mm=String(v).match(/\\/screens\\/([^/?]+)\\/screenshot/); if(mm&&SNAP.shots[decodeURIComponent(mm[1])]) return SNAP.shots[decodeURIComponent(mm[1])];
    for(var n in SNAP.assets){ if(SNAP.assets[n]&&String(v).indexOf(n)>=0) return SNAP.assets[n]; } return v; }
  var desc=Object.getOwnPropertyDescriptor(HTMLImageElement.prototype,'src');
  Object.defineProperty(HTMLImageElement.prototype,'src',{get:function(){return desc.get.call(this);},set:function(v){desc.set.call(this,fix(v));},configurable:true});
  function scan(el){ if(el.tagName==='IMG'){var s=el.getAttribute('src')||'';var f=fix(s);if(f!==s)el.setAttribute('src',f);} if(el.querySelectorAll)el.querySelectorAll('img').forEach(scan); }
  new MutationObserver(function(ms){ms.forEach(function(mu){mu.addedNodes.forEach(function(n){if(n.nodeType===1)scan(n);});if(mu.type==='attributes'&&mu.target.tagName==='IMG')scan(mu.target);});})
    .observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:['src']});
})();`;

const favicon = assets["favicon.png"] || "";
const html = `<!doctype html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" type="image/png" href="${favicon}">
<title>VERDICT — ${id}</title>
<style>${css}</style>
<script>window.__VERDICT_SNAP__=${snapJson};</script>
<script>${shim}</script>
</head><body><div id="root"></div>
<script type="module">${js}</script>
</body></html>`;

writeFileSync(outFile, html);
const mb = (Buffer.byteLength(html) / 1048576).toFixed(1);
console.log(`wrote ${outFile}  (${mb} MB)  | evidence:${Object.keys(evidence).length}/${evIds.length} cited  screenshots:${Object.keys(shots).length}`);
