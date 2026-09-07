// ベンチ採点(read-only・ツール非依存)。runs/<id>/state.sqlite を集計して客観スコアカードを出す。
//   usage: node scripts/bench-score.mjs [id ...]     # id 省略時は runs/ を全走査
//   出力: per-run の phase / 到達画面 / 重大度別 finding / confirmed カテゴリ / 実際に撃った脆弱性クラス / surface-reach
// 「pwn」は intended flag 依存なので自動判定しない(人手列のまま)。客観列だけ機械化する。
import { runsDir } from "./verdict-source.mjs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { readdirSync, existsSync, readFileSync } from "node:fs";

// 人手の intended-vuln ラベル → 「テストできた」とみなすツールのクラストークン群。
//   ツールに probe が無いクラス(ssti/xxe/default-creds/graphql/cve/deserialization 等)は空集合に近く、
//   → tested-classes に出ようがない = 「probe無し型」gap として自動で立つ。
const VULN_NORM = [
  [/x[\s-]?ss/i, ["xss-reflected", "xss-stored", "xss-dom"]],
  [/ssti|template/i, ["ssti"]],
  [/blind\s*sqli|bsqli|sql/i, ["sqli"]],
  [/idor|bola|object/i, ["idor", "idor-write"]],
  [/privesc|privilege/i, ["auth-bypass", "idor", "mass-assignment"]],
  [/ssrf/i, ["ssrf"]],
  [/lfi|path\s*traversal|traversal/i, ["path-traversal"]],
  [/\bxxe\b/i, ["xxe"]],
  [/default\s*creds|weak\s*cred/i, ["default-creds"]],
  [/\bcve\b/i, ["vulnerable-component"]],
  [/cmdi|command/i, ["rce", "command"]],
  [/graphql/i, ["graphql"]],
  [/brute/i, ["default-creds", "rate-limit"]],
  [/deserial/i, ["deserialization"]],
  [/file\s*upload|upload/i, ["upload"]],
  [/info(rmation)?[\s_-]*disclosure|secret/i, ["info-disclosure"]],
];
function intendedClasses(vulnLabel) {
  const out = new Set();
  for (const [re, toks] of VULN_NORM) if (re.test(vulnLabel)) toks.forEach((t) => out.add(t));
  return [...out];
}

const SEV = ["critical","high","medium","low","info"];
const P = (s)=>{try{return JSON.parse(s)}catch{return{}}};
// finding の category はタイトル接頭辞 [category] に入る(専用カラムは無い)。先頭の [..] を拾う。
const catOf = (title)=>{ const m=/^\[([a-z0-9?✓-]+)\]/i.exec(title||""); return m?m[1]:null; };

function score(id){
  const db = new DatabaseSync(join(runsDir, id, "state.sqlite"), { readOnly: true });
  const q=(s)=>db.prepare(s).all();
  const phase = (q("SELECT * FROM assessments").at(0)||{}).phase ?? "?";
  const screens = q("SELECT 1 FROM screens").length;
  const fnd = q("SELECT data FROM findings").map(r=>P(r.data));
  const sev = Object.fromEntries(SEV.map(s=>[s,0]));
  const cats = new Set();
  for(const f of fnd){ if(sev[f.severity]!=null) sev[f.severity]++; const c=catOf(f.title); if(c && c!=="burp" && c!=="burp✓" && c!=="burp?") cats.add(c); }
  // 「実際にテストしたクラス」は coverage トークン [class:found|tested-clean|not-applicable] が権威。
  //   found/tested-clean = 能動的に撃った、not-applicable = 撃ってない。これで substring 誤検出(souRCE 等)を回避。
  const tested = new Set(), na = new Set();
  const evText = q("SELECT payload FROM events").map(r=>(r.payload||"")).join("\n");
  for(const m of evText.matchAll(/([a-z][a-z0-9-]{1,24}):(found|tested-clean|not-applicable)/gi)){
    (m[2]==="not-applicable" ? na : tested).add(m[1].toLowerCase());
  }
  db.close?.();
  return { id, phase, screens, reach: screens>0, sev, cats:[...cats], tested:[...tested], na:[...na], findings: fnd.length };
}

// --map <tsv> で intended-vuln/pwn を読み込み、撃つべきクラス vs 撃ったクラスを突き合わせる。
const mapArg = process.argv.indexOf("--map");
let MAP = null;
if (mapArg >= 0) {
  MAP = new Map();
  const lines = readFileSync(process.argv[mapArg + 1], "utf8").trim().split("\n").slice(1);
  for (const ln of lines) { const [id, benchmark, vuln, pre, pwn] = ln.split("\t"); MAP.set(id, { benchmark, vuln, pre, pwn }); }
}
let ids = process.argv.slice(2).filter((a) => !a.startsWith("--") && a !== (mapArg >= 0 ? process.argv[mapArg + 1] : null));
if (ids.length === 0) ids = MAP ? [...MAP.keys()] : readdirSync(runsDir).filter((d) => existsSync(join(runsDir, d, "state.sqlite")));

const rows = [];
for(const id of ids){ try{ rows.push(score(id)); }catch(e){ rows.push({id, err:String(e).slice(0,60)}); } }

if (MAP) {
  // intended 照合モード: gap を自動分類 — UNTESTED(probe無し/未到達) / SHALLOW(撃ったが pwn=n) / PWNED。
  const h = ["benchmark", "pwn", "reach", "intended-class", "tested?", "GAP"];
  console.log("| " + h.join(" | ") + " |");
  console.log("|" + h.map(() => "---").join("|") + "|");
  const buckets = { UNTESTED: [], SHALLOW: [], PWNED: [], NA: [] };
  for (const r of rows) {
    const m = MAP.get(r.id) || {};
    const intended = intendedClasses(m.vuln || "");
    const testedSet = new Set(r.tested || []);
    const untested = intended.filter((c) => !testedSet.has(c));
    const allTested = intended.length > 0 && untested.length === 0;
    let gap = "?";
    if (m.pwn === "y") { gap = "✅ pwned"; buckets.PWNED.push(m.benchmark); }
    else if (intended.length === 0) { gap = "n/a (no class map)"; buckets.NA.push(m.benchmark); }
    else if (!r.reach) { gap = "🚧 never reached surface"; buckets.UNTESTED.push(m.benchmark); }
    else if (untested.length === intended.length) { gap = `🔴 NO-PROBE: never tested ${untested.join("/")}`; buckets.UNTESTED.push(m.benchmark); }
    else if (allTested) { gap = "🟠 SHALLOW: tested but false-negative"; buckets.SHALLOW.push(m.benchmark); }
    else { gap = `🟡 PARTIAL: missed ${untested.join("/")}`; buckets.SHALLOW.push(m.benchmark); }
    console.log(`| ${m.benchmark || r.id} | ${m.pwn || "?"} | ${r.reach ? "Y" : "-"} | ${intended.join(",") || "-"} | ${[...testedSet].filter((c) => intended.includes(c)).join(",") || "-"} | ${gap} |`);
  }
  const pwn = buckets.PWNED.length, total = rows.length;
  console.log(`\n**${total} mapped runs** · pwn ${pwn}/${total} (${Math.round(100 * pwn / total)}%) · surface-reach ${rows.filter(r=>r.reach).length}/${total}`);
  console.log(`GAP buckets → 🔴 NO-PROBE/unreached: ${buckets.UNTESTED.length} (${buckets.UNTESTED.join(", ")})`);
  console.log(`             🟠 SHALLOW (tested, false-neg): ${buckets.SHALLOW.length} (${buckets.SHALLOW.join(", ")})`);
} else {
  // 客観モード(intended 無し)
  const h = ["run-id","phase","scr","reach","crit","high","med","low","info","confirmed-cats","tested-classes"];
  console.log("| "+h.join(" | ")+" |");
  console.log("|"+h.map(()=>"---").join("|")+"|");
  for(const r of rows){
    if(r.err){ console.log(`| ${r.id} | ERR ${r.err} |`); continue; }
    console.log(`| ${r.id} | ${r.phase} | ${r.screens} | ${r.reach?"Y":"-"} | ${r.sev.critical} | ${r.sev.high} | ${r.sev.medium} | ${r.sev.low} | ${r.sev.info} | ${r.cats.join(",")||"-"} | ${r.tested.join(",")||"-"} |`);
  }
  const ok = rows.filter(r=>!r.err);
  const reached = ok.filter(r=>r.reach).length;
  console.log(`\n**${ok.length} runs** · surface-reach ${reached}/${ok.length} (${Math.round(100*reached/ok.length)}%) · ≥1 finding ${ok.filter(r=>r.findings>0).length}/${ok.length}`);
}
