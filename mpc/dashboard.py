"""Self-contained HTML dashboard of one MPC run: what each party holds, sent and
received, and what a coalition of colluding parties can (not) reconstruct.

    python -m mpc.dashboard variance 12 7 30 21 9 --t 3 -o dashboard.html
    python -m mpc.dashboard dot 1 2 3 --b 4 5 6 --t 2 -o dashboard.html
"""

from __future__ import annotations

import argparse
import json

from .apps import secure_average, secure_dot_product, secure_variance
from .runner import CircuitRun


def dashboard_data(run: CircuitRun, title: str, result_text: str) -> dict:
    """Everything the page needs, as JSON-safe data (big integers as strings)."""
    parties = []
    for i in range(run.n):
        log = [
            {"dir": m["dir"], "peer": m["peer"], "msg": json.loads(m["raw"])}
            for m in run.wire_logs[i]
        ]
        parties.append({"index": i, "wireShares": {str(w): str(y) for w, y in run.wire_shares[i].items()}, "log": log})
    return {
        "title": title,
        "p": str(2**127 - 1),
        "n": run.n,
        "t": run.t,
        "gates": [{"op": g.op, "args": list(g.args)} for g in run.circuit.gates],
        "outputs": run.circuit.outputs,
        "inputs": [[str(v) for v in row] for row in run.inputs],
        "result": str(run.result[0]),
        "resultText": result_text,
        "messages": run.message_count,
        "parties": parties,
    }


def render_dashboard(run: CircuitRun, title: str, result_text: str) -> str:
    blob = json.dumps(dashboard_data(run, title, result_text)).replace("</", "<\\/")
    return TEMPLATE.replace("__TITLE__", title).replace("__DATA__", blob)


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate an HTML dashboard for a secure computation")
    ap.add_argument("kind", choices=["average", "dot", "variance"])
    ap.add_argument("values", nargs="+", type=int)
    ap.add_argument("--b", nargs="+", type=int, help="second vector for the dot product")
    ap.add_argument("--t", type=int, default=2)
    ap.add_argument("-o", "--output", default="dashboard.html")
    a = ap.parse_args()
    if a.kind == "average":
        val, run = secure_average(a.values, a.t)
        title, text = "Secure average", f"sum revealed, then ÷ n: {val} = {float(val):.4g}"
    elif a.kind == "variance":
        val, run = secure_variance(a.values, a.t)
        title, text = "Secure variance", f"n²·Var = {run.result[0]}, so Var = {val} = {float(val):.4g}"
    else:
        if not a.b:
            ap.error("dot needs --b")
        val, run = secure_dot_product(a.values, a.b, a.t)
        title, text = "Secure dot product", f"Σ aᵢ·bᵢ = {val}"
    with open(a.output, "w", encoding="utf-8") as f:
        f.write(render_dashboard(run, title, text))
    print(f"wrote {a.output}: {run.n} parties, t={run.t}, {run.message_count} messages")


TEMPLATE = r'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>__TITLE__ · MPC dashboard</title>
<style>
:root{--bg:#f6f4ee;--fg:#14202f;--mut:#566170;--card:#fff;--line:#d9d5c8;--acc:#1b6f68;--bad:#a32d2d;--chip:#e9e6da}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0f1b2d;--fg:#f2efe6;--mut:#a9b4c2;--card:#17263b;--line:#2c3d55;--acc:#5ec4b8;--bad:#ff8f8f;--chip:#223552}}
:root[data-theme="dark"]{--bg:#0f1b2d;--fg:#f2efe6;--mut:#a9b4c2;--card:#17263b;--line:#2c3d55;--acc:#5ec4b8;--bad:#ff8f8f;--chip:#223552}
:root{box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}
html{scroll-padding-top:env(safe-area-inset-top,0px)}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:28px;margin:0 0 4px}h2{font-size:19px;margin:0 0 10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:16px 0}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}.chip{background:var(--chip);border-radius:999px;padding:3px 12px;font-size:14px}
.mut{color:var(--mut)}.ok{color:var(--acc);font-weight:600}.bad{color:var(--bad);font-weight:600}
.tabs{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
button{font:inherit;color:var(--fg);background:var(--chip);border:1px solid var(--line);border-radius:8px;padding:6px 14px;cursor:pointer}
button.on{background:var(--acc);color:var(--bg);border-color:var(--acc)}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
label{margin-right:14px;white-space:nowrap}
</style></head><body><main>
<h1>__TITLE__</h1>
<p class="mut">What each party holds, sends and receives in a real run over TCP, and what colluding parties can learn.</p>
<div class="card"><div id="summary"></div><div class="chips" id="chips"></div></div>
<div class="card"><h2>Circuit</h2><div class="scroll"><table id="circuit"></table></div></div>
<div class="card"><h2>Rounds</h2><div class="scroll"><table id="rounds"></table></div></div>
<div class="card"><h2>One party’s view</h2><div class="tabs" id="tabs"></div><div id="party"></div></div>
<div class="card"><h2>Collusion explorer</h2>
<p class="mut">Pick parties that pool everything they received. A private input can be recovered only when the coalition holds at least t of its shares.</p>
<div id="boxes"></div><div class="scroll"><table id="coal"></table></div><p class="mut" id="coalnote"></p></div>
<script id="data" type="application/json">__DATA__</script>
<script>
const D = JSON.parse(document.getElementById("data").textContent);
const P = BigInt(D.p);
// BEGIN MATH
const md = (a) => ((a % P) + P) % P;
function pw(b, e) { let r = 1n; b = md(b); while (e > 0n) { if (e & 1n) r = md(r * b); b = md(b * b); e >>= 1n; } return r; }
function lagrange0(pts) {
  let s = 0n;
  for (let i = 0; i < pts.length; i++) {
    let num = 1n, den = 1n;
    for (let j = 0; j < pts.length; j++) if (i !== j) { num = md(num * -pts[j][0]); den = md(den * (pts[i][0] - pts[j][0])); }
    s = md(s + pts[i][1] * num * pw(den, P - 2n));
  }
  return s;
}
// END MATH
const $ = (id) => document.getElementById(id);
const short = (s) => (s.length > 16 ? s.slice(0, 8) + "…" + s.slice(-5) : s);
const cell = (s) => '<td><code title="' + s + '">' + short(s) + "</code></td>";
const gdesc = (w) => { const g = D.gates[w], a = g.args; return { input: "input of P" + a[0] + " (slot " + a[1] + ")", const: "constant " + a[0],
  add: "w" + a[0] + " + w" + a[1], sub: "w" + a[0] + " − w" + a[1], cmul: a[1] + " × w" + a[0], mul: "w" + a[0] + " × w" + a[1] + " (interactive)" }[g.op]; };
const round = (m) => (m.type === "in" ? "Input sharing" : m.type === "mul" ? "Multiplication w" + m.gate : "Output opening");

$("summary").innerHTML = "<b>Revealed result:</b> <span class='ok'>" + D.resultText + "</span>";
$("chips").innerHTML = [D.n + " parties", "threshold t = " + D.t, D.messages + " messages", "prime field of 127 bits"].map((c) => "<span class='chip'>" + c + "</span>").join("");
$("circuit").innerHTML = "<tr><th>Wire</th><th>Gate</th></tr>" + D.gates.map((g, w) => "<tr><td>w" + w + (D.outputs.includes(w) ? " ★" : "") + "</td><td>" + gdesc(w) + "</td></tr>").join("");
const rc = {};
D.parties.forEach((p) => p.log.filter((e) => e.dir === "out").forEach((e) => { const r = round(e.msg); rc[r] = (rc[r] || 0) + 1; }));
$("rounds").innerHTML = "<tr><th>Round</th><th>Messages</th></tr>" + Object.entries(rc).map(([r, c]) => "<tr><td>" + r + "</td><td>" + c + "</td></tr>").join("");

let cur = 0, dir = "in";
function showParty() {
  const p = D.parties[cur];
  $("tabs").innerHTML = D.parties.map((q) => "<button class='" + (q.index === cur ? "on" : "") + "' onclick='cur=" + q.index + ";showParty()'>P" + q.index + "</button>").join("");
  const mine = D.inputs[cur].map((v) => "<code>" + v + "</code>").join(", ");
  const rows = D.gates.map((g, w) => "<tr><td>w" + w + "</td><td>" + gdesc(w) + "</td>" + cell(p.wireShares[w]) + "</tr>").join("");
  const msgs = p.log.filter((e) => e.dir === dir).map((e) => "<tr><td>" + round(e.msg) + "</td><td>" + (dir === "in" ? "from" : "to") + " P" + e.peer + "</td><td>" + e.msg.type + "</td>" + cell(e.msg.y) + "</tr>").join("");
  const solo = analyse([cur]).filter((r) => r.ok).length;
  $("party").innerHTML = "<p>P" + cur + " privately holds: " + mine + ". Nobody else is ever sent this value.</p>" +
    "<p>From its own view, P" + cur + " can recover <b class='" + (solo ? "bad" : "ok") + "'>" + solo + "</b> of the other parties’ inputs (needs " + D.t + " shares of one input; it holds 1).</p>" +
    "<h2>Shares held (one point per wire)</h2><div class='scroll'><table><tr><th>Wire</th><th>Gate</th><th>Share</th></tr>" + rows + "</table></div>" +
    "<h2>Messages</h2><div class='tabs'><button class='" + (dir === "in" ? "on" : "") + "' onclick='dir=\"in\";showParty()'>Received</button><button class='" + (dir === "out" ? "on" : "") + "' onclick='dir=\"out\";showParty()'>Sent</button></div>" +
    "<div class='scroll'><table><tr><th>Round</th><th>Peer</th><th>Type</th><th>Share value</th></tr>" + msgs + "</table></div>";
}

function analyse(coal) {
  const out = [];
  D.gates.forEach((g, w) => {
    if (g.op !== "input" || coal.includes(g.args[0])) return;
    const pts = [];
    coal.forEach((c) => { const m = D.parties[c].log.find((e) => e.dir === "in" && e.msg.type === "in" && e.msg.gate === w); if (m) pts.push([BigInt(m.msg.x), BigInt(m.msg.y)]); });
    const ok = pts.length >= D.t;
    out.push({ w, owner: g.args[0], have: pts.length, ok, val: ok ? lagrange0(pts.slice(0, D.t)).toString() : null, truth: D.inputs[g.args[0]][g.args[1]] });
  });
  return out;
}
const sel = new Set([0]);
$("boxes").innerHTML = D.parties.map((p) => "<label><input type='checkbox' " + (p.index === 0 ? "checked" : "") + " onchange='tog(" + p.index + ",this.checked)'> P" + p.index + "</label>").join("");
function tog(i, on) { on ? sel.add(i) : sel.delete(i); showCoal(); }
function showCoal() {
  const coal = [...sel].sort((a, b) => a - b), res = analyse(coal);
  $("coal").innerHTML = "<tr><th>Input</th><th>Owner</th><th>Shares held</th><th>Outcome</th></tr>" + res.map((r) =>
    "<tr><td>w" + r.w + "</td><td>P" + r.owner + "</td><td>" + r.have + " of " + D.t + "</td><td>" +
    (r.ok ? "<span class='bad'>recovered " + r.val + (r.val === r.truth ? " (matches the real input)" : "") + "</span>" : "<span class='ok'>nothing learned: every value is equally likely</span>") + "</td></tr>").join("");
  $("coalnote").textContent = coal.length < D.t ? "Coalition of " + coal.length + " < t = " + D.t + ": privacy holds." : "Coalition of " + coal.length + " ≥ t = " + D.t + ": the threshold is exceeded, so recovery is expected. This view checks input shares only.";
}
showParty(); showCoal();
</script></main></body></html>
'''


if __name__ == "__main__":
    main()
