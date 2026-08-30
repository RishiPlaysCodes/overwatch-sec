#!/usr/bin/env python3
"""
reporting/graph_html.py — interactive attack-graph (standalone HTML).

Renders the attack-path graph as an interactive, self-contained page using
Cytoscape.js (loaded from a CDN). Features:
  - click a node to drill down (details panel: kind, severity, CVE/CWE, MITRE)
  - filter by minimum severity
  - color-coded by node kind / severity; crown-jewel objectives highlighted

The graph data (nodes/edges) is embedded as JSON, so the file works offline for
the data; only the Cytoscape library needs network the first time it's opened.
"""

from __future__ import annotations

import html
import json

from attack_paths import graph as _graph

_SEV_COLOR = {"critical": "#8e44ad", "high": "#e74c3c", "medium": "#e67e22",
              "low": "#3498db", "info": "#7f8c8d"}
_KIND_COLOR = {"entry": "#16a085", "asset": "#2c3e50", "objective": "#8e44ad"}


def _graph_data(findings, target: str) -> dict:
    g = _graph.build(findings, target)
    # index findings for drill-down details
    fmap = {}
    for i, f in enumerate(findings):
        fmap[f"finding:{i}:{f.id}"] = f

    nodes, edges = [], []
    for nid, node in g.nodes.items():
        data = {"id": nid, "label": node.label, "kind": node.kind}
        if node.kind == "finding":
            f = fmap.get(nid)
            if f:
                data.update({
                    "severity": f.severity, "sev_rank": {"critical": 0, "high": 1, "medium": 2,
                                                          "low": 3, "info": 4}.get(f.severity, 4),
                    "cwe": f.cwe, "owasp": f.owasp, "cve": f.cve, "kev": f.kev,
                    "mitre": ", ".join(f.mitre), "confidence": f.confidence,
                    "validation": f.validation, "detail": (f.attack or f.description or "")[:280],
                    "fix": (f.patch or "")[:280],
                })
        elif node.kind == "objective":
            data["criticality"] = node.data.get("criticality", 0)
        nodes.append({"data": data})
    for src, dst, rel in g.edges:
        edges.append({"data": {"source": src, "target": dst, "rel": rel}})
    return {"nodes": nodes, "edges": edges}


def write_graph_html(assessment, path: str) -> str:
    data = _graph_data(assessment.findings, assessment.target)
    payload = json.dumps(data)
    top_paths = json.dumps([{"chain": p["chain"], "risk": p["risk_score"],
                             "objective": p.get("objective", "")}
                            for p in assessment.attack_paths[:15]])
    title = html.escape(assessment.target)

    doc = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>overwatch attack graph — __TITLE__</title>
<style>
 html,body{margin:0;height:100%;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0f1419;color:#e6e6e6}
 header{padding:12px 18px;background:#111a24;border-bottom:2px solid #1f2d3a;display:flex;gap:16px;align-items:center;flex-wrap:wrap}
 header b{color:#7fd1ff}
 #wrap{display:flex;height:calc(100% - 52px)}
 #cy{flex:1;height:100%}
 #side{width:340px;background:#131c26;padding:16px;overflow:auto;border-left:1px solid #22303c;font-size:13px}
 select,button{background:#1c2733;color:#e6e6e6;border:1px solid #2c3e50;border-radius:6px;padding:6px 10px}
 .k{color:#9ab} .v{color:#e6e6e6}
 .pill{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:11px}
 h3{margin:6px 0;border-bottom:1px solid #26333f;padding-bottom:4px}
 .path{font-size:12px;color:#ffd27f;margin:6px 0;border-left:3px solid #8e44ad;padding-left:8px}
 .muted{color:#789}
</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
</head><body>
<header>
 <span>🛡️ <b>overwatch</b> attack graph — __TITLE__</span>
 <label class="muted">min severity
  <select id="sev">
   <option value="4">info+</option><option value="3">low+</option>
   <option value="2">medium+</option><option value="1">high+</option>
   <option value="0">critical</option>
  </select></label>
 <button id="fit">fit</button>
 <span class="muted">click a node for details • drag to pan • scroll to zoom</span>
</header>
<div id="wrap">
 <div id="cy"></div>
 <div id="side">
   <h3>Details</h3>
   <div id="details" class="muted">Click a node…</div>
   <h3>Top attack paths</h3>
   <div id="paths"></div>
 </div>
</div>
<script>
const GRAPH = __PAYLOAD__;
const PATHS = __PATHS__;
const SEVCOLOR = __SEVCOLOR__;
const KINDCOLOR = __KINDCOLOR__;

function nodeColor(ele){
  const k = ele.data('kind');
  if(k === 'finding'){ return SEVCOLOR[ele.data('severity')] || '#7f8c8d'; }
  return KINDCOLOR[k] || '#34495e';
}
function nodeShape(ele){
  const k = ele.data('kind');
  return k==='objective' ? 'diamond' : (k==='entry' ? 'round-rectangle' : (k==='asset'?'rectangle':'ellipse'));
}

const cy = cytoscape({
  container: document.getElementById('cy'),
  elements: GRAPH,
  style: [
    {selector:'node', style:{
      'background-color': nodeColor, 'shape': nodeShape,
      'label':'data(label)','color':'#e6e6e6','font-size':'10px',
      'text-valign':'center','text-halign':'center','text-wrap':'wrap','text-max-width':'90px',
      'width': e=> e.data('kind')==='finding'?26:34,'height': e=> e.data('kind')==='finding'?26:34
    }},
    {selector:'node[kind="objective"]', style:{'border-width':2,'border-color':'#fff'}},
    {selector:'node[?kev]', style:{'border-width':3,'border-color':'#fff'}},
    {selector:'edge', style:{
      'width':1.5,'line-color':'#3d5468','target-arrow-color':'#3d5468',
      'target-arrow-shape':'triangle','curve-style':'bezier',
      'label':'data(rel)','font-size':'8px','color':'#8aa','text-rotation':'autorotate'
    }},
    {selector:'.hidden', style:{'display':'none'}},
    {selector:'.hl', style:{'line-color':'#f1c40f','target-arrow-color':'#f1c40f','width':3}}
  ],
  layout:{name:'breadthfirst', directed:true, spacingFactor:1.25, padding:20}
});

function esc(s){return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

cy.on('tap','node', e=>{
  const d = e.target.data();
  let h = `<b>${esc(d.label)}</b><br><span class="muted">${esc(d.kind)}</span><br><br>`;
  if(d.kind==='finding'){
    const c = SEVCOLOR[d.severity]||'#777';
    h += `<span class="pill" style="background:${c}">${esc((d.severity||'').toUpperCase())}</span>`;
    if(d.kev) h+=' <span class="pill" style="background:#8e44ad">KEV</span>';
    h += `<br><br><span class="k">confidence:</span> <span class="v">${esc(d.confidence)}</span>`;
    h += `<br><span class="k">validation:</span> <span class="v">${esc(d.validation)}</span>`;
    h += `<br><span class="k">CWE:</span> ${esc(d.cwe)} &nbsp; <span class="k">OWASP:</span> ${esc(d.owasp)}`;
    if(d.cve) h += `<br><span class="k">CVE:</span> ${esc(d.cve)}`;
    if(d.mitre) h += `<br><span class="k">ATT&CK:</span> ${esc(d.mitre)}`;
    if(d.detail) h += `<br><br><span class="k">attack:</span> ${esc(d.detail)}`;
    if(d.fix) h += `<br><br><span class="k">fix:</span> ${esc(d.fix)}`;
  } else if(d.kind==='objective'){
    h += `🎯 crown-jewel objective<br>criticality: ${esc(d.criticality)}`;
  } else if(d.kind==='asset'){ h += 'asset / host'; }
  else { h += 'entry point (Internet)'; }
  document.getElementById('details').innerHTML = h;
  cy.edges().removeClass('hl');
  e.target.connectedEdges().addClass('hl');
});

document.getElementById('sev').addEventListener('change', ev=>{
  const max = parseInt(ev.target.value,10);
  cy.nodes('[kind="finding"]').forEach(n=>{
    const r = n.data('sev_rank'); (r>max)? n.addClass('hidden'): n.removeClass('hidden');
  });
});
document.getElementById('fit').addEventListener('click',()=>cy.fit());

const pe = document.getElementById('paths');
pe.innerHTML = PATHS.length? PATHS.map((p,i)=>`<div class="path"><b>#${i+1}</b> risk ${p.risk}${p.objective?(' → 🎯 '+esc(p.objective)):''}<br>${esc(p.chain)}</div>`).join('') : '<span class="muted">none</span>';
</script>
</body></html>"""
    doc = (doc.replace("__TITLE__", title)
              .replace("__PAYLOAD__", payload)
              .replace("__PATHS__", top_paths)
              .replace("__SEVCOLOR__", json.dumps(_SEV_COLOR))
              .replace("__KINDCOLOR__", json.dumps(_KIND_COLOR)))
    with open(path, "w") as fh:
        fh.write(doc)
    return path
