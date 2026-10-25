"""Task 5: static HTML dashboard -- no extra deps, single file output.

Reads results/*.json + *.png + *.csv and writes results/dashboard.html
with embedded (base64) plots so it opens offline.

Usage: python src/dashboard.py [--out results/dashboard.html]
"""
from __future__ import annotations

import argparse
import base64
import html
import json
import logging
from pathlib import Path

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("argus.dashboard")

BASE = Path(__file__).resolve().parent.parent
RESULTS = BASE / "results"


def img_b64(p: Path) -> str:
    if not p.exists():
        return ""
    return base64.b64encode(p.read_bytes()).decode()


def img_tag(p: Path, title: str) -> str:
    b = img_b64(p)
    if not b:
        return f"<p><i>missing {html.escape(p.name)}</i></p>"
    return (f"<figure><figcaption>{html.escape(title)}</figcaption>"
            f"<img src='data:image/png;base64,{b}' style='max-width:100%'/></figure>")


def load_json(p: Path) -> dict:
    return json.loads(p.read_text()) if p.exists() else {}


def git_log(n: int = 10) -> str:
    """Recent commits for the dashboard changelog (best-effort)."""
    import subprocess
    try:
        out = subprocess.run(
            ["git", "log", f"-{n}", "--format=%h %ad %s", "--date=short"],
            capture_output=True, text=True, timeout=15,
            cwd=BASE_DIR,
        )
        lines = [ln for ln in out.stdout.splitlines() if ln.strip()]
        if not lines:
            return "<p><i>git history unavailable</i></p>"
        items = "".join(f"<li><code>{html.escape(ln)}</code></li>\n" for ln in lines)
        return f"<ol>\n{items}</ol>"
    except Exception:
        return "<p><i>git history unavailable</i></p>"


def unified_table(uni: dict) -> str:
    rows = uni.get("protocols", [])
    if not rows:
        return "<p><i>unified_report.json missing -- run src/validate_unified.py</i></p>"
    trs = "".join(
        f"<tr><td>{html.escape(r['protocol'])}</td><td>{r['n_test']}</td>"
        f"<td>{r['f1']:.4f}</td><td>{r['roc_auc']:.4f}</td></tr>\n" for r in rows)
    verdict = html.escape(uni.get("verdict", ""))
    return (f"<table border=1 cellpadding=4><tr><th>protocol</th><th>n</th>"
            f"<th>F1</th><th>AUC</th></tr>\n{trs}</table>"
            f"<p>{verdict} See unified_report.md.</p>")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(RESULTS / "dashboard.html"))
    args = ap.parse_args()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    gen = load_json(RESULTS / "generalization_report.json")
    real = load_json(RESULTS / "real_validation_report.json")
    uni = load_json(RESULTS / "unified_report.json")
    std = gen.get("standard_group_split", {})
    m50 = std.get("at_0.5", {})
    best = gen.get("best_f1", {})
    loso = gen.get("loso", [])
    benign = gen.get("benign_fpr_standard_test", {})
    r = real.get("real_cic_malmem", {})

    fi_rows = ""
    fi_path = RESULTS / "feature_importance.csv"
    if fi_path.exists():
        fi = pd.read_csv(fi_path).head(15)
        for _, row in fi.iterrows():
            fi_rows += (f"<tr><td>{html.escape(str(row['feature']))}</td>"
                        f"<td>{float(row['importance']):.4f}</td></tr>\n")

    loso_rows = ""
    for e in loso:
        m = e.get("at_0.5", {})
        b = e.get("best_thresh_f1", {})
        loso_rows += (
            f"<tr><td>{html.escape(e.get('held_out', ''))}</td>"
            f"<td>{e.get('auc', float('nan')):.4f}</td>"
            f"<td>{m.get('f1', 0):.4f}</td><td>{m.get('recall', 0):.4f}</td>"
            f"<td>{b.get('f1', 0):.4f} @ {b.get('threshold', 0):.2f}</td></tr>\n")

    benign_rows = ""
    for k, v in benign.items():
        benign_rows += (f"<tr><td>{html.escape(k)}</td><td>{v.get('n', '')}</td>"
                        f"<td>{v.get('fpr@0.5', 0):.4f}</td></tr>\n")

    body = f"""<h1>ARGUS dashboard</h1>
<p>Static build. Sources: generalization_report.json, real_validation_report.json, feature_importance.csv</p>
<h2>Standard split (seen scenarios)</h2>
<table border=1 cellpadding=4>
<tr><th>AUC</th><th>P@0.5</th><th>R@0.5</th><th>F1@0.5</th><th>best thr (F1)</th></tr>
<tr><td>{std.get('auc', float('nan')):.4f}</td><td>{m50.get('precision', float('nan')):.4f}</td>
<td>{m50.get('recall', float('nan')):.4f}</td><td>{m50.get('f1', float('nan')):.4f}</td>
<td>{best.get('threshold', float('nan'))} (F1 {best.get('f1', float('nan')):.4f})</td></tr></table>
<h2>Leave-one-attack-out</h2>
<table border=1 cellpadding=4>
<tr><th>held-out</th><th>AUC</th><th>F1@0.5</th><th>R@0.5</th><th>best tuned</th></tr>
{loso_rows}</table>
<p><b>Reading:</b> @0.5 every unseen attack is missed. Threshold tuning rescues
persistence (AUC 1.0, miscalibrated) and partly powershell, but ransomware ranks
inverted (AUC 0.26) -- no threshold fixes disjoint indicators.</p>
<h2>Benign FPR (standard test)</h2>
<table border=1 cellpadding=4><tr><th>slice</th><th>n</th><th>FPR@0.5</th></tr>
{benign_rows}</table>
<h2>Real data (CIC-MalMem-2022, {r.get('n_rows', '?')} rows)</h2>
<table border=1 cellpadding=4>
<tr><th>P</th><th>R</th><th>F1</th><th>AUC</th><th>TN/FP/FN/TP</th></tr>
<tr><td>{r.get('precision', float('nan')):.4f}</td><td>{r.get('recall', float('nan')):.4f}</td>
<td>{r.get('f1', float('nan')):.4f}</td><td>{r.get('roc_auc', float('nan')):.4f}</td>
<td>{r.get('tn', '?')}/{r.get('fp', '?')}/{r.get('fn', '?')}/{r.get('tp', '?')}</td></tr></table>
<p>Feature spaces are disjoint (memory counters vs window behaviors, overlap
{real.get('n_overlap', '?')}); side-by-side only, no transfer. See real_validation_report.md.</p>
<h2>Unified v2 (shared primitives: does post-hoc mapping transfer?)</h2>
{unified_table(uni)}
<h2>Top features</h2>
<table border=1 cellpadding=4><tr><th>feature</th><th>importance</th></tr>
{fi_rows}</table>
<h2>Plots</h2>
{img_tag(RESULTS / 'argus_confusion_matrix.png', 'ARGUS confusion (standard split)')}
{img_tag(RESULTS / 'argus_roc_curve.png', 'ARGUS ROC (standard split)')}
{img_tag(RESULTS / 'threshold_tuning.png', 'Threshold sweep')}
{img_tag(RESULTS / 'loso_f1.png', 'LOSO F1')}
{img_tag(RESULTS / 'real_confusion_matrix.png', 'CIC-MalMem confusion')}
{img_tag(RESULTS / 'real_roc_curve.png', 'CIC-MalMem ROC')}
<h2>Reports</h2>
<ul><li>results/generalization_report.md</li><li>results/real_validation_report.md</li>
<li>results/unified_report.md</li>
<li>config.yaml + src/config.py</li><li>pytest tests/</li></ul>
<h2>Recent work (git log)</h2>
{git_log()}
"""
    doc = ("<!doctype html><html><head><meta charset=utf-8><title>ARGUS dashboard</title>"
           "<style>body{font-family:system-ui,sans-serif;max-width:1000px;margin:2em auto;padding:0 1em}"
           "figure{margin:1em 0}figcaption{font-weight:bold}</style></head><body>"
           + body + "</body></html>")
    out.write_text(doc, encoding="utf-8")
    log.info("Wrote %s (%d bytes)", out, out.stat().st_size)


if __name__ == "__main__":
    main()
