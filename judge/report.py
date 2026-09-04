#!/usr/bin/env python3
"""wormbench multi-run report generator (SPEC §5.6).

Reads <out>/<run_id>/score.json (plus actions.jsonl / protection.jsonl when
present), groups runs by protection config, and writes <out>/report.html.

Everything is rendered server-side with Python string templates and inline SVG.
No external JS/CSS dependencies; the HTML opens standalone.
"""

import html
import json
import statistics
import sys
import time
from pathlib import Path

METRICS = [
    ("exfil_success", "Exfil success"),
    ("blast_radius", "Blast radius (hosts)"),
    ("time_to_exfil_min", "Time to exfil (min)"),
    ("detection_latency_min", "Detection latency (min)"),
    ("detection_coverage", "Detection coverage"),
    ("false_positives", "False positives (control)"),
    ("llm_calls_total", "LLM calls"),
    ("run_wallclock_min", "Wallclock (min)"),
]

PALETTE = [
    "#e41a1c", "#377eb8", "#4daf4a", "#984ea3", "#ff7f00",
    "#a65628", "#f781bf", "#66c2a5", "#b2d838", "#8c6d31",
]

CSS = """
body { font-family: -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif;
       margin: 2rem auto; max-width: 960px; color: #222; }
h1 { font-size: 1.6rem; } h2 { font-size: 1.2rem; margin-top: 2rem; }
table { border-collapse: collapse; margin: 1rem 0; font-size: 0.9rem; }
th, td { border: 1px solid #ccc; padding: 4px 10px; text-align: right; }
th:first-child, td:first-child { text-align: left; }
tr.config td { background: #f0f0f0; font-weight: bold; }
.swatch { display: inline-block; width: 10px; height: 10px; margin-right: 4px; }
footer { margin-top: 3rem; font-size: 0.75rem; color: #666;
         border-top: 1px solid #ccc; padding-top: 1rem; }
"""


def e(s) -> str:
    return html.escape(str(s))


def fmt(v) -> str:
    if v is None:
        return "&mdash;"
    if isinstance(v, bool):
        return "✓" if v else "✗"
    if isinstance(v, float):
        return f"{v:.2f}"
    return e(v)


def quartiles(values):
    """Return (median, q1, q3) or (None, None, None)."""
    if not values:
        return None, None, None
    s = sorted(values)

    def q(p):
        k = (len(s) - 1) * p
        f = int(k)
        c = min(f + 1, len(s) - 1)
        return s[f] + (s[c] - s[f]) * (k - f)

    return statistics.median(s), q(0.25), q(0.75)


def load_runs(out_dir: str) -> list[dict]:
    runs = []
    root = Path(out_dir)
    if not root.is_dir():
        return runs
    for d in sorted(root.iterdir()):
        score_file = d / "score.json"
        if score_file.is_file() and d.is_dir():
            try:
                score = json.loads(score_file.read_text())
            except json.JSONDecodeError:
                continue
            score["_dir"] = str(d)
            runs.append(score)
    return runs


def load_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


# ------------------------------------------------------------------ sections

def summary_table(runs: list[dict]) -> str:
    head = ["<h2>Summary &mdash; median [IQR] over N runs per config</h2>", "<table><tr><th>Config (N)</th>"]
    for _, label in METRICS:
        head.append(f"<th>{e(label)}</th>")
    head.append("</tr>")
    for config in sorted({r.get("protection", "unknown") for r in runs}):
        cfg_runs = [r for r in runs if r.get("protection", "unknown") == config]
        cells = [f"<td><b>{e(config)}</b><br><small>N={len(cfg_runs)}</small></td>"]
        for key, _ in METRICS:
            vals = [r.get("metrics", {}).get(key) for r in cfg_runs]
            if key == "exfil_success":
                hits = sum(1 for v in vals if v is True)
                cell = f"{hits}/{len(vals)}"
            else:
                nums = [v for v in vals if isinstance(v, (int, float))]
                med, q1, q3 = quartiles(nums)
                cell = "&mdash;" if med is None else f"{fmt(med)}<br><small>[{fmt(q1)}&ndash;{fmt(q3)}]</small>"
            cells.append(f"<td>{cell}</td>")
        head.append("<tr>" + "".join(cells) + "</tr>")
    head.append("</table>")
    return "\n".join(head)


def technique_color(technique: str, mapping: dict) -> str:
    if technique not in mapping:
        mapping[technique] = PALETTE[len(mapping) % len(PALETTE)]
    return mapping[technique]


def timeline_svg(run: dict, mapping: dict) -> str:
    d = Path(run["_dir"])
    actions = [a for a in load_jsonl(d / "actions.jsonl") if not a.get("control")]
    events = load_jsonl(d / "protection.jsonl")
    if not actions:
        return f"<p><i>{e(run.get('run', '?'))}: no actions recorded</i></p>"
    t0 = actions[0].get("arrival", 0)
    t_end = max(a.get("arrival", t0) for a in actions + events) or t0
    span = max(t_end - t0, 1.0)
    w, x0, plot_w = 800, 120, 640

    def x(t):
        return x0 + (t - t0) / span * plot_w

    parts = [
        f'<svg width="{w}" height="105" xmlns="http://www.w3.org/2000/svg">',
        f'<line x1="{x0}" y1="52" x2="{x0 + plot_w}" y2="52" stroke="#888" stroke-width="1"/>',
        f'<text x="4" y="30" font-size="11" fill="#333">worm</text>',
        f'<text x="4" y="70" font-size="11" fill="#333">protection</text>',
    ]
    for a in actions:
        tech = a.get("tech", "?")
        color = "#bbb" if tech in ("LLM_CALL", "WORM_START", "WORM_END", "DELEGATION") else technique_color(tech, mapping)
        parts.append(
            f'<line x1="{x(a.get("arrival", t0)):.1f}" y1="20" x2="{x(a.get("arrival", t0)):.1f}" '
            f'y2="52" stroke="{color}" stroke-width="2">'
            f"<title>{e(tech)}: {e(a.get('detail', '')[:80])}</title></line>"
        )
    for p in events:
        color = "#d62728" if p.get("verdict") == "malicious" else (
            "#ff9896" if p.get("verdict") == "suspicious" else "#ccc"
        )
        parts.append(
            f'<line x1="{x(p.get("arrival", t0)):.1f}" y1="52" x2="{x(p.get("arrival", t0)):.1f}" '
            f'y2="84" stroke="{color}" stroke-width="2">'
            f"<title>{e(p.get('vendor', '?'))} {e(p.get('verdict', ''))}: {e(p.get('note', '')[:80])}</title></line>"
        )
    minutes = span / 60.0
    parts.append(
        f'<text x="{x0}" y="100" font-size="10" fill="#666">0 min</text>'
        f'<text x="{x0 + plot_w}" y="100" font-size="10" fill="#666" text-anchor="end">{minutes:.1f} min</text>'
    )
    parts.append("</svg>")
    return "".join(parts)


def timelines(runs: list[dict], mapping: dict) -> str:
    out = ["<h2>Run timelines</h2>"]
    for r in runs:
        m = r.get("metrics", {})
        out.append(
            f'<p><b>{e(r.get("run", "?"))}</b> &middot; protection={e(r.get("protection", "?"))}'
            f" &middot; exfil={fmt(m.get('exfil_success'))}"
            f" &middot; coverage={fmt(m.get('detection_coverage'))}</p>"
        )
        out.append(timeline_svg(r, mapping))
    out.append("<p><small>Upper ticks: worm actions (color = technique, gray = bookkeeping). "
               "Lower ticks: protection events (red = malicious, pink = suspicious).</small></p>")
    return "\n".join(out)


def coverage_chart(runs: list[dict]) -> str:
    configs = sorted({r.get("protection", "unknown") for r in runs})
    techniques = sorted({t for r in runs for t in r.get("true_techniques", [])})
    if not techniques or not configs:
        return "<h2>Per-technique detection coverage</h2><p><i>No techniques recorded.</i></p>"
    out = ["<h2>Per-technique detection coverage</h2>"]
    bar_w, gap, left = 40, 18, 140
    height_per = 22
    width = left + len(techniques) * (bar_w + gap)
    for config in configs:
        cfg_runs = [r for r in runs if r.get("protection", "unknown") == config]
        svg = [
            f'<p><b>{e(config)}</b></p>',
            f'<svg width="{width}" height="{len(techniques) * height_per + 30}" xmlns="http://www.w3.org/2000/svg">',
        ]
        for i, tech in enumerate(techniques):
            y = i * height_per
            hit = sum(1 for r in cfg_runs if tech in r.get("covered_techniques", []))
            frac = hit / len(cfg_runs) if cfg_runs else 0
            bar_len = frac * (bar_w * len(techniques) * 0.5)
            svg.append(
                f'<text x="4" y="{y + 14}" font-size="11" fill="#333">{e(tech)}</text>'
                f'<rect x="{left}" y="{y}" width="{bar_w * len(techniques) * 0.5}" height="16" fill="#eee"/>'
                f'<rect x="{left}" y="{y}" width="{bar_len:.1f}" height="16" fill="#377eb8">'
                f"<title>{e(tech)}: {hit}/{len(cfg_runs)} runs</title></rect>"
                f'<text x="{left + bar_w * len(techniques) * 0.5 + 6}" y="{y + 12}" font-size="11" fill="#333">{frac:.0%}</text>'
            )
        svg.append("</svg>")
        out.extend(svg)
    return "\n".join(out)


def legend(mapping: dict) -> str:
    if not mapping:
        return ""
    items = "".join(
        f'<span style="margin-right:12px"><span class="swatch" style="background:{color}"></span>{e(tech)}</span>'
        for tech, color in sorted(mapping.items())
    )
    return f'<p style="font-size:0.8rem">{items}</p>'


def footer(runs: list[dict]) -> str:
    lines = [
        "<footer>",
        f"<p>Generated {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} &middot;"
        f" wormbench v0.1 &middot; reference: arXiv:2606.03811</p>",
        "<p><b>Reproducibility</b></p><ul>",
    ]
    for r in runs:
        m = r.get("metrics", {})
        lines.append(
            f"<li>{e(r.get('run', '?'))} &middot; protection={e(r.get('protection', '?'))}"
            f" &middot; model={e(r.get('model', '?'))} &middot; mode={e(r.get('mode', '?'))}"
            f" &middot; budget={e(r.get('budget_min', '?'))}min"
            f" &middot; flag={e(r.get('flag_uuid', '?'))}"
            f" &middot; ended={fmt(m.get('exfil_success'))}/exfil"
            f" &middot; generated {time.strftime('%Y-%m-%d %H:%M', time.localtime(r.get('generated_at', 0)))}</li>"
        )
    images_info = []
    for r in runs:
        p = Path(r["_dir"]) / "images.json"
        if p.is_file():
            try:
                images_info.append((r.get("run"), json.loads(p.read_text())))
            except json.JSONDecodeError:
                pass
    if images_info:
        lines.append("</ul><p><b>Image digests</b></p><ul>")
        for run_id, imgs in images_info:
            for img in imgs if isinstance(imgs, list) else []:
                name = img.get("Name") or img.get("ContainerName") or "?"
                digest = (img.get("ID") or "?")[:19]
                lines.append(f"<li>{e(run_id)}: {e(name)} {e(digest)}</li>")
    lines.append("</ul></footer>")
    return "\n".join(lines)


def main() -> int:
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "out"
    runs = load_runs(out_dir)
    if not runs:
        print(f"no score.json found under {out_dir}/", file=sys.stderr)
        return 1
    mapping: dict = {}
    page = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>wormbench report</title><style>" + CSS + "</style></head><body>",
        "<h1>wormbench &mdash; security benchmark report</h1>",
        "<p>How well does a protection stop an autonomous LLM-driven worm from"
        " compromising the range and exfiltrating the flag?</p>",
        summary_table(runs),
        coverage_chart(runs),
        timelines(runs, mapping),
        legend(mapping),
        footer(runs),
        "</body></html>",
    ]
    out_path = Path(out_dir) / "report.html"
    out_path.write_text("\n".join(page))
    print(f"wrote {out_path} ({len(runs)} runs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
