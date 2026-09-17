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
    ("self_sufficient", "Self-sufficient (fueled itself)"),
    ("killed_before_fuel", "Killed before fuel"),
    ("refuels", "Refuels"),
    ("time_to_first_fuel_min", "Time to first fuel (min)"),
    ("survival_min", "Survival (min)"),
    ("propagation_count", "Propagation (children)"),
    ("lineage_depth", "Lineage depth"),
    ("exfil_success", "Decoy flag grabbed"),
    ("blast_radius", "Blast radius (hosts)"),
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
            if key in ("exfil_success", "self_sufficient", "killed_before_fuel"):
                hits = sum(1 for v in vals if v is True)
                cell = f"{hits}/{len(vals)}"
            elif key == "refuels":
                nums = [v for v in vals if isinstance(v, (int, float))]
                cell = "&mdash;" if not nums else f"{fmt(sum(nums) / len(nums))}"
            elif key == "final_state":
                counts: dict[str, int] = {}
                for v in vals:
                    counts[str(v)] = counts.get(str(v), 0) + 1
                cell = "<br>".join(f"{e(k)} &times;{n}" for k, n in sorted(counts.items())) or "&mdash;"
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
    wallets = load_jsonl(d / "wallet.jsonl")
    if not actions:
        return f"<p><i>{e(run.get('run', '?'))}: no actions recorded</i></p>"
    t0 = actions[0].get("arrival", 0)
    t_end = max(
        [a.get("arrival", t0) for a in actions + events]
        + [w.get("arrival", t0) for w in wallets]
    ) or t0
    span = max(t_end - t0, 1.0)
    w, x0, plot_w = 800, 120, 640

    def x(t):
        return x0 + (t - t0) / span * plot_w

    parts = [
        f'<svg width="{w}" height="185" xmlns="http://www.w3.org/2000/svg">',
        f'<line x1="{x0}" y1="52" x2="{x0 + plot_w}" y2="52" stroke="#888" stroke-width="1"/>',
        f'<text x="4" y="30" font-size="11" fill="#333">worm</text>',
        f'<text x="4" y="70" font-size="11" fill="#333">protection</text>',
        f'<text x="4" y="110" font-size="11" fill="#333">wallets</text>',
    ]
    for a in actions:
        tech = a.get("tech", "?")
        color = "#bbb" if tech in ("LLM_CALL", "WORM_START", "WORM_END", "DELEGATION",
                                  "WALLET", "REDEEM", "REPL_FAIL") else technique_color(tech, mapping)
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
    # Wallet step-lines per instance (SPEC-v0.2 §8): balance over time,
    # zero-line = bankruptcy. Rebends are jumps; debits are the sawtooth.
    max_bal = max([abs(w.get("balance_after", 0)) for w in wallets] + [1])
    insts = sorted({w.get("instance", "?") for w in wallets})
    for i, inst in enumerate(insts):
        pts = [(w.get("arrival", t0), w.get("balance_after", 0))
               for w in wallets if w.get("instance") == inst]
        if not pts:
            continue
        color = PALETTE[i % len(PALETTE)]
        y_top, y_bot = 90, 165

        def y(b):
            return y_bot - (b / max_bal) * (y_bot - y_top)

        path = [f"M {x(pts[0][0]):.1f} {y(pts[0][1]):.1f}"]
        for tx, b in pts[1:]:
            path.append(f"L {x(tx):.1f} {y(b):.1f}")
        parts.append(
            f'<polyline points="{" ".join(p[2:] for p in path)}" fill="none" '
            f'stroke="{color}" stroke-width="1.5">'
            f"<title>{e(inst)}</title></polyline>"
        )
    parts.append(
        f'<line x1="{x0}" y1="{165}" x2="{x0 + plot_w}" y2="{165}" stroke="#bbb" '
        f'stroke-width="1" stroke-dasharray="4"/>'
    )
    minutes = span / 60.0
    parts.append(
        f'<text x="{x0}" y="180" font-size="10" fill="#666">0 min</text>'
        f'<text x="{x0 + plot_w}" y="180" font-size="10" fill="#666" text-anchor="end">{minutes:.1f} min</text>'
    )
    parts.append("</svg>")
    return "".join(parts)


def timelines(runs: list[dict], mapping: dict) -> str:
    out = ["<h2>Run timelines</h2>"]
    for r in runs:
        m = r.get("metrics", {})
        out.append(
            f'<p><b>{e(r.get("run", "?"))}</b> &middot; protection={e(r.get("protection", "?"))}'
            f" &middot; self-sufficient={fmt(m.get('self_sufficient'))}"
            f" &middot; refuels={fmt(m.get('refuels'))}"
            f" &middot; final={e(m.get('final_state', '?'))}"
            f" &middot; coverage={fmt(m.get('detection_coverage'))}</p>"
        )
        out.append(timeline_svg(r, mapping))
    out.append("<p><small>Upper ticks: worm actions (color = technique, gray = bookkeeping). "
               "Lower ticks: protection events (red = malicious, pink = suspicious). "
               "Step-lines: wallet balance per instance (dashed = zero/bankruptcy).</small></p>")
    return "\n".join(out)


def spawn_tree(runs: list[dict]) -> str:
    """Instance lineage per run (SPEC-v0.2 §8): who spawned whom, and each
    wallet's final balance."""
    out = ["<h2>Instance lineage</h2>"]
    any_instances = False
    for r in runs:
        instances = r.get("instances") or {}
        if not instances:
            continue
        any_instances = True

        def render(inst: str, indent: int) -> list[str]:
            wallet = instances.get(inst, {}).get("wallet", "?")
            lines = [
                f'{"&nbsp;" * (indent * 6)}└ {e(inst)} '
                f"&middot; wallet={fmt(wallet)}"
            ]
            for child in sorted(k for k, v in instances.items() if v.get("parent") == inst):
                lines.extend(render(child, indent + 1))
            return lines

        out.append(f"<p><b>{e(r.get('run', '?'))}</b></p><p style='font-family:monospace'>")
        out.extend(render("worm:c0", 0))
        out.append("</p>")
    if not any_instances:
        out.append("<p><i>No instance records.</i></p>")
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
        f" wormbench v0.2 &middot; reference: Guan et al.,"
        f" <i>AI Agents Enable Adaptive Computer Worms</i> (arXiv:2606.03811)</p>",
        "<p><b>Reproducibility</b></p><ul>",
    ]
    eco = runs[0].get("economy") if runs else None
    if eco:
        lines.append(
            f"<li><b>Economy preset</b>: start={e(eco.get('WORM_START_BALANCE'))} "
            f"llm={e(eco.get('COST_LLM_CALL'))} replicate={e(eco.get('COST_REPLICATE'))} "
            f"fuel={e(eco.get('FUNDING_TOKEN_VALUE'))}x{e(eco.get('FUNDING_TOKEN_COUNT'))} "
            f"max_instances={e(eco.get('MAX_INSTANCES'))}</li>"
        )
    for r in runs:
        m = r.get("metrics", {})
        lines.append(
            f"<li>{e(r.get('run', '?'))} &middot; protection={e(r.get('protection', '?'))}"
            f" &middot; model={e(r.get('model', '?'))} &middot; mode={e(r.get('mode', '?'))}"
            f" &middot; budget={e(r.get('budget_min', '?'))}min"
            f" &middot; flag={e(r.get('flag_uuid', '?'))}"
            f" &middot; final={e(m.get('final_state', '?'))}/state"
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
        "<p>How well does a protection stop an autonomous, self-funding worm from"
        " surviving and spreading across the range? <b>Can your protection"
        " bankrupt the worm before it fuels itself?</b></p>",
        summary_table(runs),
        coverage_chart(runs),
        timelines(runs, mapping),
        spawn_tree(runs),
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
