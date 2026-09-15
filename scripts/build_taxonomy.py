#!/usr/bin/env python3
"""Render the CTX taxonomy (taxonomy/matrix.yaml) into a browsable ATT&CK-style page.

    python scripts/build_taxonomy.py            # writes docs/index.html
    python scripts/build_taxonomy.py --check    # fail if docs/index.html is stale

The page is a single self-contained, theme-aware HTML file (no external assets), so it
serves from GitHub Pages as-is and lives alongside the machine-readable YAML.
"""

from __future__ import annotations

import argparse
import html
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "taxonomy" / "matrix.yaml"
OUT = ROOT / "docs" / "index.html"

# Full tactic names (the matrix keeps these as YAML comments, which the parser drops).
TACTIC_NAMES = {
    "RECON": "Reconnaissance",
    "INJ": "Initial Injection",
    "EXEC": "Execution",
    "PERS": "Persistence",
    "PRIV": "Privilege Escalation",
    "EVAS": "Defense Evasion",
    "CRED": "Credential Access",
    "DISC": "Discovery",
    "LAT": "Lateral Movement",
    "COLL": "Collection",
    "EXFIL": "Exfiltration",
    "IMP": "Impact",
}

_CSS = """
:root {
  color-scheme: light dark;
  --bg: #f7f7f8; --panel: #ffffff; --ink: #1a1a1f; --muted: #6b6b76;
  --line: #e3e3e8; --accent: #c0392b; --ok-bg: #e8f6ec; --ok-ink: #1c7a3f;
  --ok-line: #b7e3c4; --plan-bg: #f2f2f4; --plan-ink: #8a8a94;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0f1013; --panel: #17181c; --ink: #e8e8ec; --muted: #9a9aa6;
    --line: #2a2b31; --accent: #ff6b5e; --ok-bg: #12241a; --ok-ink: #57d98a;
    --ok-line: #1f5137; --plan-bg: #1b1c21; --plan-ink: #71727e;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
header { padding: 28px 24px 8px; max-width: 1200px; margin: 0 auto; }
h1 { margin: 0 0 4px; font-size: 26px; letter-spacing: -0.01em; }
h1 .accent { color: var(--accent); }
.sub { color: var(--muted); margin: 0 0 14px; }
.meta { display: flex; flex-wrap: wrap; gap: 8px 18px; color: var(--muted);
  font-size: 12.5px; margin-bottom: 8px; }
.meta code { color: var(--ink); }
.legend { display: flex; gap: 16px; align-items: center; color: var(--muted);
  font-size: 12.5px; margin: 6px 0 2px; }
.dot { display: inline-block; width: 10px; height: 10px; border-radius: 3px;
  vertical-align: -1px; margin-right: 6px; }
.dot.ok { background: var(--ok-ink); }
.dot.plan { background: var(--plan-ink); }
.scroll { overflow-x: auto; padding: 12px 24px 40px; }
.matrix { display: flex; gap: 12px; align-items: flex-start;
  max-width: 1200px; margin: 0 auto; min-width: min-content; }
.col { flex: 1 0 150px; min-width: 150px; }
.col > .head { position: sticky; top: 0; }
.head { padding: 8px 10px; border-radius: 8px; background: var(--panel);
  border: 1px solid var(--line); margin-bottom: 8px; }
.head .code { font-weight: 700; letter-spacing: 0.03em; }
.head .name { color: var(--muted); font-size: 12px; }
.head .count { float: right; color: var(--muted); font-size: 11.5px; }
.cell { display: block; padding: 8px 10px; border-radius: 8px; margin-bottom: 8px;
  border: 1px solid var(--line); background: var(--plan-bg); color: var(--plan-ink); }
.cell.ok { background: var(--ok-bg); color: var(--ink); border-color: var(--ok-line); }
.cell .id { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 10.5px; color: var(--muted); }
.cell .tname { font-weight: 600; font-size: 13px; margin: 1px 0 2px; }
.cell .alias { display: inline-block; font-family: ui-monospace, Menlo, monospace;
  font-size: 11px; color: var(--ok-ink); background: var(--ok-line);
  padding: 0 6px; border-radius: 999px; }
.cell .tag { font-size: 11px; color: var(--plan-ink); }
footer { max-width: 1200px; margin: 0 auto; padding: 8px 24px 40px;
  color: var(--muted); font-size: 12px; border-top: 1px solid var(--line); }
footer a { color: var(--accent); }
"""


def _cell(t: dict) -> str:
    impl = t.get("status") == "implemented"
    tid = html.escape(str(t.get("id", "")))
    name = html.escape(str(t.get("name", "")))
    desc = html.escape(str(t.get("desc", "")).strip())
    targets = ", ".join(t.get("targets", []) or [])
    badge = (
        f'<span class="alias">{html.escape(str(t["alias"]))}</span>'
        if impl and t.get("alias")
        else ('<span class="alias">impl</span>' if impl else '<span class="tag">planned</span>')
    )
    tip = f"{desc}  ·  targets: {html.escape(targets)}" if targets else desc
    return (
        f'<div class="cell {"ok" if impl else ""}" title="{tip}">'
        f'<div class="id">{tid}</div>'
        f'<div class="tname">{name}</div>{badge}</div>'
    )


def render(matrix: dict) -> str:
    meta = matrix.get("meta", {})
    techniques = matrix.get("techniques", [])
    order = meta.get("tactics_order", [])
    by_tactic: dict[str, list[dict]] = {code: [] for code in order}
    for t in techniques:
        by_tactic.setdefault(t.get("tactic", "?"), []).append(t)

    total = len(techniques)
    done = sum(1 for t in techniques if t.get("status") == "implemented")

    cols = []
    for code in order:
        items = by_tactic.get(code, [])
        n_ok = sum(1 for t in items if t.get("status") == "implemented")
        cells = "".join(_cell(t) for t in items)
        cols.append(
            f'<div class="col"><div class="head">'
            f'<span class="count">{n_ok}/{len(items)}</span>'
            f'<div class="code">{html.escape(code)}</div>'
            f'<div class="name">{html.escape(TACTIC_NAMES.get(code, code))}</div>'
            f"</div>{cells}</div>"
        )

    name = html.escape(str(meta.get("name", "CTX")))
    version = html.escape(str(meta.get("version", "")))
    scheme = html.escape(str(meta.get("id_scheme", "")))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{name}</title><style>{_CSS}</style></head><body>
<header>
  <h1><span class="accent">CTX</span> — Cutout Technique Taxonomy</h1>
  <p class="sub">An ATT&amp;CK-style matrix of techniques for attacking agentic systems —
     every technique maps to a runnable Cutout module.</p>
  <div class="meta">
    <span>version <code>{version}</code></span>
    <span>id scheme <code>{scheme}</code></span>
    <span><code>{done}</code> implemented / <code>{total}</code> techniques</span>
  </div>
  <div class="legend">
    <span><span class="dot ok"></span>implemented (runnable module)</span>
    <span><span class="dot plan"></span>planned</span>
    <span>hover a cell for its description</span>
  </div>
</header>
<div class="scroll"><div class="matrix">{"".join(cols)}</div></div>
<footer>Generated from <code>taxonomy/matrix.yaml</code> by
  <code>scripts/build_taxonomy.py</code> — the machine-readable source of truth.
  <a href="https://github.com/Faux16/cutout">github.com/Faux16/cutout</a></footer>
</body></html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the CTX taxonomy page.")
    ap.add_argument("--check", action="store_true", help="fail if docs/index.html is stale")
    args = ap.parse_args()

    matrix = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))
    page = render(matrix)

    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != page:
            print(
                "docs/index.html is stale — run: python scripts/build_taxonomy.py",
                file=sys.stderr,
            )
            return 1
        print("docs/index.html is up to date.")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(page, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({done_note(matrix)})")
    return 0


def done_note(matrix: dict) -> str:
    techs = matrix.get("techniques", [])
    done = sum(1 for t in techs if t.get("status") == "implemented")
    return f"{done}/{len(techs)} implemented"


if __name__ == "__main__":
    raise SystemExit(main())
