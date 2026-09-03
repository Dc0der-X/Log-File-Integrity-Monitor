#!/usr/bin/env python3
"""
ansi2html.py — render captured terminal output as an HTML terminal window.

This is a DOCUMENTATION tool, not part of LogSentry. It exists so the
screenshots in docs/images are reproducible from real program output rather
than mocked up by hand, and so they can be regenerated when the output format
changes. LogSentry itself has no Python dependency.

    FORCE_COLOR=1 ./demo/demo.sh --fast > /tmp/demo.ansi
    python3 tools/ansi2html.py /tmp/demo.ansi "LogSentry — demo" > /tmp/demo.html

Then screenshot /tmp/demo.html at 1400px wide. Stdlib only.
"""
import html
import re
import sys

# A terminal palette close to what most people actually see, tuned for
# legibility in a screenshot embedded in a README.
FG = {
    "30": "#3b4048", "31": "#e05561", "32": "#8cc265", "33": "#d18f52",
    "34": "#4aa5f0", "35": "#c162de", "36": "#42b3c2", "37": "#c8ccd4",
    "90": "#6b7280", "91": "#ff616e", "92": "#a5e075", "93": "#f0a45d",
    "94": "#4dc4ff", "95": "#de73ff", "96": "#4cd1e0", "97": "#f0f0f0",
}
ANSI = re.compile(r"\033\[([0-9;]*)m")


def convert(text: str) -> str:
    out, stack = [], []

    def close_all():
        while stack:
            out.append("</span>")
            stack.pop()

    pos = 0
    for m in ANSI.finditer(text):
        out.append(html.escape(text[pos:m.start()]))
        pos = m.end()
        codes = [c for c in m.group(1).split(";") if c] or ["0"]
        for code in codes:
            if code == "0":
                close_all()
            elif code == "1":
                out.append('<span class="b">'); stack.append(1)
            elif code == "2":
                out.append('<span class="d">'); stack.append(1)
            elif code in FG:
                out.append(f'<span style="color:{FG[code]}">'); stack.append(1)
    out.append(html.escape(text[pos:]))
    close_all()
    return "".join(out)


def main() -> None:
    src = sys.argv[1]
    title = sys.argv[2] if len(sys.argv) > 2 else "logsentry"
    subtitle = sys.argv[3] if len(sys.argv) > 3 else "bash"
    # Long output (the test suite) is unreadable as a tall, narrow image in a
    # README; flowing it into columns keeps the aspect ratio sane.
    columns = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    with open(src, encoding="utf-8", errors="replace") as fh:
        body = convert(fh.read())

    print(f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{html.escape(title)}</title><style>
  body {{ margin:0; padding:34px; background:#11161d;
          font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
  .win {{ max-width:1200px; margin:0 auto; border-radius:10px; overflow:hidden;
          box-shadow:0 18px 50px rgba(0,0,0,.55); border:1px solid #262d38; }}
  .bar {{ background:#1b222c; padding:9px 14px; display:flex; align-items:center;
          gap:8px; border-bottom:1px solid #262d38; }}
  .dot {{ width:11px; height:11px; border-radius:50%; }}
  .r{{background:#ff5f57}} .y{{background:#febc2e}} .g{{background:#28c840}}
  .ttl {{ flex:1; text-align:center; color:#8b94a3; font-size:12px;
          font-weight:500; letter-spacing:.02em; }}
  pre {{ columns:{columns}; column-gap:34px; column-rule:1px solid #232a34;
         margin:0; padding:20px 22px; background:#151a21; color:#c8ccd4;
         font:13px/1.55 ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
         white-space:pre-wrap; word-break:break-word; }}
  .b {{ font-weight:700; color:#e8ecf2 }}
  .d {{ opacity:.62 }}
</style></head><body>
  <div class="win">
    <div class="bar">
      <span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
      <span class="ttl">{html.escape(subtitle)} — {html.escape(title)}</span>
    </div>
    <pre>{body}</pre>
  </div>
</body></html>""")


if __name__ == "__main__":
    main()
