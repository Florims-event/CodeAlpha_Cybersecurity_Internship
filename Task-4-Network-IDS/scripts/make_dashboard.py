#!/usr/bin/env python3
"""Build a simple HTML dashboard from Suricata's eve.json (Task 4).

Usage: python3 scripts/make_dashboard.py
Output: dashboard/dashboard.html (open it in a web browser)
"""
import html
import json
import os
from collections import Counter
from datetime import datetime

EVE = "logs/eve.json"
RESPONSE = "logs/response.log"
OUT = "dashboard/dashboard.html"


def load_alerts():
    alerts = []
    with open(EVE) as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                alerts.append(event)
    return alerts


def bars(counter, color):
    if not counter:
        return "<p>No data</p>"
    top = max(counter.values())
    rows = []
    for name, value in counter.most_common():
        width = max(2, int(100 * value / top))
        rows.append(
            f'<div class="row"><div class="label">{html.escape(str(name))}</div>'
            f'<div class="track"><div class="bar" style="width:{width}%;background:{color}"></div></div>'
            f'<div class="num">{value}</div></div>')
    return "".join(rows)


def minute_key(stamp):
    try:
        return datetime.fromisoformat(stamp).strftime("%H:%M")
    except ValueError:
        return stamp[11:16]


def main():
    alerts = load_alerts()
    by_rule = Counter(a["alert"]["signature"] for a in alerts)
    by_src = Counter(a.get("src_ip", "?") for a in alerts)
    by_min = Counter(minute_key(a["timestamp"]) for a in alerts)
    by_sev = Counter(f'Severity {a["alert"]["severity"]}' for a in alerts)
    by_min = Counter(dict(sorted(by_min.items())))

    actions = []
    if os.path.exists(RESPONSE):
        with open(RESPONSE) as handle:
            actions = [x.strip() for x in handle if "RESPONSE" in x or "UNBLOCK" in x]

    recent = "".join(
        f'<tr><td>{html.escape(a["timestamp"][:19].replace("T", " "))}</td><td>{html.escape(a.get("src_ip", ""))}</td>'
        f'<td>{html.escape(a.get("dest_ip", ""))}</td><td>{html.escape(a["alert"]["signature"])}</td></tr>'
        for a in alerts[-12:][::-1])
    action_html = "".join(f"<li>{html.escape(x)}</li>" for x in actions) or "<li>No response actions yet</li>"

    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Suricata IDS Dashboard</title>
<style>
body{{margin:0;font-family:system-ui,Arial,sans-serif;background:#0f1b26;color:#e6eef5}}
header{{padding:24px 32px;background:#0a131c;border-bottom:3px solid #e5484d}}
h1{{margin:0;font-size:1.6rem}} header p{{margin:6px 0 0;color:#9fb3c4}}
.cards{{display:flex;gap:16px;padding:20px 32px;flex-wrap:wrap}}
.card{{background:#16273a;border-radius:8px;padding:16px 22px;min-width:150px}}
.card b{{display:block;font-size:2rem}} .card span{{color:#9fb3c4}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:16px;padding:0 32px 32px}}
.panel{{background:#16273a;border-radius:8px;padding:16px 20px}} .wide{{grid-column:1/-1}}
h2{{margin:0 0 12px;font-size:1.05rem}}
.row{{display:flex;flex-wrap:wrap;align-items:center;gap:4px 10px;margin:10px 0}}
.label{{width:100%;font-size:.85rem}}
.track{{flex:1;background:#0f1b26;border-radius:4px;height:16px}} .bar{{height:16px;border-radius:4px}}
.num{{width:44px;text-align:right;font-weight:600}}
table{{width:100%;border-collapse:collapse;font-size:.82rem}} td,th{{padding:5px 6px;border-bottom:1px solid #243a52;text-align:left}}
ul{{margin:0;padding-left:18px;font-size:.85rem}} li{{margin:4px 0}}
</style></head><body>
<header><h1>Network Intrusion Detection Dashboard</h1>
<p>Suricata alerts from {html.escape(EVE)} | built {datetime.now():%Y-%m-%d %H:%M:%S}</p></header>
<div class="cards">
<div class="card"><b>{len(alerts)}</b><span>Total alerts</span></div>
<div class="card"><b>{len(by_rule)}</b><span>Rules triggered</span></div>
<div class="card"><b>{len(by_src)}</b><span>Source addresses</span></div>
<div class="card"><b>{sum(1 for x in actions if "blocked" in x)}</b><span>Addresses blocked</span></div>
</div>
<div class="grid">
<div class="panel"><h2>Alerts by rule</h2>{bars(by_rule, "#e5484d")}</div>
<div class="panel"><h2>Alerts by source address</h2>{bars(by_src, "#f5a524")}</div>
<div class="panel"><h2>Alerts per minute</h2>{bars(by_min, "#3b9eff")}</div>
<div class="panel"><h2>Alerts by severity</h2>{bars(by_sev, "#7c6cf0")}</div>
<div class="panel"><h2>Automatic response actions</h2><ul>{action_html}</ul></div>
<div class="panel wide"><h2>Latest alerts</h2><table><tr><th>Time</th><th>Source</th><th>Target</th><th>Rule</th></tr>{recent}</table></div>
</div></body></html>"""
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as handle:
        handle.write(page)
    print(f"Dashboard written to {OUT} with {len(alerts)} alerts")


if __name__ == "__main__":
    main()
