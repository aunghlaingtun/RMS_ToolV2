"""RMS (Rotork Master Station) log analyser - parsers, per-FCU health model, troubleshooting findings.
Read-only: it only analyses exported CSV/XLSX/TGZ files."""
import io, re, csv, tarfile
import numpy as np
import pandas as pd

VERSION = "2026-11-22-fcu-trace"   # bump when the analysis changes; used to refresh the app cache
SYSTEM_ADDR = {10000, 10001}  # master station / classic loop controller, not FCUs


# ---------------------------------------------------------------- reading
def read_table(name, data):
    if name.lower().endswith((".xlsx", ".xls")):
        return pd.read_excel(io.BytesIO(data))
    return pd.read_csv(io.BytesIO(data))


def meta(name):
    n = name.lower()
    kind = next((k for k in ["alarmlog", "datalog", "hostanalyser", "hostcommandlog", "loop_map", "syslogs"] if n.startswith(k)), None)
    side = re.search(r"side([ab])", n)
    chan = re.search(r"(ethernet|rtu\d)", n)
    return kind, (side.group(1).upper() if side else "?"), (chan.group(1) if chan else "?")


def parse_loop_map(data):
    rows = list(csv.reader(io.StringIO(data.decode("utf-8", "ignore"))))
    hi = next(i for i, r in enumerate(rows) if r and r[0] == "Position")
    links = pd.DataFrame([r[:5] for r in rows[1:hi] if r and r[0]], columns=rows[0][:5])
    cols = rows[hi][:9]
    fcu = pd.DataFrame([r[:9] for r in rows[hi + 1:] if r and r[0]], columns=cols)
    fcu = fcu.rename(columns={"Address": "Addr", "FCU Soft Ver": "Ver", "Tags": "Tag"})
    for c in ["Position", "Addr", "Failures"]:
        fcu[c] = pd.to_numeric(fcu[c], errors="coerce")
    return links, fcu


# ---------------------------------------------------------------- alarms / data log
def alarm_features(al):
    al = al.copy()
    al["t"] = pd.to_datetime(al["Timestamp"], unit="ms")
    al = al.sort_values("t")
    raised = al[al.AlarmLevel != "Cleared"].pivot_table(index="Address", columns="AlarmKey", values="Number", aggfunc="count", fill_value=0)
    raised.columns = [f"n_{c.replace(' ', '_')}" for c in raised.columns]
    episodes = []
    for (addr, key), g in al.groupby(["Address", "AlarmKey"]):
        start = None
        for _, r in g.iterrows():
            if r.AlarmLevel != "Cleared" and start is None:
                start = r.t
            elif r.AlarmLevel == "Cleared" and start is not None:
                episodes.append((addr, key, start, r.t, (r.t - start).total_seconds())); start = None
        if start is not None:
            episodes.append((addr, key, start, pd.NaT, np.nan))
    ep = pd.DataFrame(episodes, columns=["Address", "AlarmKey", "start", "end", "seconds"])
    return al, raised, ep


# ---------------------------------------------------------------- Modbus frames
def decode(msg):
    b = [int(x, 16) for x in str(msg).split(":")]
    return b


def parse_host(df, channel):
    """Return transactions (request->response pairing seen by Side B) and raw frames."""
    d = df.copy().rename(columns={"Milliseconds After Midnight": "ms"})
    d = d.sort_values(["ms", "Number"], ascending=[True, False]).reset_index(drop=True)
    m = d.Address.str.extract(r"(Rx|Tx)(Side[AB])\[(.+)\]")
    d["dir"], d["side"], d["ep"] = m[0], m[1].str[-1], m[2]
    d["bytes"] = d.Message.map(decode)
    d["fc"] = d.bytes.str[1]
    d["channel"] = channel
    d["t"] = pd.to_datetime(d.Date_ISO8601.astype(str) + " " + d.Time.astype(str), errors="coerce")
    tx, q = [], {}
    # The analyser log does not always capture every response, and hosts send the next request before the
    # previous response is logged. So each response is matched to the oldest pending request of the same
    # function code whose expected response length fits; requests never matched become "not_logged".
    def expected(p):
        if p["fc"] in (1, 2): return 3 + (p["qty"] + 7) // 8
        if p["fc"] in (3, 4): return 3 + 2 * p["qty"]
        return 6 if p["fc"] == 5 else None
    for r in d[d.side == "B"].itertuples():
        qq = q.setdefault(r.ep, [])
        b = r.bytes
        if r.dir == "Rx":
            qq.append(dict(channel=channel, ep=r.ep, ms=r.ms, time=r.t, fc=b[1], start=(b[2] << 8 | b[3]) if len(b) >= 6 else None,
                           qty=(b[4] << 8 | b[5]) if len(b) >= 6 else None, req=r.Message))
            continue
        exc = b[1] >= 0x80
        cand = [i for i, p in enumerate(qq) if p["fc"] == (b[1] & 0x7F) and r.ms - p["ms"] <= 1000
                and (exc or expected(p) is None or expected(p) == len(b))]
        i = (cand[-1] if exc else cand[0]) if cand else None   # exceptions answer the most recent request
        if i is None:
            tx.append(dict(channel=channel, ep=r.ep, ms=r.ms, fc=b[1] & 0x7F, status="unmatched_response", resp_len=len(b))); continue
        p = qq.pop(i)
        p["rt_ms"] = r.ms - p["ms"]
        if exc:
            p["status"], p["exc"] = "exception", b[2] if len(b) > 2 else None
        else:
            p["status"] = "ok" if (p["fc"] != 5 or r.Message == p["req"]) else "bad_length_or_echo"
            if p["fc"] in (1, 2, 3, 4):
                p["resp"] = tuple(b)
        tx.append(p)
    for qq in q.values():
        for p in qq:
            tx.append(dict(p, status="not_logged"))
    return pd.DataFrame(tx), d


def side_a_coverage(frames):
    """% of Side-B requests / responses that Side A also heard within 100 ms (RTU only)."""
    a = frames[frames.side == "A"].sort_values("ms")
    if a.empty:
        return None
    out = {}
    for d in ("Rx", "Tx"):
        b = frames[(frames.side == "B") & (frames.dir == d)].sort_values("ms")
        mm = pd.merge_asof(b[["ms", "Message", "ep"]], a[["ms", "Message", "ep"]].rename(columns={"ms": "ms_a"}),
                           left_on="ms", right_on="ms_a", by=["Message", "ep"], direction="nearest", tolerance=100)
        out["requests_heard" if d == "Rx" else "responses_heard"] = round(100 * float(mm.ms_a.notna().mean()), 1)
    return out


def polling_gaps(frames):
    out = []
    for ep, g in frames[(frames.side == "B") & (frames.dir == "Rx")].groupby("ep"):
        gap = g.ms.diff().dropna()
        if len(gap):
            out.append(dict(ep=ep, requests=len(g), median_gap_ms=gap.median(), max_gap_ms=gap.max()))
    return pd.DataFrame(out)


# ---------------------------------------------------------------- syslog
def parse_syslog(data):
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        m = next((x for x in t.getmembers() if x.name.split("/")[-1] == "syslog"), None)
        text = t.extractfile(m).read().decode("utf-8", "ignore") if m else ""
    pat = re.compile(r"^(\S+) \S+ (\S+): (WARNING|ERROR) \d+ \d+ (\S+) \d+ (\S+) : (.*)$")
    rows = []
    for line in text.splitlines():
        g = pat.match(line)
        if g:
            rows.append((g[1], g[3], g[2], g[4], re.sub(r"\d+", "#", g[6])[:140]))
    df = pd.DataFrame(rows, columns=["time", "level", "process", "source", "message"])
    if df.empty:
        return df
    return (df.groupby(["level", "source", "message"]).agg(count=("time", "size"), first=("time", "min"), last=("time", "max"))
            .reset_index().sort_values("count", ascending=False))


# ---------------------------------------------------------------- findings helper
def F(sev, area, target, title, evidence, action):
    return dict(severity=sev, area=area, target=str(target), title=title, evidence=evidence, action=action)


SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}



BUFFER_LIMIT = {"alarmlog": 1000, "datalog": 10000, "hostanalyser": 10000, "hostcommandlog": 10000}


def _fmt_span(td):
    if pd.isna(td):
        return ""
    s = int(td.total_seconds())
    d, r = divmod(s, 86400); h, r = divmod(r, 3600); m, sec = divmod(r, 60)
    if d: return f"{d} d {h} h"
    if h: return f"{h} h {m} min"
    if m: return f"{m} min {sec} s"
    return f"{sec} s"


def _coverage_row(name, kind, df):
    limit = BUFFER_LIMIT[kind]
    t = (pd.to_datetime(df["Date_ISO8601"].astype(str) + " " + df["Time"].astype(str), errors="coerce")
         if {"Date_ISO8601", "Time"} <= set(df.columns) else pd.Series(dtype="datetime64[ns]"))
    start, end = (t.min(), t.max()) if len(t) else (pd.NaT, pd.NaT)
    _, side, chan = meta(name)
    return dict(file=name, log=KIND_INFO[kind][0], side=side, channel=chan, rows=len(df), buffer_limit=limit, start=start, end=end,
                covers=_fmt_span(end - start) if len(t) else "",
                status="Full - older entries were overwritten" if len(df) >= 0.99 * limit else "OK")


def decode_coil(c):
    """1-based coil -> (scope, command, fcu) using the Yokogawa / Honeywell SI host database."""
    ms = {1: "Global ESD", 15: "Change master", 16: "Reset loop", 32: "Alarm accept"}
    if c in ms: return "Master Station", ms[c], None
    if 33 <= c <= 512: return "FCU", ("Close" if c % 2 == 1 else "Open"), (c - 31) // 2
    if 513 <= c <= 752: return "FCU", "Open", c - 512
    if 753 <= c <= 992: return "FCU", "Stop", c - 752
    if 993 <= c <= 1232: return "FCU", "Close", c - 992
    if 1233 <= c <= 1472: return "FCU", "ESD", c - 1232
    return "Unknown", f"coil {c}", None


CMD_COLS = ["time", "channel", "host", "fc", "coil", "value", "scope", "command", "fcu", "action", "detail"]


def parse_commands(cmdlogs):
    rows = []
    for side, chan, df in cmdlogs:
        d = df.copy()
        m = d.Address.str.extract(r"(Rx|Tx)(Side[AB])\[(.+)\]")
        d["dir"], d["side"], d["host"] = m[0], m[1].str[-1], m[2]
        d["t"] = pd.to_datetime(d.Date_ISO8601.astype(str) + " " + d.Time.astype(str), errors="coerce")
        d = d[d.dir == "Rx"]
        d = d[d.side == "B"] if (d.side == "B").any() else d      # Side A rows are the listening copy
        for r in d.itertuples():
            b = decode(r.Message)
            items = []
            if b[1] == 5 and len(b) >= 6:
                items = [((b[2] << 8 | b[3]) + 1, b[4] << 8 | b[5])]
            elif b[1] == 15 and len(b) >= 8:
                start, qty, data = (b[2] << 8 | b[3]) + 1, b[4] << 8 | b[5], b[7:7 + b[6]]
                items = [(start + i, 0xFF00 if (data[i // 8] >> (i % 8)) & 1 else 0) for i in range(qty) if i // 8 < len(data)]
            for coil, val in items:
                scope, command, fcu = decode_coil(coil)
                rows.append(dict(time=r.t, channel=chan, host=r.host, fc=b[1], coil=coil, value=val, scope=scope, command=command, fcu=fcu,
                                 action="Energise (command)" if val else "Clear (0x0000)", detail=""))
            regs = []
            if b[1] == 6 and len(b) >= 6:
                regs = [((b[2] << 8 | b[3]) + 1, b[4] << 8 | b[5])]
            elif b[1] == 16 and len(b) >= 9:
                st0, q0 = (b[2] << 8 | b[3]) + 1, b[4] << 8 | b[5]
                regs = [(st0 + i, b[7 + 2 * i] << 8 | b[8 + 2 * i]) for i in range(q0) if 8 + 2 * i < len(b)]
            for reg, val in regs:
                rows.append(dict(time=r.t, channel=chan, host=r.host, fc=b[1], coil=reg, value=val, scope="FCU", command="Set position", fcu=reg,
                                 action="Setpoint", detail=f"{val / 32767 * 100:.1f} %"))
    out = pd.DataFrame(rows, columns=CMD_COLS)
    return out.drop_duplicates(["time", "channel", "host", "coil", "value"]) if len(out) else out


def build_reset_timeline(dl, cmd, lf):
    rows = []
    if dl is not None and len(dl):
        for x in dl[dl.DataKey.astype(str).str.contains("RESET", na=False)].itertuples():
            src = str(x.Source); web = src.startswith("WebAPI")
            rows.append(dict(time=x.t, event="Reset loop" if "ResetLoop" in str(x.DataKey) else "Reset network",
                             via="Web interface" if web else "Host (Modbus)", source=src, ip=src.split(":")[-1] if web else "",
                             in_datalog=True, in_host_log=False))
    if cmd is not None and len(cmd):
        for h in cmd[(cmd.command == "Reset loop") & (cmd.value != 0)].itertuples():
            hit = [r for r in rows if r["event"] == "Reset loop" and abs((r["time"] - h.time).total_seconds()) < 3]
            if hit:
                hit[0]["in_host_log"] = True
            else:
                rows.append(dict(time=h.time, event="Reset loop", via="Host (Modbus)", source=f"{h.channel} {h.host}",
                                 ip=str(h.host).split(":")[0], in_datalog=False, in_host_log=True))
    tl = pd.DataFrame(rows, columns=["time", "event", "via", "source", "ip", "in_datalog", "in_host_log"])
    tl["loop_faults_within_5min"] = [int(((lf.t - t).abs() <= pd.Timedelta("5min")).sum()) if lf is not None and len(lf) else 0 for t in tl.time]
    return tl.sort_values("time", ascending=False).reset_index(drop=True)


RELAY_BITS = {1: "Close", 2: "Open", 4: "Stop", 8: "ESD"}


def control_value_label(v):
    try:
        n = int(str(v), 16)
    except ValueError:
        return "unknown"
    names = [nm for bit, nm in RELAY_BITS.items() if n & bit]
    return " + ".join(names) if names and n < 16 else "unknown"


# ---------------------------------------------------------------- main
def analyze(files, main_loop=None):
    """files: {filename: bytes}. Returns dict of tables + findings."""
    R = dict(findings=[], notes=[])
    loops, alarms, datal, hosts, sys_logs, cmdlogs = {}, {}, {}, [], {}, []
    cov_rows, boots = [], {}
    for name, data in files.items():
        kind, side, chan = meta(name)
        tbl = None
        if kind in BUFFER_LIMIT:
            tbl = read_table(name, data)
            cov_rows.append(_coverage_row(name, kind, tbl))
        if kind == "loop_map":
            loops[name] = parse_loop_map(data)
        elif kind == "alarmlog":
            alarms[name] = tbl
        elif kind == "datalog":
            datal[name] = tbl
        elif kind == "hostanalyser":
            hosts.append((side, chan, tbl))
        elif kind == "hostcommandlog":
            cmdlogs.append((side, chan, tbl))
        elif kind == "syslogs":
            sys_logs[side] = parse_syslog(data)
            boots[side] = parse_boot(data)
        else:
            R["notes"].append(f"Ignored unrecognised file: {name}")
    R["loop_maps"] = list(loops)
    R["log_coverage"] = pd.DataFrame(cov_rows)
    R["findings_f"] = []
    fnd = R["findings"]

    # --- alarm logs (A and B are synchronised; use first, note if identical)
    if len(alarms) > 1:
        v = list(alarms.values())
        if all(x.equals(v[0]) for x in v):
            R["notes"].append("Side A and Side B alarm logs are identical (synchronised) - analysed once.")
    al = None
    if alarms:
        al, raised, ep = alarm_features(list(alarms.values())[0])
        R["alarms"], R["episodes"] = al, ep
    # --- data log events
    if datal:
        dl = list(datal.values())[0].copy()
        dl["t"] = pd.to_datetime(dl["Timestamp"], unit="ms")
        R["datalog"] = dl
        ctrl = dl[dl.DataKey == "DigCtrlNet0ControlVal"].groupby("Address").size().rename("ctrl_events")
        resets = dl[dl.DataKey.str.contains("RESET", na=False)]
        R["resets"] = resets[["t", "Address", "DataKey", "Source"]]
    else:
        ctrl, resets = pd.Series(dtype=int, name="ctrl_events"), pd.DataFrame()

    # --- loop map / FCU table
    if loops:
        main = main_loop if main_loop in loops else list(loops)[0]
        links, fcu = loops[main]
        R["links"], R["main_loop"] = links, main
        fcu = fcu.set_index("Addr")
        if len(loops) > 1:
            cmp = pd.DataFrame({n: f.set_index("Addr").Status for n, (_, f) in loops.items()})
            R["loop_compare"] = cmp[cmp.nunique(axis=1) > 1]
            fc = pd.DataFrame({n: pd.to_numeric(f.set_index("Addr").Failures, errors="coerce") for n, (_, f) in loops.items()})
            R["failures_compare"] = fc
            for n in fc:
                if fc[n].sum() == 0 and (fc.drop(columns=n).sum() > 0).any():
                    R["notes"].append(f"Loop map '{n}' shows 0 failures for every FCU. The failure counter is cleared by a Reset loop command, "
                                      "so this snapshot was probably taken right after a reset - do not read it as 'healthy'.")
        bad_links = links[links["Link OK"] != "OK"] if not links.empty else links
        if len(bad_links):
            fnd.append(F("High", "Loop", f"{len(bad_links)} link(s)", "Loop links not OK",
                         ", ".join(bad_links["From Device"] + "->" + bad_links["To Device"]), "Check cable and terminals between these devices."))
    else:
        fcu = pd.DataFrame(index=pd.Index([], name="Addr"))

    # --- per-FCU table
    T = fcu.copy()
    if al is not None:
        T = T.join(raised, how="outer")
        T = T.join(ep[ep.AlarmKey == "Comms Loss"].groupby("Address").agg(cl_downtime_s=("seconds", "sum"), cl_open=("end", lambda s: bool(s.isna().any()))), how="left")
    T = T.join(ctrl, how="left")
    T.index.name = "Addr"
    T = T[~T.index.isin(SYSTEM_ADDR)]
    num = [c for c in T.columns if c.startswith("n_") or c in ("cl_downtime_s", "ctrl_events", "Failures")]
    T[num] = T[num].apply(pd.to_numeric, errors="coerce").fillna(0)
    for c in ("n_Comms_Loss", "n_Manual_Movement", "n_Battery_Low", "n_General_Alarm", "cl_downtime_s", "Failures"):
        if c not in T: T[c] = 0
    T["cl_open"] = T.get("cl_open", False)
    T["cl_open"] = T["cl_open"].fillna(False).astype(bool)
    T["maint"] = (T.get("Status", "") == "Maintenance Required") if "Status" in T else False
    T["Health"] = (100 - np.minimum(40, 6 * T.n_Comms_Loss) - 20 * T.cl_open - 15 * T.maint
                   - np.minimum(15, 3 * T.Failures) - np.minimum(10, 2 * T.n_Manual_Movement)).clip(0, 100)
    feats = ["n_Comms_Loss", "cl_downtime_s", "Failures", "n_Manual_Movement", "n_Battery_Low", "n_General_Alarm", "ctrl_events"]
    X = T[feats].astype(float)
    T["Anomaly"] = 0.0
    if len(X) >= 10 and X.std().sum() > 0:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import RobustScaler
        iso = IsolationForest(n_estimators=300, contamination="auto", random_state=0).fit(RobustScaler().fit_transform(X))
        s = -iso.score_samples(RobustScaler().fit_transform(X))
        T["Anomaly"] = ((s - s.min()) / (s.max() - s.min() + 1e-9)).round(2)
    T["Rank"] = T.Health.rank(method="min")
    R["fcu"] = T.reset_index().sort_values(["Health", "Anomaly"], ascending=[True, False])

    # --- FCU findings
    for addr, r in T.iterrows():
        tag = f"FCU {addr}" + (f" ({r['Tag']})" if "Tag" in r and isinstance(r["Tag"], str) else "")
        if r.cl_open:
            fnd.append(F("High", "FCU", tag, "Comms Loss never cleared in log (offline at end)", f"{int(r.n_Comms_Loss)} Comms Loss events, {r.cl_downtime_s:.0f}s cleared downtime",
                         "First check the actuator has mains power: a powered-down field unit is bypassed on the loop and shows as Comms Loss. Then check loop wiring and the field unit card."))
        if r.n_Comms_Loss >= 3:
            fnd.append(F("Medium" if r.n_Comms_Loss < 10 else "High", "FCU", tag, "Repeated Comms Loss",
                         f"{int(r.n_Comms_Loss)} events, {r.cl_downtime_s:.0f}s total downtime",
                         "Intermittent comms: check this unit's supply, then cable screen continuity, insulation to earth and loop speed. Alarm needs 3 failed polls in a row, so the failure counter shows more than the alarm log."))
        if r.n_Manual_Movement and r.n_Manual_Movement >= 5:
            fnd.append(F("Low", "FCU", tag, "Frequent manual movement alarms", f"{int(r.n_Manual_Movement)} events", "Confirm local operation was intentional."))
    top = R["fcu"][R["fcu"].Anomaly >= 0.75].head(5)
    for _, r in top.iterrows():
        fnd.append(F("Info", "FCU", f"FCU {r.Addr}", "Unusual compared with peers (Isolation Forest)", f"anomaly score {r.Anomaly}, health {r.Health:.0f}", "Review alarms and loop-map entry for this device."))

    # --- loop segment findings
    classic = loops and "Link Type" in links.columns and links["Link Type"].str.lower().eq("classic").any()
    if loops and not classic:
        R["notes"].append("Loop map is not a Pakscan Classic loop: Position is only list order on a Modbus network, so neighbour-based cable-fault hints were skipped.")
    if loops and classic:
        f0 = fcu.reset_index().sort_values("Position")
        bad = (f0.Status != "Normal").to_numpy()
        i = 0
        while i < len(f0):
            if bad[i]:
                j = i
                while j + 1 < len(f0) and bad[j + 1]: j += 1
                if j - i + 1 >= 3:
                    seg = f0.iloc[i:j + 1]
                    fnd.append(F("Medium", "Loop", f"positions {seg.Position.min():.0f}-{seg.Position.max():.0f}", f"{len(seg)} adjacent devices in Maintenance Required",
                                 "addresses " + ", ".join(seg.Addr.astype(int).astype(str)),
                                 "Neighbours failing together on a Classic loop suggests a shared cause (cable section, junction, supply) rather than individual actuators. Check cable resistance/capacitance and screen continuity around these positions."))
                i = j + 1
            else:
                i += 1
    cmd = parse_commands(cmdlogs)
    R["cmd_decoded"] = cmd
    lf = (al[(al.Address.isin(SYSTEM_ADDR)) & (al.AlarmKey == "Classic Loop Fault") & (al.AlarmLevel != "Cleared")] if al is not None else None)
    R["reset_timeline"] = build_reset_timeline(R.get("datalog"), cmd, lf)
    if al is not None:
        if len(lf):
            near = ""
            rt = R["reset_timeline"]
            if len(rt):
                n = sum(((rt.time - t).abs() < pd.Timedelta("2min")).any() for t in lf.t)
                near = f"; {n} of them within 2 min of a loop/network reset (host or web)"
            fnd.append(F("High", "Loop", "10001", "Classic Loop Faults", f"{len(lf)} faults between {lf.t.min():%d %b %H:%M} and {lf.t.max():%d %b %H:%M}{near}",
                         "Check loop continuity. A loop fault shows where the break is when a loopback is present (Loop Diagnostics page). Faults right after a Reset loop or network reset may be caused by the reset itself."))

    # --- host traffic (Side B view of transactions)
    tx_all, cov_rows, gap_rows, cmd_rows = [], [], [], []
    for side, chan, df in hosts:
        tx, fr = parse_host(df, chan)
        tx["file_side"] = side
        tx_all.append(tx)
        c = side_a_coverage(fr)
        if c is not None:
            cov_rows.append(dict(file_side=side, channel=chan, **c))
        g = polling_gaps(fr); g["channel"], g["file_side"] = chan, side
        gap_rows.append(g)
    if tx_all:
        TX = pd.concat(tx_all, ignore_index=True)
        R["tx"] = TX
        T2 = TX[TX.status != "unmatched_response"]
        S = T2.groupby(["file_side", "channel", "ep"]).agg(
            requests=("status", "size"), answered=("status", lambda s: (s != "not_logged").sum()),
            exceptions=("status", lambda s: (s == "exception").sum()), bad=("status", lambda s: (s == "bad_length_or_echo").sum()),
            rt_p50=("rt_ms", "median"), rt_p95=("rt_ms", lambda s: s.quantile(.95)), rt_max=("rt_ms", "max")).round(1).reset_index()
        R["host_summary"] = S
        cls = T2.groupby(["file_side", "channel", "ep", "fc", "qty"]).status.agg(
            requests="size", answered=lambda s: (s != "not_logged").sum()).reset_index()
        cls["answered_%"] = (100 * cls.answered / cls.requests).round(1)
        R["request_classes"] = cls
        R["coverage"] = pd.DataFrame(cov_rows)
        R["gaps"] = pd.concat(gap_rows, ignore_index=True) if gap_rows else pd.DataFrame()
        for r in S.itertuples():
            tgt = f"Side {r.file_side} / {r.channel} / {r.ep}"
            exc_rate = 100 * r.exceptions / max(r.answered, 1)
            if r.exceptions:
                e = TX[(TX.file_side == r.file_side) & (TX.channel == r.channel) & (TX.ep == r.ep) & (TX.status == "exception")]
                top = e.groupby(["fc", "start", "qty", "exc"]).size().sort_values(ascending=False).head(3)
                ev = f"{r.exceptions} exceptions ({exc_rate:.1f}% of logged responses). Most common (fc,start,qty,code): " + "; ".join(f"{tuple(int(x) for x in k)}x{v}" for k, v in top.items())
                fnd.append(F("Medium" if exc_rate < 5 else "High", "Host Modbus", tgt, "Host receives Modbus exception responses", ev,
                             "Code 2 = illegal data address: the host reads registers that the selected RMS host database does not contain. Check the RMS host database setting and the DCS register range."))
            if r.bad:
                fnd.append(F("Medium", "Host Modbus", tgt, "Write echo mismatch", f"{r.bad} writes", "Echo differs from request: command may have been rejected."))
            if r.rt_p95 and r.rt_p95 > 500:
                fnd.append(F("Low", "Host Modbus", tgt, "Slow responses", f"p95 {r.rt_p95:.0f} ms, max {r.rt_max:.0f} ms", "Check RMS load and serial baud rate."))
        for r in cls.itertuples():
            tgt = f"Side {r.file_side} / {r.channel} / {r.ep}"
            if r.requests >= 20 and 5 < r._8 < 95:
                fnd.append(F("Medium", "Host Modbus", tgt, "Some requests get no response", f"fc{r.fc} start-class qty {int(r.qty)}: {r._8}% of {r.requests} answered",
                             "Partial loss suggests a real comms/timeout problem on this channel."))
            elif r.requests >= 20 and r._8 <= 5:
                fnd.append(F("Info", "Host Modbus", tgt, "No logged response for this request type", f"fc{r.fc} qty {int(r.qty)}: 0 of {r.requests} responses in analyser log",
                             "Consistent 0% usually means the analyser did not capture large responses, not a comms fault - confirm with a packet capture."))
        for r in R["coverage"].itertuples():
            if min(r.requests_heard, r.responses_heard) < 95:
                fnd.append(F("Medium", "Side A/B", f"{r.channel} (file Side {r.file_side})", "Side A does not log all frames Side B handles",
                             f"Side A also logged {r.requests_heard}% of requests and {r.responses_heard}% of responses",
                             "A standby side set to Passive only listens to the bus. Missing frames can mean an RS-485 cross-connection, termination or biasing problem on Side A, or a log-capture limit. Re-capture both sides at the same time."))
        if not R["gaps"].empty:
            for r in R["gaps"].itertuples():
                if r.median_gap_ms and r.max_gap_ms > 20 * r.median_gap_ms and r.max_gap_ms > 2000:
                    fnd.append(F("Medium", "Host Modbus", f"{r.channel}/{r.ep}", "Polling gap", f"max gap {r.max_gap_ms/1000:.1f}s vs median {r.median_gap_ms:.0f} ms",
                                 "Host stopped polling for a period: check DCS comms or network."))
    # command acknowledgement
    if tx_all:
        w = TX[TX.fc == 5]
        if len(w):
            ack = w.groupby(["file_side", "channel", "ep"]).status.apply(lambda s: round((s == "ok").sum() / max((s != "not_logged").sum(), 1) * 100, 1)).rename("write_ack_%").reset_index()
            R["write_ack"] = ack
            for r in ack.itertuples():
                if r._4 < 99 and (w[(w.file_side == r.file_side) & (w.channel == r.channel) & (w.ep == r.ep)].status != 'not_logged').any():
                    fnd.append(F("High", "Commands", f"Side {r.file_side}/{r.channel}/{r.ep}", "Write commands not echoed/acknowledged", f"{r._4}% acknowledged", "Check whether commands reached the RMS and were rejected."))

    # decoded host commands
    if len(cmd):
        act = cmd[cmd.value != 0]
        R["cmd_summary"] = (cmd.groupby(["channel", "scope", "command", "action"], dropna=False)
                            .agg(writes=("value", "size"), fcus=("fcu", "nunique"), first=("time", "min"), last=("time", "max")).reset_index())
        R["cmd_active"] = act.sort_values("time", ascending=False)
        who = lambda e: ", ".join(sorted({f"{c} {h}" for c, h in zip(e.channel, e.host)}))
        for key, label in (("Global ESD", "Global ESD"), ("Change master", "Change master (side changeover)")):
            e = act[act.command == key]
            if len(e):
                fnd.append(F("High", "Commands", "Master Station", f"{label} asserted by host",
                             f"{len(e)} non-zero write(s) between {e.time.min():%d %b %H:%M:%S} and {e.time.max():%d %b %H:%M:%S} from {who(e)}",
                             "Confirm with the DCS engineer that this was intended."))
        fe = act[(act.scope == "FCU") & (act.command == "ESD")]
        if len(fe):
            fnd.append(F("High", "Commands", "FCUs " + ", ".join(map(str, sorted(fe.fcu.dropna().astype(int).unique())[:15])),
                         "ESD asserted on FCU(s) by host", f"{len(fe)} non-zero ESD write(s), last {fe.time.max():%d %b %H:%M:%S}", "Confirm the ESD was intended."))
        fc_act = act[(act.scope == "FCU") & (act.command != "ESD")]
        fc_all = cmd[cmd.scope == "FCU"]
        if len(fc_act):
            br = ", ".join(f"{k} x{v}" for k, v in fc_act.command.value_counts().items())
            fnd.append(F("Info", "Commands", "FCUs", f"Host sent {len(fc_act)} FCU command(s): {br}",
                         f"to {fc_act.fcu.nunique()} FCU(s); last {fc_act.time.max():%d %b %H:%M:%S}", "Use the Commands tab to see which FCU and when."))
        elif len(fc_all):
            fnd.append(F("Info", "Commands", "FCUs", "No FCU Open/Close/Stop command was asserted in this capture",
                         f"The host only wrote 0x0000 (clear) to FCU command coils in the {len(fc_all)} writes captured",
                         "If you are chasing a command that did not work, it is not in this window: export the log right after the attempt."))
        unk = cmd[cmd.scope == "Unknown"]
        if len(unk) / len(cmd) > 0.2:
            fnd.append(F("Medium", "Commands", "Coil decoding", "Many host writes use coils outside the assumed host database",
                         f"{len(unk)} of {len(cmd)} writes. Names assume the Yokogawa / Honeywell SI database.",
                         "If the site uses the Generic database, coil numbers mean something else: check the RMS host database setting."))
    # log buffer coverage
    cv_ = R["log_coverage"]
    if len(cv_):
        full = cv_[cv_.status.str.startswith("Full")]
        if len(full):
            ev = "; ".join(f"{r.log}{' ' + r.channel if r.channel != '?' else ''}: {r.covers}" for r in full.drop_duplicates(["log", "channel"]).itertuples())
            fnd.append(F("Low", "Logs", f"{len(full)} log(s)", "Exported logs are at their buffer limit",
                         "Only the newest entries are kept. Time covered: " + ev,
                         "Export straight after an event. Clear the log before a planned capture so the window you need is not overwritten."))

    # syslog
    for side, s in sys_logs.items():
        R[f"syslog_{side}"] = s
        for r in s.head(40).itertuples():
            if "Failed to connect to Modbus server" in r.message:
                fnd.append(F("Medium", "RMS software", f"Side {side}", "RMS cannot connect to internal Modbus server", f"{r.count}x: {r.message}", "RTU channel service not reachable: check RTU port configuration/restart."))
            elif r.count >= 1000:
                fnd.append(F("Low", "RMS software", f"Side {side}", "High-volume error in syslog", f"{r.count}x [{r.source}] {r.message}", "Send to Rotork support if this is not seen on a healthy unit."))

    # restarts, loop driver and per-FCU Modbus analysis
    system_findings(R, al, R.get("episodes"), fcu if loops else None, boots)
    fcu_modbus_findings(R, fcu if loops else None)

    fnd.sort(key=lambda f: SEV_ORDER[f["severity"]])
    R["findings_df"] = pd.DataFrame(fnd)
    return R


# ---------------------------------------------------------------- upload guidance (used by the UI)
KIND_INFO = {
    "alarmlog": ("AlarmLog", "Alarm history per FCU: Comms Loss, loop faults, battery, local stop"),
    "loop_map": ("loop_map", "Loop layout, FCU tags, status and failure counts"),
    "datalog": ("DataLog", "Control and reset events (shows if resets caused loop faults)"),
    "hostanalyser": ("HostAnalyser", "Raw Modbus frames between host/DCS and RMS (ethernet, rtu1, rtu2)"),
    "hostcommandlog": ("HostCommandLog", "Write commands received from the host"),
    "syslogs": ("syslogs", "RMS system log archive (.tgz) with software warnings and errors"),
}


def describe_files(names):
    rows = []
    for n in names:
        kind, side, chan = meta(n)
        rows.append(dict(file=n, recognised="Yes" if kind else "No - name not recognised",
                         type=KIND_INFO[kind][0] if kind else "-", side=side if kind in ("alarmlog", "datalog", "hostanalyser", "hostcommandlog", "syslogs") else "-",
                         channel=chan if kind in ("hostanalyser", "hostcommandlog") else "-"))
    return pd.DataFrame(rows)


def capabilities(names):
    k = {meta(n)[0] for n in names}
    return [
        ("FCU health ranking and Comms Loss history", "alarmlog" in k, "AlarmLog"),
        ("FCU tags, status and failure counts", "loop_map" in k, "loop_map"),
        ("Loop faults vs reset commands", {"alarmlog", "datalog"} <= k, "AlarmLog + DataLog"),
        ("Host Modbus checks (exceptions, response time, polling)", "hostanalyser" in k, "HostAnalyser"),
        ("Command write acknowledgement", "hostanalyser" in k, "HostAnalyser"),
        ("RMS software errors", "syslogs" in k, "syslogs .tgz"),
    ]


# ---------------------------------------------------------------- Excel report
def build_excel(R):
    """Readable Excel report: real dates (yyyy-mm-dd hh:mm:ss), fitted column widths, bold header, frozen top row."""
    from openpyxl.styles import Font, Alignment
    from openpyxl.utils import get_column_letter
    sheets = {"Findings": R.get("findings_df"), "FCU health": R.get("fcu"), "Host summary": R.get("host_summary"),
              "Request types": R.get("request_classes"), "Side A vs B": R.get("coverage"),
              "Alarm episodes": R.get("episodes"), "System restarts": R.get("system_events"), "AIM episodes": R.get("aim_episodes"), "FCU Modbus summary": R.get("fcu_modbus"), "Commands summary": R.get("cmd_summary"),
              "Active commands": R.get("cmd_active"), "Log coverage": R.get("log_coverage"),
              "Loop map changes": R["loop_compare"].reset_index() if "loop_compare" in R else None,
              "Failure counters": R["failures_compare"].reset_index() if "failures_compare" in R else None}
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as w:
        for name, df in sheets.items():
            if df is None or len(df) == 0:
                continue
            df = df.copy()
            if name == "Alarm episodes":
                df = df.rename(columns={"start": "Start", "end": "End", "seconds": "Duration (s)"})
                df["Duration (s)"] = df["Duration (s)"].round(1)
            for c in df.select_dtypes(include=["datetime", "datetimetz"]).columns:
                df[c] = df[c].dt.floor("s")
            df.to_excel(w, sheet_name=name, index=False)
            ws = w.sheets[name]
            ws.freeze_panes = "A2"
            for j, col in enumerate(df.columns, start=1):
                letter = get_column_letter(j)
                is_dt = str(df[col].dtype).startswith("datetime")
                if is_dt:
                    width = 20
                    for cell in ws[letter][1:]:
                        cell.number_format = "yyyy-mm-dd hh:mm:ss"
                else:
                    longest = max([len(str(col))] + [len(str(v)) for v in df[col].head(500)])
                    width = min(max(longest + 2, 8), 60)
                    if longest > 60:
                        for cell in ws[letter][1:]:
                            cell.alignment = Alignment(wrap_text=True, vertical="top")
                ws.column_dimensions[letter].width = width
            for cell in ws[1]:
                cell.font = Font(bold=True)
        if not w.sheets:
            pd.DataFrame({"Result": ["No recognised log files were analysed."]}).to_excel(w, sheet_name="Result", index=False)
    return buf.getvalue()


# ---------------------------------------------------------------- boot log
def parse_boot(data):
    """Boot evidence from the syslog archive: boot time and whether the previous shutdown was clean."""
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as t:
            m = next((x for x in t.getmembers() if x.name.split("/")[-1] == "boot"), None)
            text = t.extractfile(m).read().decode("utf-8", "ignore") if m else ""
    except Exception:
        return {}
    pat = re.compile(r"^([A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d \d{4}): (.*)$")
    boot, unclean, notes = None, False, []
    for line in text.splitlines():
        g = pat.match(line)
        if not g:
            continue
        ts = pd.to_datetime(g[1], format="%a %b %d %H:%M:%S %Y", errors="coerce")
        boot = boot if boot is not None else ts
        if "recovering journal" in g[2]:
            unclean = True
        if "Free blocks count wrong" in g[2]:
            notes.append("free-block count was wrong and was repaired")
    return dict(boot_time=boot, unclean=unclean, notes=sorted(set(notes)))


# ---------------------------------------------------------------- restarts, AIM, loopback
def _fmt_dur(seconds):
    return _fmt_span(pd.Timedelta(seconds=float(seconds))) if pd.notna(seconds) else "never cleared"


def system_findings(R, al, ep, fcu, boots):
    fnd = R["findings"]
    R["boot_info"] = boots
    if al is None:
        return
    sysal = al[al.Address == 10000]
    # CPU restarts
    pu = sysal[sysal.AlarmKey.str.contains("Powered Up", na=False) & (sysal.AlarmLevel != "Cleared")].copy()
    rows = []
    if len(pu):
        pu["side"] = pu.AlarmKey.str.extract(r"SIDE ([AB])", expand=False).str.upper()
        oc = sysal[sysal.AlarmKey == "Other CPU Unavailable"].sort_values("t")
        wins, start = [], None
        for r in oc.itertuples():
            if r.AlarmLevel != "Cleared" and start is None:
                start = r.t
            elif r.AlarmLevel == "Cleared" and start is not None:
                wins.append((start, r.t)); start = None
        if start is not None:
            wins.append((start, pd.NaT))
        for side, g in pu.sort_values("t").groupby("side"):
            last = None
            for t in g.t:
                if last is not None and (t - last).total_seconds() < 10:
                    continue                       # both sides log the same restart
                last = t
                w = [w for w in wins if w[0] <= t and (pd.isna(w[1]) or 0 <= (t - w[1]).total_seconds() <= 120)]
                lost = w[-1][0] if w else pd.NaT
                rows.append(dict(restart_time=t, side=side, peer_lost_contact_at=lost,
                                 unreachable_before_restart=_fmt_span(t - lost) if pd.notna(lost) else ""))
    ev = pd.DataFrame(rows, columns=["restart_time", "side", "peer_lost_contact_at", "unreachable_before_restart"])
    R["system_events"] = ev
    for side, g in ev.groupby("side"):
        unclean = boots.get(side, {}).get("unclean") if boots else None
        extra = ""
        if boots.get(side):
            b = boots[side]
            extra = (f" Boot log of Side {side} at {b['boot_time']:%d %b %H:%M:%S}: " +
                     ("the filesystem journal had to be recovered, so the previous shutdown was NOT clean (power loss or hard reset)"
                      + (f"; {', '.join(b['notes'])}" if b["notes"] else "") if unclean else "no journal recovery (clean shutdown)") + ".")
        times = ", ".join(f"{t:%d %b %H:%M}" for t in g.restart_time.head(10))
        gaps = [x for x in g.unreachable_before_restart if x]
        fnd.append(F("High" if len(g) >= 2 else "Medium", "System", f"CPU Side {side}", f"Side {side} restarted {len(g)} time(s) in the alarm log",
                     f"Power-up alarms at: {times}. Before each one, the other side could not reach it for: {', '.join(gaps) if gaps else 'n/a'}.{extra}",
                     "The CPU was unreachable for minutes and then powered up, with a filesystem recovery at boot: that fits power being lost or the unit "
                     "being power-cycled, not a commanded reboot. An automatic watchdog restart would be back within about a minute or two. "
                     "Check the supply, connector and who or what cycled the power. The log from before the restart is lost on reboot, so the cause is not recorded."))
    # AIM (loop interface module) not found
    aim = sysal[sysal.AlarmKey.str.contains("Interface Not Found", na=False)].sort_values("t")
    if len(aim):
        log_end = al.t.max()
        rows = []
        for key, g in aim.groupby("AlarmKey"):
            side = key.split()[1][:1].upper()
            fails = g[g.AlarmLevel != "Cleared"]
            if not len(fails):
                continue
            last = fails.t.max()
            clears = g[(g.AlarmLevel == "Cleared") & (g.t > last)]
            rest = ev[(ev.side == side) & (ev.restart_time > last)] if len(ev) else ev
            if len(clears):
                end, how = clears.t.min(), "cleared"
            elif len(rest):
                end, how = rest.restart_time.min(), "ended by a restart of that side"
            else:
                end, how = log_end, "no clear recorded by end of log"
            rows.append(dict(alarm=key, failures=len(fails), first_failure=fails.t.min(), last_failure=last, ended=end, how_it_ended=how,
                             last_episode=_fmt_span(end - last)))
        R["aim_episodes"] = pd.DataFrame(rows)
        for r in rows:
            secs = (r["ended"] - r["last_failure"]).total_seconds()
            long_ = secs >= 300 and r["how_it_ended"] != "ended by a restart of that side"
            fnd.append(F("High" if long_ else "Medium", "System", r["alarm"], "Loop interface module (AIM) not found",
                         f"{r['failures']} event(s), last at {r['last_failure']:%d %b %H:%M:%S}; that episode lasted {r['last_episode']} ({r['how_it_ended']}).",
                         "The CPU could not detect this AIM (the module that drives the loop). Reseat or replace the module, check the backplane "
                         "connector, and compare the times with CPU restarts."))
    # loopback pairs
    lb = al[(al.AlarmKey == "Actuator Loop Back") & (al.AlarmLevel != "Cleared")].sort_values("t")
    if len(lb) >= 2:
        cl = (lb.t.diff().dt.total_seconds() > 5).cumsum()
        have = fcu is not None and len(fcu) and "Position" in fcu.columns
        loop_addrs = set(fcu.index.astype(int)) if have else set()
        missing = sorted(set(range(1, max(loop_addrs) + 1)) - loop_addrs) if loop_addrs else []
        comms = al[(al.AlarmKey == "Comms Loss") & (al.AlarmLevel != "Cleared")].groupby("Address").size()
        for _, g in lb.groupby(cl):
            a = sorted(g.Address.astype(int).unique())
            if len(a) < 2:
                continue
            between = [m for m in missing if a[0] < m < a[-1]]
            ev_txt = f"FCUs {', '.join(map(str, a))} went into loopback together at {g.t.min():%d %b %H:%M:%S}."
            if between:
                ev_txt += " Address " + ", ".join(map(str, between)) + " lies between them but is not in the loop map" + \
                          "".join(f" and logged {int(comms.get(m, 0))} Comms Loss event(s)" for m in between[:1]) + "."
            fnd.append(F("High", "Loop", f"FCUs {a[0]}-{a[-1]}", "FCUs on both sides of a point went into loopback",
                         ev_txt, "Loopback closes the loop at the break: the cable fault or dead unit lies between these two FCUs. "
                                 + (f"Check the supply, wiring and address setting of FCU {', '.join(map(str, between))}." if between else
                                    "Check the cable and terminals between them.")))


# ---------------------------------------------------------------- per-FCU Modbus trace (Yokogawa / Honeywell SI database)
BIT_NAMES = ["AUX1", "AUX2", "OAS (open)", "CAS (closed)", "STOP", "MOVE", "MRO", "MRC", "AUX3", "AUX4", "LBON", "NALM", "ALARM", "MEMF",
             "COMMS", "LOCAL", "POWR", "WDOG", "MREL", "THERM", "LSTOP", "SFAIL", "VOBS", "VJAM", "AUXOR", "VTT", "R", "MMOVE", "EOT"]
LOC_BASE = {1: 1, 2: 10001, 3: 40001, 4: 30001}


def fcu_items(n):
    """(name, function code, 1-based database location) of every value held for FCU n."""
    it = [("CAS closed (status pair)", 2, 10256 + 2 * n - 1), ("OAS open (status pair)", 2, 10256 + 2 * n)]
    it += [(nm, 2, 10736 + 240 * k + n) for k, nm in enumerate(BIT_NAMES)]
    it += [(f"Relay {r} status", 2, base + n) for r, base in ((4, 17696), (1, 17936), (3, 18176), (2, 18416))]
    it += [("Position", 4, 30000 + n), ("Analogue input 1", 4, 30240 + n), ("Analogue input 2", 4, 30480 + n),
           ("Pulse input", 4, 30720 + n), ("Current force", 4, 30960 + n), ("Setpoint readback", 3, 40000 + n),
           ("Close coil readback", 1, 31 + 2 * n), ("Open coil readback", 1, 32 + 2 * n),
           ("Open coil (individual) readback", 1, 512 + n), ("Stop coil readback", 1, 752 + n),
           ("Close coil (individual) readback", 1, 992 + n), ("ESD coil readback", 1, 1232 + n)]
    return it


def _extract(fc, first_loc, loc, resp):
    idx = loc - first_loc
    try:
        if fc in (1, 2):
            return (resp[3 + idx // 8] >> (idx % 8)) & 1
        return (resp[3 + 2 * idx] << 8) | resp[4 + 2 * idx]
    except (IndexError, TypeError):
        return None


def _fmt_val(item, v):
    return f"{v / 32767 * 100:.1f} %" if item in ("Position", "Setpoint readback") else str(int(v))


def fcu_trace(R, n, t0, t1, alarms_all=False):
    """Everything known about FCU n between t0 and t1: host commands, what the host polled/read, alarms, one merged timeline."""
    out, ev = {}, []
    cmd, tx, al = R.get("cmd_decoded"), R.get("tx"), R.get("alarms")
    if cmd is not None and len(cmd):
        c = cmd[(cmd.fcu == n) & cmd.time.between(t0, t1)].sort_values("time")
        out["commands"] = c
        for r in c[c.value != 0].itertuples():
            ev.append((r.time, "Host command", f"{r.command} {r.detail}".strip() + f" ({r.channel} {r.host})"))
    if tx is not None and len(tx):
        t = tx[tx.fc.isin([1, 2, 3, 4]) & tx.time.between(t0, t1)].drop_duplicates(["time", "ep", "fc", "start", "qty"])
        rows = []
        for name, fc, loc in fcu_items(n):
            first = t.start + LOC_BASE[fc]
            for r in t[(t.fc == fc) & (first <= loc) & (loc < first + t.qty)].itertuples():
                val = _extract(fc, int(r.start) + LOC_BASE[fc], loc, r.resp) if r.status == "ok" and isinstance(getattr(r, "resp", None), tuple) else None
                rows.append(dict(time=r.time, channel=r.channel, host=r.ep, item=name, location=loc, status=r.status, response_ms=r.rt_ms, value=val))
        P = pd.DataFrame(rows, columns=["time", "channel", "host", "item", "location", "status", "response_ms", "value"]).sort_values("time")
        out["polls"] = P
        if len(P):
            out["poll_summary"] = (P.groupby(["item", "channel", "host"]).agg(
                polls=("status", "size"), answered=("status", lambda s: int((s != "not_logged").sum())),
                exceptions=("status", lambda s: int((s == "exception").sum())), first=("time", "min"), last=("time", "max"),
                last_value=("value", lambda s: s.dropna().iloc[-1] if s.notna().any() else None)).reset_index())
            for item, g in P[P.value.notna()].groupby("item"):
                prev = None
                for r in g.itertuples():
                    if prev is None or r.value != prev:
                        ev.append((r.time, "Host read", f"{item} = {_fmt_val(item, r.value)}" + (" (first seen)" if prev is None else f" (was {_fmt_val(item, prev)})")))
                    prev = r.value
    if al is not None:
        a = al[al.Address == n]
        if not alarms_all:
            a = a[a.t.between(t0 - pd.Timedelta("10min"), t1 + pd.Timedelta("10min"))]
        out["alarms"] = a[["t", "AlarmKey", "AlarmLevel", "MasterstationSide"]].sort_values("t")
        for r in a.itertuples():
            ev.append((r.t, "Alarm", f"{r.AlarmKey}: {r.AlarmLevel} (Side {r.MasterstationSide[-1:]})"))
    tl = pd.DataFrame(ev, columns=["time", "source", "what"]).sort_values("time").reset_index(drop=True)
    out["timeline"] = tl
    return out


def fcu_modbus_summary(R, addrs, t0, t1):
    cmd, tx, al = R.get("cmd_decoded"), R.get("tx"), R.get("alarms")
    classes = None
    if tx is not None and len(tx):
        classes = (tx[tx.fc.isin([1, 2, 3, 4])].groupby(["channel", "ep", "fc", "start", "qty"])
                   .agg(n=("status", "size"), ans=("status", lambda s: int((s != "not_logged").sum()))).reset_index())
    rows = []
    for n in addrs:
        r = dict(FCU=int(n))
        if cmd is not None and len(cmd):
            c = cmd[(cmd.fcu == n) & cmd.time.between(t0, t1)]
            act = c[c.value != 0]
            r.update(commands_sent=len(act), clear_writes=int((c.value == 0).sum()), last_command=act.time.max() if len(act) else pd.NaT)
        if classes is not None:
            items, polled, tot, ans = fcu_items(n), set(), 0, 0
            for cl in classes.itertuples():
                first = cl.start + LOC_BASE[cl.fc]
                if any(f == cl.fc and first <= loc < first + cl.qty for _, f, loc in items):
                    tot += cl.n; ans += cl.ans; polled.add(cl.channel)
            r.update(polled_by=", ".join(sorted(polled)) or "no host reads this FCU", polls=tot, responses_logged_pct=round(100 * ans / tot, 1) if tot else None)
        if al is not None:
            a = al[al.Address == n]
            r.update(comms_loss_events=int(((a.AlarmKey == "Comms Loss") & (a.AlarmLevel != "Cleared")).sum()), alarm_events_in_window=int(a.t.between(t0, t1).sum()))
        rows.append(r)
    return pd.DataFrame(rows)


def fcu_modbus_findings(R, fcu):
    """Which FCUs does each host channel read? Flags loop FCUs that a channel never reads."""
    tx = R.get("tx")
    if tx is None or not len(tx):
        R["host_window"] = R["full_window"] = None
        return
    allt = pd.concat([tx.time.dropna(), (R["cmd_decoded"].time.dropna() if len(R.get("cmd_decoded", [])) else pd.Series(dtype="datetime64[ns]"))])
    R["host_window"] = (tx.time.min(), tx.time.max()) if tx.time.notna().any() else None      # HostAnalyser range
    R["full_window"] = (allt.min(), allt.max()) if len(allt) else None
    if R["full_window"] is not None and "fcu" in R:
        R["fcu_modbus"] = fcu_modbus_summary(R, sorted(int(a) for a in R["fcu"]["Addr"].dropna()), *R["full_window"])
    if fcu is None or not len(fcu):
        return
    addrs = sorted(int(a) for a in fcu.index if a not in SYSTEM_ADDR)
    for ch, g in tx[tx.fc == 4].dropna(subset=["start", "qty"]).groupby("channel"):
        covered = set()
        for cl in g.drop_duplicates(["start", "qty"]).itertuples():
            lo, hi = int(cl.start) + 30001, int(cl.start) + 30000 + int(cl.qty)
            covered |= {loc - 30000 for loc in range(max(lo, 30001), min(hi, 30240) + 1)}
        miss = [a for a in addrs if a not in covered]
        if miss and covered:
            rng = f"{min(miss)}-{max(miss)}" if len(miss) > 2 else ", ".join(map(str, miss))
            R["findings"].append(F("Info", "Host Modbus", f"{ch} host(s)", "Host never reads the position of some loop FCUs",
                                   f"Position registers read cover FCU {min(covered)}-{max(covered)}; loop FCUs not read: {rng} ({len(miss)})",
                                   "If the DCS should show these FCUs on this channel, extend its read ranges; if another channel covers them, ignore."))
