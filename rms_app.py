"""RMS Troubleshooter - run with:  streamlit run rms_app.py
Upload the RMS exports (AlarmLog, DataLog, HostAnalyser_*, HostCommandLog_*, loop_map, syslogs .tgz) from Side A and/or Side B."""
import io
import pandas as pd
import streamlit as st
import rms_analyzer as ra

st.set_page_config(page_title="RMS Troubleshooter", layout="wide")

if "uploader_key" not in st.session_state:
    st.session_state.uploader_key = 0


def reset_all():
    """Forget the uploaded files and the saved analysis so the next RMS files start clean."""
    st.cache_data.clear()
    st.session_state.uploader_key += 1

st.title("Rotork Master Station - troubleshooting analyser")
st.caption("Read-only analysis of exported RMS logs. Nothing is sent to the RMS or DCS, and this app does not save your files.")

with st.sidebar:
    st.button("Start new analysis (clear all data)", on_click=reset_all, type="primary", key="reset_sidebar", use_container_width=True)
    st.header("About")
    st.write("Upload the log exports from your Rotork Master Station (Side A and/or Side B) and get a ranked list of problems to check.")
    st.link_button("Rotork Master Station (rotork.com)", "https://www.rotork.com/products-and-services/control-networks/master-station")
    st.caption("REMARK! This is an unofficial tool, not made or endorsed by ROTORK. Just use it as a guide for where to look, then confirm on the Rotork Masterstation (RMS) and in the field. "
               "If hosted on a cloud service, uploaded files are processed on that service's servers - Remember to follow your company's data policy.")

st.subheader("How it works")
c1, c2, c3 = st.columns(3)
with c1.container(border=True):
    st.markdown("**1. Export**")
    st.write("From the RMS utility, export the log files for Side A and/or Side B. Keep the original file names.")
with c2.container(border=True):
    st.markdown("**2. Upload**")
    st.write("Drop all the files in the box below at once. The app shows which ones it recognised.")
with c3.container(border=True):
    st.markdown("**3. Read the results**")
    st.write("Start at **Findings** (High first), then check **FCU health** and **Host Modbus**.")

with st.expander("Which files do I need?", expanded=True):
    st.markdown("**Minimum for a useful result:** `AlarmLog` + `loop_map`. Add more files to unlock more checks.")
    st.table(pd.DataFrame([(v[0] + "_...", v[1]) for v in ra.KIND_INFO.values()], columns=["File name starts with", "What it gives you"]))
    st.markdown("Names should also contain `sideA` or `sideB`, and for host files `ethernet`, `rtu1` or `rtu2` "
                "(for example `HostAnalyser_MRR2-MS-1B-Right_sideB_primary_rtu1.csv`). Excel (.xlsx) copies work too. "
                "You can upload Side A and Side B together.")

ups = st.file_uploader("Upload Side A and/or Side B files (CSV, XLSX, syslogs .tgz)", accept_multiple_files=True,
                       type=["csv", "xlsx", "xls", "tgz"], key=f"uploader_{st.session_state.uploader_key}")
if not ups:
    st.info("Waiting for files. Select all the exported files at once -I advise upload SideA and SideB of all logs files from under Utilities - that you can pick many in the log files.")
    st.stop()

files = {u.name: u.getvalue() for u in ups}

st.subheader("Files received")
st.button("Start new analysis (clear all data)", on_click=reset_all, key="reset_main")
desc = ra.describe_files(list(files))
st.dataframe(desc, use_container_width=True, hide_index=True)
if (desc.recognised != "Yes").any():
    st.warning("Some files were not recognised and will be ignored. Check that the file names still start with AlarmLog, DataLog, "
               "HostAnalyser, HostCommandLog, loop_map or syslogs.")
if ((desc.side == "?") & (desc.type != "-")).any():
    st.warning("Some files have no sideA / sideB in the name, so their side shows as '?'. Results still work, but Side A vs Side B comparisons may be unclear.")
caps = ra.capabilities(list(files))
st.markdown("**What this upload lets you analyse**")
for label, ok, need in caps:
    st.write(("✅ " if ok else "➖ ") + label + ("" if ok else f"  _(add: {need})_"))


@st.cache_data(show_spinner="Analysing...")
def run(files, main_loop, version):
    return ra.analyze(files, main_loop)


loops = [n for n in files if n.lower().startswith("loop_map")]
main_loop = st.sidebar.selectbox("Main loop map (for per-FCU status)", loops) if loops else None
R = run(files, main_loop, getattr(ra, "VERSION", "0"))
for n in R["notes"]:
    st.sidebar.info(n)

cov = R.get("log_coverage")
if cov is not None and len(cov):
    full = cov[cov.status.str.startswith("Full")]
    with st.expander("Log coverage" + (f" - {len(full)} of {len(cov)} logs are at their buffer limit" if len(full) else ""), expanded=False):
        if len(full):
            st.warning("These logs keep only the newest entries (alarm log 1,000, other logs 10,000). Older events were overwritten, so the "
                       "time covered can be short, especially for the serial host logs. Export right after an event.")
        st.dataframe(cov, use_container_width=True, hide_index=True)

fd = R["findings_df"]
c = st.columns(4)
for col, sev in zip(c, ["High", "Medium", "Low", "Info"]):
    col.metric(sev, int((fd.severity == sev).sum()) if not fd.empty else 0)

tabs = st.tabs(["Findings", "FCU health", "Alarm timeline", "Loop map", "Host Modbus", "Commands", "FCU trace", "System events", "System log", "Export"])

with tabs[0]:
    if fd.empty:
        st.success("No findings.")
    else:
        sev = st.multiselect("Severity", ["High", "Medium", "Low", "Info"], default=["High", "Medium"])
        area = st.multiselect("Area", sorted(fd.area.unique()), default=sorted(fd.area.unique()))
        v = fd[fd.severity.isin(sev) & fd.area.isin(area)]
        for r in v.itertuples():
            icon = {"High": "🔴", "Medium": "🟠", "Low": "🟡", "Info": "🔵"}[r.severity]
            with st.expander(f"{icon} {r.target} - {r.title}"):
                st.write(f"**Evidence:** {r.evidence}")
                st.write(f"**What to check:** {r.action}")

with tabs[1]:
    T = R["fcu"]
    st.caption("Health = 100 minus penalties for comms loss, offline-at-end, maintenance status, loop-map failures, manual movement. "
               "Anomaly = Isolation Forest score vs peer FCUs (1 = most unusual).")
    cols = [c for c in ["Addr", "Tag", "Type", "Port", "Position", "Status", "Failures", "n_Comms_Loss", "cl_downtime_s", "cl_open",
                        "n_Manual_Movement", "n_Battery_Low", "n_General_Alarm", "ctrl_events", "Health", "Anomaly"] if c in T]
    st.dataframe(T[cols], use_container_width=True, hide_index=True)
    st.bar_chart(T.sort_values("Addr").set_index("Addr")["Health"])

with tabs[2]:
    if "episodes" in R:
        ep = R["episodes"]
        key = st.selectbox("Alarm type", sorted(ep.AlarmKey.unique()), index=sorted(ep.AlarmKey.unique()).index("Comms Loss") if "Comms Loss" in set(ep.AlarmKey) else 0)
        e = ep[ep.AlarmKey == key]
        st.dataframe(e, use_container_width=True, hide_index=True)
        st.scatter_chart(e.assign(t=e.start).rename(columns={"seconds": "duration_s"}).fillna({"duration_s": 0}), x="t", y="Address", size="duration_s")
    else:
        st.write("No AlarmLog uploaded.")

with tabs[3]:
    for n in R["notes"]:
        if n.startswith(("Loop map", "Loop map '")):
            st.info(n)
    if "failures_compare" in R:
        st.subheader("Failure counter per FCU in each loop-map snapshot")
        st.caption("The counter counts every failed poll and is cleared by a Reset loop. A snapshot with all zeros was probably taken just after a reset.")
        st.dataframe(R["failures_compare"][R["failures_compare"].max(axis=1) > 0], use_container_width=True)
    if "loop_compare" in R:
        st.subheader("FCUs whose status differs between loop-map snapshots")
        st.dataframe(R["loop_compare"], use_container_width=True)
    if "links" in R:
        st.subheader("Loop links")
        st.dataframe(R["links"], use_container_width=True, hide_index=True)

with tabs[4]:
    if "host_summary" in R:
        st.subheader("Per channel / host (as seen by Side B)")
        st.dataframe(R["host_summary"], use_container_width=True, hide_index=True)
        st.subheader("Request types and how many responses were logged")
        st.dataframe(R["request_classes"], use_container_width=True, hide_index=True)
        if len(R["coverage"]):
            st.subheader("Side A vs Side B on RTU (% of Side B frames Side A also logged)")
            st.dataframe(R["coverage"], use_container_width=True, hide_index=True)
        st.subheader("Polling gaps")
        st.dataframe(R["gaps"], use_container_width=True, hide_index=True)
    else:
        st.write("No HostAnalyser files uploaded.")

with tabs[5]:
    cmd = R.get("cmd_decoded")
    st.caption("Host write commands decoded with the Yokogawa / Honeywell SI host database: coil 1 Global ESD, 15 Change master, 16 Reset loop, "
               "32 Alarm accept, 33-512 FCU Close/Open pairs, 513 and up individual Open / Stop / Close / ESD. "
               "A write of 0x0000 clears a command; only non-zero writes act.")
    if cmd is None or cmd.empty:
        st.write("No HostCommandLog uploaded.")
    else:
        act = R.get("cmd_active", cmd[cmd.value != 0])
        st.subheader("Commands that were actually asserted (non-zero)")
        if act.empty:
            st.success("None in this capture. The host only wrote 0x0000 (clear).")
        else:
            st.dataframe(act, use_container_width=True, hide_index=True)
        st.subheader("All decoded writes, summarised")
        st.dataframe(R.get("cmd_summary", cmd), use_container_width=True, hide_index=True)

with tabs[6]:
    st.caption("Pick one FCU and a time window to see the Modbus commands sent to it, what the host read back about it, and its alarms in one timeline. "
               "Decoded with the Yokogawa / Honeywell SI host database.")
    win, hw = R.get("full_window"), R.get("host_window")
    if win is None or R.get("tx") is None:
        st.write("Upload HostAnalyser (and HostCommandLog) files to use this view.")
    elif win[0] >= win[1]:
        st.write("The host logs cover too short a time to trace.")
    else:
        FT = R["fcu"]
        fcus = sorted(int(x) for x in FT["Addr"].dropna().unique()) or list(range(1, 84))
        tags = dict(zip(FT["Addr"].dropna().astype(int), FT["Tag"])) if "Tag" in FT else {}
        c1, c2 = st.columns([1, 3])
        n = c1.selectbox("FCU", fcus, format_func=lambda x: f"{x}  {tags.get(x, '') if isinstance(tags.get(x, ''), str) else ''}".strip())
        lo, hi = win[0].to_pydatetime(), win[1].to_pydatetime()
        d0, d1 = (hw or win)[0].to_pydatetime(), (hw or win)[1].to_pydatetime()
        t0, t1 = c2.slider("Time window", min_value=lo, max_value=hi, value=(max(lo, d0), min(hi, d1)), format="DD MMM HH:mm:ss")
        all_alarms = st.checkbox("Show this FCU's alarms from the whole alarm log", value=False)
        tr = ra.fcu_trace(R, int(n), pd.Timestamp(t0), pd.Timestamp(t1), alarms_all=all_alarms)
        cm = tr.get("commands", pd.DataFrame(columns=ra.CMD_COLS))
        m = st.columns(4)
        m[0].metric("Commands sent (non-zero)", int((cm.value != 0).sum()) if len(cm) else 0)
        m[1].metric("Clear writes (0x0000)", int((cm.value == 0).sum()) if len(cm) else 0)
        m[2].metric("Host reads of this FCU", len(tr.get("polls", [])))
        m[3].metric("Alarm events", len(tr.get("alarms", [])))
        st.subheader("Timeline")
        tl = tr["timeline"]
        if len(tl):
            st.dataframe(tl, use_container_width=True, hide_index=True)
        else:
            st.write("Nothing recorded for this FCU in the window.")
        st.subheader("Host commands to this FCU")
        show_clear = st.checkbox("Include clear (0x0000) writes", value=False)
        cmv = cm if show_clear else cm[cm.value != 0]
        if len(cmv):
            st.dataframe(cmv.drop(columns=["scope"], errors="ignore"), use_container_width=True, hide_index=True)
        else:
            st.write("No non-zero command or setpoint was sent to this FCU in the window.")
        st.subheader("What the host read about this FCU")
        ps = tr.get("poll_summary")
        if ps is not None and len(ps):
            st.caption("Replies of 250 bytes are not captured by the analyser, so some reads show 0 answered.")
            st.dataframe(ps, use_container_width=True, hide_index=True)
            P = tr["polls"]
            pos = P[(P.item == "Position") & P.value.notna()]
            if len(pos):
                st.line_chart(pos.assign(percent=pos.value / 32767 * 100).set_index("time")["percent"])
        else:
            st.write("No host read covers this FCU in the window.")
        st.subheader("Alarms for this FCU")
        al_ = tr.get("alarms")
        if al_ is not None and len(al_):
            st.dataframe(al_, use_container_width=True, hide_index=True)
        else:
            st.write("No alarms in the window.")
        with st.expander("All FCUs - overview for the same window"):
            st.dataframe(ra.fcu_modbus_summary(R, fcus, pd.Timestamp(t0), pd.Timestamp(t1)), use_container_width=True, hide_index=True)

with tabs[7]:
    ev = R.get("system_events")
    st.subheader("CPU restarts (power-up alarms)")
    if ev is not None and len(ev):
        st.dataframe(ev, use_container_width=True, hide_index=True)
    else:
        st.write("No power-up alarms in the alarm log.")
    aim = R.get("aim_episodes")
    if aim is not None and len(aim):
        st.subheader("Loop interface module (AIM) not found")
        st.dataframe(aim, use_container_width=True, hide_index=True)
    bi = R.get("boot_info")
    if bi:
        st.subheader("Boot evidence from the syslog archive")
        st.dataframe(pd.DataFrame([dict(side=k, boot_time=v.get("boot_time"), previous_shutdown="NOT clean (journal recovered)" if v.get("unclean") else "clean",
                                        notes=", ".join(v.get("notes", []))) for k, v in bi.items()]), use_container_width=True, hide_index=True)
    st.subheader("Related findings")
    rel = fd[fd.area.isin(["System", "Loop"])] if not fd.empty else fd
    if len(rel):
        st.dataframe(rel[["severity", "target", "title", "evidence", "action"]], use_container_width=True, hide_index=True)

with tabs[8]:
    for k in [k for k in R if k.startswith("syslog_")]:
        st.subheader(f"Side {k[-1]} - top warnings/errors")
        st.dataframe(R[k].head(30), use_container_width=True, hide_index=True)
    if not any(k.startswith("syslog_") for k in R):
        st.write("No syslog .tgz uploaded.")

with tabs[9]:
    xlsx_bytes = ra.build_excel(R)
    st.download_button("Download troubleshooting report (Excel)", xlsx_bytes, "rms_troubleshooting_report.xlsx",
                       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    md = "# RMS troubleshooting report\n\n" + "\n".join(
        f"- **[{r.severity}] {r.target}: {r.title}** - {r.evidence}. _Check:_ {r.action}" for r in fd.itertuples())
    st.download_button("Download findings (Markdown)", md, "rms_findings.md")
