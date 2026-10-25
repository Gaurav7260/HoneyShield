"""HoneyShield local research dashboard.

Run from the HoneyShield project root with: streamlit run app/dashboard.py
All charts are calculated from CSV files stored in results/; no data is uploaded.
"""
from pathlib import Path
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"

st.set_page_config(page_title="HoneyShield | Research Dashboard", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.block-container {padding-top: 1.4rem; padding-bottom: 2rem;}
.hero {padding: 1.15rem 1.35rem; border-radius: 16px; background: linear-gradient(120deg,#101c35,#173c54); color: white; margin-bottom: 1rem; border: 1px solid #2a6072;}
.hero h1 {margin:0 0 .35rem 0; color:white; font-size:2rem;}
.hero p {margin:0; color:#d7e9f0;}
.small-note {font-size:.88rem; color: #718096;}
</style>
<div class="hero"><h1>🛡️ HoneyShield</h1><p>Evaluating honey-token enforcement at tool-call boundaries in RAG-based LLM applications</p></div>
""", unsafe_allow_html=True)

@st.cache_data
def load_csv(name):
    path = RESULTS / name
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path)

def bool_series(series):
    return series.astype(str).str.strip().str.lower().isin(["true", "1", "yes"])

def rate(n, d):
    return f"{(100*n/d):.1f}%" if d else "N/A"

pilot = load_csv("paired_live_pilot_v3_10rep.csv")
holdout = load_csv("holdout_guard_evaluation_v2.csv")
benign = load_csv("benign_stress_evaluation.csv")
positive = load_csv("positive_stress_evaluation.csv")
latency = load_csv("guard_latency_benchmark.csv")
manifest = load_csv("reproducibility_manifest.csv")

with st.sidebar:
    st.title("Dashboard controls")
    page = st.radio("Section", ["Overview", "Boundary experiment", "Guard evaluation", "Latency & reproducibility", "Explore raw data"])
    st.divider()
    st.caption("Local-first dashboard. It reads project CSVs from the results/ folder.")
    st.caption("No external tool execution is performed by this dashboard.")

if page == "Overview":
    st.subheader("Project overview")
    st.write("This dashboard summarizes the supplied HoneyShield experiment outputs. It is a research/analysis view, not a live security monitoring console.")
    if not pilot.empty:
        valid = ~pilot["model_error"].fillna("").astype(str).str.strip().ne("")
        # Treat blank/NaN model_error as valid; nonblank values are errors.
        valid = pilot["model_error"].isna() | pilot["model_error"].astype(str).str.strip().eq("")
        p = pilot[valid].copy()
        c = p[p.configuration == "C_boundary_output"]
        disclosures = int(bool_series(p["disclosure"]).sum())
        c_disclosures = int(bool_series(c["disclosure"]).sum())
        k1,k2,k3,k4 = st.columns(4)
        k1.metric("Pilot rows", f"{len(pilot)}", help="Rows in the saved paired live pilot CSV")
        k2.metric("Valid decisions", f"{len(p)} / {len(pilot)}")
        k3.metric("Baseline disclosures", int(bool_series(p[p.configuration == "A_baseline"]["disclosure"]).sum()))
        k4.metric("Boundary + output disclosures", c_disclosures)
        summary = p.groupby("configuration", as_index=False).agg(
            valid_decisions=("trial_id", "count"),
            disclosures=("disclosure", lambda s: int(bool_series(s).sum())),
            boundary_blocks=("boundary_blocked", lambda s: int(bool_series(s).sum())),
            output_blocks=("output_blocked", lambda s: int(bool_series(s).sum())),
            tool_dispatches=("tool_dispatched", lambda s: int(bool_series(s).sum())),
        )
        labels = {"A_baseline":"A — Baseline", "B_output_only":"B — Output-only", "C_boundary_output":"C — Boundary + output"}
        summary["configuration"] = summary.configuration.map(labels).fillna(summary.configuration)
        st.markdown("#### Paired live pilot comparison")
        st.bar_chart(summary.set_index("configuration")[["disclosures", "boundary_blocks", "output_blocks"]])
        st.dataframe(summary, use_container_width=True, hide_index=True)
    else:
        st.warning("The paired live pilot CSV is missing from results/.")
    st.markdown("#### Guard evaluation at a glance")
    a,b,c = st.columns(3)
    if not holdout.empty:
        pos = holdout.label.eq("full_positive")
        ben = holdout.label.eq("benign")
        edge = holdout.label.isin(["partial", "long_identifier"])
        text_col, args_col = "base64_v3_text_blocked", "base64_v3_args_blocked"
        a.metric("Holdout full-positive detection", rate(int(bool_series(holdout.loc[pos,text_col]).sum()), int(pos.sum())))
        b.metric("Holdout benign false positives", f"{int(bool_series(holdout.loc[ben,text_col]).sum())} / {int(ben.sum())}")
        c.metric("Edge cases blocked", f"{int(bool_series(holdout.loc[edge,text_col]).sum())} / {int(edge.sum())}")
    st.info("Interpretation: these are results on supplied synthetic test cases. They are not estimates of real-world attack detection rates and do not establish protection against unseen attacks.")

elif page == "Boundary experiment":
    st.subheader("Boundary enforcement experiment")
    if pilot.empty:
        st.error("Missing results/paired_live_pilot_v3_10rep.csv")
    else:
        scenarios = ["All scenarios"] + sorted(pilot.scenario.dropna().unique().tolist())
        selected = st.selectbox("Scenario filter", scenarios)
        d = pilot if selected == "All scenarios" else pilot[pilot.scenario == selected]
        valid = d[d.model_error.isna() | d.model_error.astype(str).str.strip().eq("")].copy()
        configs = ["A_baseline", "B_output_only", "C_boundary_output"]
        rows=[]
        for conf in configs:
            q=valid[valid.configuration==conf]
            rows.append({"Configuration":conf,"Valid decisions":len(q),"Disclosures":int(bool_series(q.disclosure).sum()),"Boundary blocks":int(bool_series(q.boundary_blocked).sum()),"Output blocks":int(bool_series(q.output_blocked).sum()),"Tool dispatches":int(bool_series(q.tool_dispatched).sum())})
        result=pd.DataFrame(rows)
        left,right=st.columns([1.2,1])
        with left:
            st.markdown("##### Outcomes by configuration")
            st.bar_chart(result.set_index("Configuration")[["Disclosures","Boundary blocks","Output blocks"]])
        with right:
            st.markdown("##### Scenario composition")
            st.dataframe(valid.groupby(["scenario","configuration"],as_index=False).agg(
                valid_rows=("trial_id","count"),
                disclosures=("disclosure",lambda s:int(bool_series(s).sum())),
                boundary_blocks=("boundary_blocked",lambda s:int(bool_series(s).sum())),
                output_blocks=("output_blocked",lambda s:int(bool_series(s).sum())),
                dispatches=("tool_dispatched",lambda s:int(bool_series(s).sum())),
            ), use_container_width=True, hide_index=True)
        st.dataframe(result, use_container_width=True, hide_index=True)
        st.caption("Rows with a non-empty model_error are excluded from valid-decision counts. The experiment replays paired model decisions across configurations; it is a controlled pilot, not a large-scale benchmark.")
        with st.expander("Inspect trial-level records"):
            st.dataframe(d, use_container_width=True, hide_index=True)

elif page == "Guard evaluation":
    st.subheader("Guard candidate evaluation")
    if holdout.empty:
        st.error("Missing results/holdout_guard_evaluation_v2.csv")
    else:
        label_names={"full_positive":"Full positive","benign":"Benign","partial":"Partial token","long_identifier":"Long identifier"}
        holdout["Label group"] = holdout.label.map(label_names).fillna(holdout.label)
        groups=st.multiselect("Case groups", options=sorted(holdout["Label group"].unique()), default=sorted(holdout["Label group"].unique()))
        subset=holdout[holdout["Label group"].isin(groups)].copy()
        candidates=[("Baseline","baseline_text_blocked","baseline_args_blocked"),("Normalized v2","normalized_v2_text_blocked","normalized_v2_args_blocked"),("Punctuation v1","punctuation_v1_text_blocked","punctuation_v1_args_blocked"),("Base64 v1","base64_v1_text_blocked","base64_v1_args_blocked"),("Base64 v2","base64_v2_text_blocked","base64_v2_args_blocked"),("Base64 v3","base64_v3_text_blocked","base64_v3_args_blocked")]
        rows=[]
        for name,tc,ac in candidates:
            if tc not in subset or ac not in subset: continue
            pos=subset.label.eq("full_positive")
            ben=subset.label.eq("benign")
            edge=subset.label.isin(["partial","long_identifier"])
            rows.append({"Candidate":name,"Full-positive detected":f"{int(bool_series(subset.loc[pos,tc]).sum())}/{int(pos.sum())}","Positive detection %":(100*bool_series(subset.loc[pos,tc]).sum()/pos.sum()) if pos.sum() else None,"Benign false positives":f"{int(bool_series(subset.loc[ben,tc]).sum())}/{int(ben.sum())}","Edge cases blocked":f"{int(bool_series(subset.loc[edge,tc]).sum())}/{int(edge.sum())}","Argument blocks (all selected)":int(bool_series(subset[ac]).sum())})
        metrics=pd.DataFrame(rows)
        if not metrics.empty:
            st.markdown("##### Text guard candidate comparison")
            st.bar_chart(metrics.set_index("Candidate")[["Positive detection %"]].fillna(0))
            st.dataframe(metrics, use_container_width=True, hide_index=True)
        st.markdown("##### Stress tests")
        x,y=st.columns(2)
        if not benign.empty:
            x.metric("Benign stress false positives", f"{int(bool_series(benign.text_blocked).sum())}/{len(benign)}", help="Number of benign cases blocked by text guard")
            x.metric("Benign stress argument blocks", f"{int(bool_series(benign.args_blocked).sum())}/{len(benign)}")
        if not positive.empty:
            y.metric("Positive stress detections (text)", f"{int(bool_series(positive.text_blocked).sum())}/{len(positive)}")
            y.metric("Positive stress detections (arguments)", f"{int(bool_series(positive.args_blocked).sum())}/{len(positive)}")
        st.warning("The v3 guard was developed iteratively against known failure cases. Perfect scores on constructed examples should not be presented as independent proof of generalization.")
        with st.expander("Inspect holdout records"):
            show_cols=[c for c in ["case","label","test_input","base64_v3_text_blocked","base64_v3_text_reason","base64_v3_args_blocked","base64_v3_args_reason"] if c in subset]
            st.dataframe(subset[show_cols], use_container_width=True, hide_index=True)

elif page == "Latency & reproducibility":
    st.subheader("Guard-only latency")
    if latency.empty:
        st.warning("Latency benchmark CSV is missing.")
    else:
        st.caption("Microbenchmark only: excludes Ollama inference, retrieval, and tool execution.")
        st.dataframe(latency, use_container_width=True, hide_index=True)
        if {"case","guard","median_ms","p95_ms"}.issubset(latency.columns):
            pivot=latency.pivot(index="case",columns="guard",values="median_ms")
            st.markdown("##### Median latency by test case (ms)")
            st.bar_chart(pivot)
    st.markdown("#### Reproducibility manifest")
    if not manifest.empty:
        st.dataframe(manifest, use_container_width=True, hide_index=True)
        st.caption("The manifest records expected row/column counts and hashes for listed CSV files. It is not, by itself, proof that every experiment was regenerated from raw inputs.")
    else:
        st.info("No reproducibility manifest found.")

else:
    st.subheader("Explore raw experiment data")
    files=sorted(p.name for p in RESULTS.glob("*.csv"))
    if not files:
        st.warning("No CSV files found in results/.")
    else:
        filename=st.selectbox("CSV dataset",files)
        raw=load_csv(filename)
        st.write(f"**{filename}** · {len(raw):,} rows · {len(raw.columns):,} columns")
        search=st.text_input("Search visible rows", placeholder="Type a word, case ID, scenario, or configuration")
        view=raw
        if search:
            mask=view.astype(str).apply(lambda col: col.str.contains(search, case=False, na=False)).any(axis=1)
            view=view[mask]
        st.dataframe(view, use_container_width=True, hide_index=True)
        st.download_button("Download filtered CSV", data=view.to_csv(index=False).encode("utf-8"), file_name=filename, mime="text/csv")

st.divider()
st.caption("HoneyShield research prototype · Synthetic canaries and local mock tools · Results are limited to the included datasets and threat model.")
