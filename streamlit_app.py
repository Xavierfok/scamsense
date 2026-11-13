"""ScamSense: paste a suspicious message, find out if it's a scam.

Run locally:   streamlit run streamlit_app.py
AI key:        GROQ_API_KEY in .streamlit/secrets.toml, a .env file, or an
               environment variable. Without it the app uses the rule checker only.
"""

import html
import os

import streamlit as st

from analyzer import check_message
from rules import defang

st.set_page_config(page_title="ScamSense: Is this message a scam?", page_icon="🛡️", layout="wide")

# --- API key: Streamlit secrets (cloud) > .env file (local) > environment ---
try:
    if "GROQ_API_KEY" in st.secrets:
        os.environ["GROQ_API_KEY"] = st.secrets["GROQ_API_KEY"]
except Exception:
    pass  # no secrets.toml locally; that's fine
if os.path.exists(".env"):
    for line in open(".env", encoding="utf-8"):
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.strip().split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"'))

COLOURS = {"Likely scam": "#b42318", "Suspicious": "#b54708", "Probably safe": "#067647"}
ICONS = {"Likely scam": "🚨", "Suspicious": "⚠️", "Probably safe": "✅"}
CHANNELS = ["SMS", "WhatsApp", "Email", "Social media DM", "Phone call (describe it)"]

EXAMPLES = {
    "📦 Parcel fee": ("SingPost: Your parcel is on hold due to an unpaid $1.99 delivery fee. Pay within 24 hours or it will be returned: https://singpost-redelivery.top/pay", "SMS"),
    "💼 Easy job": ("Hi dear, we are hiring part-time staff! Earn $300 per day just by liking videos on TikTok. No experience needed. WhatsApp me at wa.me/6591234567 to start today.", "WhatsApp"),
    "🏦 Bank alert": ("DBS Alert: Unusual login detected. Your account will be suspended. Verify now at bit.ly/dbs-secure and enter the OTP we send you. Do not share this with anyone.", "SMS"),
    "👮 'Police' call": ("This is the police. Your bank account is linked to a money laundering case. Transfer your savings to a safe account immediately and do not tell your family.", "Phone call (describe it)"),
    "🍜 Lunch plans": ("Hey! Are we still on for lunch at 12:30 tomorrow? I booked a table at the usual place 🙂", "WhatsApp"),
}


def load_example(name: str):
    text, channel = EXAMPLES[name]
    st.session_state.message = text
    st.session_state.channel = channel
    st.session_state.pop("result", None)


def verdict_card(result: dict) -> str:
    v = result["verdict"]
    scam_type = result.get("scam_type") or ""
    scam_type = f" · {html.escape(scam_type)}" if scam_type and scam_type != "None detected" else ""
    mode = "AI analysis + rule checks" if result["mode"] == "ai" else "Rule checks only (AI not connected)"
    return f"""
<div style="border-radius:14px;padding:18px 20px;background:{COLOURS[v]};color:#fff;margin-bottom:12px">
  <div style="font-size:1.6rem;font-weight:700;color:#fff">{ICONS[v]} {v}{scam_type}</div>
  <div style="margin-top:8px;background:rgba(255,255,255,.25);border-radius:999px;height:10px;overflow:hidden">
    <div style="width:{result['score']}%;height:100%;background:#fff"></div>
  </div>
  <div style="margin-top:6px;font-size:.95rem;color:#fff">Risk score: <b>{result['score']}/100</b> · {mode}</div>
</div>"""


st.title("🛡️ ScamSense")
st.markdown("**Got a message that feels off?** Paste it below and ScamSense will tell you if it looks like a scam, "
            "point out the warning signs, and tell you what to do next.")
st.caption("🔒 Long numbers and email names are masked before anything is sent to the AI. Please don't paste passwords or OTPs.")

st.write("**Try an example:**")
for col, name in zip(st.columns(len(EXAMPLES)), EXAMPLES):
    col.button(name, on_click=load_example, args=(name,), use_container_width=True)

left, right = st.columns([3, 4], gap="large")

with left:
    message = st.text_area("The message you received", key="message", height=170, max_chars=5000,
                           placeholder="e.g. Your parcel is on hold. Pay $1.99 here: …")
    channel = st.radio("Where did it come from?", CHANNELS, key="channel", horizontal=True)
    if st.button("Check this message", type="primary", use_container_width=True):
        if not message.strip():
            st.warning("Paste a message above first.")
        else:
            with st.spinner("Checking…"):
                st.session_state.result = check_message(message, channel)

with right:
    result = st.session_state.get("result")
    if not result:
        st.info("Your result will appear here.")
    else:
        st.markdown(verdict_card(result), unsafe_allow_html=True)
        if result.get("explanation"):
            st.markdown(f"#### Why\n{result['explanation']}")
        if result.get("floor_applied"):
            st.warning("The rule checker found strong warning signs, so this can't be marked safe.")
        if result["red_flags"]:
            lines = []
            for f in result["red_flags"]:
                # defang + code span: a scam checker must never show a clickable scam link
                ev = defang(f.get("evidence", "")).replace("`", "'")
                lines.append(f"- **{f['flag']}**" + (f" — `{ev}`" if ev else ""))
            st.markdown("#### Red flags found\n" + "\n".join(lines))
        if result["what_to_do"]:
            st.markdown("#### What to do\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(result["what_to_do"], 1)))
        st.caption("ScamSense is a helper, not a guarantee. If in doubt, don't click, don't pay, and check with someone you trust.")
