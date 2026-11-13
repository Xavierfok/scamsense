"""ScamSense: paste a suspicious message, find out if it's a scam.

Run locally:   python app.py
Needs:         GROQ_API_KEY environment variable for AI analysis
               (without it, the app still works using the rule checker only).
"""

import html
import os

import gradio as gr

from analyzer import check_message
from rules import defang

# Load a local .env file if present (never commit it!)
if os.path.exists(".env"):
    for line in open(".env", encoding="utf-8"):
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.strip().split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"'))

COLOURS = {"Likely scam": "#b42318", "Suspicious": "#b54708", "Probably safe": "#067647"}
ICONS = {"Likely scam": "🚨", "Suspicious": "⚠️", "Probably safe": "✅"}

EXAMPLES = [
    ["SingPost: Your parcel is on hold due to an unpaid $1.99 delivery fee. Pay within 24 hours or it will be returned: https://singpost-redelivery.top/pay", "SMS"],
    ["Hi dear, we are hiring part-time staff! Earn $300 per day just by liking videos on TikTok. No experience needed. WhatsApp me at wa.me/6591234567 to start today.", "WhatsApp"],
    ["DBS Alert: Unusual login detected. Your account will be suspended. Verify now at bit.ly/dbs-secure and enter the OTP we send you. Do not share this with anyone.", "SMS"],
    ["Hey! Are we still on for lunch at 12:30 tomorrow? I booked a table at the usual place 🙂", "WhatsApp"],
    ["This is the police. Your bank account is linked to a money laundering case. Transfer your savings to a safe account immediately and do not tell your family.", "Phone call (describe it)"],
]


def render(result: dict) -> tuple[str, str]:
    v = result["verdict"]
    colour = COLOURS[v]
    scam_type = f" · {html.escape(result['scam_type'])}" if result.get("scam_type") and result["scam_type"] != "None detected" else ""
    mode = "AI analysis + rule checks" if result["mode"] == "ai" else "Rule checks only (AI not connected)"
    card = f"""
<div style="border-radius:14px;padding:18px 20px;background:{colour};color:#fff">
  <div style="font-size:1.6rem;font-weight:700;color:#fff !important">{ICONS[v]} {v}{scam_type}</div>
  <div style="margin-top:8px;background:rgba(255,255,255,.25);border-radius:999px;height:10px;overflow:hidden">
    <div style="width:{result['score']}%;height:100%;background:#fff"></div>
  </div>
  <div style="margin-top:6px;font-size:.95rem;color:#fff !important">Risk score: <b style="color:#fff !important">{result['score']}/100</b> · {mode}</div>
</div>"""

    md = []
    if result.get("explanation"):
        md.append(f"### Why\n{result['explanation']}")
    if result.get("floor_applied"):
        md.append("> The rule checker found strong warning signs, so this can't be marked safe.")
    if result["red_flags"]:
        md.append("### Red flags found")
        for f in result["red_flags"]:
            # defang + code span: a scam checker must never show a clickable scam link
            ev_text = defang(f.get("evidence", "")).replace("`", "'")
            ev = f" — `{ev_text}`" if ev_text else ""
            md.append(f"- **{f['flag']}**{ev}")
    if result["what_to_do"]:
        md.append("### What to do")
        md.extend(f"{i}. {step}" for i, step in enumerate(result["what_to_do"], 1))
    md.append("\n<sub>ScamSense is a helper, not a guarantee. If in doubt, don't click, don't pay, and check with someone you trust.</sub>")
    return card, "\n".join(md)


def on_check(message: str, channel: str):
    if not message or not message.strip():
        return "", "Paste a message above first."
    if len(message) > 5000:
        message = message[:5000]
    return render(check_message(message, channel))


with gr.Blocks(title="ScamSense: Is this message a scam?") as demo:
    gr.Markdown(
        "# 🛡️ ScamSense\n"
        "**Got a message that feels off?** Paste it below and ScamSense will tell you if it looks like a scam, "
        "point out the warning signs, and tell you what to do next.\n\n"
        "🔒 *Long numbers and email names are masked before anything is sent to the AI. "
        "Please don't paste passwords or OTPs.*"
    )
    with gr.Row():
        with gr.Column(scale=3):
            msg = gr.Textbox(label="The message you received", lines=7,
                             placeholder="e.g. Your parcel is on hold. Pay $1.99 here: …")
            channel = gr.Radio(["SMS", "WhatsApp", "Email", "Social media DM", "Phone call (describe it)"],
                               value="SMS", label="Where did it come from?")
            with gr.Row():
                btn = gr.Button("Check this message", variant="primary")
                clear = gr.ClearButton(value="Clear")
        with gr.Column(scale=4):
            card = gr.HTML()
            details = gr.Markdown()
    gr.Examples(EXAMPLES, inputs=[msg, channel], label="Try an example")
    clear.add([msg, card, details])

    btn.click(on_check, [msg, channel], [card, details])
    msg.submit(on_check, [msg, channel], [card, details])

if __name__ == "__main__":
    demo.launch()
