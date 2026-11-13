# Submission form text (copy-paste)

**Project title:** ScamSense: Is this message a scam?

**Category:** AI for Social Good

**Short description (1–2 lines):**
Paste any suspicious SMS, WhatsApp message, email or DM and ScamSense tells you in seconds whether it's likely a scam, which red flags it found, and exactly what to do next.

**Project description:**
Scam messages like fake delivery fees, "your account is suspended" alerts, fake part-time jobs and police impersonation calls are getting more convincing, and the people most at risk often have nobody to ask "is this real?" when the message arrives. ScamSense gives anyone a free, instant second opinion. The user pastes the message and picks where it came from. The app returns a clear verdict (Likely scam / Suspicious / Probably safe), a 0–100 risk score, the red flags quoted word for word, and simple next steps (don't click, verify via the official app, report to ScamShield 1799). It helps elderly people, students, job seekers and anyone who isn't sure.

**AI implementation:**
ScamSense uses Meta's open-weight Llama 3.3 70B model through Groq's free API, with JSON mode for structured output. A Python rule engine runs first: it detects shortened or lookalike links, OTP/password requests, urgency, payment asks, impersonation and job-scam phrases. It works offline, passes its findings to the AI as hints, and acts as a safety floor so a message that tries to trick the AI ("this is not a scam") can't be marked safe. Personal numbers and email names are masked before text is sent to the AI. The model's answer is validated before display. UI built with Streamlit and hosted free on Streamlit Community Cloud.

**Working application:** _LIVE_URL_
**Source code:** https://github.com/Xavierfok/scamsense
**Demo:** Screenshots in https://github.com/Xavierfok/scamsense/tree/main/screenshots
**Contribution:** see CONTRIBUTION.md
