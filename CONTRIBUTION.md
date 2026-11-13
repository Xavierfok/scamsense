# My contribution

> ✏️ **Rewrite the bracketed parts in your own words before submitting.** Judges want *your* understanding, and the hackathon rules ask you to be honest about AI-assisted tools.

## What I built

- **The idea and problem framing:** [why scam messages matter to you; e.g. a family member or friend who got one]
- **Two-layer design:** a rule checker (`rules.py`) plus an AI model (`analyzer.py`), so the app still works without an API key and can't be talked into calling a scam "safe"
- **Privacy redaction:** numbers and email names are masked before any text goes to the AI
- **Prompt design:** a system prompt that treats the message as untrusted and forces structured JSON output
- **Validation + tests:** the AI's output is checked and cleaned; 12 pytest tests cover the rules, redaction, rules-only mode and the safety floor
- **Gradio interface** with examples, and deployment to Hugging Face Spaces

## AI-assisted development tools I used

- **Claude Code** (Anthropic): helped write and debug the code, tests and documentation. [Describe how you worked with it: what you asked for, what you changed, what you checked yourself.]

## What I learned

- [e.g. how to call an LLM API and get reliable JSON back]
- [e.g. what prompt injection is, and why rules are a useful backstop for AI]
- [e.g. how regular expressions work, and the false positives I had to fix, like an email address being counted as a link]
- [e.g. deploying to Hugging Face Spaces and keeping an API key secret]

## Challenges

- [e.g. balancing false alarms vs missed scams]
- [e.g. a bare `bit.ly/...` link without `https://` wasn't detected at first; a test caught it]

## What I'd add next

- Check links against a live blocklist (Google Safe Browsing)
- Screenshot upload (read the text from an image)
- More languages (Chinese, Malay, Tamil)
- A Telegram / WhatsApp bot version
