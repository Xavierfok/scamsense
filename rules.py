"""Rule-based scam signals.

These checks run instantly, work offline, and never send data anywhere.
They do two jobs:
  1. Give the AI model concrete hints about what is in the message.
  2. Act as a safety floor: if the rules find strong evidence, the final
     verdict can't drop to "Probably safe", even if the AI is fooled
     (for example by a message that says "this is not a scam").
"""

import re
from dataclasses import dataclass


@dataclass
class Flag:
    category: str   # short label shown to the user
    evidence: str   # the exact text that triggered it
    weight: int     # how much it adds to the risk score


SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd", "shorturl.at", "s.id", "tiny.cc", "ow.ly", "rebrand.ly")

URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"
    r"|\b(?:" + "|".join(re.escape(s) for s in SHORTENERS) + r")/[^\s<>\"']*"
    r"|(?<![@\w.-])(?:[a-z0-9-]+\.)+(?:com|net|org|xyz|top|click|icu|shop|live|info|vip|cc|link|site|online|sg|me|io|co)\b(?:/[^\s<>\"']*)?",
    re.I)
RISKY_TLDS = (".xyz", ".top", ".click", ".icu", ".shop", ".live", ".vip", ".cc", ".link", ".site", ".online")

# (category, weight, patterns). Patterns are matched case-insensitively.
KEYWORD_RULES = [
    ("Asks for codes or passwords", 35, [
        r"\botp\b", r"one[- ]time (?:password|pin|code)", r"verification code", r"\bpassword\b",
        r"\bpin\b", r"\bcvv\b", r"card number", r"login details", r"singpass",
    ]),
    ("Asks you to pay a small fee", 20, [
        r"(?:unpaid|outstanding|pending|small) .{0,25}(?:fee|payment|charge|duty|toll)",
        r"\bpay (?:the |a |only )?(?:\$|s\$|usd|rm)\s?\d", r"(?:delivery|shipping|customs|redelivery) fee",
    ]),
    ("Pressure / urgency", 15, [
        r"\burgent(?:ly)?\b", r"\bimmediately\b", r"within \d+ ?(?:hours?|hrs?|minutes?|mins?)",
        r"\bfinal (?:notice|warning|reminder)\b", r"\bact now\b",
        r"(?:will be|has been|is) (?:suspended|locked|blocked|frozen|terminated|deactivated)",
        r"\bexpir(?:e|es|ed|ing)\b", r"last chance",
    ]),
    ("Money, prizes or payments", 20, [
        r"\bgift ?cards?\b", r"\bbitcoin\b", r"\busdt\b", r"\bcrypto(?:currency)?\b",
        r"(?:transfer|send|pay) (?:the |a )?(?:money|fee|deposit|payment)", r"processing fee",
        r"\byou(?:'ve| have)? won\b", r"\bprize\b", r"\blottery\b", r"\bunclaimed\b",
        r"\bclaim (?:your|now)\b", r"\brefund\b",
    ]),
    ("Pretends to be an official body or company", 15, [
        r"\bpolice\b", r"\bcustoms\b", r"\bministry\b", r"\bgovernment\b", r"\bIRAS\b", r"\bICA\b",
        r"\bMOM\b", r"\bCPF\b", r"\bIRS\b", r"\bHMRC\b", r"\bDBS\b", r"\bOCBC\b", r"\bUOB\b",
        r"\bpaypal\b", r"\bDHL\b", r"\bfedex\b", r"\bsingpost\b", r"\bamazon\b", r"\bnetflix\b",
    ]),
    ("Too-good-to-be-true job offer", 25, [
        r"earn (?:up to )?(?:\$|s\$|usd|rm)?\s?\d+", r"\$\d+ ?(?:per|a|/) ?(?:day|hour|hr)",
        r"\bpart[- ]time\b.*\b(?:task|like|review)", r"\blike (?:videos|posts)\b",
        r"\bwork from home\b", r"\bcommission\b",
    ]),
    ("Moves you to a private chat", 10, [
        r"\b(?:whatsapp|telegram|wechat|line) me\b", r"\badd me on\b", r"\bcontact (?:me|us) on (?:whatsapp|telegram)\b",
        r"t\.me/", r"wa\.me/",
    ]),
    ("Asks you to keep it secret", 20, [
        r"don'?t tell (?:anyone|your)", r"\bkeep (?:this|it) (?:confidential|secret|private)\b",
        r"\bdo not (?:inform|tell) (?:anyone|the bank)\b",
    ]),
    ("Asks you to install an app or give remote access", 30, [
        r"\b(?:anydesk|teamviewer)\b", r"\bdownload (?:this|the) (?:app|apk)\b", r"\.apk\b",
        r"\bremote access\b",
    ]),
]

_COMPILED = [(cat, w, [re.compile(p, re.I) for p in pats]) for cat, w, pats in KEYWORD_RULES]


def find_links(text: str) -> list[str]:
    return [m.group(0).rstrip(".,;:!?)") for m in URL_RE.finditer(text)]


def check_links(text: str) -> list[Flag]:
    flags = []
    for url in find_links(text):
        low = url.lower()
        host = re.sub(r"^(?:https?://)?(?:www\.)?", "", low).split("/")[0]
        if any(host == s or host.endswith("." + s) for s in SHORTENERS):
            flags.append(Flag("Shortened link hides the real address", url, 20))
        elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", host):
            flags.append(Flag("Link goes to a bare IP address", url, 25))
        elif host.endswith(RISKY_TLDS):
            flags.append(Flag("Link uses a domain ending often used in scams", url, 20))
        elif re.search(r"[a-z][0-9][a-z]|-(?:secure|verify|login|update|support)|(?:secure|verify|login|update)-", host):
            flags.append(Flag("Lookalike or 'verify/login' style web address", url, 20))
        else:
            flags.append(Flag("Contains a link (check it before tapping)", url, 5))
    return flags


def check_keywords(text: str) -> list[Flag]:
    flags = []
    for category, weight, patterns in _COMPILED:
        for pat in patterns:
            m = pat.search(text)
            if m:
                flags.append(Flag(category, m.group(0), weight))
                break  # one hit per category is enough
    return flags


def analyse(text: str) -> dict:
    """Run every rule. Returns flags and a 0-100 risk score."""
    flags = check_keywords(text) + check_links(text)
    score = min(100, sum(f.weight for f in flags))
    return {"flags": flags, "score": score}


def verdict_for(score: int) -> str:
    if score >= 60:
        return "Likely scam"
    if score >= 25:
        return "Suspicious"
    return "Probably safe"


def defang(text: str) -> str:
    """Make links unclickable so the app never hands users a live scam link.

    https://bad.top/pay  ->  hxxps://bad[.]top/pay
    """
    def _one(m):
        url = m.group(0)
        url = re.sub(r"^http", "hxxp", url, flags=re.I)
        host_end = url.find("/", url.find("://") + 3 if "://" in url else 0)
        host, rest = (url, "") if host_end == -1 else (url[:host_end], url[host_end:])
        return host.replace(".", "[.]") + rest
    return URL_RE.sub(_one, text)


# --- Privacy: strip personal details before anything leaves the machine ---

def redact(text: str) -> str:
    """Mask long numbers (cards, phones, account numbers) and email names.

    Links are kept, because the AI needs to see them to judge them.
    """
    text = re.sub(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@", r"\1***@", text)
    text = re.sub(r"(?<![\w/.])(\+?\d[\d \-]{6,}\d)(?![\w/.])",
                  lambda m: re.sub(r"\d", "•", m.group(1)[:-3]) + m.group(1)[-3:], text)
    return text
