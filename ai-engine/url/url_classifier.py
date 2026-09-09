import re
import tldextract


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd"
}


def classify_urls(urls):
    suspicious = []
    score_bump = 0

    for url in urls:
        reasons = []

        if re.match(r"https?://(?:\d{1,3}\.){3}\d{1,3}", url):
            reasons.append("IP-based URL")

        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"

        if domain in SHORTENERS:
            reasons.append("URL shortener")

        if any(char.isdigit() for char in extracted.domain):
            reasons.append("Possible lookalike domain")

        if reasons:
            suspicious.append({
                "url": url,
                "reasons": reasons
            })
            score_bump += 10

    return {
        "suspiciousUrls": suspicious,
        "scoreBump": min(score_bump, 30)
    }