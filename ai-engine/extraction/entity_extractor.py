import re
import tldextract


def extract_entities(email_body, headers):
    text = email_body + "\n" + headers

    raw_urls = re.findall(r'https?://[^\s<>"\'\)]+', text)
    urls = [re.sub(r'[.,;:!]+$', '', u) for u in raw_urls]
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

    domains = []

    for url in urls:
        extracted = tldextract.extract(url)
        if extracted.domain and extracted.suffix:
            domains.append(f"{extracted.domain}.{extracted.suffix}")

    domains = list(dict.fromkeys(domains))
    urls = list(dict.fromkeys(urls))
    ips = list(dict.fromkeys(ips))

    sender_claim = "unknown"
    sender_actual = "unknown"

    from_match = re.search(
        r'From:\s*(.+)',
        headers,
        re.IGNORECASE
    )

    return {
        "urls": urls,
        "ips": ips,
        "domains": domains,
        "senderClaim": from_match.group(1).strip() if from_match else sender_claim,
        "senderActual": sender_actual
    }