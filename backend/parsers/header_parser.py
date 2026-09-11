"""
TraceMail AI Backend — RFC 822 Forensic Header Parser
Implements Identity Verification, Display Name Spoofing, BEC, and Hop Reconstruction (Root Causes 1, 3, 9)
"""
import re
import socket
import email.utils
from typing import Dict, List, Any


KNOWN_BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "internshala": ["internshala.com"],
    "google": ["google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "meta": ["meta.com", "facebook.com"],
    "facebook": ["facebook.com"],
    "linkedin": ["linkedin.com"],
    "github": ["github.com"],
}


class HeaderParser:
    SPF_PATTERN = re.compile(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", re.IGNORECASE)
    DKIM_PATTERN = re.compile(r"dkim=(pass|fail|none)", re.IGNORECASE)
    DMARC_PATTERN = re.compile(r"dmarc=(pass|fail|none)", re.IGNORECASE)
    IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    @classmethod
    def parse_headers(cls, headers_dict: Dict[str, Any], raw_headers_text: str = "") -> Dict[str, Any]:
        raw_sender = headers_dict.get("From") or headers_dict.get("from") or ""
        display_name, sender_email = email.utils.parseaddr(raw_sender)
        if not sender_email and "@" in raw_sender:
            sender_email = raw_sender.strip().strip("<>").strip()

        raw_recipient = headers_dict.get("To") or headers_dict.get("to") or ""
        _, recipient_email = email.utils.parseaddr(raw_recipient)
        if not recipient_email and "@" in raw_recipient:
            recipient_email = raw_recipient.strip().strip("<>").strip()

        raw_reply_to = headers_dict.get("Reply-To") or headers_dict.get("reply-to") or ""
        _, reply_to_email = email.utils.parseaddr(raw_reply_to)

        raw_return_path = headers_dict.get("Return-Path") or headers_dict.get("return-path") or ""
        _, return_path_email = email.utils.parseaddr(raw_return_path)

        # Extract domain
        sender_domain = ""
        if "@" in sender_email:
            sender_domain = sender_email.split("@")[-1].strip().strip(">").strip(";").strip(")").lower()

        reply_to_domain = ""
        if "@" in reply_to_email:
            reply_to_domain = reply_to_email.split("@")[-1].strip().strip(">").strip(";").strip(")").lower()

        return_path_domain = ""
        if "@" in return_path_email:
            return_path_domain = return_path_email.split("@")[-1].strip().strip(">").strip(";").strip(")").lower()

        # Identity Mismatch & BEC Spoofing checks (Root Causes 1 & 9)
        display_name_spoofing = False
        impersonated_brand = None
        spoofing_detail = ""

        if display_name:
            lower_display = display_name.lower()
            for brand, legitimate_domains in KNOWN_BRAND_DOMAINS.items():
                if brand in lower_display:
                    if not any(sender_domain.endswith(d) for d in legitimate_domains):
                        display_name_spoofing = True
                        impersonated_brand = brand.capitalize()
                        spoofing_detail = (
                            f"Display name claims brand '{display_name}', but sender domain is untrusted '{sender_domain}'."
                        )
                        break

        reply_to_mismatch = bool(reply_to_domain and sender_domain and reply_to_domain != sender_domain)
        return_path_mismatch = bool(return_path_domain and sender_domain and return_path_domain != sender_domain)

        result = {
            "message_id": headers_dict.get("Message-ID") or headers_dict.get("message-id") or "",
            "sender": sender_email or raw_sender,
            "display_name": display_name,
            "recipient": recipient_email or raw_recipient,
            "reply_to": reply_to_email or raw_reply_to,
            "subject": headers_dict.get("Subject") or headers_dict.get("subject") or "No Subject",
            "date": headers_dict.get("Date") or headers_dict.get("date") or "",
            "return_path": return_path_email or raw_return_path,
            "spf": "none",
            "dkim": "none",
            "dmarc": "none",
            "received_hops": [],
            "structured_hops": [],
            "hop_ips": [],
            "domain": sender_domain,
            "origin_ip": "",
            "display_name_spoofing": display_name_spoofing,
            "impersonated_brand": impersonated_brand,
            "spoofing_detail": spoofing_detail,
            "reply_to_mismatch": reply_to_mismatch,
            "return_path_mismatch": return_path_mismatch
        }

        # Scan text for cryptographic authentication results
        combined_text = raw_headers_text or str(headers_dict)
        
        spf_m = cls.SPF_PATTERN.search(combined_text)
        if spf_m:
            result["spf"] = spf_m.group(1).lower()

        dkim_m = cls.DKIM_PATTERN.search(combined_text)
        if dkim_m:
            result["dkim"] = dkim_m.group(1).lower()

        dmarc_m = cls.DMARC_PATTERN.search(combined_text)
        if dmarc_m:
            result["dmarc"] = dmarc_m.group(1).lower()

        # Parse Received lines
        received_list = headers_dict.get("Received") or []
        if isinstance(received_list, str):
            received_list = [received_list]

        for hop in received_list:
            hop_str = hop.strip() if isinstance(hop, str) else str(hop).strip()
            result["received_hops"].append(hop_str)
            
            ips = cls.IP_PATTERN.findall(hop_str)
            for ip in ips:
                if ip not in result["hop_ips"]:
                    result["hop_ips"].append(ip)

            by_m = re.search(r"\bby\s+([^\s;]+)", hop_str, re.IGNORECASE)
            from_m = re.search(r"\bfrom\s+([^\s;]+)", hop_str, re.IGNORECASE)
            time_m = re.search(r";\s*([A-Za-z]+,\s+\d+.*)$", hop_str)
            
            hop_obj = {
                "server": (by_m.group(1) if by_m else (from_m.group(1) if from_m else "mail-relay.net")).strip(),
                "from_server": from_m.group(1).strip() if from_m else "",
                "by_server": by_m.group(1).strip() if by_m else "",
                "ip": ips[0] if ips else "",
                "timestamp": time_m.group(1).strip() if time_m else ""
            }
            result["structured_hops"].append(hop_obj)

        # Determine true origin public IP from hops
        for ip in reversed(result["hop_ips"]):
            if cls._is_public_ip(ip):
                result["origin_ip"] = ip
                break

        if not result["origin_ip"]:
            for ip in result["hop_ips"]:
                if cls._is_public_ip(ip):
                    result["origin_ip"] = ip
                    break

        # Dynamic DNS resolution if no public IP exists in Received headers
        if not result["origin_ip"] and result["domain"]:
            try:
                resolved_ip = socket.gethostbyname(result["domain"])
                if cls._is_public_ip(resolved_ip):
                    result["origin_ip"] = resolved_ip
            except Exception:
                pass

        return result

    @classmethod
    def _is_public_ip(cls, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            o1, o2, o3, o4 = [int(p) for p in parts]
            if o1 == 10:
                return False
            if o1 == 127:
                return False
            if o1 == 192 and o2 == 168:
                return False
            if o1 == 172 and (16 <= o2 <= 31):
                return False
            if o1 == 0 or o1 >= 224:
                return False
            return True
        except ValueError:
            return False

