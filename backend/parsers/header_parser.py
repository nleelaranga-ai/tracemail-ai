"""
TraceMail AI Backend — RFC 822 Header Parser
"""
import re
from typing import Dict, List, Any


class HeaderParser:
    SPF_PATTERN = re.compile(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", re.IGNORECASE)
    DKIM_PATTERN = re.compile(r"dkim=(pass|fail|none)", re.IGNORECASE)
    DMARC_PATTERN = re.compile(r"dmarc=(pass|fail|none)", re.IGNORECASE)
    IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    @classmethod
    def parse_headers(cls, headers_dict: Dict[str, Any], raw_headers_text: str = "") -> Dict[str, Any]:
        result = {
            "message_id": headers_dict.get("Message-ID") or headers_dict.get("message-id"),
            "sender": headers_dict.get("From") or headers_dict.get("from"),
            "recipient": headers_dict.get("To") or headers_dict.get("to"),
            "subject": headers_dict.get("Subject") or headers_dict.get("subject"),
            "date": headers_dict.get("Date") or headers_dict.get("date"),
            "return_path": headers_dict.get("Return-Path") or headers_dict.get("return-path"),
            "spf": "none",
            "dkim": "none",
            "dmarc": "none",
            "received_hops": [],
            "hop_ips": []
        }

        # Scan text for authentication results
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
            result["received_hops"].append(hop.strip())
            for ip in cls.IP_PATTERN.findall(hop):
                if ip not in result["hop_ips"]:
                    result["hop_ips"].append(ip)

        return result
