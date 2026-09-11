"""
TraceMail AI Backend — Email MIME Parser
"""
import email
from email import policy
from email.message import EmailMessage
from typing import Dict, Any, List
from backend.parsers.header_parser import HeaderParser
from backend.parsers.attachment_parser import AttachmentParser
from backend.parsers.ioc_parser import IOCParser


class EmailParser:
    @classmethod
    def parse_eml_bytes(cls, eml_bytes: bytes) -> Dict[str, Any]:
        msg = email.message_from_bytes(eml_bytes, policy=policy.default)
        return cls._extract_email_components(msg, eml_bytes.decode("utf-8", errors="replace"))

    @classmethod
    def parse_eml_text(cls, eml_text: str) -> Dict[str, Any]:
        msg = email.message_from_string(eml_text, policy=policy.default)
        return cls._extract_email_components(msg, eml_text)

    @classmethod
    def _extract_email_components(cls, msg: EmailMessage, raw_text: str) -> Dict[str, Any]:
        # Collect headers
        raw_headers_dict = {}
        for k, v in msg.items():
            if k in raw_headers_dict:
                if isinstance(raw_headers_dict[k], list):
                    raw_headers_dict[k].append(str(v))
                else:
                    raw_headers_dict[k] = [raw_headers_dict[k], str(v)]
            else:
                raw_headers_dict[k] = str(v)

        header_analysis = HeaderParser.parse_headers(raw_headers_dict, raw_text)

        body_text_parts: List[str] = []
        body_html_parts: List[str] = []
        attachments: List[Dict[str, Any]] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition") or "")

                if "attachment" in content_disposition or part.get_filename():
                    filename = part.get_filename() or "attachment"
                    payload = part.get_payload(decode=True) or b""
                    att_info = AttachmentParser.parse_attachment(filename, payload, content_type)
                    attachments.append(att_info)
                elif content_type == "text/plain":
                    payload = part.get_payload(decode=True) or b""
                    body_text_parts.append(payload.decode("utf-8", errors="replace"))
                elif content_type == "text/html":
                    payload = part.get_payload(decode=True) or b""
                    body_html_parts.append(payload.decode("utf-8", errors="replace"))
        else:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True) or b""
            text = payload.decode("utf-8", errors="replace")
            if content_type == "text/html":
                body_html_parts.append(text)
            else:
                body_text_parts.append(text)

        body_text = "\n".join(body_text_parts).strip()
        body_html = "\n".join(body_html_parts).strip()

        # Extract IOCs from both header text and body text
        combined_content = f"{raw_text}\n{body_text}"
        iocs = IOCParser.extract_iocs(combined_content)

        sender = header_analysis.get("sender") or msg.get("From", "")
        recipient = header_analysis.get("recipient") or msg.get("To", "")
        subject = header_analysis.get("subject") or msg.get("Subject", "")
        domain = header_analysis.get("domain") or (sender.split("@")[-1].strip().strip(">").strip(";").strip(")") if "@" in sender else "")
        origin_ip = header_analysis.get("origin_ip") or (header_analysis.get("hop_ips", [""])[0] if header_analysis.get("hop_ips") else "")

        return {
            "sender": sender,
            "display_name": header_analysis.get("display_name", ""),
            "recipient": recipient,
            "subject": subject,
            "domain": domain,
            "origin_ip": origin_ip,
            "reply_to": header_analysis.get("reply_to", ""),
            "return_path": header_analysis.get("return_path", ""),
            "message_id": header_analysis.get("message_id", ""),
            "body_text": body_text,
            "body_html": body_html,
            "raw_headers": raw_text[:5000],  # Header block excerpt
            "headers": header_analysis,
            "display_name_spoofing": header_analysis.get("display_name_spoofing", False),
            "impersonated_brand": header_analysis.get("impersonated_brand"),
            "spoofing_detail": header_analysis.get("spoofing_detail", ""),
            "reply_to_mismatch": header_analysis.get("reply_to_mismatch", False),
            "return_path_mismatch": header_analysis.get("return_path_mismatch", False),
            "structured_hops": header_analysis.get("structured_hops", []),
            "attachments": attachments,
            "iocs": iocs
        }

