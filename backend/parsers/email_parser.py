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

        return {
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "body_text": body_text,
            "body_html": body_html,
            "raw_headers": raw_text[:5000],  # Header block excerpt
            "headers": header_analysis,
            "attachments": attachments,
            "iocs": iocs
        }
