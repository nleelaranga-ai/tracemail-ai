"""
TraceMail AI Backend — Email Attachment Forensic Parser
"""
import hashlib
from typing import Dict, Any, List

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".bat", ".cmd", ".ps1", ".js", ".jar",
    ".hta", ".cpl", ".iso", ".img", ".vbe", ".wsf", ".lnk", ".dll"
}


class AttachmentParser:
    @staticmethod
    def parse_attachment(filename: str, content: bytes, content_type: str = "application/octet-stream") -> Dict[str, Any]:
        if content is None:
            content = b""
        elif isinstance(content, str):
            content = content.encode("utf-8", errors="replace")
        elif not isinstance(content, (bytes, bytearray)):
            content = bytes(content)

        size_bytes = len(content)
        md5 = hashlib.md5(content).hexdigest()
        sha256 = hashlib.sha256(content).hexdigest()
        
        is_suspicious = False
        lower_name = filename.lower() if filename else ""
        for ext in DANGEROUS_EXTENSIONS:
            if lower_name.endswith(ext):
                is_suspicious = True
                break

        return {
            "filename": filename or "unnamed_attachment",
            "content_type": content_type,
            "size_bytes": size_bytes,
            "md5": md5,
            "sha256": sha256,
            "is_suspicious": is_suspicious
        }
