"""
TraceMail AI Backend — Email Parsing Schemas
"""
from pydantic import BaseModel
from typing import Optional, List


class AttachmentInfo(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    md5: str
    sha256: str
    is_suspicious: bool = False


class HeaderInfo(BaseModel):
    message_id: Optional[str] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    return_path: Optional[str] = None
    spf: Optional[str] = "none"
    dkim: Optional[str] = "none"
    dmarc: Optional[str] = "none"
    received_hops: List[str] = []


class EmailParsedData(BaseModel):
    sender: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    body_text: str = ""
    body_html: str = ""
    headers: HeaderInfo
    attachments: List[AttachmentInfo] = []
    extracted_urls: List[str] = []
    extracted_ips: List[str] = []
    extracted_domains: List[str] = []


class EmailUploadResponse(BaseModel):
    investigationId: str
    status: str = "complete"
    message: str = "Email uploaded and analyzed successfully."
