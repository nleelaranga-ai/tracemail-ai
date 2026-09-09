"""
TraceMail AI Backend — Email Upload & Parse API
"""
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from backend.database.connection import get_db, Session
from backend.schemas.email_schema import EmailUploadResponse, EmailParsedData, HeaderInfo, AttachmentInfo
from backend.services.email_service import EmailService
from backend.parsers.email_parser import EmailParser

router = APIRouter(prefix="/api/v1/email", tags=["Email"])


@router.post("/upload", response_model=EmailUploadResponse)
async def upload_email(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Upload and process .eml file."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename required.")
    content = await file.read()
    inv = await EmailService.process_eml_file(db, content, file.filename)
    return EmailUploadResponse(
        investigationId=inv.id,
        status=inv.status,
        message="Email parsed and investigation initiated."
    )


@router.post("/parse", response_model=EmailParsedData)
async def parse_email_only(file: UploadFile = File(...)):
    """Parses .eml file and returns structured headers and body without persisting."""
    content = await file.read()
    parsed = EmailParser.parse_eml_bytes(content)
    
    headers_info = HeaderInfo(
        message_id=parsed["headers"].get("message_id"),
        sender=parsed["headers"].get("sender"),
        recipient=parsed["headers"].get("recipient"),
        subject=parsed["headers"].get("subject"),
        date=parsed["headers"].get("date"),
        return_path=parsed["headers"].get("return_path"),
        spf=parsed["headers"].get("spf", "none"),
        dkim=parsed["headers"].get("dkim", "none"),
        dmarc=parsed["headers"].get("dmarc", "none"),
        received_hops=parsed["headers"].get("received_hops", [])
    )

    attachments = [
        AttachmentInfo(**att) for att in parsed.get("attachments", [])
    ]

    return EmailParsedData(
        sender=parsed["sender"],
        recipient=parsed["recipient"],
        subject=parsed["subject"],
        body_text=parsed["body_text"],
        body_html=parsed["body_html"],
        headers=headers_info,
        attachments=attachments,
        extracted_urls=parsed["iocs"].get("urls", []),
        extracted_ips=parsed["iocs"].get("ips", []),
        extracted_domains=parsed["iocs"].get("domains", [])
    )
