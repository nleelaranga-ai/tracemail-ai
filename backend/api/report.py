from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Response, Query
from backend.database.connection import get_db, Session
from backend.models.scan import Investigation
from backend.models.user import User
from backend.middleware.auth import get_current_user
from backend.services.report_service import ReportService

router = APIRouter(tags=["Reports"])


def _verify_investigation_access(inv: Optional[Investigation], current_user: Optional[User]):
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    if inv.owner_user_id is not None:
        if not current_user or (current_user.id != inv.owner_user_id and getattr(current_user, "role", "") != "admin"):
            raise HTTPException(status_code=404, detail="Investigation not found.")


@router.get("/api/report/pdf/{id}")
def download_pdf_report(
    id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Downloads official forensic PDF investigation report."""
    inv = db.query(Investigation).filter(Investigation.id == id).first()
    _verify_investigation_access(inv, current_user)

    pdf_bytes = ReportService.generate_pdf_report_bytes(inv)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="TraceMail_Forensic_Report_{id}.pdf"'
        }
    )


@router.get("/api/report/html/{id}")
def view_html_report(
    id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Renders standalone HTML forensic investigation report."""
    inv = db.query(Investigation).filter(Investigation.id == id).first()
    _verify_investigation_access(inv, current_user)

    html_content = ReportService.generate_html_report(inv)
    return Response(
        content=html_content,
        media_type="text/html"
    )


@router.get("/api/report/json/{id}")
def get_json_report(
    id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Returns structured forensic report JSON for CERT-In or API consumers."""
    inv = db.query(Investigation).filter(Investigation.id == id).first()
    _verify_investigation_access(inv, current_user)

    return ReportService.generate_json_report(inv)


@router.get("/api/v1/report/{id}")
@router.get("/api/report/{id}", include_in_schema=False)
def get_report_by_format(
    id: str,
    format: str = Query("json", description="Report format: pdf, html, or json"),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Multi-format report generation endpoint: format=pdf|html|json."""
    fmt = format.lower().strip()
    inv = db.query(Investigation).filter(Investigation.id == id).first()
    _verify_investigation_access(inv, current_user)

    if fmt == "pdf":
        pdf_bytes = ReportService.generate_pdf_report_bytes(inv)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="TraceMail_Forensic_Report_{id}.pdf"'
            }
        )
    elif fmt == "html":
        return Response(
            content=ReportService.generate_html_report(inv),
            media_type="text/html"
        )
    else:
        return ReportService.generate_json_report(inv)
