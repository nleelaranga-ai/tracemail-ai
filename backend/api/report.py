from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Response, Query
from backend.database.connection import get_db, Session
from backend.models.scan import Investigation
from backend.services.report_service import ReportService

router = APIRouter(tags=["Reports"])


@router.get("/api/report/pdf/{id}")
def download_pdf_report(id: str, db: Session = Depends(get_db)):
    """Downloads official forensic PDF investigation report."""
    inv = db.query(Investigation).filter(Investigation.id == id).first()
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {id} not found.")

    pdf_bytes = ReportService.generate_pdf_report_bytes(inv)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="TraceMail_Forensic_Report_{id}.pdf"'
        }
    )


@router.get("/api/report/html/{id}")
def view_html_report(id: str, db: Session = Depends(get_db)):
    """Renders standalone HTML forensic investigation report."""
    inv = db.query(Investigation).filter(Investigation.id == id).first()
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {id} not found.")

    html_content = ReportService.generate_html_report(inv)
    return Response(
        content=html_content,
        media_type="text/html"
    )


@router.get("/api/report/json/{id}")
def get_json_report(id: str, db: Session = Depends(get_db)):
    """Returns structured forensic report JSON for CERT-In or API consumers."""
    inv = db.query(Investigation).filter(Investigation.id == id).first()
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {id} not found.")

    return ReportService.generate_json_report(inv)


@router.get("/api/v1/report/{id}")
@router.get("/api/report/{id}", include_in_schema=False)
def get_report_by_format(
    id: str,
    format: str = Query("json", description="Report format: pdf, html, or json"),
    db: Session = Depends(get_db)
):
    """Multi-format report generation endpoint: format=pdf|html|json."""
    fmt = format.lower().strip()
    inv = db.query(Investigation).filter(Investigation.id == id).first()
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {id} not found.")

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
