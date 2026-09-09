"""
TraceMail AI — Team Reports: Reports Engine
File   : team_reports/reports/router/reports_router.py
Purpose: FastAPI router exposing the Reports Engine endpoints.
         This router is mounted into the main Backend FastAPI app.

Endpoints:
    GET  /api/report/pdf/{investigationId}   → StreamingResponse (PDF)
    GET  /api/report/json/{investigationId}  → JSONResponse (JSON report)
    POST /api/v1/reports/generate            → Generate both (returns URLs)

Integration:
    Backend mounts this router:
        app.include_router(reports_router, prefix="/api")

    The backend assembles InvestigationPayload and passes it in the
    request body for POST, or the router calls back to the backend
    internal service for GET endpoints (via dependency injection).
"""

from __future__ import annotations

import io
import logging
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Path, status
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

from team_reports.reports.json.json_report import (
    JSONReport,
    JSONReportGenerator,
)
from team_reports.reports.pdf.pdf_generator import PDFReportGenerator
from team_reports.reports.schemas.report_schema import validate_report_dict

logger = logging.getLogger(__name__)

reports_router = APIRouter(tags=["Reports"])

# Singleton generators (stateless, thread-safe)
_json_gen = JSONReportGenerator()
_pdf_gen = PDFReportGenerator()


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


def get_json_generator() -> JSONReportGenerator:
    return _json_gen


def get_pdf_generator() -> PDFReportGenerator:
    return _pdf_gen


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@reports_router.get(
    "/report/json/{investigationId}",
    summary="Generate JSON forensic report",
    description=(
        "Accepts assembled investigation data from the backend and returns "
        "a complete machine-readable JSON forensic report. "
        "The Reports Engine never queries the database directly."
    ),
    response_class=JSONResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "JSON forensic report"},
        422: {"description": "Invalid investigation data"},
        500: {"description": "Report generation failed"},
    },
)
async def get_json_report(
    investigationId: Annotated[str, Path(description="Unique investigation identifier")],
    payload: Annotated[
        dict[str, Any],
        Body(description="Assembled investigation data from backend"),
    ],
    json_gen: JSONReportGenerator = Depends(get_json_generator),
) -> JSONResponse:
    """Generate and return a machine-readable JSON forensic report."""
    logger.info("JSON report requested for investigation_id=%s", investigationId)

    # Validate payload
    try:
        investigation = json_gen.validate_payload(payload)
    except Exception as exc:
        logger.warning("Invalid payload for investigation_id=%s: %s", investigationId, exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid investigation payload: {exc}",
        ) from exc

    # Enforce ID consistency
    if investigation.investigation_id != investigationId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"URL investigationId '{investigationId}' does not match "
                f"payload investigation_id '{investigation.investigation_id}'"
            ),
        )

    # Generate report
    try:
        report: JSONReport = json_gen.generate(investigation)
    except Exception as exc:
        logger.exception("JSON generation failed for investigation_id=%s", investigationId)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {exc}",
        ) from exc

    # Validate output against schema
    report_dict = json_gen.to_dict(report)
    errors = validate_report_dict(report_dict)
    if errors:
        logger.error("Generated report failed schema validation: %s", errors)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Generated report failed schema validation: {errors}",
        )

    logger.info(
        "JSON report generated: report_id=%s investigation_id=%s",
        report.report_id,
        investigationId,
    )
    return JSONResponse(content=report_dict, status_code=200)


@reports_router.get(
    "/report/pdf/{investigationId}",
    summary="Generate PDF forensic report",
    description=(
        "Accepts assembled investigation data from the backend and returns "
        "a streaming PDF forensic report ready for download."
    ),
    response_class=StreamingResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "PDF forensic report (application/pdf)"},
        422: {"description": "Invalid investigation data"},
        500: {"description": "PDF generation failed"},
    },
)
async def get_pdf_report(
    investigationId: Annotated[str, Path(description="Unique investigation identifier")],
    payload: Annotated[
        dict[str, Any],
        Body(description="Assembled investigation data from backend"),
    ],
    json_gen: JSONReportGenerator = Depends(get_json_generator),
    pdf_gen: PDFReportGenerator = Depends(get_pdf_generator),
) -> StreamingResponse:
    """Generate and stream a PDF forensic report."""
    logger.info("PDF report requested for investigation_id=%s", investigationId)

    # Validate payload and generate JSON report first
    try:
        investigation = json_gen.validate_payload(payload)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid investigation payload: {exc}",
        ) from exc

    if investigation.investigation_id != investigationId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL investigationId does not match payload investigation_id",
        )

    try:
        report: JSONReport = json_gen.generate(investigation)
        pdf_bytes: bytes = await run_in_threadpool(pdf_gen.generate_pdf, report)
    except RuntimeError as exc:
        logger.exception("PDF generation failed for investigation_id=%s", investigationId)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected error for investigation_id=%s", investigationId)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PDF generation failed: {exc}",
        ) from exc

    filename = pdf_gen.generate_pdf_filename(report)
    logger.info(
        "PDF report generated: filename=%s size=%d bytes",
        filename,
        len(pdf_bytes),
    )

    return StreamingResponse(
        content=io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Report-ID": report.report_id,
            "X-Investigation-ID": investigationId,
            "X-Report-Hash": report.report_hash,
        },
    )


@reports_router.post(
    "/v1/reports/generate",
    summary="Generate both PDF and JSON reports",
    description=(
        "Accepts assembled investigation data and returns metadata about "
        "both the PDF and JSON reports, including their download URLs."
    ),
    status_code=status.HTTP_200_OK,
)
async def generate_reports(
    payload: Annotated[
        dict[str, Any],
        Body(description="Assembled investigation data from backend"),
    ],
    json_gen: JSONReportGenerator = Depends(get_json_generator),
) -> JSONResponse:
    """Generate both report types and return their download endpoint URLs."""
    try:
        investigation = json_gen.validate_payload(payload)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid investigation payload: {exc}",
        ) from exc

    inv_id = investigation.investigation_id
    return JSONResponse(
        content={
            "investigation_id": inv_id,
            "reports": {
                "json": {
                    "url": f"/api/report/json/{inv_id}",
                    "method": "GET",
                    "description": "Machine-readable JSON forensic report",
                },
                "pdf": {
                    "url": f"/api/report/pdf/{inv_id}",
                    "method": "GET",
                    "description": "Downloadable PDF forensic report",
                },
            },
            "note": (
                "Pass the same investigation payload body to each endpoint to retrieve the report."
            ),
        }
    )
