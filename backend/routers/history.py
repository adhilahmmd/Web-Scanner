"""
Scan history endpoints — list, get, delete saved scans for the logged-in user.
"""

import json
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.dependencies import get_db, get_current_user
from database.models import User, ScanResult
from routers.scan import UnifiedScanResult

router = APIRouter()


# ── Pydantic schemas ──────────────────────────────────────────────────────────
class ScanSummary(BaseModel):
    id: int
    target_url: str
    modules_run: List[str]
    risk_level: Optional[str]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_findings: int
    scan_duration: Optional[int]
    created_at: str


class ScanDetail(ScanSummary):
    result_json: Optional[dict]


# ── Helpers ───────────────────────────────────────────────────────────────────
def _scan_to_summary(scan: ScanResult) -> ScanSummary:
    try:
        modules = json.loads(scan.modules_run) if scan.modules_run else []
    except Exception:
        modules = []
    return ScanSummary(
        id=scan.id,
        target_url=scan.target_url,
        modules_run=modules,
        risk_level=scan.risk_level,
        critical_count=scan.critical_count or 0,
        high_count=scan.high_count or 0,
        medium_count=scan.medium_count or 0,
        low_count=scan.low_count or 0,
        total_findings=scan.total_findings or 0,
        scan_duration=scan.scan_duration,
        created_at=scan.created_at.isoformat(),
    )


def _scan_to_detail(scan: ScanResult) -> ScanDetail:
    summary = _scan_to_summary(scan)
    try:
        result = json.loads(scan.result_json) if scan.result_json else None
    except Exception:
        result = None
    return ScanDetail(**summary.model_dump(), result_json=result)


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.get("", response_model=List[ScanSummary], summary="List all scans for the current user")
def list_history(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scans = (
        db.query(ScanResult)
        .filter(ScanResult.user_id == current_user.id)
        .order_by(ScanResult.created_at.desc())
        .all()
    )
    return [_scan_to_summary(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanDetail, summary="Get full details of a saved scan")
def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.query(ScanResult).filter(
        ScanResult.id == scan_id,
        ScanResult.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return _scan_to_detail(scan)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a saved scan")
def delete_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.query(ScanResult).filter(
        ScanResult.id == scan_id,
        ScanResult.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    db.delete(scan)
    db.commit()

@router.post("/save", response_model=ScanSummary, summary="Save an aggregated scan result from frontend")
def save_scan(
    result: UnifiedScanResult,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = ScanResult(
        user_id=current_user.id,
        target_url=result.url,
        modules_run=json.dumps(result.modules_requested),
        result_json=json.dumps(result.results),
        risk_level=result.overall_risk,
        critical_count=result.critical_count,
        high_count=result.high_count,
        medium_count=result.medium_count,
        low_count=result.low_count,
        total_findings=result.total_vulnerabilities,
        scan_duration=0,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return _scan_to_summary(scan)
