import logging
from fastapi import APIRouter, Depends, BackgroundTasks, Request
from fastapi.responses import Response, HTMLResponse
from auth import require_auth, SessionEntry
from utils.ipam_engine import IPAMDiscoveryEngine, get_ipam_snapshot
from utils.ipam_export import generate_solarwinds_csv
from templates_module import templates

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/discover")
async def start_discovery(background_tasks: BackgroundTasks, session: SessionEntry = Depends(require_auth)):
    engine = IPAMDiscoveryEngine(session=session)
    background_tasks.add_task(engine.run)
    return {"status": "Discovery started in background"}

@router.get("/status")
async def get_discovery_status():
    snapshot = get_ipam_snapshot()
    if not snapshot:
        return {"status": "No discovery performed yet"}
    return {
        "status": "Ready",
        "last_run": snapshot.get("last_run"),
        "stats": snapshot.get("stats")
    }

@router.get("/export")
async def export_ipam_csv(session: SessionEntry = Depends(require_auth)):
    snapshot = get_ipam_snapshot()
    if not snapshot:
        return Response(content="No data to export", status_code=404)

    csv_data = generate_solarwinds_csv(snapshot.get("master_ip_map", {}))
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=solarwinds_ipam_export.csv"}
    )

@router.get("/dashboard-data")
async def get_ipam_dashboard_data(request: Request, session: SessionEntry = Depends(require_auth)):
    snapshot = get_ipam_snapshot()
    if not snapshot:
        return {"full": [], "orphaned": [], "gaps": [], "stats": {}}

    # We might want to filter or paginate here if the data is huge
    master_map = snapshot.get("master_ip_map", {})

    # Process for UI
    full_list = []
    orphaned_list = []
    for ip, data in master_map.items():
        row = {"ip": ip, **data}
        full_list.append(row)
        if data.get("status") == "Orphaned":
            orphaned_list.append(row)

    return {
        "stats": snapshot.get("stats"),
        "full": full_list,
        "orphaned": orphaned_list,
        "gaps": snapshot.get("dual_stack_gaps", []),
        "last_run": snapshot.get("last_run")
    }
