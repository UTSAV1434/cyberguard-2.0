import os
import sys
import json
import logging
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

# Load environment variables and configure logging
from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("CyberGuardServer")

from integrations.armorclaw import ArmorClawClient
from integrations.armoriq import ArmorIQClient
from integrations.notion import NotionClient
from services.audit_service import AuditService
from services.policy_service import PolicyService
from services.incident_service import IncidentService
from agents.threat_analyzer import ThreatAnalyzer
from agents.response_agent import ResponseAgent
from agents.rollback_agent import RollbackAgent

# Initialize FastAPI App
app = FastAPI(
    title="CyberGuard AI API Server",
    description="Backend API for CyberGuard Incident Detection and Response System",
    version="1.0.0"
)

# Enable CORS for local testing/development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared client / service instantiations
mock_mode = os.getenv("MOCK_MODE", "True").lower() == "true"
notion_token = os.getenv("NOTION_TOKEN")
notion_db = os.getenv("NOTION_DATABASE_ID")
armoriq_key = os.getenv("ARMORIQ_API_KEY")
armorclaw_key = os.getenv("ARMORCLAW_API_KEY")

claw_client = ArmorClawClient(api_key=armorclaw_key, mock_mode=mock_mode)
iq_client = ArmorIQClient(api_key=armoriq_key, mock_mode=mock_mode)
notion_client = NotionClient(token=notion_token, database_id=notion_db, mock_mode=mock_mode)

audit_service = AuditService()
policy_service = PolicyService(armoriq_client=iq_client)
incident_service = IncidentService(
    audit_service=audit_service,
    policy_service=policy_service,
    armorclaw_client=claw_client,
    notion_client=notion_client
)

analyzer = ThreatAnalyzer()
response_agent = ResponseAgent(incident_service=incident_service)
rollback_agent = RollbackAgent(
    incident_service=incident_service,
    policy_service=policy_service,
    audit_service=audit_service,
    notion_client=notion_client
)

# Data Models for API requests
class UndoRequest(BaseModel):
    reason: str = "False Positive"

# --- API Routes ---

@app.get("/api/status")
def get_system_status():
    """Returns general server state and configuration details."""
    return {
        "status": "online",
        "mock_mode": mock_mode,
        "notion_integrated": bool(notion_token and notion_db),
        "armoriq_integrated": bool(armoriq_key),
        "armorclaw_integrated": bool(armorclaw_key)
    }

@app.get("/api/incidents")
def get_incidents():
    """Fetches all incident records from Notion/Mock database."""
    try:
        incidents = notion_client.get_all_incidents()
        return incidents
    except Exception as e:
        logger.error(f"Failed to fetch incidents: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/incidents/{incident_id}")
def get_incident_detail(incident_id: str):
    """Retrieves full information for a specific incident page."""
    try:
        # In mock mode, read directly from the mock database dict
        if notion_client.mock_mode:
            db = notion_client._read_mock_db()
            record = db.get(incident_id)
            if not record:
                raise HTTPException(status_code=404, detail="Incident not found.")
            return record
        
        # In live mode, query standard and detail endpoints
        # Note: Notion details require fetching blocks. We return properties for now.
        page_id = notion_client.find_page_id_by_incident_id(incident_id)
        if not page_id:
            raise HTTPException(status_code=404, detail="Incident page not found in Notion.")
        
        import requests
        headers = {
            "Authorization": f"Bearer {notion_client.token}",
            "Notion-Version": "2022-06-28"
        }
        
        # Query page properties
        res_page = requests.get(f"https://api.notion.com/v1/pages/{page_id}", headers=headers, timeout=10)
        if res_page.status_code != 200:
            raise HTTPException(status_code=500, detail=f"Notion API error: {res_page.text}")
            
        props = res_page.json().get("properties", {})
        ip = props.get("IP Address", {}).get("select", {}).get("name", "")
        status = props.get("Status", {}).get("select", {}).get("name", "")
        threat_type = props.get("Threat Type", {}).get("select", {}).get("name", "")
        severity = props.get("Severity", {}).get("select", {}).get("name", "")
        risk_score = props.get("Risk Score", {}).get("number", 0)
        
        rec_action = ""
        ra_prop = props.get("Recommended Action", {}).get("rich_text", [])
        if ra_prop:
            rec_action = ra_prop[0].get("text", {}).get("content", "")
            
        armorclaw = ""
        ac_prop = props.get("ArmorClaw Result", {}).get("rich_text", [])
        if ac_prop:
            armorclaw = ac_prop[0].get("text", {}).get("content", "")
            
        armoriq = ""
        ai_prop = props.get("ArmorIQ Decision", {}).get("rich_text", [])
        if ai_prop:
            armoriq = ai_prop[0].get("text", {}).get("content", "")
            
        executed = ""
        ex_prop = props.get("Executed Action", {}).get("rich_text", [])
        if ex_prop:
            executed = ex_prop[0].get("text", {}).get("content", "")
            
        compliance = ""
        cr_prop = props.get("Compliance Report", {}).get("rich_text", [])
        if cr_prop:
            compliance = cr_prop[0].get("text", {}).get("content", "")
            
        # Re-fetch children blocks to render Timeline text
        res_blocks = requests.get(f"https://api.notion.com/v1/blocks/{page_id}/children", headers=headers, timeout=10)
        timeline_str = "Timeline retrieval pending."
        if res_blocks.status_code == 200:
            blocks = res_blocks.json().get("results", [])
            timeline_items = []
            capture = False
            for b in blocks:
                b_type = b.get("type")
                if b_type == "heading_2":
                    h_text = b.get("heading_2", {}).get("rich_text", [{}])[0].get("text", {}).get("content", "")
                    if h_text == "Security Timeline":
                        capture = True
                        continue
                    elif capture:
                        # End of timeline section
                        break
                if capture and b_type == "bulleted_list_item":
                    text_runs = b.get("bulleted_list_item", {}).get("rich_text", [])
                    item_text = "".join([t.get("text", {}).get("content", "") for t in text_runs])
                    timeline_items.append(item_text)
            if timeline_items:
                timeline_str = "\n".join(timeline_items)

        return {
            "Incident ID": incident_id,
            "Timestamp": props.get("Timestamp", {}).get("rich_text", [{}])[0].get("text", {}).get("content", ""),
            "IP Address": ip,
            "Threat Type": threat_type,
            "Risk Score": risk_score,
            "Severity": severity,
            "Recommended Action": rec_action,
            "ArmorClaw Result": armorclaw,
            "ArmorIQ Decision": armoriq,
            "Executed Action": executed,
            "Status": status,
            "Timeline": timeline_str,
            "Compliance Report": compliance
        }
    except Exception as e:
        logger.error(f"Failed to fetch incident details: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/incidents/{incident_id}/undo")
def trigger_undo(incident_id: str, req: UndoRequest):
    """Triggers RollbackAgent to unblock an IP and update database status."""
    try:
        result = rollback_agent.rollback_incident(incident_id, req.reason)
        if result["success"]:
            return {"success": True, "message": result["message"]}
        else:
            raise HTTPException(status_code=400, detail=result["message"])
    except Exception as e:
        logger.error(f"Error during rollback trigger: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/simulation/run")
def trigger_simulation():
    """Runs a simulated authentication log scan and applies automated block containment."""
    log_path = os.path.join("c:/Users/utsav/OneDrive/Desktop/uodated hackathon/sample_logs", "auth_failures.json")
    if not os.path.exists(log_path):
        raise HTTPException(status_code=404, detail="Simulated logs file sample_logs/auth_failures.json not found.")
        
    try:
        with open(log_path, "r") as f:
            logs = json.load(f)
            
        detected_threats = analyzer.analyze_logs(logs)
        results = []
        for threat in detected_threats:
            incident = response_agent.handle_threat(threat)
            results.append({
                "id": incident.id,
                "ip_address": incident.ip_address,
                "threat_type": incident.threat_type,
                "severity": incident.severity,
                "risk_score": incident.risk_score,
                "status": incident.status,
                "executed_action": incident.executed_action
            })
        return {
            "success": True,
            "message": f"Successfully parsed {len(logs)} log entries. Discovered {len(detected_threats)} threat scenarios.",
            "results": results
        }
    except Exception as e:
        logger.error(f"Error during simulation run: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/firewall/blocks")
def get_blocked_ips():
    """Retrieves all currently blocked IP addresses."""
    try:
        blocked = list(incident_service._get_blocked_ips())
        return {"blocked_ips": blocked}
    except Exception as e:
        logger.error(f"Failed to query blocked IPs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit-logs")
def get_audit_logs():
    """Fetches all system audit logs recorded locally."""
    try:
        log_path = audit_service.audit_log_path
        if os.path.exists(log_path):
            with open(log_path, "r") as f:
                return json.load(f)
        return []
    except Exception as e:
        logger.error(f"Failed to read audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# --- Serve Single Page App Dashboard ---

# Serve app static directory
os.makedirs("c:/Users/utsav/OneDrive/Desktop/uodated hackathon/static", exist_ok=True)
app.mount("/static", StaticFiles(directory="c:/Users/utsav/OneDrive/Desktop/uodated hackathon/static"), name="static")

# Catch-all endpoint to serve the UI SPA
@app.get("/{full_path:path}", response_class=HTMLResponse)
def serve_index_page(full_path: str):
    """Serves the index page for all non-API paths."""
    index_file = os.path.join("c:/Users/utsav/OneDrive/Desktop/uodated hackathon/static", "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return HTMLResponse(
        content="<h3>CyberGuard AI Web Dashboard UI assets not found. Make sure index.html is generated in static/</h3>",
        status_code=404
    )

if __name__ == "__main__":
    import uvicorn
    # Read port from env or fallback to 8000
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("server:app", host="127.0.0.1", port=port, reload=True)
