import os
import json
import logging
from datetime import datetime
from models.audit import AuditEntry
from typing import List

logger = logging.getLogger(__name__)

class AuditService:
    def __init__(self):
        if os.environ.get("VERCEL"):
            self.audit_log_path = "/tmp/audit_log.json"
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.audit_log_path = os.path.join(base_dir, "audit_log.json")
        self._init_log()

    def _init_log(self):
        if not os.path.exists(self.audit_log_path):
            initial_logs = [
                {
                    "timestamp": "2026-10-24T09:12:00Z",
                    "event_type": "THREAT_DETECTED",
                    "incident_id": "inc-001",
                    "status": "SUCCESS",
                    "description": "Detected threat Brute Force Attack from IP 198.51.100.99"
                },
                {
                    "timestamp": "2026-10-24T09:12:05Z",
                    "event_type": "SCAN_COMPLETED",
                    "incident_id": "inc-001",
                    "status": "SUCCESS",
                    "description": "Scan complete. Reputation: High"
                },
                {
                    "timestamp": "2026-10-24T09:12:10Z",
                    "event_type": "ACTION_EXECUTED",
                    "incident_id": "inc-001",
                    "status": "SUCCESS",
                    "description": "Successfully blocked IP 198.51.100.99"
                },
                {
                    "timestamp": "2026-10-25T14:30:00Z",
                    "event_type": "THREAT_DETECTED",
                    "incident_id": "inc-002",
                    "status": "SUCCESS",
                    "description": "Detected threat Port Scan Activity from IP 203.0.113.15"
                },
                {
                    "timestamp": "2026-10-25T14:30:05Z",
                    "event_type": "POLICY_REJECTED",
                    "incident_id": "inc-002",
                    "status": "BLOCKED",
                    "description": "Escalated action to manual review: Require Human Approval"
                }
            ]
            with open(self.audit_log_path, "w") as f:
                json.dump(initial_logs, f, indent=4)

    def log_event(self, event_type: str, incident_id: str, description: str, status: str = "SUCCESS") -> AuditEntry:
        """
        Creates an audit entry, writes it locally to the audit JSON log, and logs to the application logger.
        """
        entry = AuditEntry(
            event_type=event_type,
            incident_id=incident_id,
            description=description,
            status=status
        )
        
        logger.info(f"[AuditService] Event: {event_type} | Incident ID: {incident_id} | Status: {status} | Desc: {description}")
        
        try:
            entries = []
            if os.path.exists(self.audit_log_path):
                with open(self.audit_log_path, "r") as f:
                    entries = json.load(f)
            
            entries.append(entry.dict())
            
            with open(self.audit_log_path, "w") as f:
                json.dump(entries, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to write to local audit log: {str(e)}")
            
        return entry

    def get_incident_audit_trail(self, incident_id: str) -> List[AuditEntry]:
        """
        Retrieves all audit entries linked to a specific incident.
        """
        try:
            if not os.path.exists(self.audit_log_path):
                return []
            with open(self.audit_log_path, "r") as f:
                entries = json.load(f)
            return [AuditEntry(**e) for e in entries if e.get("incident_id") == incident_id]
        except Exception as e:
            logger.error(f"Failed to read audit log: {str(e)}")
            return []
