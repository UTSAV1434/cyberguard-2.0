import logging
from typing import Dict, Any, Optional
from services.incident_service import IncidentService
from services.policy_service import PolicyService
from services.audit_service import AuditService
from integrations.notion import NotionClient

logger = logging.getLogger(__name__)

class RollbackAgent:
    def __init__(
        self,
        incident_service: IncidentService,
        policy_service: PolicyService,
        audit_service: AuditService,
        notion_client: NotionClient
    ):
        self.incident_service = incident_service
        self.policy_service = policy_service
        self.audit_service = audit_service
        self.notion_client = notion_client

    def rollback_incident(self, incident_id: str, reason: str) -> Dict[str, Any]:
        """
        Undoes an IP blocking containment action:
        1. Fetch incident from Notion or Mock DB
        2. Verify IP is blocked
        3. Request rollback policy approval from ArmorIQ
        4. Unblock IP
        5. Log rollback audit entry
        6. Update Notion incident status, timeline, and compliance records
        """
        logger.info(f"[RollbackAgent] Requesting rollback for incident ID: {incident_id}")
        
        # 1. Fetch incident detail
        incident_data = self._fetch_incident_data(incident_id)
        if not incident_data:
            error_msg = f"Incident ID {incident_id} not found in Notion or local database."
            logger.error(error_msg)
            return {"success": False, "message": error_msg}

        ip_address = incident_data.get("IP Address") or incident_data.get("ip_address")
        status = incident_data.get("Status") or incident_data.get("status")
        
        if not ip_address:
            error_msg = f"Could not determine IP address for incident {incident_id}."
            logger.error(error_msg)
            return {"success": False, "message": error_msg}

        # 2. Check if IP is blocked in firewall state
        is_blocked = self.incident_service.is_ip_blocked(ip_address)
        if not is_blocked and status == "Rolled Back":
            return {"success": True, "message": f"IP {ip_address} has already been unblocked. Incident status is Rolled Back."}

        # 3. Check Rollback Policy Gating via ArmorIQ
        is_approved, armoriq_decision = self.policy_service.evaluate_rollback_policy(
            incident_id, ip_address, reason
        )
        
        if not is_approved:
            error_msg = f"Rollback action rejected by ArmorIQ policies. Reason: {armoriq_decision.get('reason')}"
            logger.error(error_msg)
            self.audit_service.log_event(
                "ROLLBACK_REJECTED",
                incident_id,
                f"Rollback rejected by policy: {armoriq_decision.get('reason')}",
                status="FAILED"
            )
            return {"success": False, "message": error_msg}

        # 4. Perform firewall unblock
        unblocked = self.incident_service.unblock_ip(ip_address)
        
        # 5. Log audit trail
        self.audit_service.log_event(
            "ROLLBACK_EXECUTED",
            incident_id,
            f"Rollback executed: IP {ip_address} unblocked. Reason: {reason}",
            status="SUCCESS" if unblocked or not is_blocked else "FAILED"
        )

        # 6. Re-generate Timeline and Compliance Report, and Update Notion
        timeline = incident_data.get("Timeline", [])
        if isinstance(timeline, str):
            # Parse timeline back from mock DB string representation or build new
            # In live mode it's a list. Let's make sure it handles both.
            from datetime import datetime
            new_event = f"[{datetime.utcnow().isoformat() + 'Z'}] Rollback Executed: IP unblocked. Reason: {reason}"
            updated_timeline_str = timeline + "\n" + new_event
            
            # Format new compliance report
            updated_report = incident_data.get("Compliance Report", "")
            updated_report += f"\n\n## Rollback Activity\n*   **Rollback Status:** Reverted\n*   **Rollback Reason:** {reason}\n*   **ArmorIQ Rollback Approval:** Approved (Policy: {armoriq_decision.get('policy_name')})"
            
            updates = {
                "status": "Rolled Back",
                "executed_action": "Unblock IP",
                "Timeline": updated_timeline_str,
                "Compliance Report": updated_report
            }
        else:
            # Struct representation
            from datetime import datetime
            new_event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event": "Rollback Executed",
                "description": f"IP {ip_address} unblocked by admin. Reason: {reason}"
            }
            # Append new event
            timeline_list = list(timeline)
            timeline_list.append(new_event)
            
            # Rebuild compliance report using incident_service logic if we have incident model
            # For simplicity, we can append text or rebuild:
            updated_report = incident_data.get("compliance_report", "")
            updated_report += f"\n\n## Rollback Activity\n*   **Rollback Status:** Reverted\n*   **Rollback Reason:** {reason}\n*   **ArmorIQ Rollback Approval:** Approved (Policy: {armoriq_decision.get('policy_name')})"
            
            updates = {
                "status": "Rolled Back",
                "executed_action": "Unblock IP",
                "timeline": timeline_list,
                "compliance_report": updated_report
            }

        # Save to Notion / Mock DB
        updated_ok = self.notion_client.update_incident_record(incident_id, updates)
        
        if updated_ok:
            logger.info(f"[RollbackAgent] Incident {incident_id} rollback state updated in Notion.")
            return {"success": True, "message": f"Successfully unblocked IP {ip_address} and updated database records."}
        else:
            logger.error(f"[RollbackAgent] Failed to update Notion database record for rollback.")
            return {"success": True, "message": f"IP {ip_address} unblocked, but failed to sync database status."}

    def _fetch_incident_data(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves incident details from Notion or local mock DB.
        """
        if self.notion_client.mock_mode:
            db = self.notion_client._read_mock_db()
            return db.get(incident_id)
        else:
            # Query live page contents
            page_id = self.notion_client.find_page_id_by_incident_id(incident_id)
            if not page_id:
                return None
            try:
                import requests
                headers = {
                    "Authorization": f"Bearer {self.notion_client.token}",
                    "Notion-Version": "2022-06-28"
                }
                # Retrieve page properties
                response = requests.get(f"https://api.notion.com/v1/pages/{page_id}", headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    props = data.get("properties", {})
                    # Parse properties out
                    ip = props.get("IP Address", {}).get("select", {}).get("name", "")
                    status = props.get("Status", {}).get("select", {}).get("name", "")
                    compliance = ""
                    cr_prop = props.get("Compliance Report", {}).get("rich_text", [])
                    if cr_prop:
                        compliance = cr_prop[0].get("text", {}).get("content", "")
                        
                    # Return compatible dict representation
                    return {
                        "id": incident_id,
                        "ip_address": ip,
                        "status": status,
                        "timeline": [], # timeline will be appended in updates
                        "compliance_report": compliance
                    }
                return None
            except Exception as e:
                logger.error(f"Error fetching live Notion incident data: {str(e)}")
                return None
