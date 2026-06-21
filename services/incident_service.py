import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from models.incident import Incident, TimelineEvent
from services.audit_service import AuditService
from services.policy_service import PolicyService
from integrations.armorclaw import ArmorClawClient
from integrations.notion import NotionClient

logger = logging.getLogger(__name__)

class IncidentService:
    def __init__(
        self,
        audit_service: AuditService,
        policy_service: PolicyService,
        armorclaw_client: ArmorClawClient,
        notion_client: NotionClient
    ):
        self.audit_service = audit_service
        self.policy_service = policy_service
        self.armorclaw_client = armorclaw_client
        self.notion_client = notion_client
        if os.environ.get("VERCEL"):
            self.firewall_state_path = "/tmp/firewall_state.json"
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.firewall_state_path = os.path.join(base_dir, "firewall_state.json")
        self._init_firewall_state()

    def _init_firewall_state(self):
        if not os.path.exists(self.firewall_state_path):
            with open(self.firewall_state_path, "w") as f:
                json.dump({"blocked_ips": ["198.51.100.99"]}, f, indent=4)

    def _get_blocked_ips(self) -> Set[str]:
        try:
            with open(self.firewall_state_path, "r") as f:
                data = json.load(f)
                return set(data.get("blocked_ips", []))
        except Exception:
            return set()

    def _save_blocked_ips(self, blocked_ips: Set[str]):
        try:
            with open(self.firewall_state_path, "w") as f:
                json.dump({"blocked_ips": list(blocked_ips)}, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to write firewall state: {str(e)}")

    def block_ip(self, ip_address: str) -> bool:
        blocked = self._get_blocked_ips()
        blocked.add(ip_address)
        self._save_blocked_ips(blocked)
        logger.info(f"[Firewall] Blocked IP: {ip_address}")
        return True

    def unblock_ip(self, ip_address: str) -> bool:
        blocked = self._get_blocked_ips()
        if ip_address in blocked:
            blocked.remove(ip_address)
            self._save_blocked_ips(blocked)
            logger.info(f"[Firewall] Unblocked IP: {ip_address}")
            return True
        return False

    def is_ip_blocked(self, ip_address: str) -> bool:
        return ip_address in self._get_blocked_ips()

    def process_detected_threat(self, threat_data: Dict[str, Any]) -> Incident:
        """
        Main orchestration logic when a threat is identified by the Threat Analyzer.
        """
        ip = threat_data["ip_address"]
        threat_type = threat_data["threat_type"]
        risk_score = threat_data["risk_score"]
        severity = threat_data["severity"]
        explanation = threat_data["explanation"]
        confidence = threat_data.get("confidence", 100)

        # 1. Instantiate new Incident
        incident = Incident(
            ip_address=ip,
            threat_type=threat_type,
            risk_score=risk_score,
            severity=severity,
            explanation=explanation
        )
        
        # Add initial timeline event
        incident.add_timeline_event("Threat Detected", f"Suspicious activity categorized as '{threat_type}' (Risk: {risk_score}/100).")
        self.audit_service.log_event("THREAT_DETECTED", incident.id, f"Detected threat {threat_type} from IP {ip}")

        # 2. Run ArmorClaw verification
        incident.add_timeline_event("ArmorClaw Scan Started", f"Initiating reputation check for IP {ip}.")
        self.audit_service.log_event("SCAN_INITIATED", incident.id, f"Initiating ArmorClaw scanning for {ip}")
        
        scan_result = self.armorclaw_client.scan_ip(ip)
        incident.armorclaw_result = scan_result
        incident.add_timeline_event("Scan Completed", f"ArmorClaw scan concluded. Reputation: {scan_result.get('reputation')}. Verified: {scan_result.get('verified')}")
        self.audit_service.log_event("SCAN_COMPLETED", incident.id, f"Scan complete. Reputation: {scan_result.get('reputation')}")

        # Recalculate parameters based on scan findings if necessary
        # E.g. If reputation is confirmed High threat, risk score and severity could escalate
        adjusted_data = {
            "risk_score": max(risk_score, scan_result.get("threat_score", 0)) if scan_result.get("verified") else risk_score,
            "severity": "Critical" if scan_result.get("reputation") == "High" else severity,
            "confidence": confidence,
            "ip_address": ip
        }
        
        # Update incident with adjusted values
        incident.risk_score = adjusted_data["risk_score"]
        incident.severity = adjusted_data["severity"]

        # 3. Policy Gating via PolicyService & ArmorIQ
        incident.add_timeline_event("Policy Requested", "Submitting containment action request to ArmorIQ policy manager.")
        self.audit_service.log_event("POLICY_REQUESTED", incident.id, "Submitting BLOCK_IP action request to ArmorIQ")
        
        is_approved, recommended_action, armoriq_decision = self.policy_service.evaluate_containment_policy(adjusted_data)
        
        incident.armoriq_decision = armoriq_decision
        incident.recommended_action = recommended_action

        # Handle Policy Decision Outcomes
        if is_approved:
            incident.status = "Action Executed"
            incident.add_timeline_event("Policy Approved", f"ArmorIQ approved containment action. Policy: {armoriq_decision.get('policy_name')}")
            self.audit_service.log_event("POLICY_APPROVED", incident.id, f"ArmorIQ approved blocking {ip}", status="SUCCESS")
            
            # Execute firewall block action
            self.block_ip(ip)
            incident.executed_action = "Block IP"
            incident.add_timeline_event("IP Blocked", f"Firewall successfully blocked traffic from IP {ip}.")
            self.audit_service.log_event("ACTION_EXECUTED", incident.id, f"Successfully blocked IP {ip}", status="SUCCESS")
        else:
            incident.executed_action = "None"
            
            if recommended_action == "Require Human Approval":
                incident.status = "Pending Approval"
                incident.add_timeline_event("Policy Rejected / Escalated", f"Policy evaluation requires human review. Reason: {armoriq_decision.get('reason')}")
                self.audit_service.log_event("POLICY_REJECTED", incident.id, f"Escalated action to manual review: {armoriq_decision.get('reason')}", status="BLOCKED")
            elif recommended_action == "Monitor Activity":
                incident.status = "Resolved"
                incident.add_timeline_event("Policy Rejected", f"Action declined by policy. Continuous monitoring active. Reason: {armoriq_decision.get('reason')}")
                self.audit_service.log_event("POLICY_REJECTED", incident.id, f"Policy declined blocking. Monitoring enabled.", status="BLOCKED")
            else:
                incident.status = "Resolved"
                incident.add_timeline_event("Policy Rejected", f"Action declined. Threat classified as negligible. Reason: {armoriq_decision.get('reason')}")
                self.audit_service.log_event("POLICY_REJECTED", incident.id, "Policy declined blocking. Event ignored.", status="BLOCKED")

        # 4. Generate Compliance Report
        compliance_doc = self.generate_compliance_report(incident)
        incident.compliance_report = compliance_doc

        # 5. Notion Documentation
        notion_incident_data = {
            "id": incident.id,
            "timestamp": incident.timestamp,
            "ip_address": incident.ip_address,
            "threat_type": incident.threat_type,
            "risk_score": incident.risk_score,
            "severity": incident.severity,
            "recommended_action": incident.recommended_action,
            "armorclaw_result": incident.armorclaw_result,
            "armoriq_decision": incident.armoriq_decision,
            "executed_action": incident.executed_action,
            "status": incident.status,
            "timeline": [t.dict() for t in incident.timeline],
            "compliance_report": incident.compliance_report,
            "explanation": incident.explanation
        }
        
        try:
            page_id = self.notion_client.create_incident_record(notion_incident_data)
            logger.info(f"[IncidentService] Incident logged successfully on Notion. Page: {page_id}")
        except Exception as e:
            logger.error(f"Failed to log incident to Notion: {str(e)}")

        return incident

    def generate_compliance_report(self, incident: Incident) -> str:
        """
        Creates a clean compliance-ready audit report.
        """
        timeline_rows = []
        for event in incident.timeline:
            timeline_rows.append(f"| {event.timestamp} | {event.event} | {event.description} |")

        report = f"""# SECURITY COMPLIANCE REPORT
**Incident ID:** {incident.id}
**Report Generated:** {datetime.utcnow().isoformat() + "Z"}

## Incident Summary
*   **Threat Type:** {incident.threat_type}
*   **Target IP:** {incident.ip_address}
*   **Risk Score:** {incident.risk_score}/100
*   **Severity Level:** {incident.severity}
*   **Recommended Action:** {incident.recommended_action}
*   **Current Status:** {incident.status}

## Threat Verification & Reputation (ArmorClaw)
*   **Reputation Rating:** {incident.armorclaw_result.get('reputation', 'Unknown')}
*   **Threat Score:** {incident.armorclaw_result.get('threat_score', 0)}/100
*   **Verified Threat Indicator:** {incident.armorclaw_result.get('verified', False)}
*   **Verification Explanation:** {incident.armorclaw_result.get('details', '')}

## Policy Gating & Decision (ArmorIQ)
*   **Policy Name:** {incident.armoriq_decision.get('policy_name', 'N/A')}
*   **Decision:** {"Approved" if incident.armoriq_decision.get('approved') else "Declined/Escalated"}
*   **Intent Token:** `{incident.armoriq_decision.get('intent_token', 'N/A')}`
*   **Policy Logic Context:** {incident.armoriq_decision.get('reason', 'N/A')}

## Actions Executed
*   **Enforcement Action:** {incident.executed_action}
*   **Timestamp:** {incident.timestamp}

## Incident Security Timeline
| Timestamp | Action/Event | Description |
| :--- | :--- | :--- |
"""
        report += "\n".join(timeline_rows)
        return report
