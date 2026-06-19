import logging
from typing import Dict, Any, Tuple
from integrations.armoriq import ArmorIQClient

logger = logging.getLogger(__name__)

class PolicyService:
    def __init__(self, armoriq_client: ArmorIQClient, confidence_threshold: int = 70):
        self.armoriq_client = armoriq_client
        self.confidence_threshold = confidence_threshold

    def evaluate_containment_policy(self, incident_data: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Evaluate whether the incident can be automatically contained or requires manual escalation.
        Returns:
            (is_approved: bool, recommended_action: str, armoriq_decision: Dict[str, Any])
        """
        risk_score = incident_data.get("risk_score", 0)
        severity = incident_data.get("severity", "Low")
        confidence = incident_data.get("confidence", 100) # Default to high confidence if not provided
        ip_address = incident_data.get("ip_address", "")

        # 1. Check False Positive / Confidence Threshold
        if confidence < self.confidence_threshold:
            logger.info(f"[PolicyService] Incident confidence ({confidence}%) is below threshold ({self.confidence_threshold}%). Marking as Potential False Positive.")
            decision = {
                "approved": False,
                "policy_name": "LowConfidenceEscalation",
                "reason": f"Confidence score ({confidence}%) is below safety threshold ({self.confidence_threshold}%). Potential False Positive.",
                "intent_token": "mock-token-low-confidence-escalated"
            }
            return False, "Require Human Approval", decision

        # 2. Query ArmorIQ policy-gated control
        context = {
            "severity": severity,
            "risk_score": risk_score,
            "target": ip_address,
            "confidence": confidence
        }
        
        armoriq_decision = self.armoriq_client.evaluate_policy("BLOCK_IP", context)
        is_approved = armoriq_decision.get("approved", False)
        
        # Determine final action recommendation based on ArmorIQ evaluation
        if is_approved:
            action = "Block IP"
        else:
            if severity in ["High", "Critical"]:
                action = "Require Human Approval"
            elif severity == "Medium":
                action = "Monitor Activity"
            else:
                action = "Ignore Event"

        return is_approved, action, armoriq_decision

    def evaluate_rollback_policy(self, incident_id: str, ip_address: str, reason: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Evaluate if a rollback / unblock action is permitted.
        """
        context = {
            "incident_id": incident_id,
            "target": ip_address,
            "reason": reason
        }
        armoriq_decision = self.armoriq_client.evaluate_policy("UNBLOCK_IP", context)
        is_approved = armoriq_decision.get("approved", False)
        return is_approved, armoriq_decision
