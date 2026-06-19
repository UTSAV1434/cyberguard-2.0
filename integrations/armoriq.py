import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class ArmorIQClient:
    def __init__(self, api_key: Optional[str] = None, mock_mode: bool = True):
        self.api_key = api_key or os.getenv("ARMORIQ_API_KEY")
        self.mock_mode = mock_mode
        if self.api_key and os.getenv("MOCK_MODE", "True").lower() != "true":
            self.mock_mode = False

        self._has_sdk = False
        if not self.mock_mode:
            try:
                # Attempt to import armoriq SDK if installed
                import armoriq
                self._has_sdk = True
                logger.info("[ArmorIQ] Successfully loaded armoriq SDK.")
            except ImportError:
                logger.warning("[ArmorIQ] armoriq-sdk package not found. Using direct HTTP API fallback.")

    def evaluate_policy(self, action_type: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Submits an action request and evaluates it against defined policies.
        """
        severity = context.get("severity", "Low")
        risk_score = context.get("risk_score", 0)
        target = context.get("target", "")

        if self.mock_mode:
            logger.info(f"[ArmorIQ MOCK] Evaluating policy for action: {action_type} on {target}")
            
            # Simple policy rules for mock demonstration:
            # 1. Unblock IP (rollback) is always approved if reason is supplied
            if action_type == "UNBLOCK_IP":
                return {
                    "approved": True,
                    "policy_name": "DefaultRollbackPolicy",
                    "reason": "Rollback authorized. Action reversed by admin command.",
                    "intent_token": "mock-token-rollback-approved"
                }

            # 2. Block IP policy gating based on severity and risk
            if severity == "Critical" or (severity == "High" and risk_score >= 80):
                return {
                    "approved": True,
                    "policy_name": "CriticalThreatAutoBlock",
                    "reason": f"Auto-block approved due to high severity ({severity}) and risk score ({risk_score}).",
                    "intent_token": f"mock-token-autoblock-{risk_score}"
                }
            elif severity == "High" or severity == "Medium":
                # Escalate for human approval or require explicit review
                return {
                    "approved": False,
                    "policy_name": "ModerateThreatEscalation",
                    "reason": f"Action requires Human Approval. Risk score ({risk_score}) is below critical auto-block threshold.",
                    "intent_token": "mock-token-human-review-required"
                }
            else:
                # Low severity threat -> Policy rejects automated blocking
                return {
                    "approved": False,
                    "policy_name": "LowSeverityDefaultDeny",
                    "reason": "Automated blocking denied. Low severity incidents should only be monitored.",
                    "intent_token": "mock-token-deny-low-threat"
                }
        else:
            logger.info(f"[ArmorIQ LIVE] Evaluating live policy for: {action_type} on {target}")
            if self._has_sdk:
                try:
                    # Example SDK implementation matching docs.armoriq.ai structure
                    import armoriq
                    client = armoriq.Client(api_key=self.api_key)
                    # Define security plan/intent
                    plan = {
                        "action": action_type,
                        "target": target,
                        "context": context
                    }
                    # Request signed intent token from ArmorIQ
                    token_response = client.get_intent_token(plan)
                    # Verify if the token was signed and approved
                    approved = token_response.get("status") == "approved"
                    return {
                        "approved": approved,
                        "policy_name": token_response.get("policy_name", "LiveArmorIQPolicy"),
                        "reason": token_response.get("reason", "Decision by Live ArmorIQ Policy"),
                        "intent_token": token_response.get("token", "")
                    }
                except Exception as e:
                    logger.error(f"ArmorIQ SDK execution failed: {str(e)}. Falling back to mock rules.")
                    self.mock_mode = True
                    return self.evaluate_policy(action_type, context)
            else:
                # Direct HTTP request fallback
                try:
                    import requests
                    headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
                    response = requests.post(
                        "https://api.armoriq.ai/v1/policy/evaluate",
                        json={
                            "action": action_type,
                            "target": target,
                            "context": context
                        },
                        headers=headers,
                        timeout=10
                    )
                    if response.status_code == 200:
                        data = response.json()
                        return {
                            "approved": data.get("approved", False),
                            "policy_name": data.get("policy_name", "LiveHTTPPolicy"),
                            "reason": data.get("reason", "Approved via Live API"),
                            "intent_token": data.get("intent_token", "")
                        }
                    else:
                        logger.warning(f"ArmorIQ API returned error {response.status_code}. Fallback applied.")
                        self.mock_mode = True
                        return self.evaluate_policy(action_type, context)
                except Exception as e:
                    logger.error(f"ArmorIQ HTTP request failed: {str(e)}. Fallback applied.")
                    self.mock_mode = True
                    return self.evaluate_policy(action_type, context)

    def log_intent_execution(self, intent_token: str, action_status: str, details: Dict[str, Any]) -> bool:
        """
        Submit intent audit and execution results back to ArmorIQ.
        """
        if self.mock_mode:
            logger.info(f"[ArmorIQ MOCK] Log execution status '{action_status}' for token: {intent_token}")
            return True
        else:
            logger.info(f"[ArmorIQ LIVE] Logging execution for token: {intent_token}")
            if self._has_sdk:
                try:
                    import armoriq
                    client = armoriq.Client(api_key=self.api_key)
                    client.log_execution(intent_token, action_status, details)
                    return True
                except Exception as e:
                    logger.error(f"ArmorIQ SDK execution log failed: {str(e)}")
                    return False
            else:
                try:
                    import requests
                    headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
                    response = requests.post(
                        "https://api.armoriq.ai/v1/audit/execution",
                        json={
                            "token": intent_token,
                            "status": action_status,
                            "details": details
                        },
                        headers=headers,
                        timeout=10
                    )
                    return response.status_code == 200
                except Exception as e:
                    logger.error(f"ArmorIQ HTTP audit request failed: {str(e)}")
                    return False
