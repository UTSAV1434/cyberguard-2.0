from typing import Dict, Any, Optional
import os
import logging

logger = logging.getLogger(__name__)

class ArmorClawClient:
    def __init__(self, api_key: Optional[str] = None, mock_mode: bool = True):
        self.api_key = api_key or os.getenv("ARMORCLAW_API_KEY")
        self.mock_mode = mock_mode
        # If API key is set, we can allow turning off mock mode unless overridden
        if self.api_key and os.getenv("MOCK_MODE", "True").lower() != "true":
            self.mock_mode = False

    def scan_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Verify the security reputation of a specific IP address.
        """
        if self.mock_mode:
            logger.info(f"[ArmorClaw MOCK] Scanning reputation for IP: {ip_address}")
            # Mock reputation rules
            if ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address == "127.0.0.1":
                return {
                    "reputation": "Low",
                    "threat_score": 5,
                    "verified": False,
                    "details": "Internal or loopback address. Recognized safe zone."
                }
            elif ip_address.endswith(".91") or ip_address.endswith(".99") or ip_address.endswith(".200"):
                return {
                    "reputation": "High",
                    "threat_score": 95,
                    "verified": True,
                    "details": "Known malicious source. High frequency of failed access attempts observed in global feed."
                }
            else:
                return {
                    "reputation": "Medium",
                    "threat_score": 45,
                    "verified": False,
                    "details": "Uncategorized public IP. No active threat indicators registered."
                }
        else:
            logger.info(f"[ArmorClaw LIVE] Querying ArmorClaw API for IP: {ip_address}")
            try:
                import requests
                headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
                # Hypothetical or standard ArmorClaw endpoint
                response = requests.post(
                    "https://api.armoriq.ai/v1/armorclaw/scan",
                    json={"ip": ip_address},
                    headers=headers,
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "reputation": data.get("reputation", "Medium"),
                        "threat_score": data.get("threat_score", 50),
                        "verified": data.get("verified", False),
                        "details": data.get("details", "Scanned via live API")
                    }
                else:
                    logger.warning(f"ArmorClaw API error status {response.status_code}. Falling back to safe mock.")
                    return {
                        "reputation": "Medium",
                        "threat_score": 50,
                        "verified": False,
                        "details": f"API error {response.status_code}. Fallback applied."
                    }
            except Exception as e:
                logger.error(f"Failed to scan IP via ArmorClaw: {str(e)}")
                return {
                    "reputation": "Medium",
                    "threat_score": 50,
                    "verified": False,
                    "details": f"Error: {str(e)}. Fallback applied."
                }
