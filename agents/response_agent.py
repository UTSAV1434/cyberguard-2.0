import logging
from typing import Dict, Any
from services.incident_service import IncidentService
from models.incident import Incident

logger = logging.getLogger(__name__)

class ResponseAgent:
    def __init__(self, incident_service: IncidentService):
        self.incident_service = incident_service

    def handle_threat(self, threat_data: Dict[str, Any]) -> Incident:
        """
        Coordinates the containment response workflow:
        1. Verifies threat via ArmorClaw (delegated to incident_service)
        2. Evaluates policies with ArmorIQ (delegated to incident_service)
        3. Executes blocking actions if approved (delegated to incident_service)
        4. Saves and logs results (delegated to incident_service)
        """
        ip = threat_data.get("ip_address")
        logger.info(f"[ResponseAgent] Starting containment coordinator for IP: {ip}")
        
        # Process threat and enforce policy-gated responses
        incident = self.incident_service.process_detected_threat(threat_data)
        
        logger.info(f"[ResponseAgent] Containment sequence completed for IP: {ip}. Status: {incident.status}")
        return incident
