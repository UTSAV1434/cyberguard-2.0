from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

class TimelineEvent(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    event: str
    description: str

class Incident(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    ip_address: str
    threat_type: str = "Unknown"
    risk_score: int = 0
    severity: str = "Low"  # Low, Medium, High, Critical
    recommended_action: str = "Monitor Activity"  # Block IP, Monitor Activity, Require Human Approval, Ignore Event
    explanation: str = ""
    armorclaw_result: Dict[str, Any] = Field(default_factory=dict)
    armoriq_decision: Dict[str, Any] = Field(default_factory=dict)
    executed_action: str = "None"
    status: str = "Pending Approval"  # Potential False Positive, Pending Approval, Action Executed, Resolved, Rolled Back
    timeline: List[TimelineEvent] = Field(default_factory=list)
    compliance_report: str = ""

    def add_timeline_event(self, event: str, description: str):
        self.timeline.append(TimelineEvent(event=event, description=description))
