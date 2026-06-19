from pydantic import BaseModel, Field
from datetime import datetime
import uuid

class AuditEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    event_type: str  # THREAT_DETECTED, SCAN_COMPLETED, POLICY_APPROVED, ACTION_EXECUTED, ROLLBACK_EXECUTED
    incident_id: str
    description: str
    status: str = "SUCCESS"  # SUCCESS, FAILED, BLOCKED
