from pydantic import BaseModel, Field
from typing import Optional, Any, Dict
from datetime import datetime

class ResponseAction(BaseModel):
    action_type: str  # BLOCK_IP, UNBLOCK_IP
    target: str       # target IP address
    status: str       # PENDING, APPROVED, REJECTED, EXECUTED, FAILED
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    approval_details: Optional[Dict[str, Any]] = None
    undo_token: Optional[str] = None
