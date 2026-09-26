"""Audit trail records (Layer 9): who did what to which evidence, and when.

The gateway writes its own records straight to PostgreSQL. The ingestion service has no
database, so it pushes records onto AUDIT_QUEUE in the same Redis transaction that
queues the email, and the gateway persists them: an email cannot enter the pipeline
without its submission being recorded.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

AUDIT_QUEUE = "audit_events_queue"


class AuditEvent(BaseModel):
    at: datetime = Field(default_factory=datetime.utcnow)
    service: str
    username: Optional[str] = Field(None, description="None when the caller was not authenticated")
    role: Optional[str] = None
    action: str = Field(..., description="e.g. login, email.ingest, report.view")
    resource: Optional[str] = Field(None, description="The email id or account the action touched")
    success: bool = True
    client_ip: Optional[str] = None
    detail: Dict[str, Any] = Field(default_factory=dict)
