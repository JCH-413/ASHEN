from pydantic import BaseModel
from typing import Optional


class AttackRecommendRequest(BaseModel):
    scan_id: int
    vuln_id: Optional[int] = None


class RemediationRequest(BaseModel):
    vuln_id: Optional[int] = None
    exploit_id: Optional[int] = None
    description: Optional[str] = None


class ReviewRequest(BaseModel):
    action: str  # "accept", "reject", "regenerate"


class AIChatRequest(BaseModel):
    question: str
    vuln_id: Optional[int] = None
    exploit_id: Optional[int] = None
    remediation_context: Optional[str] = None
