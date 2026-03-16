from pydantic import BaseModel


class ScanStartRequest(BaseModel):
    ip_address: str
    ack_disclaimer: bool


class ScanRequestCreate(BaseModel):
    ip_address: str
    reason: str
