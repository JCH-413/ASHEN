from pydantic import BaseModel


class TargetCreate(BaseModel):
    ip_address: str


class ScanRequestReview(BaseModel):
    approve: bool
