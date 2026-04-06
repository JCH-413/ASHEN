import ipaddress
from pydantic import BaseModel, field_validator


class TargetCreate(BaseModel):
    ip_address: str

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        v = v.strip()
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v


class ScanRequestReview(BaseModel):
    approve: bool
