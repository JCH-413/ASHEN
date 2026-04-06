import ipaddress
from pydantic import BaseModel, field_validator


class ScanStartRequest(BaseModel):
    ip_address: str
    ack_disclaimer: bool

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        v = v.strip()
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v


class ScanRequestCreate(BaseModel):
    ip_address: str
    reason: str

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        v = v.strip()
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v
