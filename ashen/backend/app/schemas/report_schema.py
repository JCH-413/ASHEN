from pydantic import BaseModel


class ReportGenerateRequest(BaseModel):
    scan_id: int
    format: str = "html"  # "html" or "csv"
