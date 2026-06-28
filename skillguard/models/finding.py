from pydantic import BaseModel, Field

class Finding(BaseModel):
    id: str = Field(..., description="Unique vulnerability rule ID (e.g., CMD001)")
    severity: str = Field(..., description="Risk severity level: CRITICAL, HIGH, MEDIUM, or LOW")
    confidence: str = Field("HIGH", description="Confidence level: HIGH, MEDIUM, or LOW")
    category: str = Field(..., description="Risk category (e.g., COMMAND_EXECUTION)")
    file: str = Field(..., description="Relative path of the scanned file")
    line: int = Field(..., description="Line number of detection (1-indexed)")
    message: str = Field(..., description="Human-readable description of the risk")
