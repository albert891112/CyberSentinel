from pydantic import BaseModel, HttpUrl
from typing import Dict, Any, Optional

class AnalyzeRequest(BaseModel):
    url: str

class AnalyzeResponse(BaseModel):
    url: str
    risk_score: float
    verdict: str
    reasoning: str
    details: Optional[Dict[str, Any]] = None
