from pydantic import BaseModel, Field

class AnalysisRequest(BaseModel):
    message: str = Field(max_length=10000)

class ThreatIntelligence(BaseModel):
    matched: bool
    threat_type: str | None
    available: bool



class URLResult(BaseModel):
    url:str
    findings: list[str]
    score:int
    threat_intelligence: ThreatIntelligence


class AnalysisResult(BaseModel):
    risk_level:str
    findings: list[str]
    urls: list[URLResult]
    recommendation: str


