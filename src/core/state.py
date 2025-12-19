from typing import TypedDict, List, Dict, Any, Optional

class AgentState(TypedDict):
    url: str
    lexical: Optional[Dict[str, Any]]
    infrastructure: Optional[Dict[str, Any]]
    visual: Optional[Dict[str, Any]]
    risk_score: float
    verdict: str # "benign", "malicious", "suspicious"
    reasoning: str
    messages: List[Any] # For LLM context
