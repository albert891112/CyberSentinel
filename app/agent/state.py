from typing import TypedDict, Annotated, List, Any
import operator
from langchain_core.messages import BaseMessage

class AgentState(TypedDict):
    url: str
    messages: Annotated[List[BaseMessage], operator.add]
    reflex_data: dict
    vision_data: dict
    final_verdict: str
    risk_score: int
    explanation: str
