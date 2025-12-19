from langgraph.graph import StateGraph, END
from app.agent.state import AgentState
from app.agent.nodes import reflex_node, vision_node, analyst_node

def route_after_reflex(state: AgentState):
    """Conditional routing: Short-circuit if high confidence malicious."""
    reflex_data = state.get("reflex_data", {})
    if reflex_data.get("verdict") == "malicious" or reflex_data.get("verdict") == "safe":
        return "analyst_node" # Jump straight to analyst to finalize report (skip expensive vision)
        
    return "vision_node"

workflow = StateGraph(AgentState)

# Add nodes
workflow.add_node("reflex_node", reflex_node)
workflow.add_node("vision_node", vision_node)
workflow.add_node("analyst_node", analyst_node)

# Add edges
workflow.set_entry_point("reflex_node")

workflow.add_conditional_edges(
    "reflex_node",
    route_after_reflex,
    {
        "analyst_node": "analyst_node",
        "vision_node": "vision_node"
    }
)

workflow.add_edge("vision_node", "analyst_node")
workflow.add_edge("analyst_node", END)

# Compile
agent_app = workflow.compile()
