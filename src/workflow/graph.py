from langgraph.graph import StateGraph, END
from src.core.state import AgentState
from src.workflow.nodes import lexical_node, infrastructure_node, visual_node, decision_node

def create_graph():
    workflow = StateGraph(AgentState)

    # Add Nodes
    workflow.add_node("lexical", lexical_node)
    workflow.add_node("infrastructure", infrastructure_node)
    workflow.add_node("visual", visual_node)
    workflow.add_node("decision", decision_node)

    # Define Entry Point
    workflow.set_entry_point("lexical")

    # Define Edges
    # Conditional edge: If DGA is extremely high, maybe just stop?
    # For now, let's flow through everything to get a full report.
    
    workflow.add_edge("lexical", "infrastructure")
    workflow.add_edge("infrastructure", "visual")
    workflow.add_edge("visual", "decision")
    workflow.add_edge("decision", END)

    return workflow.compile()
