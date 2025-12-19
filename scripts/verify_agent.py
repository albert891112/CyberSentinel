import asyncio
import sys
import os

sys.path.append(os.getcwd())

from app.agent.graph import agent_app

async def main():
    print("🚀 Starting Agent Orchestration Verification...\n")
    
    # Test Case 1: Standard Check (Expect Full Path)
    url_1 = "https://www.google.com"
    print(f"--- Testing URL: {url_1} ---")
    inputs = {"url": url_1}
    
    # Run the graph
    result = await agent_app.ainvoke(inputs)
    
    print(f"Final Verdict: {result.get('final_verdict')}")
    print(f"Risk Score: {result.get('risk_score')}")
    print(f"Path Taken: Reflex -> {'Vision -> ' if 'vision_data' in result and result['vision_data'] else ''}Analyst")
    print("-" * 30)

    # Test Case 2: Homoglyph (Simulated High Static Risk)
    # This might not trigger >90 depending on exact entropy implementation, 
    # but we want to see it processed.
    url_2 = "http://xn--paypl-login-secure-v5d.com/login" 
    print(f"\n--- Testing URL: {url_2} ---")
    inputs = {"url": url_2}
    
    result = await agent_app.ainvoke(inputs)
    
    print(f"Final Verdict: {result.get('final_verdict')}")
    print(f"Risk Score: {result.get('risk_score')}")
    
    reflex_risk = result['reflex_data'].get('risk_score')
    print(f"Reflex Risk: {reflex_risk}")
    
    if reflex_risk > 90:
        print("✅ Short-circuit triggered (High Reflex Risk)")
    else:
        print("ℹ️ Continued to Vision Layer")

if __name__ == "__main__":
    asyncio.run(main())
