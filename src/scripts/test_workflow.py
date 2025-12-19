import asyncio
import os
import sys

# Ensure src is in path
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))

from src.workflow.graph import create_graph

async def run_workflow():
    print("=== Phase 4: Full Workflow Test ===\n")
    
    app = create_graph()
    
    # Test Case 1: Example (Benign)
    url = "https://example.com"
    print(f"[*] Analyzing {url}...")
    
    initial_state = {
         "url": url, 
         "messages": [],
         "risk_score": 0.0,
         "verdict": "pending",
         "reasoning": "",
         "lexical": None,
         "infrastructure": None,
         "visual": None
    }
    
    try:
        final_state = await app.ainvoke(initial_state)
        print("\n=== Final Report ===")
        print(f"Verdict: {final_state['verdict'].upper()}")
        print(f"Score:   {final_state['risk_score']}")
        print(f"Reason:  {final_state['reasoning']}")
        
        if final_state['visual']:
            print(f"Visual Match: {final_state['visual'].get('match')} (Score: {final_state['visual'].get('score')})")
            
    except Exception as e:
        print(f"[-] Workflow Execution Failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(run_workflow())
