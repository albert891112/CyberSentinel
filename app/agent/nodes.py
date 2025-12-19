import asyncio
from typing import Dict, Any
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_openai import ChatOpenAI

from app.agent.state import AgentState
from app.reflex.engine import ReflexEngine
from app.vision.acquisition import PageAcquirer
from app.vision.embedding import VisualEncoder
from app.vision.matching import BrandMatcher

# Initialize engines lazily or globally
reflex_engine = ReflexEngine()
page_acquirer = PageAcquirer()
visual_encoder = VisualEncoder()
brand_matcher = BrandMatcher() # connect to Qdrant

from app.defense.allowlist import AllowListChecker
from app.defense.safety import PromptGuard
allowlist_checker = AllowListChecker()
prompt_guard = PromptGuard()

async def reflex_node(state: AgentState) -> Dict[str, Any]:
    """Node to run low-level reflex analysis."""
    print(f"--- [Reflex Node] Analyzing: {state['url']} ---")
    
    # 0. Check Allowlist
    if allowlist_checker.is_safe(state['url']):
        print("✅ URL is in Allowlist. Skipping analysis.")
        return {
            "reflex_data": {
                "source": "allowlist",
                "risk_score": 0,
                "verdict": "safe",
                "static_analysis": {},
                "enrichment": {}
            }
        }

    result = await reflex_engine.analyze(state['url'])
    return {"reflex_data": result}

async def vision_node(state: AgentState) -> Dict[str, Any]:
    """Node to run high-level vision analysis."""
    print(f"--- [Vision Node] Viewing: {state['url']} ---")
    
    # 1. Capture
    capture_result = await page_acquirer.capture(state['url'])
    if capture_result['status'] == 'error':
        return {"vision_data": {"error": capture_result['error']}}
    
    # 1.a Safety Check (Pre-LLM)
    safety = prompt_guard.check_content(capture_result.get('html', ''))
    if not safety['safe']:
        print(f"⚠️ Safety Alert: {safety['reason']}")
        return {
             "vision_data": {
                 "error": "Safety Violation", 
                 "details": safety['reason'],
                 "has_screenshot": False 
             }
        }
    
    screenshot = capture_result['screenshot']
    
    # 2. Embed
    embedding = visual_encoder.encode_image(screenshot)
    
    # 3. Match
    params = {}
    matches = brand_matcher.find_similar(embedding, threshold=0.85)
    
    match_data = []
    if matches:
        for m in matches:
            brand_info = m.payload if m.payload else {"brand": "Unknown"}
            match_data.append({
                "brand": brand_info.get("brand"),
                "score": m.score
            })
            
    return {
        "vision_data": {
            "has_screenshot": True,
            "matches": match_data,
            "html_snippet": capture_result['html'][:500] if capture_result['html'] else ""
        }
    }

async def analyst_node(state: AgentState) -> Dict[str, Any]:
    """Node to synthesize findings and generate a verdict."""
    print("--- [Analyst Node] Synthesizing ---")
    
    # Construct prompt from state
    reflex = state.get("reflex_data", {})
    vision = state.get("vision_data", {})
    url = state['url']
    
    prompt = f"""
    You are a Cyber Security Analyst. Analyze this URL: {url}
    
    [REFLEX LAYER]
    Risk Score: {reflex.get('risk_score')}
    Details: {reflex}
    
    [VISION LAYER]
    Brand Matches: {vision.get('matches')}
    
    Decide if this is Phishing, Suspicious, or Clean.
    Provide a JSON response with: {{ "score": 0-100, "verdict": "string", "reason": "string" }}
    """
    
    # For now, simplistic rule-based fallback if no LLM configured, 
    # but structured to use LLM.
    # TOOD: Use actual LLM here.
    
    # Mock decision for Phase 4 verification
    final_score = reflex.get('risk_score', 0)
    matches = vision.get('matches', [])
    if matches:
        final_score = max(final_score, 90)
        
    verdict = "malicious" if final_score > 80 else "clean"
    
    return {
        "final_verdict": verdict,
        "risk_score": final_score,
        "explanation": "Automated logic based on reflex and vision signals."
    }
