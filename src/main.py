from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from src.api.models import AnalyzeRequest, AnalyzeResponse
from src.api.middleware import whitelist_checker
from src.workflow.graph import create_graph

load_dotenv()

app = FastAPI(title="CyberSentinel", version="0.1.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Graph
agent_graph = create_graph()

@app.get("/")
async def root():
    return {"message": "CyberSentinel Agent is online"}

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_url(request: AnalyzeRequest):
    url = request.url
    
    # 1. Whitelist Check
    if whitelist_checker.is_safe(url):
        return AnalyzeResponse(
            url=url,
            risk_score=0.0,
            verdict="benign",
            reasoning="Domain is in the trusted top 1M whitelist.",
            details={}
        )

    # 2. Run Workflow
    try:
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
        
        final_state = await agent_graph.ainvoke(initial_state)
        
        return AnalyzeResponse(
            url=url,
            risk_score=final_state.get("risk_score", 0.0),
            verdict=final_state.get("verdict", "unknown"),
            reasoning=final_state.get("reasoning", ""),
            details={
                "lexical": final_state.get("lexical"),
                "visual": final_state.get("visual"),
                # Omit infrastructure if too large, or include selected fields
                "infrastructure_summary": "present" if final_state.get("infrastructure") else "missing"
            }
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
