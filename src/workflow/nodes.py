import asyncio
from src.core.state import AgentState
from src.analysis.lexical.analyzer import LexicalAnalyzer
from src.analysis.infrastructure.dns_resolver import DNSResolver
from src.analysis.infrastructure.whois_client import WhoisClient
from src.analysis.infrastructure.reputation import ReputationChecker
from src.analysis.visual.browser import BrowserService
from src.analysis.visual.scanner import VisualScanner
from src.analysis.llm_analyst import LLMAnalyst

# Initialize services (could be Dependency Injected)
lexical_analyzer = LexicalAnalyzer()
dns_resolver = DNSResolver()
whois_client = WhoisClient()
reputation_checker = ReputationChecker()
browser_service = BrowserService()
visual_scanner = VisualScanner()
llm_analyst = LLMAnalyst()

def lexical_node(state: AgentState) -> AgentState:
    url = state["url"]
    print(f"[*] Node: Lexical Analysis on {url}")
    result = lexical_analyzer.analyze(url)
    
    # Heuristic update
    if result["is_dga"]:
        state["risk_score"] = 90.0
        state["verdict"] = "malicious"
        state["reasoning"] = "Detected high entropy or DGA characteristics."
    
    state["lexical"] = result
    return state

async def infrastructure_node(state: AgentState) -> AgentState:
    url = state["url"]
    print(f"[*] Node: Infrastructure Analysis on {url}")
    
    # Parallel execution
    try:
        # Extract domain from url for DNS/Whois. 
        # Ideally helper function, but simple parsing here:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        if not domain: domain = url
    except:
        domain = url

    dns_task = dns_resolver.get_dns_records(domain)
    whois_task = whois_client.get_whois_info(domain)
    rep_task = reputation_checker.aggregate_reputation(url)
    
    results = await asyncio.gather(dns_task, whois_task, rep_task, return_exceptions=True)
    
    infra_data = {
        "dns": results[0] if not isinstance(results[0], Exception) else str(results[0]),
        "whois": results[1] if not isinstance(results[1], Exception) else str(results[1]),
        "reputation": results[2] if not isinstance(results[2], Exception) else str(results[2])
    }
    
    state["infrastructure"] = infra_data
    return state

async def visual_node(state: AgentState) -> AgentState:
    url = state["url"]
    print(f"[*] Node: Visual Analysis on {url}")
    
    screenshot = await browser_service.capture_screenshot(url)
    if screenshot:
        comparison = visual_scanner.compare(screenshot)
        state["visual"] = comparison
    else:
        state["visual"] = {"error": "Screenshot failed"}
    
    return state

async def decision_node(state: AgentState) -> AgentState:
    print(f"[*] Node: LLM Decision")
    # Combine previous findings
    
    # If already high risk from lexical, we might skip heavy visual... 
    # But usually visual confirms phishing.
    
    decision = await llm_analyst.analyze(state)
    
    state["risk_score"] = decision.get("risk_score", 0)
    state["verdict"] = decision.get("verdict", "unknown")
    state["reasoning"] = decision.get("reasoning", "")
    
    return state
