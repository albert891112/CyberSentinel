import os
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from typing import Dict, Any

class LLMAnalyst:
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        if self.api_key:
            self.llm = ChatOpenAI(model="gpt-4o-mini", temperature=0) # Use mini for cost per plan
        else:
            self.llm = None
            print("[-] OPENAI_API_KEY not found. LLM Analysis will be mocked.")

    async def analyze(self, state_data: Dict[str, Any]) -> Dict[str, Any]:
        if not self.llm:
            return {
                "risk_score": 0.5,
                "verdict": "suspicious",
                "reasoning": "LLM API Key missing, defaulting to suspicious."
            }

        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a senior cybersecurity analyst. Analyze the provided data about a URL.
            
            Data includes:
            - Lexical: Entropy, DGA likelihood.
            - Infrastructure: Whois age, DNS, VirusTotal score.
            - Visual: Visual similarity to known brands (spoofing).
            
            Your task:
            1. Determine a risk score (0-100).
            2. Provide a verdict (benign, suspicious, malicious).
            3. Explain your reasoning in 2-3 sentences.
            4. Look for contradictions (e.g., visual looks like Microsoft but domain is not microsoft.com).
            
            Return JSON: {{ "risk_score": float, "verdict": str, "reasoning": str }}
            """),
            ("user", "{data}")
        ])

        chain = prompt | self.llm | JsonOutputParser()
        
        try:
            # Filter relevant data to keep prompt small
            context = {
                "url": state_data.get("url"),
                "lexical": state_data.get("lexical"),
                "infrastructure": state_data.get("infrastructure"),
                "visual": state_data.get("visual")
            }
            result = await chain.ainvoke({"data": str(context)})
            return result
        except Exception as e:
            return {
                "risk_score": 0.0,
                "verdict": "error",
                "reasoning": f"LLM analysis failed: {e}"
            }
