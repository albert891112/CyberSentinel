import asyncio
from app.reflex.static import StaticAnalyzer
from app.reflex.enrichment import EnrichmentModule
from app.reflex.caching import AnalysisCache

class ReflexEngine:
    def __init__(self):
        self.static_analyzer = StaticAnalyzer()
        self.enricher = EnrichmentModule()
        self.cache = AnalysisCache()

    async def analyze(self, url: str) -> dict:
        # 1. Check Cache
        cached = await self.cache.get_result(url)
        if cached:
            cached['source'] = 'cache'
            return cached

        # 2. Static Analysis
        static_result = self.static_analyzer.analyze(url)
        
        # 3. Enrichment (Parallel if needed, but doing sequential here for simplicity or could be parallel)
        enrichment_result = await self.enricher.enrich(url)

        # 4. Aggregation
        total_risk = max(static_result['static_risk_score'], enrichment_result['enrichment_risk_score'])
        
        result = {
            "url": url,
            "risk_score": total_risk,
            "static_analysis": static_result,
            "enrichment": enrichment_result,
            "verdict": "malicious" if total_risk > 90 else "suspicious" if total_risk > 50 else "clean",
            "source": "live"
        }
        
        # 5. Cache Result
        await self.cache.set_result(url, result)
        
        return result
