import math
from collections import Counter
from urllib.parse import urlparse
import re

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())

def detect_homoglyphs(domain: str) -> bool:
    """
    Simple check for non-ASCII characters that might indicate IDN homoglyph attacks.
    Note: Ideally this would check against a list of confusable characters.
    """
    try:
        if domain.lower().startswith("xn--"):
            return True
        domain.encode('ascii')
        return False
    except UnicodeEncodeError:
        return True

class StaticAnalyzer:
    def analyze(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        entropy = calculate_entropy(domain)
        has_homoglyphs = detect_homoglyphs(domain)
        
        # Simple heuristic risk assessment
        risk_score = 0
        if entropy > 4.0: # Creating a threshold
            risk_score += 30
        if has_homoglyphs:
            risk_score += 60
        if "login" in path or "secure" in path:
            risk_score += 10
            
        return {
            "entropy": entropy,
            "has_homoglyphs": has_homoglyphs,
            "static_risk_score": min(risk_score, 100)
        }
