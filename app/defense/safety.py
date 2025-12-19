class PromptGuard:
    def __init__(self):
        self.blocklist = [
            "ignore previous instructions",
            "system prompt",
            "you are a hacked agent",
            "reveal your instructions"
        ]

    def check_content(self, text: str) -> dict:
        """
        scans text (HTML or extracted text) for injection attempts.
        Returns: {'safe': bool, 'reason': str}
        """
        if not text:
            return {"safe": True, "reason": None}
            
        lower_text = text.lower()
        for phrase in self.blocklist:
            if phrase in lower_text:
                return {
                    "safe": False, 
                    "reason": f"Potential Prompt Injection detected: '{phrase}'"
                }
        
        return {"safe": True, "reason": None}
