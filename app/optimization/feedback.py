import json
import os
from datetime import datetime

class FeedbackSystem:
    def __init__(self, feedback_file="feedback_log.jsonl"):
        self.feedback_file = feedback_file

    def submit_feedback(self, url: str, agent_verdict: str, user_verdict: str, comments: str = ""):
        """
        Log user corrections or confirmations.
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "url": url,
            "agent_verdict": agent_verdict,
            "user_verdict": user_verdict,
            "comments": comments,
            "match": agent_verdict == user_verdict
        }
        
        with open(self.feedback_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
            
        print(f"📝 Feedback received for {url}. Logged to {self.feedback_file}")

feedback_system = FeedbackSystem()
