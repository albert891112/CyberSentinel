import sys
import os

sys.path.append(os.getcwd())

from app.optimization.feedback import feedback_system

def main():
    print("🚀 Verifying Feedback Loop...")
    
    url = "https://ambiguous-site.com"
    agent_verdict = "suspicious"
    user_verdict = "safe" # User correcting the agent
    
    feedback_system.submit_feedback(url, agent_verdict, user_verdict, "False positive, this is a partner site.")
    
    # Check if file exists and has content
    if os.path.exists("feedback_log.jsonl"):
        with open("feedback_log.jsonl", "r") as f:
            lines = f.readlines()
            last_entry = lines[-1]
            print(f"✅ Log Entry Found: {last_entry.strip()}")
            if "False positive" in last_entry:
                print("✅ Comments persisted correctly.")
    else:
        print("❌ Feedback file not created.")

if __name__ == "__main__":
    main()
