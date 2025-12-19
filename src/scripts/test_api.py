from fastapi.testclient import TestClient
from src.main import app
import os
import sys

# Ensure src is in path
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))

client = TestClient(app)

def test_api():
    print("=== Phase 5: API Verification ===\n")
    
    # 1. Test Root
    response = client.get("/")
    assert response.status_code == 200
    print("[+] Root Endpoint: OK")

    # 2. Test Whitelist
    print("[*] Testing Whitelisted URL (google.com)...")
    payload = {"url": "https://www.google.com"}
    response = client.post("/analyze", json=payload)
    if response.status_code == 200:
        data = response.json()
        print(f"    Verdict: {data['verdict']}")
        if data['verdict'] == "benign":
            print("[+] Whitelist Check: SUCCESS")
        else:
            print("[-] Whitelist Check: FAILED")
    else:
        print(f"[-] Request failed: {response.text}")

    # 3. Test Workflow (Mocked if needed)
    print("\n[*] Testing Analysis Workflow (Example.com)...")
    # Note: Example.com is in my mock whitelist in middleware.py, so I should remove it or use another one.
    # Actually, example.com IS in middleware.py whitelist. 
    # Let's use something else: "http://test-phishing.com"
    
    payload = {"url": "http://test-phishing.com"}
    response = client.post("/analyze", json=payload)
    if response.status_code == 200:
        data = response.json()
        print(f"    Verdict: {data['verdict']}")
        print(f"    Reasoning: {data['reasoning']}")
        print("[+] Analysis Endpoint: OK")
    else:
        print(f"[-] Request failed: {response.text}")

if __name__ == "__main__":
    test_api()
