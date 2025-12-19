import asyncio
import sys
import os
import uuid

# Add project root to sys.path
sys.path.append(os.getcwd())

from app.vision.acquisition import PageAcquirer
from app.vision.embedding import VisualEncoder
from app.vision.matching import BrandMatcher

async def main():
    print("🚀 Starting Vision Layer Verification...\n")
    
    # 1. Test Acquisition
    print("📸 Testing Page Acquisition...")
    acquirer = PageAcquirer()
    # Use example.com for safety and reliability
    result = await acquirer.capture("https://example.com")
    
    if result['status'] == 'error':
        print(f"❌ Capture Failed: {result['error']}")
        return

    screenshot = result['screenshot']
    print(f"✅ Capture Successful. Screenshot size: {len(screenshot)} bytes")
    
    # 2. Test Embedding
    print("\n🧠 Testing CLIP Embedding...")
    encoder = VisualEncoder()
    vector = encoder.encode_image(screenshot)
    print(f"✅ Embedding generated. Dimension: {len(vector)}")
    
    if len(vector) != 512:
        print(f"❌ Unexpected vector dimension: {len(vector)}")
        return

    # 3. Test Matching
    print("\n🔍 Testing Brand Matching (Qdrant)...")
    matcher = BrandMatcher()
    
    # Add a mock brand using this exact screenshot
    test_brand = f"TestBrand_{uuid.uuid4().hex[:8]}"
    print(f"Adding brand: {test_brand}")
    matcher.add_brand(test_brand, vector)
    
    # Search for it
    print("Searching for similar brands...")
    matches = matcher.find_similar(vector, threshold=0.90)
    
    if matches:
        print(f"DEBUG: Payload = {matches[0].payload}")

    if matches and matches[0].payload and matches[0].payload['brand'] == test_brand:
        print(f"✅ Match Successful! Found: {matches[0].payload['brand']} (Score: {matches[0].score})")
    else:
        print(f"❌ Match Failed. Results: {matches}")

if __name__ == "__main__":
    asyncio.run(main())
