import os
from PIL import Image
from io import BytesIO
from typing import List, Dict, Any, Optional
from qdrant_client import QdrantClient
from qdrant_client.http import models
from sentence_transformers import SentenceTransformer

class VisualScanner:
    def __init__(self):
        self.qdrant_url = os.getenv("QDRANT_URL", "http://localhost:6333")
        self.client = QdrantClient(url=self.qdrant_url)
        self.collection_name = "brand_vectors"
        
        # Load CLIP model (lightweight version)
        # We use 'clip-ViT-B-32' which is standard.
        print("[*] Loading CLIP model (this may take a moment)...")
        self.model = SentenceTransformer('clip-ViT-B-32')

    def embed_image(self, image_data: bytes) -> List[float]:
        """Convert image bytes to vector."""
        image = Image.open(BytesIO(image_data))
        return self.model.encode(image).tolist()

    def index_brand(self, brand_name: str, image_path: str):
        """Index a reference image for a brand."""
        if not os.path.exists(image_path):
            print(f"[-] Image not found: {image_path}")
            return

        print(f"[*] Indexing {brand_name} from {image_path}...")
        image = Image.open(image_path)
        vector = self.model.encode(image).tolist()
        
        # Upsert to Qdrant
        # We use brand_name hash as ID for simplicity or random int
        import hashlib
        point_id = int(hashlib.sha256(brand_name.encode()).hexdigest(), 16) % (10**15)

        self.client.upsert(
            collection_name=self.collection_name,
            points=[
                models.PointStruct(
                    id=point_id,
                    vector=vector,
                    payload={"brand": brand_name}
                )
            ]
        )
        print(f"[+] Indexed {brand_name}")

    def compare(self, screenshot_bytes: bytes) -> Dict[str, Any]:
        """Compare screenshot against known brands."""
        if not screenshot_bytes:
            return {"error": "No image data"}

        vector = self.embed_image(screenshot_bytes)
        
        search_result = self.client.query_points(
            collection_name=self.collection_name,
            query=vector,
            limit=1
        ).points

        if not search_result:
            return {"match": None, "score": 0.0}
        
        best = search_result[0]
        return {
            "match": best.payload["brand"],
            "score": best.score
        }
