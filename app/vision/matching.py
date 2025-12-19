from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from app.config import settings
import uuid

class BrandMatcher:
    def __init__(self, collection_name="brands"):
        self.client = QdrantClient(url=settings.QDRANT_URL)
        self.collection_name = collection_name
        self.vector_size = 512 # CLIP ViT-B/32 output size
        self._ensure_collection()

    def _ensure_collection(self):
        try:
            cols = self.client.get_collections()
            exists = any(c.name == self.collection_name for c in cols.collections)
            
            if not exists:
                self.client.create_collection(
                    collection_name=self.collection_name,
                    vectors_config=VectorParams(size=self.vector_size, distance=Distance.COSINE)
                )
        except Exception as e:
             print(f"Error ensuring collection: {e}")

    def add_brand(self, brand_name: str, embedding: list[float]):
        """Add a brand reference image embedding to the database."""
        point_id = str(uuid.uuid4())
        from qdrant_client.models import Batch
        self.client.upsert(
            collection_name=self.collection_name,
            points=Batch(
                ids=[point_id],
                vectors=[embedding],
                payloads=[{"brand": brand_name}]
            ),
            wait=True
        )

    def find_similar(self, embedding: list[float], threshold: float = 0.85):
        """Find visually similar brands."""
        search_result = self.client.query_points(
            collection_name=self.collection_name,
            query=embedding,
            limit=1,
            with_payload=True,
            score_threshold=threshold
        ).points
        return search_result
