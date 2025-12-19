from transformers import CLIPProcessor, CLIPModel
from PIL import Image
import io
import torch

class VisualEncoder:
    def __init__(self):
        # Using a smaller model for efficiency, can be swapped for larger ones
        self.model_name = "openai/clip-vit-base-patch32"
        try:
            self.model = CLIPModel.from_pretrained(self.model_name)
            self.processor = CLIPProcessor.from_pretrained(self.model_name)
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
            self.model.to(self.device)
            print(f"✅ Loaded CLIP model on {self.device}")
        except Exception as e:
            print(f"❌ Failed to load CLIP model: {e}")
            raise

    def encode_image(self, image_bytes: bytes) -> list[float]:
        try:
            image = Image.open(io.BytesIO(image_bytes))
            
            inputs = self.processor(images=image, return_tensors="pt").to(self.device)
            
            with torch.no_grad():
                image_features = self.model.get_image_features(**inputs)
            
            # Normalize and convert to list
            image_features /= image_features.norm(dim=-1, keepdim=True)
            return image_features.cpu().numpy()[0].tolist()
        except Exception as e:
            print(f"Error encoding image: {e}")
            return []
