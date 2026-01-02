"""
N-Gram Feature Extraction for Malicious URL Detection

Based on literature recommendations:
- Trigram extraction: Split URL into 3-character sequences
- Top-K selection: Use most frequent trigrams from training corpus
- Binary encoding: 1 if trigram present, 0 otherwise
"""

from collections import Counter
import pickle
import os


class TrigramFeatureExtractor:
    """
    Extracts trigram (3-character) features from URLs.
    
    The extractor learns the most common trigrams from training data
    and uses them to create a binary feature vector for each URL.
    """
    
    def __init__(self, top_k: int = 500):
        """
        Initialize the trigram feature extractor.
        
        Args:
            top_k: Number of most frequent trigrams to use as features.
        """
        self.top_k = top_k
        self.top_trigrams: list[str] = []
    
    def _extract_trigrams(self, text: str) -> list[str]:
        """Extract all trigrams from a text string."""
        if len(text) < 3:
            return []
        return [text[i:i+3] for i in range(len(text) - 2)]
    
    def fit(self, urls: list[str]) -> "TrigramFeatureExtractor":
        """
        Learn top-k trigrams from training URLs.
        
        Args:
            urls: List of URL strings to learn from.
            
        Returns:
            Self for method chaining.
        """
        trigram_counts: Counter[str] = Counter()
        
        for url in urls:
            # Normalize URL to lowercase for consistent trigrams
            normalized = url.lower()
            trigrams = self._extract_trigrams(normalized)
            trigram_counts.update(trigrams)
        
        # Select top-k most common trigrams
        self.top_trigrams = [t for t, _ in trigram_counts.most_common(self.top_k)]
        
        return self
    
    def transform(self, url: str) -> dict[str, float]:
        """
        Extract trigram features for a single URL.
        
        Args:
            url: The URL string to extract features from.
            
        Returns:
            Dictionary mapping trigram feature names to binary values.
        """
        if not self.top_trigrams:
            raise ValueError("Extractor must be fitted before transform. Call fit() first.")
        
        # Get trigrams from this URL
        normalized = url.lower()
        url_trigrams = set(self._extract_trigrams(normalized))
        
        # Create binary feature vector
        return {
            f"trigram_{t}": 1.0 if t in url_trigrams else 0.0 
            for t in self.top_trigrams
        }
    
    def fit_transform(self, urls: list[str]) -> list[dict[str, float]]:
        """
        Learn trigrams from URLs and transform them.
        
        Args:
            urls: List of URL strings.
            
        Returns:
            List of feature dictionaries for each URL.
        """
        self.fit(urls)
        return [self.transform(url) for url in urls]
    
    def get_feature_names(self) -> list[str]:
        """Get list of feature names (for DataFrame columns)."""
        return [f"trigram_{t}" for t in self.top_trigrams]
    
    def save(self, path: str) -> None:
        """Save the fitted extractor to disk."""
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self.top_trigrams, f)
    
    def load(self, path: str) -> "TrigramFeatureExtractor":
        """Load a fitted extractor from disk."""
        with open(path, "rb") as f:
            self.top_trigrams = pickle.load(f)
        return self
