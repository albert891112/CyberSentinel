"""
Tests for the lexical analysis module.
"""

import pytest
import os
from src.analysis.lexical.features import calculate_entropy, extract_features
from src.analysis.lexical.ngram_features import TrigramFeatureExtractor
from src.analysis.lexical.analyzer import LexicalAnalyzer


class TestEntropy:
    """Tests for entropy calculation."""
    
    def test_entropy_uniform(self):
        # All same characters has 0 entropy
        assert calculate_entropy("aaaaa") == 0.0
    
    def test_entropy_varied(self):
        # Varied characters have higher entropy
        assert calculate_entropy("abcde") > 2.0
    
    def test_entropy_empty(self):
        assert calculate_entropy("") == 0.0


class TestFeatureExtraction:
    """Tests for feature extraction."""
    
    def test_basic_features(self):
        url = "https://www.google.com"
        feats = extract_features(url)
        
        # Should have many features now (26+ lexical features)
        assert len(feats) >= 20
        assert "url_length" in feats
        assert "url_entropy" in feats
        assert "domain_length" in feats
    
    def test_sensitive_keyword_detection(self):
        # URL with login keyword
        feats = extract_features("https://fake-site.com/login/verify")
        assert feats["has_sensitive_keyword"] == 1.0
        
        # URL without keywords
        feats = extract_features("https://google.com")
        assert feats["has_sensitive_keyword"] == 0.0
    
    def test_suspicious_extension_detection(self):
        # URL with suspicious extension
        feats = extract_features("https://example.com/download.exe")
        assert feats["has_suspicious_extension"] == 1.0
        
        # Normal URL
        feats = extract_features("https://google.com/search")
        assert feats["has_suspicious_extension"] == 0.0
    
    def test_entropy_feature(self):
        feats = extract_features("https://google.com")
        assert "url_entropy" in feats
        assert feats["url_entropy"] > 0


class TestTrigramFeatures:
    """Tests for N-gram feature extraction."""
    
    def test_trigram_fit(self):
        extractor = TrigramFeatureExtractor(top_k=10)
        urls = ["http://google.com", "http://facebook.com", "http://test.com"]
        extractor.fit(urls)
        
        assert len(extractor.top_trigrams) <= 10
        assert len(extractor.top_trigrams) > 0
    
    def test_trigram_transform(self):
        extractor = TrigramFeatureExtractor(top_k=5)
        extractor.fit(["http://google.com"])
        
        feats = extractor.transform("http://google.com")
        assert len(feats) == 5
        assert all(isinstance(v, float) for v in feats.values())
    
    def test_trigram_not_fitted(self):
        extractor = TrigramFeatureExtractor()
        with pytest.raises(ValueError):
            extractor.transform("test.com")
    
    def test_trigram_save_load(self, tmp_path):
        extractor = TrigramFeatureExtractor(top_k=10)
        extractor.fit(["http://example.com", "http://test.org"])
        
        save_path = str(tmp_path / "test_trigrams.pkl")
        extractor.save(save_path)
        
        # Load into new extractor
        new_extractor = TrigramFeatureExtractor()
        new_extractor.load(save_path)
        
        assert new_extractor.top_trigrams == extractor.top_trigrams


class TestAnalyzerIntegration:
    """Integration tests for the analyzer."""
    
    @pytest.fixture
    def analyzer(self):
        if not os.path.exists("models/lexical_rf.pkl"):
            pytest.skip("Model not found, skipping integration test")
        return LexicalAnalyzer()
    
    def test_analyze_returns_expected_keys(self, analyzer):
        result = analyzer.analyze("google.com")
        
        assert "score" in result
        assert "is_malicious" in result
        assert "prediction" in result
        assert "features" in result
    
    def test_benign_url(self, analyzer):
        result = analyzer.analyze("google.com")
        assert result["score"] < 0.5
        assert not result["is_malicious"]
        assert result["prediction"] == "Benign"
    
    def test_malicious_url(self, analyzer):
        result = analyzer.analyze("secure-login-bank.xyz/account/verify.php")
        # Should have higher risk score than benign
        benign_result = analyzer.analyze("google.com")
        assert result["score"] > benign_result["score"]
    
    def test_batch_analyze(self, analyzer):
        urls = ["google.com", "facebook.com"]
        results = analyzer.batch_analyze(urls)
        
        assert len(results) == 2
        assert all("score" in r for r in results)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
