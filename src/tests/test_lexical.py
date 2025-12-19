import pytest
import os
from src.analysis.lexical.features import calculate_entropy, extract_features
from src.analysis.lexical.analyzer import LexicalAnalyzer

def test_entropy():
    # "aaaaa" has 0 entropy (all same chars) -> Actually it's -sum(p*log(p)). 1 * log2(1) = 0.
    assert calculate_entropy("aaaaa") == 0.0
    # "abcde" has max entropy for length 5 distinct chars.
    assert calculate_entropy("abcde") > 2.0 

def test_features_extraction():
    url = "https://www.google.com"
    feats = extract_features(url)
    # google.com -> len=10, entropy>0, digits=0, special=1 (.), consonant=2 (gl)
    assert len(feats) == 5
    assert feats[0] == 10.0 # google.com
    assert feats[2] == 0.0 # digits

def test_analyzer_integration():
    # Ensure model exists
    if not os.path.exists("models/lexical_rf.pkl"):
        pytest.skip("Model not found, skipping integration test")
    
    analyzer = LexicalAnalyzer()
    
    # Test Benign
    res_good = analyzer.analyze("google.com")
    assert res_good["score"] < 0.5
    assert not res_good["is_dga"]
    
    # Test DGA
    res_bad = analyzer.analyze("xkyz1234abcqwe.com")
    assert res_bad["score"] > 0.5
    # Threshold check might vary, but should be higher than benign
    assert res_bad["score"] > res_good["score"]

if __name__ == "__main__":
    pytest.main([__file__])
