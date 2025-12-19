import math
import re
from urllib.parse import urlparse
from typing import List, Dict

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0
    length = len(text)
    for x in set(text):
        p_x = text.count(x) / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def count_special_chars(text: str) -> int:
    """Counts special characters in the text."""
    return sum(1 for c in text if not c.isalnum())

def longest_consecutive_consonants(text: str) -> int:
    """Finds the length of the longest consecutive consonant sequence."""
    consonants = "bcdfghjklmnpqrstvwxyz"
    current_len = 0
    max_len = 0
    for char in text.lower():
        if char in consonants:
            current_len += 1
            max_len = max(max_len, current_len)
        else:
            current_len = 0
    return max_len

def is_ip_address(domain: str) -> bool:
    """Checks if the domain is an IP address."""
    try:
        parts = domain.split('.')
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def extract_features(url: str) -> List[float]:
    """
    Extracts numerical features from a URL for the ML model.
    Features: [
        domain_length, 
        domain_entropy, 
        num_digits, 
        num_special_chars, 
        longest_consonant_seq
    ]
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path  # Handle cases without scheme
        if ":" in domain: # remove port
            domain = domain.split(":")[0]
    except Exception:
        domain = url
    
    # Remove www prefix for better feature consistency
    if domain.startswith("www."):
        domain = domain[4:]

    return [
        float(len(domain)),
        calculate_entropy(domain),
        float(sum(c.isdigit() for c in domain)),
        float(count_special_chars(domain)),
        float(longest_consecutive_consonants(domain))
    ]
