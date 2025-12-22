import math
from urllib.parse import urlparse
from typing import Dict
import ipaddress

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
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False

def extract_features(url: str) -> Dict[str, float]:
    """
    Extracts lexical features from a given URL based on common characteristics
    of malicious URLs.

    Args:
        url: The URL string to analyze.

    Returns:
        A dictionary where keys are feature names and values are the
        computed feature values.
    """
    features = {}

    # Pre-process URL to ensure it has a scheme for urlparse
    if not url.startswith('http://') and not url.startswith('https://'):
        url_to_parse = 'http://' + url
    else:
        url_to_parse = url

    try:
        parsed_url = urlparse(url_to_parse)
        netloc = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
    except Exception:
        netloc, path, query = "", "", ""

    # --- General URL Characteristics ---
    features['url_length'] = float(len(url))
    letters = float(sum(c.isalpha() for c in url))
    digits = float(sum(c.isdigit() for c in url))
    features['digit_to_letter_ratio'] = digits / (letters + 1e-6)
    features['semicolon_count'] = float(url.count(';'))
    features['underscore_count'] = float(url.count('_'))
    features['question_mark_count'] = float(url.count('?'))
    features['equals_count'] = float(url.count('='))
    features['ampersand_count'] = float(url.count('&'))

    # --- Primary Domain and TLD Features ---
    domain = netloc.split('@')[-1].split(':')[0]
    features['domain_length'] = float(len(domain))
    features['domain_digits'] = float(sum(c.isdigit() for c in domain))
    features['domain_non_alnum'] = float(sum(not c.isalnum() for c in domain if c != '.'))
    features['domain_is_ip'] = 1.0 if is_ip_address(domain) else 0.0
    features['domain_hyphens'] = float(domain.count('-'))
    features['at_symbol_present'] = 1.0 if '@' in netloc else 0.0
    suspicious_tlds = {'xyz', 'top', 'club', 'site', 'online', 'live', 'info', 'loan', 'work', 'gdn', 'link', 'click'}
    tld = domain.split('.')[-1]
    features['suspicious_tld'] = 1.0 if tld in suspicious_tlds else 0.0
    
    # --- Subdomain and Path Characteristics ---
    features['subdomain_levels'] = float(domain.count('.'))
    features['path_special_chars'] = float(sum(not c.isalnum() and c not in ['/', '.'] for c in path))
    features['path_zeroes'] = float(path.count('0'))
    features['path_double_slashes'] = float(path.count('//'))
    path_segments = [segment for segment in path.split('/') if segment]
    features['single_char_dirs'] = float(sum(1 for segment in path_segments if len(segment) == 1))
    features['uppercase_dirs'] = float(sum(1 for segment in path_segments if segment.isupper() and segment.isalpha()))
    features['num_subdirectories'] = float(path.count('/'))
    features['path_encoded_chars'] = float(path.lower().count('%20'))
    path_upper = float(sum(c.isupper() for c in path))
    path_lower = float(sum(c.islower() for c in path))
    features['path_case_ratio'] = path_upper / (path_lower + 1e-6)

    # --- Query and Parameter Features ---
    features['query_length'] = float(len(query))
    features['num_query_params'] = float(len(query.split('&'))) if query else 0.0

    return features