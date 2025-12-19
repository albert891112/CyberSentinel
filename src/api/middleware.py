from typing import Optional

class WhitelistChecker:
    def __init__(self):
        # Mock top 1m list
        self.whitelist = {
            "google.com", "facebook.com", "youtube.com", "twitter.com",
            "amazon.com", "linkedin.com", "wikipedia.org", "microsoft.com",
            "github.com", "stackoverflow.com", "example.com"
        }

    def is_safe(self, url: str) -> bool:
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            if not domain:
                 domain = url
            
            # Remove port
            if ":" in domain:
                domain = domain.split(":")[0]
            
            # Remove www
            if domain.startswith("www."):
                domain = domain[4:]
            
            return domain in self.whitelist
        except:
            return False

whitelist_checker = WhitelistChecker()
