class AllowListChecker:
    def __init__(self):
        # In prod, this would load a large CSV (Alexa/Tranco)
        # For dev, we use a small set.
        self.allowlist = {
            "google.com",
            "www.google.com",
            "facebook.com",
            "www.facebook.com",
            "amazon.com",
            "www.amazon.com",
            "microsoft.com",
            "www.microsoft.com",
            "github.com",
            "www.github.com"
        }

    def is_safe(self, url: str) -> bool:
        from urllib.parse import urlparse
        try:
            domain = urlparse(url).netloc
            if domain in self.allowlist:
                return True
            # Check base domain too (simple logic)
            parts = domain.split('.')
            if len(parts) > 2:
                base = ".".join(parts[-2:])
                if base in self.allowlist:
                    return True
            return False
        except Exception:
            return False
