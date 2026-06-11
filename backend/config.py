"""
AgenticPhishDetector — Application Configuration

Reads environment variables from .env using Pydantic Settings.
All secrets (NVIDIA API key, worker token) are loaded here and
never exposed to API responses or logs.
"""

from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    Attributes:
        nvidia_api_key: NVIDIA NIM API key for Nemotron-3-Ultra access.
        nvidia_model: The NVIDIA model identifier to use.
        allowed_origins: Comma-separated list of CORS-allowed origins.
        rate_limit_per_minute: Max API requests per IP per minute.
        max_body_length: Maximum email body character count.
        max_subject_length: Maximum email subject character count.
        worker_secret: Shared secret for Cloudflare Worker authentication.
        debug: Enable debug mode (verbose logging, relaxed CORS).
    """

    nvidia_api_key: str = ""
    nvidia_model: str = "nvidia/llama-3.3-nemotron-super-49b-v1"
    allowed_origins: str = "http://localhost:5173,http://localhost:3000"
    rate_limit_per_minute: int = 10
    max_body_length: int = 50000
    max_subject_length: int = 500
    worker_secret: str = ""
    debug: bool = False
    request_timeout: int = 90

    @property
    def origins_list(self) -> List[str]:
        """Parse comma-separated origins into a list of exact origins (no wildcards)."""
        from urllib.parse import urlparse
        origins = []
        for o in self.allowed_origins.split(","):
            o_str = o.strip()
            if not o_str:
                continue
            if "*" in o_str:
                # Wildcards are handled via allowed_origin_regex
                continue
            # Parse URL to clean up trailing slashes, paths, etc.
            parsed = urlparse(o_str)
            if parsed.scheme and parsed.netloc:
                origins.append(f"{parsed.scheme}://{parsed.netloc}")
            else:
                origins.append(o_str)
        return origins

    @property
    def allowed_origin_regex(self) -> str | None:
        """
        Generate a regular expression matching allowed wildcard origins.
        Converts patterns like 'https://*.example.com' or 'https://example.com/*' into a regex.
        """
        import re
        from urllib.parse import urlparse
        
        wildcards = []
        for o in self.allowed_origins.split(","):
            o_str = o.strip()
            if not o_str:
                continue
            if "*" in o_str:
                parsed = urlparse(o_str)
                if parsed.scheme and parsed.netloc:
                    origin_part = f"{parsed.scheme}://{parsed.netloc}"
                else:
                    origin_part = o_str.rstrip("/")
                    if origin_part.endswith("/*"):
                        origin_part = origin_part[:-2]
                    elif origin_part.endswith("*"):
                        origin_part = origin_part[:-1]
                wildcards.append(origin_part)
                
        if not wildcards:
            return None
            
        regex_parts = []
        for w in wildcards:
            escaped = re.escape(w)
            pattern = escaped.replace(r'\*\.', r'(?:[^/]*\.)?')
            pattern = pattern.replace(r'\*', r'[^/]*')
            regex_parts.append(f"^{pattern}$")
            
        return "|".join(regex_parts)

    model_config = {
        "env_file": os.path.join(os.path.dirname(__file__), ".env"),
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }


# Singleton settings instance
settings = Settings()
