"""Central configuration. Mirrors the pasted OLLAMA_BASE_URL / CHROMA_HOST
style and sets model defaults that fit a 12GB GPU. Reads a local .env if
python-dotenv is installed (optional)."""
import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:  # python-dotenv is optional
    pass


@dataclass
class Settings:
    # Service endpoints (full URLs with scheme, as in your config)
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    CHROMA_HOST: str = os.getenv("CHROMA_HOST", "http://localhost:8000")

    # --- 12GB-friendly model layer (NOT Llama-3.1-70B) ---
    # One workhorse code model handles patch generation; a small reasoning
    # model handles the analyst/root-cause roles. On 12GB you host one large
    # model at a time, so feel free to point both at the same model.
    CODE_MODEL: str = os.getenv("CODE_MODEL", "qwen2.5-coder:7b")
    REASONING_MODEL: str = os.getenv("REASONING_MODEL", "llama3.1:8b")
    EMBED_MODEL: str = os.getenv("EMBED_MODEL", "nomic-embed-text")

    # Retrieval
    COLLECTION: str = os.getenv("COLLECTION", "osv_advisories")
    RETRIEVE_K: int = int(os.getenv("RETRIEVE_K", "4"))

    # Validation
    SEMGREP_CONFIG: str = os.getenv("SEMGREP_CONFIG", "vulnfix_rules.yml,p/default,p/security-audit,p/python,p/java")
    MAX_PATCH_ATTEMPTS: int = int(os.getenv("MAX_PATCH_ATTEMPTS", "2"))


settings = Settings()
