"""Retrieval against the ChromaDB advisory/fix collection built by
ingest_osv.py. Embeds with the local Ollama model. Imports are lazy so the
graph can be built/inspected without a running Chroma."""
from urllib.parse import urlparse

from config import settings


def _chroma_client(url: str):
    import chromadb
    p = urlparse(url if "://" in url else f"http://{url}")
    return chromadb.HttpClient(
        host=p.hostname or "localhost",
        port=p.port or 8000,
        ssl=(p.scheme == "https"),
    )


def _embed(text: str):
    import requests
    r = requests.post(
        f"{settings.OLLAMA_BASE_URL}/api/embed",
        json={"model": settings.EMBED_MODEL, "input": [text]},
        timeout=300,
    )
    r.raise_for_status()
    return r.json()["embeddings"][0]


def retrieve_context(query: str, k: int = None) -> str:
    """Return similar advisories/fixes as a single context block. Never
    raises — returns a note if retrieval is unavailable."""
    k = k or settings.RETRIEVE_K
    try:
        coll = _chroma_client(settings.CHROMA_HOST).get_collection(settings.COLLECTION)
        res = coll.query(query_embeddings=[_embed(query)], n_results=k)
        docs = (res.get("documents") or [[]])[0]
        return "\n\n---\n\n".join(docs) if docs else "(no similar advisories found)"
    except Exception as e:  # noqa: BLE001 - retrieval is best-effort grounding
        return f"(retrieval unavailable: {e})"
