#!/usr/bin/env python3
"""
Retrieval test for the OSV advisory collection.

Takes a free-text vulnerability description (as a report would contain)
and returns the most semantically similar advisories, with their CWE,
affected packages, fixed versions and patch references — i.e. the
grounding an agent would condition a fix on.

Usage:
    python query.py "deserialization of untrusted data in Jackson"
    python query.py "SQL injection in a Spring repository query" --eco Maven -k 5
"""

import argparse
from urllib.parse import urlparse

import requests
import chromadb


def chroma_client_from_url(url):
    """Accept 'http://localhost:8000', 'localhost:8000' or 'localhost'."""
    p = urlparse(url if "://" in url else f"http://{url}")
    return chromadb.HttpClient(
        host=p.hostname or "localhost",
        port=p.port or 8000,
        ssl=(p.scheme == "https"),
    )


def embed(text, model, ollama_url):
    r = requests.post(f"{ollama_url}/api/embed",
                      json={"model": model, "input": [text]}, timeout=300)
    r.raise_for_status()
    return r.json()["embeddings"][0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("query", help="Vulnerability description to search for")
    ap.add_argument("-k", "--top-k", type=int, default=5)
    ap.add_argument("--eco", help="Restrict to one ecosystem (PyPI/Maven/NuGet)")
    ap.add_argument("--collection", default="osv_advisories")
    ap.add_argument("--embed-model", default="nomic-embed-text")
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    ap.add_argument("--chroma-url", default="http://localhost:8000",
                    help="ChromaDB base URL, e.g. http://localhost:8000")
    args = ap.parse_args()

    client = chroma_client_from_url(args.chroma_url)
    collection = client.get_collection(name=args.collection)

    vector = embed(args.query, args.embed_model, args.ollama_url)
    where = {"ecosystem": args.eco} if args.eco else None
    res = collection.query(query_embeddings=[vector], n_results=args.top_k,
                           where=where)

    ids = res["ids"][0]
    metas = res["metadatas"][0]
    dists = res["distances"][0]

    print(f"\nTop {len(ids)} matches for: {args.query!r}\n")
    for rank, (osv_id, meta, dist) in enumerate(zip(ids, metas, dists), 1):
        print(f"{rank}. {osv_id}  (cosine distance {dist:.3f})")
        for field in ("aliases", "ecosystem", "packages", "cwe",
                      "severity", "fixed_versions"):
            if meta.get(field):
                print(f"     {field:14}: {meta[field]}")
        print()


if __name__ == "__main__":
    main()
