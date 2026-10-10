#!/usr/bin/env python3
"""
Ingest OSV.dev advisories into ChromaDB using Ollama embeddings.

Pulls the per-ecosystem `all.zip` dumps from OSV (PyPI = Python,
Maven = Java, NuGet = .NET), turns each advisory into a retrievable
document, embeds it with a local Ollama model, and upserts into a
ChromaDB collection.

Resilient embedding: documents are length-capped and blanks skipped; on a
batch error the script retries per-item and skips only the offending record,
printing Ollama's actual error body.

Usage:
    python ingest_osv.py --ecosystems PyPI Maven NuGet
    python ingest_osv.py --ecosystems NuGet --limit 500   # quick test
"""

import argparse
import io
import json
import sys
import time
import zipfile
from urllib.parse import urlparse

import requests
import chromadb

OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"

# Cap the final document length so no single advisory exceeds the embedding
# model's context window (which makes some Ollama versions return HTTP 400).
MAX_DOC_CHARS = 6000


def chroma_client_from_url(url):
    """Accept 'http://localhost:8000', 'localhost:8000' or 'localhost'."""
    p = urlparse(url if "://" in url else f"http://{url}")
    return chromadb.HttpClient(
        host=p.hostname or "localhost",
        port=p.port or 8000,
        ssl=(p.scheme == "https"),
    )


def download_ecosystem(ecosystem):
    """Stream-download <ecosystem>/all.zip and yield parsed OSV records."""
    url = f"{OSV_BASE}/{ecosystem}/all.zip"
    print(f"  downloading {url} ...")
    resp = requests.get(url, timeout=600)
    resp.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        names = [n for n in zf.namelist() if n.endswith(".json")]
        print(f"  {ecosystem}: {len(names)} advisories")
        for name in names:
            try:
                yield json.loads(zf.read(name))
            except (json.JSONDecodeError, KeyError):
                continue


def _join(values, limit=40):
    seen, out = set(), []
    for v in values:
        if v and v not in seen:
            seen.add(v)
            out.append(str(v))
        if len(out) >= limit:   # avoid runaway affected-version lists
            out.append("...")
            break
    return ", ".join(out)


def osv_to_document(rec, ecosystem):
    """Convert an OSV record into (id, document_text, metadata)."""
    osv_id = rec.get("id")
    if not osv_id:
        return None

    summary = (rec.get("summary", "") or "")[:1000]
    details = (rec.get("details", "") or "")[:4000]
    aliases = rec.get("aliases", []) or []          # usually CVE IDs

    packages, fixed_versions = [], []
    cwes = list((rec.get("database_specific", {}) or {}).get("cwe_ids", []) or [])
    for aff in rec.get("affected", []) or []:
        pkg = (aff.get("package", {}) or {}).get("name")
        if pkg:
            packages.append(pkg)
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if ev.get("fixed"):
                    fixed_versions.append(ev["fixed"])
        cwes += list((aff.get("database_specific", {}) or {}).get("cwe_ids", []) or [])

    severity = ""
    for sev in rec.get("severity", []) or []:
        if sev.get("score"):
            severity = sev["score"]
            break

    refs = [r.get("url") for r in (rec.get("references", []) or []) if r.get("url")]

    text = "\n".join(filter(None, [
        f"Advisory: {osv_id}",
        f"Ecosystem: {ecosystem}",
        f"Aliases (CVE): {_join(aliases)}" if aliases else "",
        f"Affected packages: {_join(packages)}" if packages else "",
        f"CWE: {_join(cwes)}" if cwes else "",
        f"Severity (CVSS): {severity}" if severity else "",
        f"Summary: {summary}" if summary else "",
        f"Details: {details}" if details else "",
        f"Fixed in: {_join(fixed_versions)}" if fixed_versions else "",
        f"References: {_join(refs[:8])}" if refs else "",
    ]))[:MAX_DOC_CHARS]   # hard cap the whole document

    metadata = {
        "osv_id": osv_id,
        "ecosystem": ecosystem,
        "aliases": _join(aliases),
        "packages": _join(packages),
        "cwe": _join(cwes),
        "severity": severity,
        "fixed_versions": _join(fixed_versions),
        "published": rec.get("published", "") or "",
        "modified": rec.get("modified", "") or "",
    }
    metadata = {k: v for k, v in metadata.items() if v != ""}
    return osv_id, text, metadata


def embed_batch(texts, model, ollama_url, retries=3, num_ctx=8192):
    """Embed a batch via Ollama /api/embed. Prints the response body on error.
    num_ctx raises the context window (Ollama defaults to ~2048, but
    nomic-embed-text supports 8192)."""
    for attempt in range(retries):
        try:
            r = requests.post(
                f"{ollama_url}/api/embed",
                json={"model": model, "input": texts,
                      "options": {"num_ctx": num_ctx}},
                timeout=600,
            )
            if r.status_code >= 400:
                # surface Ollama's actual message, then raise
                raise requests.HTTPError(f"{r.status_code}: {r.text[:300]}")
            return r.json()["embeddings"]
        except (requests.RequestException, KeyError) as e:
            if attempt == retries - 1:
                raise
            print(f"    embed retry {attempt + 1} after error: {e}")
            time.sleep(2 * (attempt + 1))


def embed_resilient(texts, model, ollama_url, num_ctx=8192):
    """Try a batch; on failure embed per-item and return None for any item
    the model rejects, so one bad record doesn't abort the run."""
    try:
        return embed_batch(texts, model, ollama_url, num_ctx=num_ctx)
    except requests.RequestException as e:
        print(f"    batch failed ({e}); retrying per-item ...")
        out = []
        for t in texts:
            try:
                out.append(embed_batch([t], model, ollama_url,
                                       retries=1, num_ctx=num_ctx)[0])
            except Exception as ie:  # noqa: BLE001
                print(f"      skipping one record: {ie}")
                out.append(None)
        return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ecosystems", nargs="+",
                    default=["PyPI", "Maven", "NuGet"],
                    help="OSV ecosystems (PyPI=Python, Maven=Java, NuGet=.NET)")
    ap.add_argument("--collection", default="osv_advisories")
    ap.add_argument("--embed-model", default="nomic-embed-text")
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    ap.add_argument("--chroma-url", default="http://localhost:8000",
                    help="ChromaDB base URL, e.g. http://localhost:8000")
    ap.add_argument("--batch-size", type=int, default=64)
    ap.add_argument("--num-ctx", type=int, default=8192,
                    help="Embedding context window (nomic supports 8192)")
    ap.add_argument("--limit", type=int, default=0,
                    help="Max advisories per ecosystem (0 = all)")
    args = ap.parse_args()

    client = chroma_client_from_url(args.chroma_url)
    collection = client.get_or_create_collection(
        name=args.collection, metadata={"hnsw:space": "cosine"})

    total = 0
    for eco in args.ecosystems:
        print(f"\n[{eco}]")
        ids, docs, metas = [], [], []
        count = 0

        def flush():
            if not ids:
                return
            # drop blank documents, keep ids/metas aligned
            trios = [(i, d, m) for i, d, m in zip(ids, docs, metas) if d.strip()]
            if not trios:
                ids.clear(); docs.clear(); metas.clear()
                return
            b_ids = [t[0] for t in trios]
            b_docs = [t[1] for t in trios]
            b_metas = [t[2] for t in trios]
            vectors = embed_resilient(b_docs, args.embed_model,
                                      args.ollama_url, num_ctx=args.num_ctx)
            # drop any item the model rejected
            keep = [(i, v, d, m) for i, v, d, m in
                    zip(b_ids, vectors, b_docs, b_metas) if v is not None]
            if keep:
                collection.upsert(
                    ids=[k[0] for k in keep],
                    embeddings=[k[1] for k in keep],
                    documents=[k[2] for k in keep],
                    metadatas=[k[3] for k in keep],
                )
            ids.clear(); docs.clear(); metas.clear()

        for rec in download_ecosystem(eco):
            parsed = osv_to_document(rec, eco)
            if not parsed:
                continue
            osv_id, text, meta = parsed
            ids.append(osv_id); docs.append(text); metas.append(meta)
            count += 1; total += 1
            if len(ids) >= args.batch_size:
                flush()
                print(f"    ingested {count} ...", end="\r")
            if args.limit and count >= args.limit:
                break
        flush()
        print(f"\n    {eco}: {count} advisories processed")

    print(f"\nDone. Collection '{args.collection}' now holds "
          f"{collection.count()} documents.")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        print(f"\nNetwork/Ollama/Chroma error: {e}", file=sys.stderr)
        sys.exit(1)