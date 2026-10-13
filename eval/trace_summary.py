"""Summarize MLflow trace spans into a per-agent timing and token table.

Reads the local SQLite trace store (mlruns/mlflow.db) written by MLflow autolog
and prints, per span type, how many times it ran and how long it took on
average. No MLflow or server needed: it reads the db directly, so it works on
any machine with Python.

Usage, from the repo root:
    python eval/trace_summary.py
    python eval/trace_summary.py --db mlruns/mlflow.db --csv results/eval/run7_traced/trace_summary.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from collections import defaultdict


def summarize(db_path):
    c = sqlite3.connect(db_path)
    rows = c.execute(
        "SELECT name, start_time_unix_nano, end_time_unix_nano, content "
        "FROM spans").fetchall()

    by_name = defaultdict(list)          # name -> list of durations in seconds
    tokens_by_name = defaultdict(lambda: [0, 0])  # name -> [prompt, completion]

    for name, start, end, content in rows:
        if start is None or end is None:
            continue
        dur = (end - start) / 1e9       # nanoseconds -> seconds
        by_name[name].append(dur)
        # token counts live in the span content JSON when present
        if content:
            try:
                data = json.loads(content)
            except Exception:
                data = None
            usage = _find_usage(data) if data is not None else None
            if usage:
                tokens_by_name[name][0] += usage.get("prompt", 0)
                tokens_by_name[name][1] += usage.get("completion", 0)

    out = []
    for name, durs in sorted(by_name.items(), key=lambda kv: -sum(kv[1])):
        n = len(durs)
        total = sum(durs)
        pt, ct = tokens_by_name[name]
        out.append({
            "span": name,
            "calls": n,
            "total_s": round(total, 1),
            "avg_s": round(total / n, 2) if n else 0,
            "prompt_tokens": pt,
            "completion_tokens": ct,
        })
    return out


def _find_usage(obj):
    """Walk a span's content looking for a token-usage dict, tolerant of shape."""
    found = {}
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                lk = k.lower()
                if lk in ("prompt_tokens", "input_tokens"):
                    found["prompt"] = found.get("prompt", 0) + (v or 0)
                elif lk in ("completion_tokens", "output_tokens"):
                    found["completion"] = found.get("completion", 0) + (v or 0)
                else:
                    walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)
    walk(obj)
    return found or None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="mlruns/mlflow.db")
    ap.add_argument("--csv", default=None)
    args = ap.parse_args()

    summary = summarize(args.db)
    w = max(len(r["span"]) for r in summary)
    print(f"{'span':<{w}}  {'calls':>5}  {'total_s':>8}  {'avg_s':>6}  "
          f"{'prompt_tok':>10}  {'compl_tok':>9}")
    for r in summary:
        print(f"{r['span']:<{w}}  {r['calls']:>5}  {r['total_s']:>8}  "
              f"{r['avg_s']:>6}  {r['prompt_tokens']:>10}  {r['completion_tokens']:>9}")

    if args.csv:
        import os
        os.makedirs(os.path.dirname(args.csv), exist_ok=True)
        with open(args.csv, "w", newline="") as fh:
            wr = csv.DictWriter(fh, fieldnames=list(summary[0].keys()))
            wr.writeheader(); wr.writerows(summary)
        print(f"\nwrote {args.csv}")


if __name__ == "__main__":
    main()
