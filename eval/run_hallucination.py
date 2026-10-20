"""Measure the hallucination rate across committed patches.

Runs the import/API hallucination checker over every patched Python file in the
eval runs and reports: how many patches had a hallucinated import or API, as a
rate. Python only (the checker is Python-specific). No model, no GPU.

Usage (repo root):
    python eval/run_hallucination.py
"""
from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval.hallucination import check_python     # noqa: E402

RUN_FILES = [
    "results/eval/run8_home/runs.jsonl",
    "results/eval/run8_heldout/runs.jsonl",
    "results/eval/run7_traced/runs.jsonl",
]


def _patched_code_from_diff(diff):
    """Reconstruct the '+' side of a unified diff into runnable code (best effort).
    We only need the import/call structure, so taking added+context lines is fine."""
    lines = []
    for ln in (diff or "").splitlines():
        if ln.startswith("+++") or ln.startswith("---") or ln.startswith("@@"):
            continue
        if ln.startswith("+"):
            lines.append(ln[1:])
        elif ln.startswith("-"):
            continue
        else:
            lines.append(ln[1:] if ln.startswith(" ") else ln)
    return "\n".join(lines)


def main():
    rows = []
    for path in RUN_FILES:
        if not os.path.exists(path):
            continue
        for line in open(path):
            try:
                r = json.loads(line)
            except Exception:
                continue
            if (r.get("patch_diff") and r.get("language") == "python"
                    and not str(r.get("status", "")).startswith("ERROR")):
                rows.append(r)

    total = 0
    with_import_hall = 0
    with_api_hall = 0
    examples = []
    for r in rows:
        code = _patched_code_from_diff(r["patch_diff"])
        if not code.strip():
            continue
        rep = check_python(code)
        total += 1
        if rep.import_hallucinations > 0:
            with_import_hall += 1
            bad = [i["module"] for i in rep.imports if not i["ok"]]
            examples.append((r["case_id"], "import", bad))
        if rep.api_hallucinations > 0:
            with_api_hall += 1
            bad = [f"{a['module']}.{a['attr']}" for a in rep.attributes if a["status"] == "missing"]
            examples.append((r["case_id"], "api", bad))

    any_hall = sum(1 for r in rows
                   if (lambda rep: rep.import_hallucinations or rep.api_hallucinations)
                   (check_python(_patched_code_from_diff(r["patch_diff"]))))

    print(f"python patches analyzed: {total}")
    print(f"with hallucinated import: {with_import_hall} ({round(100*with_import_hall/total,1)}%)")
    print(f"with hallucinated API:    {with_api_hall} ({round(100*with_api_hall/total,1)}%)")
    print(f"\nsample hallucinations:")
    seen = set()
    for cid, kind, bad in examples:
        key = (cid, kind, tuple(bad))
        if key in seen:
            continue
        seen.add(key)
        print(f"  {cid:14} {kind}: {bad}")
        if len(seen) >= 10:
            break

    out = "results/golden/hallucination_rate.json"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump({"patches_analyzed": total,
               "import_hallucination_rate": round(with_import_hall/total, 3),
               "api_hallucination_rate": round(with_api_hall/total, 3)},
              open(out, "w"), indent=2)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
