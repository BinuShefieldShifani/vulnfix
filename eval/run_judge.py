"""Run the LLM judge over the golden set and calibrate against human labels.

For each labeled patch, builds the prompt (pure or oracle-assisted), calls the
model, parses the verdict, then reports agreement with the human labels. Runs
both modes so we can compare "LLM alone" vs "LLM + execution evidence".

Needs Ollama (the pipeline's model). ~80 calls per mode, a few minutes.

Usage (from repo root, with Ollama up):
    python eval/run_judge.py
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval.judge import build_prompt, parse_verdict, calibrate   # noqa: E402

TO_LABEL = "results/golden/to_label.jsonl"
LABELS = "results/golden/labels.jsonl"


def _call_model(system, user, model, base_url):
    from langchain_ollama import ChatOllama
    llm = ChatOllama(model=model, base_url=base_url, temperature=0.0,
                     num_predict=20)
    resp = llm.invoke([("system", system), ("human", user)])
    return resp.content if hasattr(resp, "content") else str(resp)


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="llama3.1:8b")
    ap.add_argument("--base-url", default="http://localhost:11434")
    ap.add_argument("--out", default="results/golden/judge_calibration.json")
    args = ap.parse_args()

    patches = {json.loads(l)["idx"]: json.loads(l) for l in open(TO_LABEL)}
    human = {}
    for l in open(LABELS):
        r = json.loads(l)
        if r["human_verdict"] != "unsure":   # exclude unsure from calibration
            human[r["idx"]] = r["human_verdict"]

    print(f"calibrating on {len(human)} human-labeled patches "
          f"(excluding 'unsure')\n")

    results = {}
    for mode in ("pure", "assisted"):
        print(f"--- judge mode: {mode} ---", flush=True)
        verdicts = {}
        for idx, hv in human.items():
            p = patches[idx]
            oracle = ({"exploit": p["exploit"], "behavior": p["behavior"],
                       "compiles": p["compiles"]} if mode == "assisted" else None)
            system, user = build_prompt(f"{p['case_id']} vulnerability",
                                        p["patch_diff"], oracle)
            try:
                raw = _call_model(system, user, args.model, args.base_url)
                verdicts[idx] = parse_verdict(raw)
            except Exception as e:
                verdicts[idx] = "unsure"
                print(f"  idx {idx}: error {type(e).__name__}")
        metrics = calibrate(human, verdicts)
        results[mode] = metrics
        print(f"  accuracy={metrics['accuracy']}  "
              f"miss_rate_on_bad={metrics['miss_rate_on_bad']} "
              f"({metrics['bad_patches_called_good']}/{metrics['bad_patches_total']} "
              f"bad patches called good)\n", flush=True)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump({"golden_set_size": len(human), "judge_model": args.model,
               "modes": results}, open(args.out, "w"), indent=2)

    print("=== calibration summary ===")
    print(f"{'mode':<10}{'accuracy':>10}{'miss_rate_on_bad':>18}")
    for mode in ("pure", "assisted"):
        m = results[mode]
        print(f"{mode:<10}{m['accuracy']:>10}{m['miss_rate_on_bad']:>18}")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
