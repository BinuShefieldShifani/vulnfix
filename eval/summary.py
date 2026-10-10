"""Pure summary math over evaluation rows. No model, no GPU, no heavy imports,
so CI can test it. The harness imports from here."""
from __future__ import annotations


def _rate(rows, pred):
    done = [r for r in rows if "status" in r and not str(r["status"]).startswith("ERROR")]
    if not done:
        return None
    return round(sum(1 for r in done if pred(r)) / len(done), 2)


def summarize(per_case, repeats, has_exploit, has_behavior):
    """per_case: {case_id: [row, ...]}. has_exploit/has_behavior: {case_id: bool}."""
    out = []
    for cid, rows in per_case.items():
        he = has_exploit.get(cid, False)
        hb = has_behavior.get(cid, False)
        errors = sum(1 for r in rows if str(r.get("status", "")).startswith("ERROR"))
        out.append({
            "case_id": cid,
            "repeats": repeats,
            "errors": errors,
            "validated_rate": _rate(rows, lambda r: r.get("validated")),
            "truly_fixed_rate": _rate(rows, lambda r: r.get("exploit") == "safe") if he else None,
            "behavior_ok_rate": _rate(rows, lambda r: r.get("behavior") == "ok") if hb else None,
            "compile_rate": _rate(rows, lambda r: r.get("compiles")),
            "validated_but_exploitable": _rate(
                rows, lambda r: r.get("validated") and r.get("exploit") == "exploited") if he else None,
            "validated_but_broken": _rate(
                rows, lambda r: r.get("validated") and r.get("behavior") == "broken") if hb else None,
        })
    return out
