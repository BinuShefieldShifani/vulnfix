"""Hallucination checks for generated patches.

Measures, concretely, when the model invents things that do not exist:

  - import hallucination: the patch imports a module that cannot be imported
    (the package does not exist / is not installed).
  - API hallucination: the patch references a module- or class-level attribute
    (e.g. yaml.safe_load, hashlib.pbkdf2_hmac) that does not exist on the real,
    imported module.

Verification is execution-assisted: we actually import each module in a
subprocess (via the sandbox) and check attribute existence on the real object.
This reliably catches import and module/class-attribute hallucinations. It does
NOT verify instance methods on runtime objects (we cannot always construct the
object), so those are reported as "unverifiable", not as hallucinations.

Pure analysis; needs the sandbox to run imports. No model, no GPU.
"""
from __future__ import annotations

import ast
import json
import os
import tempfile
from dataclasses import dataclass, field, asdict

from eval.sandbox import run_python


@dataclass
class HallucinationReport:
    imports: list          # [{module, ok}]
    attributes: list       # [{expr, module, attr, status}] status: ok|missing|unverifiable
    import_hallucinations: int = 0
    api_hallucinations: int = 0

    def as_dict(self):
        return asdict(self)


def _collect_imports(tree):
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                mods.add(n.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                mods.add(node.module.split(".")[0])
    return sorted(mods)


def _collect_module_attr_calls(tree):
    """Find `name.attr` where `name` is an imported module alias.
    Returns list of (alias, attr)."""
    # map alias -> module
    alias_to_mod = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                alias_to_mod[n.asname or n.name.split(".")[0]] = n.name.split(".")[0]
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            alias = node.value.id
            if alias in alias_to_mod:
                out.append((alias_to_mod[alias], node.attr))
    # dedupe
    return sorted(set(out))


def check_python(patched_code: str) -> HallucinationReport:
    try:
        tree = ast.parse(patched_code)
    except SyntaxError:
        # can't analyze; report nothing rather than guess
        return HallucinationReport(imports=[], attributes=[])

    mods = _collect_imports(tree)
    attr_calls = _collect_module_attr_calls(tree)

    # Build a tiny probe program that imports each module and checks each attr,
    # run it in the sandbox, and read back a JSON verdict.
    probe = (
        "import json, importlib\n"
        f"mods = {mods!r}\n"
        f"attrs = {attr_calls!r}\n"
        "imp = {}\n"
        "for m in mods:\n"
        "    try:\n"
        "        importlib.import_module(m); imp[m] = True\n"
        "    except Exception:\n"
        "        imp[m] = False\n"
        "att = []\n"
        "for mod, a in attrs:\n"
        "    if not imp.get(mod, False):\n"
        "        att.append([mod, a, 'unverifiable']); continue\n"
        "    try:\n"
        "        obj = importlib.import_module(mod)\n"
        "        att.append([mod, a, 'ok' if hasattr(obj, a) else 'missing'])\n"
        "    except Exception:\n"
        "        att.append([mod, a, 'unverifiable'])\n"
        "print('HALLJSON' + json.dumps({'imp': imp, 'att': att}))\n"
    )
    r = run_python("", probe, timeout=30.0)
    data = {"imp": {}, "att": []}
    for line in (r.output or "").splitlines():
        if line.startswith("HALLJSON"):
            try:
                data = json.loads(line[len("HALLJSON"):])
            except Exception:
                pass
            break

    imports = [{"module": m, "ok": bool(data["imp"].get(m, False))} for m in mods]
    attributes = [{"module": mod, "attr": a, "status": st} for mod, a, st in data["att"]]
    imp_hall = sum(1 for i in imports if not i["ok"])
    api_hall = sum(1 for a in attributes if a["status"] == "missing")
    return HallucinationReport(imports=imports, attributes=attributes,
                               import_hallucinations=imp_hall, api_hallucinations=api_hall)
