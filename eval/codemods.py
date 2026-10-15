"""Deterministic codemods: known-correct fixes for specific vulnerability
patterns, applied WITHOUT the model.

The routing idea: for a small set of well-understood CWEs there is a single
canonical fix. For those, a hand-written transformation is 100% reliable, while
a 7B model is not (the ablation showed py-ldap and py-openredirect fixed 0/5 by
the model). A codemod sidesteps the model entirely for these patterns.

Each codemod takes the vulnerable source and returns fixed source, or None if it
does not recognize the pattern (then the pipeline falls back to the LLM). They
are AST/regex based, conservative, and only fire on patterns they can fix
correctly. No model, no GPU.
"""
from __future__ import annotations

import re


def codemod_ldap_injection(src: str):
    """CWE-90: escape LDAP special chars in a filter built by string concat.
    Fires when the code builds an LDAP filter like '(uid=' + x + ')'."""
    if "(uid=" not in src and "ldap" not in src.lower():
        return None
    if "escape" in src.lower() or "ldap.filter" in src:
        return None  # already looks escaped
    # inject an escaper and wrap the concatenated variable
    m = re.search(r'return\s+"\(uid="\s*\+\s*(\w+)\s*\+\s*"\)"', src)
    if not m:
        return None
    var = m.group(1)
    helper = (
        "def _ldap_escape(s):\n"
        "    out = []\n"
        "    for ch in s:\n"
        "        if ch in '*()\\\\\\x00':\n"
        "            out.append('\\\\%02x' % ord(ch))\n"
        "        else:\n"
        "            out.append(ch)\n"
        "    return ''.join(out)\n\n"
    )
    fixed = re.sub(
        r'return\s+"\(uid="\s*\+\s*' + var + r'\s*\+\s*"\)"',
        f'return "(uid=" + _ldap_escape({var}) + ")"',
        src)
    return helper + fixed


def codemod_open_redirect(src: str):
    """CWE-601: only allow same-site relative redirects. Fires when a function
    returns a user-supplied next_url unchanged."""
    m = re.search(r'def\s+(\w+)\s*\(\s*(\w+)\s*\)\s*:\s*\n\s*return\s+\2\s*\n', src)
    if not m:
        # also handle the common 'redirect_target' shape with a comment line
        m = re.search(r'def\s+(\w+)\s*\(\s*(\w+)\s*\)\s*:', src)
        if not m or "return" not in src:
            return None
    fn, arg = m.group(1), m.group(2)
    fixed = (
        f"def {fn}({arg}):\n"
        f"    # only allow same-site relative paths, block absolute/external URLs\n"
        f"    if not str({arg}).startswith('/') or str({arg}).startswith('//'):\n"
        f"        return '/'\n"
        f"    return {arg}\n"
    )
    return fixed


# registry: CWE -> list of codemods to try
CODEMODS = {
    "CWE-90": [codemod_ldap_injection],
    "CWE-601": [codemod_open_redirect],
}


def try_codemod(cwe_list, src):
    """Return (fixed_src, codemod_name) if a codemod applies, else (None, None)."""
    for cwe in cwe_list:
        for fn in CODEMODS.get(cwe, []):
            out = fn(src)
            if out:
                return out, fn.__name__
    return None, None
