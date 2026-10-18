"""Lever 2: give the patch model the context it was missing.

Two additive signals, injected into the patch prompt:

1. Available dependencies, so the model stops hallucinating packages that are
   not installed (the jbcrypt / passlib / dill failures). It is told to use only
   installed packages or the standard library.

2. Per-CWE fix guidance, a short, curated "the correct fix for CWE-X is Y" note
   for CWEs where the model reliably picks a wrong or shallow approach (e.g. SSRF
   checking the scheme instead of blocking private IPs). Only CWEs we have
   guidance for get a note; everything else is unchanged.

Both are PURELY ADDITIVE: for a CWE with no guidance and with the default
dependency context, the extra text is minimal and never contradicts the base
prompt. This can only inform the model, not change control flow, so cases that
already pass cannot regress.
"""
from __future__ import annotations

# Packages the sandbox/runtime actually has. Keep in sync with requirements.
# The model is told to use ONLY these (plus the stdlib), so it stops reaching
# for libraries that are not installed.
INSTALLED_PACKAGES = {
    "python": ["bcrypt", "pyyaml (yaml)", "requests", "lxml", "defusedxml",
               "cryptography", "sqlalchemy", "flask", "jinja2"],
    "java": ["java.security, javax.crypto (PBKDF2WithHmacSHA256), "
             "java.sql PreparedStatement, java.util"],
    "csharp": ["System.Security.Cryptography (Rfc2898DeriveBytes), "
               "System.Data.SqlClient parameters, System.Text.Json"],
}

# Per-CWE correct-fix guidance. Keyed by the bare CWE number (string).
# Short, concrete, and about the APPROACH, not the code, so it steers without
# dictating. Only add entries you are confident are correct.
CWE_GUIDANCE = {
    "918": (  # SSRF
        "To fix SSRF, validating the URL scheme is NOT enough. Resolve the host "
        "and REJECT requests to private/loopback/link-local IP ranges "
        "(127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1). Prefer an "
        "allowlist of permitted hosts. Do not just check http/https."),
    "22": (  # path traversal
        "To fix path traversal, resolve the final path (os.path.realpath / "
        "Path.resolve) and verify it stays INSIDE the intended base directory; "
        "rejecting '..' by substring is weaker and can miss encodings."),
    "327": (  # weak crypto / hashing
        "For weak password hashing, use a slow salted KDF. In Python use the "
        "installed `bcrypt` package. In Java/C# with no third-party libs, use a "
        "standard-library PBKDF2 (javax.crypto PBKDF2WithHmacSHA256 / "
        "System.Security.Cryptography.Rfc2898DeriveBytes). Do NOT import "
        "bcrypt/jbcrypt/BCrypt.Net unless told they are installed."),
    "502": (  # insecure deserialization
        "For insecure deserialization, switch to a data-only format (JSON) if "
        "possible. If native deserialization must stay (Java/.NET), restrict it "
        "with a class allowlist (ObjectInputStream.resolveClass). Note: Apache "
        "Commons SerializationUtils is STILL native deserialization and does not "
        "fix it."),
    "78": (  # command injection
        "To fix command injection, do not build a shell string. Pass the command "
        "and each argument as separate list elements with no shell "
        "(subprocess.run([...]) / ProcessBuilder(list) / Process with argument "
        "array), or avoid the shell entirely (e.g. a library call)."),
    "89": (  # SQL injection
        "To fix SQL injection, use a parameterized query / prepared statement "
        "with bound parameters. Never concatenate user input into the SQL text."),
}


def dependency_note(language: str) -> str:
    lang = (language or "python").lower()
    if lang in ("cs", "c#"):
        lang = "csharp"
    pkgs = INSTALLED_PACKAGES.get(lang, INSTALLED_PACKAGES["python"])
    return ("Prefer the standard library. Commonly available packages: "
            + ", ".join(pkgs) + ". Avoid importing packages not listed here.")


def cwe_note(cwe_list) -> str:
    """Return guidance for the first CWE we have a note for, else empty."""
    for cwe in cwe_list or []:
        num = str(cwe).upper().replace("CWE-", "").strip().lstrip("0")
        if num in CWE_GUIDANCE:
            return "FIX GUIDANCE for CWE-" + num + ": " + CWE_GUIDANCE[num]
    return ""


def build_guidance(language: str, cwe_list) -> str:
    """The additive context block for the patch prompt. Always includes the
    dependency note; adds the CWE note only when we have one."""
    parts = [dependency_note(language)]
    note = cwe_note(cwe_list)
    if note:
        parts.append(note)
    return "\n".join(parts)
