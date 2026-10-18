"""Lever 2 tests: the guidance is correct and additive. No model."""
from eval.fix_guidance import dependency_note, cwe_note, build_guidance


def test_dependency_note_per_language():
    assert "bcrypt" in dependency_note("python")
    assert "standard library" in dependency_note("java").lower()
    assert "System.Security" in dependency_note("csharp")


def test_cwe_note_matches_known_cwes():
    n = cwe_note(["CWE-918"])
    assert "private" in n.lower() and "918" in n


def test_cwe_note_handles_zero_padding():
    assert cwe_note(["CWE-089"]) == cwe_note(["CWE-89"])
    assert "parameterized" in cwe_note(["CWE-089"]).lower()


def test_cwe_note_empty_for_unknown():
    assert cwe_note(["CWE-99999"]) == ""
    assert cwe_note([]) == ""


def test_build_guidance_always_has_deps_never_empty():
    g = build_guidance("python", ["CWE-99999"])
    assert "standard library" in g.lower()
    g2 = build_guidance("python", ["CWE-918"])
    assert "standard library" in g2.lower() and "FIX GUIDANCE" in g2


def test_weakhash_guidance_warns_against_unavailable_libs():
    n = cwe_note(["CWE-327"])
    assert "jbcrypt" in n.lower() or "do not import" in n.lower()


def test_deser_guidance_warns_commons_is_not_a_fix():
    n = cwe_note(["CWE-502"])
    assert "commons" in n.lower()
