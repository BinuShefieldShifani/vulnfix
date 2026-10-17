# Showcase test cases for the end-to-end UI test

15 realistic multi-function files across Python, Java, C#. For each, use the
UI's **Manual finding** mode: paste the file contents, set the CWE and file
name below, and (if your UI exposes it) the start line. Function-level patching
will target the vulnerable function.

| # | File | Lang | CWE | vuln line | file name to enter |
|---|---|---|---|---|---|
| 1 | py1_flask_sqli.py | python | CWE-89 | 19 | app.py |
| 2 | py2_cmdi_util.py | python | CWE-78 | 11 | util.py |
| 3 | py3_pickle_cache.py | python | CWE-502 | 12 | cache.py |
| 4 | py4_weak_hash.py | python | CWE-327 | 8 | auth.py |
| 5 | py5_path_traversal.py | python | CWE-22 | 14 | server.py |
| 6 | py6_ssrf.py | python | CWE-918 | 7 | avatar.py |
| 7 | py7_eval_calc.py | python | CWE-95 | 6 | calc.py |
| 8 | java1_sqli_dao.java | java | CWE-89 | 14 | UserDao.java |
| 9 | java2_cmdi.java | java | CWE-78 | 6 | Pinger.java |
| 10 | java3_weak_hash.java | java | CWE-327 | 5 | Hasher.java |
| 11 | java4_deser.java | java | CWE-502 | 12 | SessionStore.java |
| 12 | cs1_sqli.cs | csharp | CWE-89 | 13 | UserRepository.cs |
| 13 | cs2_cmdi.cs | csharp | CWE-78 | 5 | Runner.cs |
| 14 | cs3_weak_hash.cs | csharp | CWE-327 | 6 | Hasher.cs |
| 15 | cs4_deser.cs | csharp | CWE-502 | 13 | Cache.cs |

Expected outcomes (honest):
- Python (1-7): most fix cleanly and validate; pickle/ssrf may abstain if the
  scanner has no baseline.
- Java (8-11): sqli/cmdi/md5 likely validate; deserialization may abstain.
- C# (12-15): sqli and md5 may validate (Semgrep C# has a SQLi rule); cmdi and
  deserialization will often come back inconclusive (thin C# rule coverage).
  Inconclusive here is the correct behavior, VulnFix abstains rather than
  shipping an unverified fix.
