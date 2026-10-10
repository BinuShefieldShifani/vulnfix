"""Parse SARIF 2.1.0 (the common SAST output format: Semgrep, CodeQL,
Bandit) into normalized Finding objects. Tool-agnostic by design."""
import json
from typing import List, Union

from models import Finding

_CWE = "CWE-"


def parse_sarif(source: Union[str, dict]) -> List[Finding]:
    data = source if isinstance(source, dict) else json.load(open(source))
    findings: List[Finding] = []

    for run in data.get("runs", []) or []:
        # Map rule id -> CWE tags from the tool driver, if present.
        rule_cwe = {}
        driver = (run.get("tool", {}) or {}).get("driver", {}) or {}
        for rule in driver.get("rules", []) or []:
            tags = ((rule.get("properties", {}) or {}).get("tags", []) or [])
            rule_cwe[rule.get("id")] = [t for t in tags
                                        if str(t).upper().startswith(_CWE)]

        for res in run.get("results", []) or []:
            rid = res.get("ruleId", "")
            msg = (res.get("message", {}) or {}).get("text", "")
            level = res.get("level", "warning")
            for loc in res.get("locations", []) or []:
                phys = (loc.get("physicalLocation", {}) or {})
                art = (phys.get("artifactLocation", {}) or {})
                region = (phys.get("region", {}) or {})
                start = region.get("startLine", 1)
                findings.append(Finding(
                    rule_id=rid,
                    message=msg,
                    file_path=art.get("uri", ""),
                    start_line=start,
                    end_line=region.get("endLine", start),
                    severity=level,
                    cwe=rule_cwe.get(rid, []),
                    snippet=(region.get("snippet", {}) or {}).get("text", ""),
                ))
    return findings
