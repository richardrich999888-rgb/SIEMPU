#!/usr/bin/env python3
"""Validate research traceability, not application security or military readiness.

CSV files are canonical. --write-views regenerates the two Markdown views.
--self-test additionally checks rejection of representative corrupt records.
No third-party Python dependencies or network access are required.
"""

import argparse
import copy
import csv
import json
from pathlib import Path
import re
import sys


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CSV_FILES = {
    "requirements": "requirement-traceability.csv",
    "tests": "trl5-test-matrix.csv",
    "work": "integration-backlog.csv",
    "ctes": "cte-readiness-matrix.csv",
    "claims": "proposal-claim-register.csv",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def ids(rows, key, label):
    result = {row[key] for row in rows}
    require(len(result) == len(rows), f"duplicate {label} ID")
    require(all(result), f"empty {label} ID")
    return result


def tokens(value):
    return set(value.split())


def load_data():
    data = {}
    for label, filename in CSV_FILES.items():
        with (HERE / filename).open(newline="") as stream:
            data[label] = list(csv.DictReader(stream))
    for label, filename in {
        "sources": "source-evidence-register.json",
        "software": "software-dependency-registry.json",
        "baseline": "baseline-evidence.json",
        "branches": "branch-inventory.json",
    }.items():
        data[label] = json.loads((HERE / filename).read_text())
    return data


def validate(data):
    reqs = ids(data["requirements"], "requirement", "requirement")
    tests = ids(data["tests"], "test_id", "test")
    work = ids(data["work"], "id", "work package")
    ctes = ids(data["ctes"], "cte", "CTE")
    sources = ids(data["sources"], "id", "source")
    ids(data["claims"], "claim_id", "proposal claim")
    ids(data["software"], "id", "software")
    require(reqs == {f"R{n}" for n in range(1, 13)}, "missing official requirement")
    require(ctes == {f"CTE{n:02}" for n in range(1, 10)}, "missing candidate CTE")
    require({"TLS-01", "SAG-01", "CI-01"} <= tests, "missing transport/approval/CI gate")
    test_index = {t["test_id"]: t for t in data["tests"]}
    work_index = {w["id"]: w for w in data["work"]}
    covered = set()
    for test in data["tests"]:
        tid = test["test_id"]
        for field in ("requirements", "ctes", "owner_role", "work_packages", "metric_basis",
                      "procedure", "acceptance_criteria", "expected_evidence", "status"):
            require(bool(test[field].strip()), f"{tid}: empty {field}")
        require(tokens(test["requirements"]) <= reqs, f"{tid}: unknown requirement")
        require(tokens(test["ctes"]) <= ctes, f"{tid}: unknown CTE")
        require(tokens(test["work_packages"]) <= work, f"{tid}: unknown work package")
        if tid != "CI-01":
            covered |= tokens(test["requirements"])
        allowed = {"PLANNED", "NOT_ENGAGED", "EXTERNAL_BLOCKED"}
        if tid == "CI-01":
            allowed.add("EVIDENCED_FROZEN_BASELINE")
        require(test["status"] in allowed, f"{tid}: unsupported execution/approval status")
        for wid in tokens(test["work_packages"]):
            require(tid in tokens(work_index[wid]["tests"]), f"{tid}/{wid}: reciprocal mapping drift")
    require(covered == reqs, "requirement coverage missing outside generic CI gate")

    # Protect the two mismatches found in the original research branch explicitly.
    require(tokens(test_index["T5-05"]["requirements"]) == {"R2", "R5", "R10"}, "T5-05 security mapping drift")
    require(tokens(test_index["T5-05"]["ctes"]) == {"CTE01", "CTE02", "CTE05"}, "T5-05 CTE mapping drift")
    require(tokens(test_index["T5-07"]["requirements"]) == {"R2", "R10", "R12"}, "T5-07 storage/evidence mapping drift")
    require(test_index["SAG-01"]["status"] == "EXTERNAL_BLOCKED", "SAG approval requires new external evidence")
    for row in data["requirements"]:
        expected = {t["test_id"] for t in data["tests"] if row["requirement"] in tokens(t["requirements"])}
        require(tokens(row["tests"]) == expected, f"{row['requirement']}: traceability drift")
        expected_ctes = {c for tid in expected if tid != "CI-01" for c in tokens(test_index[tid]["ctes"])}
        require(tokens(row["cte"]) == expected_ctes, f"{row['requirement']}: CTE traceability drift")

    graph = {}
    for row in data["work"]:
        wid = row["id"]
        for field in ("work_package", "phase", "priority", "state", "owner_role", "owner_assignment",
                      "engineering_person_days", "estimate_basis", "requirements", "tests",
                      "acceptance_criteria", "evidence_artifact", "exit_authority", "external_gate"):
            require(bool(row[field].strip()), f"{wid}: empty {field}")
        graph[wid] = tokens(row["depends_on"])
        require(graph[wid] <= work, f"{wid}: unknown dependency")
        require(tokens(row["requirements"]) <= reqs, f"{wid}: unknown requirement")
        require(tokens(row["tests"]) <= tests, f"{wid}: unknown test")
        for tid in tokens(row["tests"]):
            require(wid in tokens(test_index[tid]["work_packages"]), f"{wid}/{tid}: reciprocal mapping drift")
    visiting, visited = set(), set()

    def visit(wid):
        require(wid not in visiting, "work-package dependency cycle")
        if wid in visited:
            return
        visiting.add(wid)
        for child in graph[wid]:
            visit(child)
        visiting.remove(wid)
        visited.add(wid)

    for wid in graph:
        visit(wid)
    for row in data["claims"]:
        require(tokens(row["work_packages"]) <= work, f"{row['claim_id']}: unknown corrective work")
        cited = set(re.findall(r"\bP\d{3}\b", row["private_source_locator"]))
        require(cited and cited <= sources, f"{row['claim_id']}: private source missing")
        require(row["finding"] and row["required_action"], f"{row['claim_id']}: incomplete decision")
    for source in data["sources"]:
        if source["id"].startswith("P"):
            require(source["url"] is None, "private source must not expose a download URL")
    for software in data["software"]:
        require(set(software["source_ids"]) <= sources, "software source not registered")
        require(software["decision"] in {"KEEP_EXISTING", "PROTOTYPE", "DEFER"}, "ambiguous software adoption")
        if software["decision"] == "KEEP_EXISTING":
            require(software["version"] and software["source_ids"], "existing tool lacks pin/evidence")
            require(software["qualification_status"] == "TESTED_FROZEN_PROTOTYPE", "unsupported dependency qualification")
    baseline = data["baseline"]
    require(baseline["implementation_tree"] == baseline["tested_tree"], "baseline tree mismatch")
    require(baseline["native_tests"] == {"total": 87, "failed": 0, "cancelled": 0, "skipped": 0}, "frozen test record drift")
    require(set(baseline["jobs"]) == {"native", "browser", "container", "secret-scan", "codeql", "package-candidate"}, "incomplete hosted jobs")
    require(set(baseline["jobs"].values()) == {"success"}, "frozen hosted evidence changed")
    inventory = data["branches"]
    require(inventory["base_sha"] == baseline["implementation_commit"], "branch baseline mismatch")
    require(len(inventory["branches"]) == inventory["branch_count"], "branch count mismatch")
    ids(inventory["branches"], "ref", "branch")
    for branch in inventory["branches"]:
        require(re.fullmatch(r"[a-f0-9]{40}", branch["sha"]) is not None, "invalid frozen branch SHA")


def render_views(data):
    test_lines = [
        "# TRL 5/6 verification matrix", "",
        "Generated from `trl5-test-matrix.csv` by `python3 research/trl56/validate.py --write-views`. Edit the CSV, then regenerate this view.", "",
        "Only CI-01 records observed frozen prototype evidence. Every other row remains planned, unengaged or externally blocked. Numerical thresholds are provisional lab targets, not IAF SLAs. A row mapping to R9 cannot replace SAG-01's external approval.", "",
        "| Test | Requirements | CTEs | Owner role | Work packages | Status |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for t in data["tests"]:
        test_lines.append("| " + " | ".join(t[k] for k in ("test_id", "requirements", "ctes", "owner_role", "work_packages", "status")) + " |")
    for t in data["tests"]:
        test_lines.extend(["", f"## {t['test_id']} — {t['test_name']}", "",
                           f"Basis: **{t['metric_basis']}**. Status: **{t['status']}**.", "",
                           f"Procedure: {t['procedure']}.", "",
                           f"Acceptance: {t['acceptance_criteria']}.", "",
                           f"Required evidence: {t['expected_evidence']}."])
    test_lines.extend(["", "## Review sequence", "",
                       "Engineer records actual outcome and hashes; test lead verifies repeatability; independent reviewer assesses scope and findings; sponsor or authorised agency makes the acceptance/readiness decision. No unexecuted row may be labelled PASS.", ""])

    work_lines = [
        "# Implementation work packages", "",
        "Generated from `integration-backlog.csv` by `python3 research/trl56/validate.py --write-views`. All owners are role placeholders, not named appointments or contracted staff. Estimates are rough engineering person-days; external lead time is additional.", "",
        "WP01–WP03 are evidenced only at the frozen implementation. WP04 is a completed repository reconciliation. WP05's document comparison is complete, but presentation corrections and owner/programme decisions remain open. Other packages are future work.", "",
        "| ID | Work package | Phase / priority | State | Depends on | Person-days |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for w in data["work"]:
        work_lines.append(f"| {w['id']} | {w['work_package']} | {w['phase']} / {w['priority']} | {w['state']} | {w['depends_on'] or 'None'} | {w['engineering_person_days']} |")
    for w in data["work"]:
        work_lines.extend(["", f"## {w['id']} — {w['work_package']}", "",
                           f"Owner role: **{w['owner_role']}** ({w['owner_assignment']}). Exit authority: **{w['exit_authority']}**.", "",
                           f"Traceability: {w['requirements']}; tests {w['tests']}.", "",
                           f"Acceptance: {w['acceptance_criteria']}.", "",
                           f"Evidence: `{w['evidence_artifact']}`.", "",
                           f"Dependency or limitation: {w['external_gate']}."])
    work_lines.extend(["", "## Execution record required for closure", "",
                       "Record actual owner, start/end, tested commit/tree/source digest, configuration and environment hashes, commands or approved manual procedure, raw evidence paths and checksums, expected versus actual metrics, defects, deviations and reviewer decision. Proposed `evidence/` paths above are an artifact contract, not files already produced. Laboratory runners are not implemented by this documentation update.", "",
                       "Existing runnable commands: `npm run validate`, `npm run test:browser`, and `python3 research/trl56/validate.py --self-test`. Browser validation requires its fresh synthetic deployment and installed Chromium as described in the application runbook. Future lab packages must add their own runnable harnesses before closure.", ""])
    return {"08-trl5-verification-matrix.md": "\n".join(test_lines),
            "18-work-packages.md": "\n".join(work_lines)}


def normalize_markdown(text):
    # Ignore Prettier's table padding and harmless whitespace, not words or mappings.
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if re.fullmatch(r"[| :\-]+", line):
            continue
        if line:
            lines.append(re.sub(r"\s*\|\s*", "|", line))
    return " ".join(" ".join(lines).split())


def validate_views(data):
    for name, expected in render_views(data).items():
        require(normalize_markdown((HERE / name).read_text()) == normalize_markdown(expected),
                f"generated Markdown drift in {name}; run --write-views")


def self_test(data):
    mutations = {
        "missing official requirement": lambda d: d["requirements"].pop(2),
        "lost storage mapping": lambda d: next(t for t in d["tests"] if t["test_id"] == "T5-07").update(requirements="R2 R12"),
        "orphan work reference": lambda d: d["tests"][0].update(work_packages="WP99"),
        "dependency cycle": lambda d: d["work"][0].update(depends_on="WP03"),
        "false SAG approval": lambda d: next(t for t in d["tests"] if t["test_id"] == "SAG-01").update(status="PASS"),
        "missing measurable criterion": lambda d: d["tests"][0].update(acceptance_criteria=""),
        "private source URL": lambda d: next(s for s in d["sources"] if s["id"] == "P001").update(url="https://example.invalid/private"),
        "untested dependency adoption": lambda d: d["software"][1].update(decision="KEEP_EXISTING"),
        "mismatched tested tree": lambda d: d["baseline"].update(tested_tree="0" * 40),
    }
    for name, mutate in mutations.items():
        changed = copy.deepcopy(data)
        mutate(changed)
        try:
            validate(changed)
        except ValueError:
            continue
        raise ValueError(f"mutation was not rejected: {name}")
    # Exercise the exact Markdown mismatch that used to go unchecked.
    rendered = render_views(data)["08-trl5-verification-matrix.md"]
    changed = rendered.replace("R2 R5 R10", "R2 R10", 1)
    require(normalize_markdown(changed) != normalize_markdown(rendered), "Markdown mapping mutation not detectable")
    return len(mutations) + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-views", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    data = load_data()
    validate(data)
    if args.write_views:
        for name, text in render_views(data).items():
            (HERE / name).write_text(text)
    validate_views(data)
    mutations = self_test(data) if args.self_test else 0
    print(json.dumps({"outcome": "PASS", "requirements": len(data["requirements"]),
                      "tests": len(data["tests"]), "ctes": len(data["ctes"]),
                      "work_packages": len(data["work"]), "proposal_claims": len(data["claims"]),
                      "mutation_checks": mutations,
                      "scope": "Research record consistency only; not execution of proposed lab tests"}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
