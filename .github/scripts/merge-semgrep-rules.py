#!/usr/bin/env python3
"""
Merge org and caller Semgrep rule files by filtering out org rules whose IDs
are overridden by the caller ruleset.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


def _resolve_path(raw_path: str, repo_root: pathlib.Path) -> pathlib.Path:
    p = pathlib.Path(raw_path)
    if p.is_absolute():
        return p
    return (repo_root / p).resolve()


def _load_rules_doc(path: pathlib.Path, label: str) -> list[dict]:
    if not path.is_file():
        raise FileNotFoundError(f"{label} Semgrep rules file not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in {label} Semgrep rules file {path}: {exc}") from exc
    if doc is None:
        return []
    if not isinstance(doc, dict):
        raise ValueError(f"{label} Semgrep rules file {path} must be a YAML mapping")
    rules = doc.get("rules")
    if rules is None:
        return []
    if not isinstance(rules, list):
        raise ValueError(f"{label} Semgrep rules file {path} 'rules' field must be a list")
    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"{label} Semgrep rules file {path} rule[{idx}] must be a mapping")
    return rules


def merge_org_rules(org_path: pathlib.Path, caller_path: pathlib.Path, out_path: pathlib.Path) -> int:
    if yaml is None:
        raise RuntimeError("PyYAML is required to run merge-semgrep-rules.py")

    caller_rules = _load_rules_doc(caller_path, "Caller")
    org_rules = _load_rules_doc(org_path, "Org")

    caller_ids = {r.get("id") for r in caller_rules if r.get("id")}
    extra_rules = [r for r in org_rules if r.get("id") not in caller_ids]

    if extra_rules:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fp:
            yaml.safe_dump({"rules": extra_rules}, fp, sort_keys=False)
    elif out_path.exists():
        out_path.unlink()

    return len(extra_rules)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deduplicate org Semgrep rules against caller overrides")
    parser.add_argument("--repo-root", default=os.environ.get("GITHUB_WORKSPACE") or os.getcwd())
    parser.add_argument("--org", required=True, help="Path to org Semgrep rules YAML")
    parser.add_argument("--caller", required=True, help="Path to caller Semgrep rules YAML")
    parser.add_argument("--out", required=True, help="Output path for non-overlapping org rules YAML")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if yaml is None:
        print("[FAIL] PyYAML is required to run merge-semgrep-rules.py", file=sys.stderr)
        return 1

    repo_root = pathlib.Path(args.repo_root).resolve()
    org_path = _resolve_path(args.org, repo_root)
    caller_path = _resolve_path(args.caller, repo_root)
    out_path = _resolve_path(args.out, repo_root)

    try:
        kept = merge_org_rules(org_path, caller_path, out_path)
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1

    print(f"[INFO] Merged org Semgrep rules: kept {kept} non-overlapping rule(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
