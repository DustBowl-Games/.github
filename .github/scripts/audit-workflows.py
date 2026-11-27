#!/usr/bin/env python3
"""
DustBowl Games - GitHub Actions Workflow Hygiene & Security Gate

Runs actionlint (with shellcheck when available) plus deterministic contract checks:
- WF_VALID_YAML: Valid YAML with triggers ('on') and 'jobs'
- WF_SHA_PINNED_USES: 40-hex SHA pinning for external actions, @sha256 for docker://,
  and @main or 40-hex SHA for DustBowl-Games/.github reusable workflows
- WF_EXPLICIT_PERMISSIONS: Top-level or per-job permissions block
- WF_PERSIST_CREDENTIALS_FALSE: actions/checkout must set persist-credentials: false
- WF_TIMEOUT_MINUTES: Every non-reusable-call job must declare timeout-minutes
- WF_FORK_PR_RUNNER_ISOLATION: Workflows with pull_request/pull_request_target must route
  fork PRs to ubuntu-latest instead of self-hosted runners
- WF_NO_SCRIPT_INJECTION: Ban ${{ ... github.event.* ... }} or ${{ ... github.head_ref ... }}
  inside step run: scripts (pass via env: instead)
- WF_NO_PULL_REQUEST_TARGET_HEAD_CHECKOUT: Ban checking out PR head under pull_request_target
- WF_NO_PAID_ACTIONS: Ban paid/GHAS actions (R4 zero-spend enforcement)
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

SHA_USES_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
ORG_REUSABLE_RE = re.compile(
    r"^DustBowl-Games/\.github/\.github/workflows/_[A-Za-z0-9_.-]+\.ya?ml@(?:main|[0-9a-f]{40})$"
)
DOCKER_SHA_RE = re.compile(r"^docker://[^\s@]+@sha256:[0-9a-f]{64}$", re.IGNORECASE)

PAID_ACTION_PREFIXES = (
    "gitleaks/gitleaks-action",
    "github/codeql-action",
    "actions/dependency-review-action",
    "sonarsource/",
    "snyk/",
    "returntocorp/semgrep-action",
    "semgrep/semgrep-action",
)

SCRIPT_INJECTION_RE = re.compile(
    r"\$\{\{[^}]*\bgithub\.(?:event\.|head_ref\b)[^}]*\}\}"
)
PR_HEAD_REF_RE = re.compile(r"(?:github\.(?:event\.pull_request\.head|head_ref)|refs/pull/)", re.IGNORECASE)
SAFE_IF_EXCLUSION_RE = re.compile(
    r"""github\.event_name\s*==\s*['"](?:push|schedule|workflow_dispatch)['"]"""
    r"""|github\.event\.pull_request\.head\.repo\.full_name\s*==\s*github\.repository"""
)
FORK_ROUTING_RE = re.compile(
    r"ubuntu-latest.*(?:head\.repo\.full_name\s*!=\s*github\.repository|head\.repo\.fork)"
    r"|(?:head\.repo\.full_name\s*!=\s*github\.repository|head\.repo\.fork).*ubuntu-latest",
    re.DOTALL,
)


def normalize_path(rel_path: str) -> str:
    norm = rel_path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    return norm


def get_triggers(doc: dict) -> dict | list | str | None:
    if True in doc:
        return doc[True]
    return doc.get("on")


def has_pr_trigger(triggers: object) -> bool:
    if isinstance(triggers, str):
        return triggers in {"pull_request", "pull_request_target"}
    if isinstance(triggers, list):
        return any(t in {"pull_request", "pull_request_target"} for t in triggers)
    if isinstance(triggers, dict):
        return "pull_request" in triggers or "pull_request_target" in triggers
    return False


def has_pr_target_trigger(triggers: object) -> bool:
    if isinstance(triggers, str):
        return triggers == "pull_request_target"
    if isinstance(triggers, list):
        return "pull_request_target" in triggers
    if isinstance(triggers, dict):
        return "pull_request_target" in triggers
    return False


def is_valid_uses(uses: str) -> bool:
    if uses.startswith("./"):
        return True
    if ORG_REUSABLE_RE.match(uses):
        return True
    if DOCKER_SHA_RE.match(uses):
        return True
    return bool(SHA_USES_RE.match(uses))


def is_paid_action(uses: str) -> bool:
    lower = uses.lower()
    return any(lower.startswith(prefix) for prefix in PAID_ACTION_PREFIXES)


def audit_workflow_doc(doc: object, rel_file: str) -> list[dict]:
    findings: list[dict] = []
    norm_file = normalize_path(rel_file)

    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict) or get_triggers(doc) is None:
        findings.append({
            "file": norm_file,
            "job": "",
            "ruleId": "WF_VALID_YAML",
            "fingerprint": "missing jobs or on triggers",
            "message": "Workflow YAML must define top-level 'on' triggers and 'jobs' mapping.",
        })
        return findings

    triggers = get_triggers(doc)
    top_perms = doc.get("permissions")
    has_top_perms = isinstance(top_perms, dict) and len(top_perms) > 0
    pr_triggered = has_pr_trigger(triggers)
    pr_target = has_pr_target_trigger(triggers)

    for job_id, job in doc["jobs"].items():
        if not isinstance(job, dict):
            continue

        job_uses = job.get("uses")
        if isinstance(job_uses, str):
            if is_paid_action(job_uses):
                findings.append({
                    "file": norm_file,
                    "job": str(job_id),
                    "ruleId": "WF_NO_PAID_ACTIONS",
                    "fingerprint": job_uses,
                    "message": f"Job '{job_id}' uses banned paid action: {job_uses}",
                })
            elif not is_valid_uses(job_uses):
                findings.append({
                    "file": norm_file,
                    "job": str(job_id),
                    "ruleId": "WF_SHA_PINNED_USES",
                    "fingerprint": job_uses,
                    "message": f"Job '{job_id}' reusable workflow must be pinned to 40-char SHA or @main org workflow: {job_uses}",
                })

        if not has_top_perms:
            job_perms = job.get("permissions")
            if not (isinstance(job_perms, dict) and len(job_perms) > 0):
                findings.append({
                    "file": norm_file,
                    "job": str(job_id),
                    "ruleId": "WF_EXPLICIT_PERMISSIONS",
                    "fingerprint": f"job:{job_id}:permissions",
                    "message": f"Job '{job_id}' lacks explicit 'permissions' (and workflow has no top-level 'permissions').",
                })

        if not job_uses and "timeout-minutes" not in job:
            findings.append({
                "file": norm_file,
                "job": str(job_id),
                "ruleId": "WF_TIMEOUT_MINUTES",
                "fingerprint": f"job:{job_id}:timeout-minutes",
                "message": f"Job '{job_id}' must define 'timeout-minutes'.",
            })

        if pr_triggered:
            runs_on = job.get("runs-on")
            runs_on_str = json.dumps(runs_on) if isinstance(runs_on, list) else str(runs_on or "")
            if "self-hosted" in runs_on_str:
                job_if = str(job.get("if") or "")
                if not SAFE_IF_EXCLUSION_RE.search(job_if) and not FORK_ROUTING_RE.search(runs_on_str):
                    findings.append({
                        "file": norm_file,
                        "job": str(job_id),
                        "ruleId": "WF_FORK_PR_RUNNER_ISOLATION",
                        "fingerprint": f"job:{job_id}:runs-on",
                        "message": f"Job '{job_id}' runs on self-hosted under pull_request without routing fork PRs to ubuntu-latest.",
                    })

        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue

        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if isinstance(uses, str):
                if is_paid_action(uses):
                    findings.append({
                        "file": norm_file,
                        "job": str(job_id),
                        "ruleId": "WF_NO_PAID_ACTIONS",
                        "fingerprint": uses,
                        "message": f"Step {idx} in '{job_id}' uses banned paid action: {uses}",
                    })
                elif not is_valid_uses(uses):
                    findings.append({
                        "file": norm_file,
                        "job": str(job_id),
                        "ruleId": "WF_SHA_PINNED_USES",
                        "fingerprint": uses,
                        "message": f"Step {idx} in '{job_id}' action is not pinned to a 40-char SHA: {uses}",
                    })

                if uses.startswith("actions/checkout@"):
                    step_with = step.get("with") or {}
                    if not isinstance(step_with, dict) or step_with.get("persist-credentials") is not False:
                        findings.append({
                            "file": norm_file,
                            "job": str(job_id),
                            "ruleId": "WF_PERSIST_CREDENTIALS_FALSE",
                            "fingerprint": f"job:{job_id}:step:{idx}:persist-credentials",
                            "message": f"actions/checkout in '{job_id}' step {idx} must set 'persist-credentials: false'.",
                        })
                    if pr_target and isinstance(step_with, dict):
                        ref_val = str(step_with.get("ref") or "")
                        if PR_HEAD_REF_RE.search(ref_val):
                            findings.append({
                                "file": norm_file,
                                "job": str(job_id),
                                "ruleId": "WF_NO_PULL_REQUEST_TARGET_HEAD_CHECKOUT",
                                "fingerprint": f"job:{job_id}:step:{idx}:pr_target_ref",
                                "message": f"Unsafe checkout of PR head ref under pull_request_target in '{job_id}'.",
                            })

            run_script = step.get("run")
            if isinstance(run_script, str):
                m_inj = SCRIPT_INJECTION_RE.search(run_script)
                if m_inj:
                    findings.append({
                        "file": norm_file,
                        "job": str(job_id),
                        "ruleId": "WF_NO_SCRIPT_INJECTION",
                        "fingerprint": m_inj.group(0),
                        "message": f"Untrusted expression {m_inj.group(0)} interpolated in run: script; bind via env: instead.",
                    })

    return findings


def run_actionlint(wf_files: list[pathlib.Path], repo_root: pathlib.Path, actionlint_bin: str = "") -> list[dict]:
    binary = actionlint_bin or shutil.which("actionlint")
    if not binary:
        return [{
            "file": ".github/workflows",
            "job": "",
            "ruleId": "WF_ACTIONLINT_MISSING",
            "fingerprint": "actionlint binary not found",
            "message": "actionlint binary not found on PATH (pass --skip-actionlint only in unit tests).",
        }]

    cmd = [binary, "-no-color", *[str(p) for p in wf_files]]
    proc = subprocess.run(
        cmd,
        cwd=repo_root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode == 0:
        return []

    output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    findings: list[dict] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.match(r"^([^:]+):(\d+):(\d+):\s*(.+)$", line)
        if m:
            fpath = normalize_path(os.path.relpath(m.group(1), repo_root)) if os.path.isabs(m.group(1)) else normalize_path(m.group(1))
            findings.append({
                "file": fpath,
                "job": "",
                "ruleId": "WF_ACTIONLINT",
                "fingerprint": m.group(4)[:140],
                "message": f"line {m.group(2)}:{m.group(3)}: {m.group(4)}",
            })
        elif line == "|" or re.match(r"^(?:\d+\s*)?\|", line):
            continue
        else:
            findings.append({
                "file": ".github/workflows",
                "job": "",
                "ruleId": "WF_ACTIONLINT",
                "fingerprint": line[:140],
                "message": line,
            })
    return findings


def load_baseline(baseline_path: pathlib.Path | None) -> list[dict]:
    if not baseline_path:
        return []
    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline file not found: {baseline_path}")
    raw = baseline_path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff").strip()
    if not raw:
        return []
    data = json.loads(raw)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("workflow_hygiene_baseline", "entries", "legacyAuditBaseline", "baseline"):
            if isinstance(data.get(key), list):
                return data[key]
    raise ValueError(f"Unsupported baseline schema in {baseline_path}")


def apply_baseline(findings: list[dict], baseline_entries: list[dict]) -> tuple[list[dict], list[dict]]:
    exact_counts: dict[tuple[str, str, str], int] = {}
    rule_counts: dict[tuple[str, str], int] = {}

    for entry in baseline_entries:
        rel = normalize_path(str(entry.get("file", "")))
        rule_id = str(entry.get("ruleId", ""))
        cnt = int(entry.get("count", 1) or 1)
        fp = entry.get("fingerprint")
        if fp:
            key = (rel, rule_id, str(fp).strip())
            exact_counts[key] = exact_counts.get(key, 0) + cnt
        else:
            key2 = (rel, rule_id)
            rule_counts[key2] = rule_counts.get(key2, 0) + cnt

    baselined: list[dict] = []
    unapproved: list[dict] = []
    for f in findings:
        ekey = (f["file"], f["ruleId"], f["fingerprint"].strip())
        rkey = (f["file"], f["ruleId"])
        if exact_counts.get(ekey, 0) > 0:
            exact_counts[ekey] -= 1
            baselined.append(f)
        elif rule_counts.get(rkey, 0) > 0:
            rule_counts[rkey] -= 1
            baselined.append(f)
        else:
            unapproved.append(f)
    return baselined, unapproved


def audit_workflows_dir(
    repo_root: pathlib.Path,
    workflows_dir: pathlib.Path,
    *,
    skip_actionlint: bool = False,
    actionlint_bin: str = "",
) -> list[dict]:
    if yaml is None:
        raise RuntimeError("PyYAML is required to run audit-workflows.py")

    wf_files = sorted(
        [*workflows_dir.glob("*.yml"), *workflows_dir.glob("*.yaml")],
        key=lambda p: p.name,
    )
    if not wf_files:
        return []

    findings: list[dict] = []
    for wf in wf_files:
        rel = normalize_path(str(wf.relative_to(repo_root)))
        try:
            doc = yaml.safe_load(wf.read_text(encoding="utf-8", errors="replace"))
        except yaml.YAMLError as exc:
            findings.append({
                "file": rel,
                "job": "",
                "ruleId": "WF_VALID_YAML",
                "fingerprint": "yaml parse error",
                "message": f"Invalid YAML syntax: {exc}",
            })
            continue
        findings.extend(audit_workflow_doc(doc, rel))

    if not skip_actionlint:
        findings.extend(run_actionlint(wf_files, repo_root, actionlint_bin=actionlint_bin))

    return findings


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DustBowl GitHub Actions Workflow Hygiene Gate")
    parser.add_argument("--repo-root", default=os.environ.get("GITHUB_WORKSPACE") or os.getcwd())
    parser.add_argument("--workflows-dir", default="")
    parser.add_argument("--baseline", default="")
    parser.add_argument("--skip-actionlint", action="store_true", default=False)
    parser.add_argument("--actionlint-bin", default="")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = pathlib.Path(args.repo_root).resolve()
    if not repo_root.is_dir():
        print(f"[FAIL] Repository root does not exist: {repo_root}", file=sys.stderr)
        return 1

    workflows_dir = (
        pathlib.Path(args.workflows_dir).resolve()
        if args.workflows_dir
        else (repo_root / ".github" / "workflows")
    )
    if not workflows_dir.is_dir():
        print(f"[INFO] No workflows directory at {workflows_dir}; skipping.")
        return 0

    baseline_entries: list[dict] = []
    if args.baseline:
        bpath = pathlib.Path(args.baseline)
        if not bpath.is_absolute():
            bpath = (repo_root / bpath).resolve()
        try:
            baseline_entries = load_baseline(bpath)
        except Exception as exc:
            print(f"[FAIL] Could not load baseline: {exc}", file=sys.stderr)
            return 1

    findings = audit_workflows_dir(
        repo_root,
        workflows_dir,
        skip_actionlint=args.skip_actionlint,
        actionlint_bin=args.actionlint_bin,
    )
    baselined, unapproved = apply_baseline(findings, baseline_entries)

    wf_count = len(list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml")))
    print(
        f"[SUMMARY] Workflow hygiene ({wf_count} workflow(s)): "
        f"baselined={len(baselined)} | unapproved={len(unapproved)}"
    )

    if unapproved:
        for v in unapproved:
            print(f"::error file={v['file']}::[{v['ruleId']}] {v['message']}", file=sys.stderr)
        return 1

    print("[PASS] All workflows passed hygiene and security contract checks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
