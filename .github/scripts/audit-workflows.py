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
- WF_CONTAINER_BASH_SHELL: Container jobs using bashisms must declare defaults.run.shell: bash or step-level shell: bash
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

GHA_EXPR_RE = re.compile(r"\$\{\{((?:[^'}]|'(?:[^']|'')*'|\}(?!\}))*)\}\}", re.DOTALL)
UNTRUSTED_GHA_EXPR_RE = re.compile(
    r"\bgithub(?:\s*\.\s*(?:event\b|head_ref\b)|\s*\[\s*['\"](?:event|head_ref)['\"]\s*\])",
    re.IGNORECASE,
)
PR_HEAD_REF_RE = re.compile(r"(?:github\.(?:event\.pull_request\.head|head_ref)|refs/pull/)", re.IGNORECASE)
GITHUB_HOSTED_LABEL_RE = re.compile(r"^(?:ubuntu|windows|macos)-[A-Za-z0-9._-]+$", re.IGNORECASE)
UBUNTU_LABEL_RE = GITHUB_HOSTED_LABEL_RE
FORK_TERNARY_UBUNTU_BRANCH_RE = re.compile(
    r"""&&\s*(?:fromJSON\s*\(\s*)?['"](\[?\s*(?:\\?["'])?ubuntu-latest(?:\\?["'])?\s*\]?)['"]\s*\)?\s*\|\|""",
    re.IGNORECASE,
)
NON_PR_EVENT_EQ_RE = re.compile(
    r"""^github\.event_name\s*==\s*['"](?:push|schedule|workflow_dispatch)['"]$""",
    re.IGNORECASE,
)
SAME_REPO_PR_EQ_RE = re.compile(
    r"""^github\.event\.pull_request\.head\.repo\.full_name\s*==\s*github\.repository$""",
    re.IGNORECASE,
)
PR_EVENT_EQ_RE = re.compile(
    r"""^github\.event_name\s*==\s*['"]pull_request(?:_target)?['"]$""",
    re.IGNORECASE,
)
SAFE_NEQ_CONJUNCT_RE = re.compile(
    r"""^github\.(?:ref|ref_name|actor|repository)\s*!=\s*['"][^'"]+['"]$""",
    re.IGNORECASE,
)
SH_SHELL_RE = re.compile(r"^(?:(?:/usr)?/bin/)?(?:sh|dash)(?:\s|$)", re.IGNORECASE)
BASHISM_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("set -o pipefail", re.compile(r"(?:^|[;&|\s])set\s+[^\n;#&|]*\bpipefail\b")),
    ("bash array assignment", re.compile(r"(?:^|[;\s])[A-Za-z_][A-Za-z0-9_]*\+?\=\(")),
    ("bash array expansion", re.compile(r"\$\{[#!]?[A-Za-z_][A-Za-z0-9_]*\[[^\]]+\]\}")),
    ("extended test [[ ... ]]", re.compile(r"(?:^|[;\s(|&])\[\[(?:\s|$)")),
    (
        "bash builtin (shopt/declare/typeset/readarray/mapfile)",
        re.compile(
            r"(?:(?:^|[;\n]|&&|\|\|)\s*|(?:\bif|\bthen|\belse)\s+)(?:shopt|declare|typeset|readarray|mapfile)\b"
        ),
    ),
    ("source builtin", re.compile(r"(?:^|[;\n]|&&|\|\|)\s*source\s+[^\s;|&]")),
    ("here-string <<<", re.compile(r"(?:^|[^<])<<<(?!<)")),
    ("process substitution", re.compile(r"(?:^|\s)[<>]\(")),
    ("bash case expansion", re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?:,,?|\^\^?)")),
    ("function keyword", re.compile(r"(?:^|[;\n]|&&|\|\|)\s*function\s+[A-Za-z_][A-Za-z0-9_]*\b")),
    ("&> redirection", re.compile(r"(?:^|\s)&>>?\s*\S")),
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


def _get_default_run_shell(mapping: object) -> str:
    if not isinstance(mapping, dict):
        return ""
    defaults = mapping.get("defaults")
    if not isinstance(defaults, dict):
        return ""
    run_defaults = defaults.get("run")
    if not isinstance(run_defaults, dict):
        return ""
    shell = run_defaults.get("shell")
    return shell.strip() if isinstance(shell, str) else ""


def _resolve_step_shell(wf_shell: str, job_shell: str, step: dict) -> str:
    step_shell = step.get("shell")
    if isinstance(step_shell, str) and step_shell.strip():
        return step_shell.strip()
    if job_shell:
        return job_shell
    if wf_shell:
        return wf_shell
    return ""


def _strip_shell_comments(script: str) -> str:
    out: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    i = 0
    n = len(script)
    while i < n:
        ch = script[i]
        if escaped:
            out.append(ch)
            escaped = False
            i += 1
            continue
        if in_single:
            out.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            out.append(ch)
            if ch == "\\":
                escaped = True
            elif ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "\\":
            out.append(ch)
            escaped = True
            i += 1
            continue
        if ch == "'":
            out.append(ch)
            in_single = True
            i += 1
            continue
        if ch == '"':
            out.append(ch)
            in_double = True
            i += 1
            continue
        if ch == "#":
            prev_ch = script[i - 1] if i > 0 else ""
            if prev_ch in ("", "\n", "\r", " ", "\t", ";", "&", "|", "(", ")"):
                while i < n and script[i] != "\n":
                    i += 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _strip_gha_expr(cond: str) -> str:
    s = cond.strip()
    if s.startswith("${{") and s.endswith("}}"):
        s = s[3:-2].strip()
    return s


def _strip_outer_parens(expr: str) -> str:
    s = expr.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        in_sq = False
        in_dq = False
        balanced_wrap = True
        for i, ch in enumerate(s):
            if ch == "'" and not in_dq:
                in_sq = not in_sq
            elif ch == '"' and not in_sq:
                in_dq = not in_dq
            elif not in_sq and not in_dq:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0 and i < len(s) - 1:
                        balanced_wrap = False
                        break
        if balanced_wrap and depth == 0:
            s = s[1:-1].strip()
        else:
            break
    return s


def _split_top_level_op(expr: str, op: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    in_sq = False
    in_dq = False
    start = 0
    i = 0
    n = len(expr)
    op_len = len(op)
    while i < n:
        ch = expr[i]
        if ch == "'" and not in_dq:
            in_sq = not in_sq
        elif ch == '"' and not in_sq:
            in_dq = not in_dq
        elif not in_sq and not in_dq:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
            elif depth == 0 and expr[i : i + op_len] == op:
                parts.append(expr[start:i].strip())
                start = i + op_len
                i += op_len
                continue
        i += 1
    parts.append(expr[start:].strip())
    return parts


def _has_negated_fork_paren(expr: str) -> bool:
    """Return True if any '!(...)' sub-expression encloses head.repo.fork or head.repo.full_name."""
    n = len(expr)
    i = 0
    in_sq = False
    in_dq = False
    while i < n:
        ch = expr[i]
        if ch == "'" and not in_dq:
            if in_sq and i + 1 < n and expr[i + 1] == "'":
                i += 2
                continue
            in_sq = not in_sq
            i += 1
            continue
        if ch == '"' and not in_sq:
            in_dq = not in_dq
            i += 1
            continue
        if not in_sq and not in_dq and ch == "!" and (i + 1 >= n or expr[i + 1] != "="):
            j = i + 1
            while j < n and expr[j].isspace():
                j += 1
            if j < n and expr[j] == "(":
                depth = 0
                k = j
                k_sq = False
                k_dq = False
                close_idx = n
                while k < n:
                    ck = expr[k]
                    if ck == "'" and not k_dq:
                        if k_sq and k + 1 < n and expr[k + 1] == "'":
                            k += 2
                            continue
                        k_sq = not k_sq
                    elif ck == '"' and not k_sq:
                        k_dq = not k_dq
                    elif not k_sq and not k_dq:
                        if ck == "(":
                            depth += 1
                        elif ck == ")":
                            depth -= 1
                            if depth == 0:
                                close_idx = k
                                break
                    k += 1
                sub = expr[j + 1 : close_idx]
                if re.search(r"head\.repo\.(?:fork|full_name)", sub, re.IGNORECASE):
                    return True
        i += 1
    return False


def is_fork_isolated_runs_on(runs_on: object) -> bool:
    """Return True when runs-on uses a standard GitHub-hosted runner or routes fork PRs to ubuntu-latest."""
    if isinstance(runs_on, str):
        s = runs_on.strip()
        if not s:
            return False
        if GITHUB_HOSTED_LABEL_RE.match(s) and "self-hosted" not in s.lower():
            return True
        if s.startswith("[") and s.endswith("]"):
            try:
                parsed = json.loads(s)
            except json.JSONDecodeError:
                return False
            if isinstance(parsed, list):
                return is_fork_isolated_runs_on(parsed)
            return False
        inner = _strip_gha_expr(s)
        if inner == "fromJSON(inputs.runner_labels)":
            return True
        m = FORK_TERNARY_UBUNTU_BRANCH_RE.search(inner)
        if not m:
            return False
        before_or = inner[: m.end()]
        dead_falsy = r"(?:\b(?:false|0|null)\b|''|\"\"|!\s*true\b)"
        if re.search(
            rf"(?:&&\s*\(*\s*{dead_falsy}\s*\)*(?:$|[)&|])|(?:^|[(&|])\s*\(*\s*{dead_falsy}\s*\)*\s*&&)",
            before_or,
            re.IGNORECASE,
        ):
            return False
        falsy_lit = r"(?:\b(?:false|0|null)\b|['\"]false['\"]|['\"]{2})"
        truthy_lit = r"\b(?:true|1)\b"
        any_truthy_lit = r"(?:\b(?:true|1)\b|['\"]true['\"])"
        str_true_lit = r"['\"]true['\"]"
        fork_prop = r"(?:github\.event\.pull_request\.)?head\.repo\.fork\b"
        has_fork_pred = (
            re.search(r"head\.repo\.full_name\s*!=\s*github\.repository", before_or, re.IGNORECASE) is not None
            or (
                re.search(r"head\.repo\.fork", before_or, re.IGNORECASE) is not None
                and not re.search(rf"head\.repo\.fork\s*==\s*{falsy_lit}", before_or, re.IGNORECASE)
                and not re.search(rf"{falsy_lit}\s*==\s*{fork_prop}", before_or, re.IGNORECASE)
                and not re.search(r"!\s*github\.event\.pull_request\.head\.repo\.fork\b", before_or, re.IGNORECASE)
            )
        )
        if not has_fork_pred:
            return False
        if "self-hosted" in before_or.lower():
            return False
        if _has_negated_fork_paren(before_or):
            return False
        if re.search(r"!(?!=)\s*(?:github\.event\.pull_request\.)?head\.repo\.fork\b", before_or, re.IGNORECASE):
            return False
        if re.search(rf"{fork_prop}\s*==\s*{falsy_lit}", before_or, re.IGNORECASE):
            return False
        if re.search(rf"{falsy_lit}\s*==\s*{fork_prop}", before_or, re.IGNORECASE):
            return False
        if re.search(rf"{fork_prop}\s*==\s*{str_true_lit}", before_or, re.IGNORECASE):
            return False
        if re.search(rf"{str_true_lit}\s*==\s*{fork_prop}", before_or, re.IGNORECASE):
            return False
        if re.search(rf"{fork_prop}\s*!=\s*{any_truthy_lit}", before_or, re.IGNORECASE):
            return False
        if re.search(rf"{any_truthy_lit}\s*!=\s*{fork_prop}", before_or, re.IGNORECASE):
            return False
        if re.search(r"([A-Za-z0-9_.\[\]'\"-]+)\s*!=\s*\1(?![A-Za-z0-9_.\[\]'\"-])", before_or, re.IGNORECASE):
            return False
        if re.search(
            r"""github\.event_name\s*==\s*['"](?:push|schedule|workflow_dispatch)['"]""",
            before_or,
            re.IGNORECASE,
        ):
            return False
        if re.search(r"""github\.event_name\s*!=\s*['"]pull_request(?:_target)?['"]""", before_or, re.IGNORECASE):
            return False
        if re.search(r"head\.repo\.full_name\s*==\s*github\.repository", before_or, re.IGNORECASE):
            return False
        if re.search(r"(?:1\s*==\s*0|0\s*==\s*1)", before_or):
            return False
        return True
    if isinstance(runs_on, list):
        if not runs_on:
            return False
        lowered = [str(x).strip().lower() for x in runs_on]
        if any("self-hosted" in x for x in lowered):
            return False
        return all(GITHUB_HOSTED_LABEL_RE.match(x) for x in lowered)
    return False


def _is_safe_non_pr_conjunct_group(expr: str, *, allow_same_repo_pr: bool) -> bool:
    s = _strip_outer_parens(expr)
    if not s:
        return False
    if re.match(r"^!\s*cancelled\s*\(\s*\)\s*&&\s*", s, re.IGNORECASE):
        s = _strip_outer_parens(re.sub(r"^!\s*cancelled\s*\(\s*\)\s*&&\s*", "", s, count=1, flags=re.IGNORECASE))
    disjuncts = _split_top_level_op(s, "||")
    if len(disjuncts) > 1:
        return all(_is_safe_non_pr_conjunct_group(d, allow_same_repo_pr=allow_same_repo_pr) for d in disjuncts)

    conjuncts = _split_top_level_op(s, "&&")
    if not conjuncts or any(not c for c in conjuncts):
        return False

    has_non_pr_event = False
    has_same_repo_pr = False
    for raw_c in conjuncts:
        c = _strip_outer_parens(raw_c)
        if not c:
            return False
        if re.search(r"\balways\s*\(", c, re.IGNORECASE):
            return False
        if "!=" in c:
            if SAFE_NEQ_CONJUNCT_RE.match(c):
                continue
            return False
        if re.fullmatch(r"true", c, re.IGNORECASE):
            return False
        if NON_PR_EVENT_EQ_RE.match(c):
            has_non_pr_event = True
            continue
        if allow_same_repo_pr and SAME_REPO_PR_EQ_RE.match(c):
            has_same_repo_pr = True
            continue
        if "pull_request" in c.lower():
            if allow_same_repo_pr and PR_EVENT_EQ_RE.match(c):
                continue
            return False
    return has_non_pr_event or has_same_repo_pr


def is_non_pr_if_guard(cond: object, *, allow_same_repo_pr: bool = False) -> bool:
    """Return True only when an explicit job if: restricts execution away from fork/PR events."""
    if not isinstance(cond, str) or not cond.strip():
        return False
    s = _strip_gha_expr(cond)
    if re.search(r"\balways\s*\(", s, re.IGNORECASE):
        return False
    if re.search(r"\|\|\s*true\b|\btrue\s*\|\|", s, re.IGNORECASE):
        return False
    return _is_safe_non_pr_conjunct_group(s, allow_same_repo_pr=allow_same_repo_pr)


def _find_script_injection(run_script: str) -> str | None:
    for m in GHA_EXPR_RE.finditer(run_script):
        if UNTRUSTED_GHA_EXPR_RE.search(m.group(1)):
            return m.group(0)
    return None


def _detect_bashism(script: str) -> str | None:
    cleaned = _strip_shell_comments(script)
    for label, pattern in BASHISM_PATTERNS:
        if pattern.search(cleaned):
            return label
    return None


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
    wf_shell = _get_default_run_shell(doc)

    for job_id, job in doc["jobs"].items():
        if not isinstance(job, dict):
            continue

        has_container = bool(job.get("container"))
        job_shell = _get_default_run_shell(job)

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

        job_exempt_from_pr = is_non_pr_if_guard(job.get("if"), allow_same_repo_pr=not pr_target)

        if pr_triggered:
            if isinstance(job_uses, str) and ORG_REUSABLE_RE.match(job_uses) and not job_exempt_from_pr:
                with_map = job.get("with") if isinstance(job.get("with"), dict) else {}
                runner_labels = with_map.get("runner_labels")
                if not isinstance(runner_labels, str) or not runner_labels.strip() or not is_fork_isolated_runs_on(runner_labels):
                    findings.append({
                        "file": norm_file,
                        "job": str(job_id),
                        "ruleId": "WF_FORK_PR_RUNNER_ISOLATION",
                        "fingerprint": f"job:{job_id}:runner_labels",
                        "message": (
                            f"Job '{job_id}' calls reusable workflow '{job_uses}' under pull_request "
                            f"without fork-PR ubuntu-latest isolated 'with.runner_labels'."
                        ),
                    })
            elif not job_uses:
                runs_on = job.get("runs-on")
                if not job_exempt_from_pr and not is_fork_isolated_runs_on(runs_on):
                    findings.append({
                        "file": norm_file,
                        "job": str(job_id),
                        "ruleId": "WF_FORK_PR_RUNNER_ISOLATION",
                        "fingerprint": f"job:{job_id}:runs-on",
                        "message": f"Job '{job_id}' runs on non-fork-isolated runner under pull_request without routing fork PRs to ubuntu-latest.",
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
                inj_match = _find_script_injection(run_script)
                if inj_match:
                    findings.append({
                        "file": norm_file,
                        "job": str(job_id),
                        "ruleId": "WF_NO_SCRIPT_INJECTION",
                        "fingerprint": inj_match,
                        "message": f"Untrusted expression {inj_match} interpolated in run: script; bind via env: instead.",
                    })
                if has_container:
                    eff_shell = _resolve_step_shell(wf_shell, job_shell, step)
                    if eff_shell == "" or SH_SHELL_RE.match(eff_shell):
                        bashism = _detect_bashism(run_script)
                        if bashism:
                            findings.append({
                                "file": norm_file,
                                "job": str(job_id),
                                "ruleId": "WF_CONTAINER_BASH_SHELL",
                                "fingerprint": f"job:{job_id}:step:{idx}:container-shell",
                                "message": (
                                    f"Step {idx} in container job '{job_id}' uses bashism ({bashism}) "
                                    f"under '{eff_shell or 'default /bin/sh'}'; set 'defaults.run.shell: bash' "
                                    f"or step-level 'shell: bash'."
                                ),
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


def _parse_baseline_count(raw_cnt: object) -> int:
    if raw_cnt is None:
        return 1
    if isinstance(raw_cnt, bool) or not isinstance(raw_cnt, int) or raw_cnt < 0:
        raise ValueError(f"Baseline entry 'count' must be a non-negative integer (got {raw_cnt!r})")
    return raw_cnt


def apply_baseline(findings: list[dict], baseline_entries: list[dict]) -> tuple[list[dict], list[dict]]:
    exact_counts: dict[tuple[str, str, str], int] = {}
    rule_counts: dict[tuple[str, str], int] = {}

    for entry in baseline_entries:
        rel = normalize_path(str(entry.get("file", "")))
        rule_id = str(entry.get("ruleId", ""))
        cnt = _parse_baseline_count(entry.get("count"))
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
    try:
        baselined, unapproved = apply_baseline(findings, baseline_entries)
    except ValueError as exc:
        print(f"[FAIL] Invalid baseline: {exc}", file=sys.stderr)
        return 1

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
