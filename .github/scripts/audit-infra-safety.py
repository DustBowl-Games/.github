#!/usr/bin/env python3
"""
DustBowl Games - Infrastructure Safety Gate (Dockerfiles, Kubernetes, Helm)

Zero-spend OSS static checks for:
- All Dockerfile, Dockerfile.*, *.Dockerfile files:
  * Multi-stage tracking requiring non-root USER in final stage
  * Ban :latest base image tags
  * Optional --require-pinned-digest (@sha256:...) enforcement
  * Ban ADD http(s):// remote URLs
  * Ban chmod 777 / a+rwx
  * Ban unverified curl/wget | sh/bash pipes
  * Optional hadolint integration (--hadolint-mode advisory|blocking)
- Optional Kubernetes / Helm manifests (--check-k8s-helm):
  * Ban insecure DB TLS flags (Trust Server Certificate=true, TrustServerCertificate=true, SslMode=Disable)
  * Ban privileged: true, allowPrivilegeEscalation: true, automountServiceAccountToken: true
  * Ban runAsNonRoot: false, runAsUser: 0
  * Ban hostNetwork / hostPID / hostIPC: true
  * Ban :latest image tags
  * Require readOnlyRootFilesystem: true in workload/values securityContext
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

IGNORED_DIRS = {
    ".git",
    ".org-ci",
    "__pycache__",
    "node_modules",
    "bin",
    "obj",
    "artifacts",
    ".venv",
    "vendor",
    ".agents",
    "tests",
}

DOCKERFILE_NAME_RE = re.compile(r"^(?:Dockerfile(?:\..+)?|.+\.Dockerfile)$")
FROM_RE = re.compile(
    r"^FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<alias>[A-Za-z0-9_.-]+))?(?:\s+#.*)?$",
    re.IGNORECASE,
)
USER_RE = re.compile(r"^USER\s+(?P<user>\S+)", re.IGNORECASE)
ADD_RE = re.compile(r"^ADD\s+(?P<rest>.+)$", re.IGNORECASE)
RUN_RE = re.compile(r"^RUN\s+(?P<rest>.+)$", re.IGNORECASE)
CHMOD_777_RE = re.compile(r"\bchmod\s+(?:-[A-Za-z]+\s+)*(?:0*777|a\+rwx)\b")
PIPE_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:(?:sudo|(?:/usr/bin/)?env)\s+)*(?:/(?:usr/(?:local/)?)?bin/)?(?:sh|bash|zsh|ash|dash)\b",
    re.IGNORECASE,
)
SHA256_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$", re.IGNORECASE)
LATEST_TAG_RE = re.compile(r":latest(?:@sha256:[0-9a-f]{64})?$", re.IGNORECASE)

K8S_RULES = [
    (
        "K8S_INSECURE_TLS_CONNSTRING",
        re.compile(r"(?:Trust\s*Server\s*Certificate|TrustServerCertificate)\s*=\s*(?:true|1|yes)|SslMode\s*=\s*Disable", re.IGNORECASE),
        "Remove Trust Server Certificate=true / SslMode=Disable; enforce verified TLS.",
    ),
    (
        "K8S_PRIVILEGED_CONTAINER",
        re.compile(r"^\s*(?:-\s*)?privileged\s*:\s*true(?:\s|$|#)", re.IGNORECASE),
        "Set securityContext.privileged to false.",
    ),
    (
        "K8S_ALLOW_PRIVILEGE_ESCALATION",
        re.compile(r"^\s*(?:-\s*)?allowPrivilegeEscalation\s*:\s*true(?:\s|$|#)", re.IGNORECASE),
        "Set securityContext.allowPrivilegeEscalation to false.",
    ),
    (
        "K8S_AUTOMOUNT_SA_TOKEN",
        re.compile(r"^\s*(?:-\s*)?automountServiceAccountToken\s*:\s*true(?:\s|$|#)", re.IGNORECASE),
        "Set automountServiceAccountToken: false unless the workload calls the Kubernetes API.",
    ),
    (
        "K8S_RUN_AS_ROOT",
        re.compile(r"^\s*(?:-\s*)?runAsNonRoot\s*:\s*false(?:\s|$|#)", re.IGNORECASE),
        "Set runAsNonRoot: true.",
    ),
    (
        "K8S_RUN_AS_USER_ZERO",
        re.compile(r"^\s*(?:-\s*)?runAsUser\s*:\s*0(?:\s|$|#)", re.IGNORECASE),
        "Set a non-zero UID for runAsUser.",
    ),
    (
        "K8S_HOST_NAMESPACE",
        re.compile(r"^\s*(?:-\s*)?(?:hostNetwork|hostPID|hostIPC)\s*:\s*true(?:\s|$|#)", re.IGNORECASE),
        "Disable hostNetwork, hostPID, and hostIPC.",
    ),
    (
        "K8S_LATEST_IMAGE_TAG",
        re.compile(r"^\s*(?:-\s*)?image\s*:\s*['\"]?[^\s'\"#]+:latest(?:\s|$|['\"#])", re.IGNORECASE),
        "Pin container image tags to immutable versions or digests instead of :latest.",
    ),
]

WORKLOAD_KIND_RE = re.compile(r"^\s*kind\s*:\s*(Deployment|StatefulSet|DaemonSet|Job|CronJob|Pod)\b", re.MULTILINE)
READONLY_ROOTFS_TRUE_RE = re.compile(r"^\s*(?:-\s*)?readOnlyRootFilesystem\s*:\s*true(?:\s|$|#)", re.MULTILINE)
READONLY_ROOTFS_FALSE_RE = re.compile(r"^\s*(?:-\s*)?readOnlyRootFilesystem\s*:\s*false(?:\s|$|#)", re.MULTILINE)
TOYAML_SEC_CTX_RE = re.compile(r"toYaml\s+[^\n]*[sS]ecurityContext")
VALUES_KEY_RE = re.compile(r"^(\s*)(?:-\s+)?([A-Za-z0-9_.-]+)\s*:\s*(.*)$")
VALUES_LATEST_TAG_VAL_RE = re.compile(r"^['\"]?latest['\"]?(?:\s+#.*)?$", re.IGNORECASE)


def normalize_path(rel_path: str) -> str:
    norm = rel_path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    return norm


def is_ignored_rel(rel_path: str) -> bool:
    parts = normalize_path(rel_path).split("/")
    return any(part in IGNORED_DIRS for part in parts[:-1])


def is_dockerfile_name(name: str) -> bool:
    return bool(DOCKERFILE_NAME_RE.match(name))


def _collapse_dockerfile_lines(content: str) -> list[tuple[int, str]]:
    """Return logical (1-based start line, instruction) tuples handling comments and trailing backslashes."""
    raw_lines = content.splitlines()
    logical: list[tuple[int, str]] = []
    buf = ""
    start_line = 0
    for idx, raw in enumerate(raw_lines, start=1):
        stripped = raw.strip()
        if not buf:
            if not stripped or stripped.startswith("#"):
                continue
            start_line = idx
        else:
            if stripped.startswith("#"):
                continue
        if raw.rstrip().endswith("\\"):
            buf += " " + raw.rstrip()[:-1].strip()
        else:
            buf = (buf + " " + stripped).strip() if buf else stripped
            logical.append((start_line, buf))
            buf = ""
    if buf:
        logical.append((start_line, buf.strip()))
    return logical


def check_dockerfile_content(
    content: str,
    rel_path: str,
    require_pinned_digest: bool = False,
) -> list[dict]:
    norm_file = normalize_path(rel_path)
    findings: list[dict] = []
    stage_aliases: set[str] = set()
    has_from = False
    last_user: str | None = None
    last_from_line = 1

    for line_no, stmt in _collapse_dockerfile_lines(content):
        m_from = FROM_RE.match(stmt)
        if m_from:
            has_from = True
            last_user = None
            last_from_line = line_no
            image = m_from.group("image")
            alias = m_from.group("alias")

            if LATEST_TAG_RE.search(image):
                findings.append({
                    "file": norm_file,
                    "line": line_no,
                    "ruleId": "DOCKERFILE_LATEST_TAG",
                    "fingerprint": f"FROM {image}",
                    "message": f"Banned :latest tag in FROM instruction: {image}",
                })

            is_stage_ref = image.lower() in stage_aliases or image.lower() == "scratch"
            if require_pinned_digest and not is_stage_ref and not SHA256_DIGEST_RE.search(image):
                findings.append({
                    "file": norm_file,
                    "line": line_no,
                    "ruleId": "DOCKERFILE_UNPINNED_DIGEST",
                    "fingerprint": f"FROM {image}",
                    "message": f"Base image must be pinned to a @sha256 digest: {image}",
                })

            if alias:
                stage_aliases.add(alias.lower())
            continue

        m_user = USER_RE.match(stmt)
        if m_user:
            last_user = m_user.group("user").strip().strip("\"'")
            continue

        m_add = ADD_RE.match(stmt)
        if m_add:
            tokens = [t for t in m_add.group("rest").split() if not t.startswith("--")]
            for tok in tokens[:-1]:
                if tok.lower().startswith(("http://", "https://")):
                    findings.append({
                        "file": norm_file,
                        "line": line_no,
                        "ruleId": "DOCKERFILE_ADD_REMOTE_URL",
                        "fingerprint": f"ADD {tok}",
                        "message": f"Avoid ADD with remote URL ({tok}); use verified download + checksum.",
                    })
            continue

        m_run = RUN_RE.match(stmt)
        if m_run:
            cmd = m_run.group("rest")
            if CHMOD_777_RE.search(cmd):
                findings.append({
                    "file": norm_file,
                    "line": line_no,
                    "ruleId": "DOCKERFILE_CHMOD_777",
                    "fingerprint": cmd[:120],
                    "message": "Overly permissive chmod 777 / a+rwx detected in Dockerfile RUN.",
                })
            if PIPE_SHELL_RE.search(cmd):
                findings.append({
                    "file": norm_file,
                    "line": line_no,
                    "ruleId": "DOCKERFILE_PIPE_TO_SHELL",
                    "fingerprint": cmd[:120],
                    "message": "Unverified curl/wget pipe to shell detected in Dockerfile RUN.",
                })

    if has_from and (
        not last_user
        or last_user.lower() == "root"
        or last_user == "0"
        or last_user.startswith("0:")
    ):
        findings.append({
            "file": norm_file,
            "line": last_from_line,
            "ruleId": "DOCKERFILE_ROOT_USER",
            "fingerprint": f"USER {last_user or 'MISSING'}",
            "message": f"Final Dockerfile stage must end with a non-root USER (found: {last_user or 'none'}).",
        })

    return findings


def check_k8s_helm_content(content: str, rel_path: str) -> list[dict]:
    norm_file = normalize_path(rel_path)
    findings: list[dict] = []
    lines = content.splitlines()

    for line_no, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for rule_id, pattern, msg in K8S_RULES:
            if pattern.search(raw):
                findings.append({
                    "file": norm_file,
                    "line": line_no,
                    "ruleId": rule_id,
                    "fingerprint": stripped[:140],
                    "message": msg,
                })
        if READONLY_ROOTFS_FALSE_RE.search(raw):
            findings.append({
                "file": norm_file,
                "line": line_no,
                "ruleId": "K8S_MISSING_READONLY_ROOT_FS",
                "fingerprint": stripped[:140],
                "message": "Set readOnlyRootFilesystem: true in container securityContext.",
            })

    # Check workload documents and values files for missing readOnlyRootFilesystem: true
    # and nested image.tag: latest in Helm values*.yaml
    base_name = pathlib.PurePosixPath(norm_file).name.lower()
    if base_name.startswith("values") and base_name.endswith((".yml", ".yaml")):
        key_stack: list[tuple[int, str]] = []
        for line_no, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m_kv = VALUES_KEY_RE.match(raw)
            if not m_kv:
                continue
            indent = len(m_kv.group(1))
            if re.match(r"^\s*-\s+", raw):
                indent += 2
            key = m_kv.group(2)
            val = m_kv.group(3).strip()
            while key_stack and key_stack[-1][0] >= indent:
                key_stack.pop()
            if key.lower() == "tag" and any(k.lower() == "image" for _, k in key_stack):
                if VALUES_LATEST_TAG_VAL_RE.match(val):
                    findings.append({
                        "file": norm_file,
                        "line": line_no,
                        "ruleId": "K8S_LATEST_IMAGE_TAG",
                        "fingerprint": stripped[:140],
                        "message": "Pin container image tags to immutable versions or digests instead of :latest.",
                    })
            elif key.lower() == "image" and re.search(r"\btag\s*:\s*['\"]?latest['\"]?(?:\b|$)", val, re.IGNORECASE):
                findings.append({
                    "file": norm_file,
                    "line": line_no,
                    "ruleId": "K8S_LATEST_IMAGE_TAG",
                    "fingerprint": stripped[:140],
                    "message": "Pin container image tags to immutable versions or digests instead of :latest.",
                })
            if not val or val.startswith("#"):
                key_stack.append((indent, key))

        if re.search(r"^\s*securityContext\s*:", content, re.MULTILINE) and not READONLY_ROOTFS_TRUE_RE.search(content):
            if not READONLY_ROOTFS_FALSE_RE.search(content):
                findings.append({
                    "file": norm_file,
                    "line": 1,
                    "ruleId": "K8S_MISSING_READONLY_ROOT_FS",
                    "fingerprint": "values securityContext missing readOnlyRootFilesystem: true",
                    "message": "Helm values securityContext should set readOnlyRootFilesystem: true.",
                })
    else:
        for doc in re.split(r"(?m)^---\s*$", content):
            if WORKLOAD_KIND_RE.search(doc) and re.search(r"^\s*containers\s*:", doc, re.MULTILINE):
                if not READONLY_ROOTFS_TRUE_RE.search(doc) and not READONLY_ROOTFS_FALSE_RE.search(doc) and not TOYAML_SEC_CTX_RE.search(doc):
                    findings.append({
                        "file": norm_file,
                        "line": 1,
                        "ruleId": "K8S_MISSING_READONLY_ROOT_FS",
                        "fingerprint": "workload missing readOnlyRootFilesystem: true",
                        "message": "Kubernetes workload should enforce readOnlyRootFilesystem: true.",
                    })

    return findings


def discover_dockerfiles(repo_root: pathlib.Path) -> list[pathlib.Path]:
    found: list[pathlib.Path] = []
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS)
        for fname in sorted(files):
            if is_dockerfile_name(fname):
                p = pathlib.Path(root) / fname
                rel = normalize_path(str(p.relative_to(repo_root)))
                if not is_ignored_rel(rel):
                    found.append(p)
    return found


def discover_k8s_helm_files(repo_root: pathlib.Path, helm_chart_dir: str = "") -> list[pathlib.Path]:
    roots: list[pathlib.Path] = []
    if helm_chart_dir:
        candidate = (repo_root / helm_chart_dir).resolve()
        if candidate.exists():
            roots.append(candidate)
    else:
        for d in ("helm", "k8s", "charts"):
            candidate = repo_root / d
            if candidate.is_dir():
                roots.append(candidate)

    files_out: list[pathlib.Path] = []
    seen: set[pathlib.Path] = set()
    for base in roots:
        if base.is_file() and base.suffix.lower() in {".yml", ".yaml"}:
            if base not in seen:
                seen.add(base)
                files_out.append(base)
            continue
        for root, dirs, files in os.walk(base):
            dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS)
            for fname in sorted(files):
                if fname.lower().endswith((".yml", ".yaml")) and fname not in {"Chart.yaml", "Chart.lock"}:
                    p = pathlib.Path(root) / fname
                    if p not in seen:
                        seen.add(p)
                        files_out.append(p)
    return files_out


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
        for key in ("infra_safety_baseline", "entries", "legacyAuditBaseline", "baseline"):
            if isinstance(data.get(key), list):
                return data[key]
    raise ValueError(f"Unsupported baseline JSON schema in {baseline_path}")


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


def run_hadolint(dockerfiles: list[pathlib.Path], repo_root: pathlib.Path, mode: str) -> list[dict]:
    if mode == "off" or not dockerfiles:
        return []
    hadolint_bin = shutil.which("hadolint")
    if not hadolint_bin:
        print("[INFO] hadolint not found on PATH; skipping optional hadolint check.")
        return []
    cmd = [hadolint_bin, "--format", "json", *[str(p) for p in dockerfiles]]
    proc = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode == 0 or not proc.stdout.strip():
        return []
    items = json.loads(proc.stdout)
    out: list[dict] = []
    for item in items:
        rel = normalize_path(os.path.relpath(item.get("file", ""), repo_root))
        out.append({
            "file": rel,
            "line": int(item.get("line", 1)),
            "ruleId": f"HADOLINT_{item.get('code', 'ERR')}",
            "fingerprint": str(item.get("message", ""))[:120],
            "message": f"[{item.get('level', 'warning')}] {item.get('message', '')}",
        })
    return out


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DustBowl Infrastructure Safety Gate")
    parser.add_argument("--repo-root", default=os.environ.get("GITHUB_WORKSPACE") or os.getcwd())
    parser.add_argument("--check-dockerfile", dest="check_dockerfile", action="store_true", default=True)
    parser.add_argument("--no-dockerfile", dest="check_dockerfile", action="store_false")
    parser.add_argument("--require-pinned-digest", action="store_true", default=False)
    parser.add_argument("--check-k8s-helm", action="store_true", default=False)
    parser.add_argument("--helm-chart-dir", default="")
    parser.add_argument("--baseline", default="")
    parser.add_argument("--hadolint-mode", choices=["off", "advisory", "blocking"], default="off")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = pathlib.Path(args.repo_root).resolve()
    if not repo_root.is_dir():
        print(f"[FAIL] Repository root does not exist: {repo_root}", file=sys.stderr)
        return 1

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

    findings: list[dict] = []
    dockerfiles: list[pathlib.Path] = []
    if args.check_dockerfile:
        dockerfiles = discover_dockerfiles(repo_root)
        for df in dockerfiles:
            rel = normalize_path(str(df.relative_to(repo_root)))
            content = df.read_text(encoding="utf-8", errors="replace")
            findings.extend(
                check_dockerfile_content(
                    content,
                    rel,
                    require_pinned_digest=args.require_pinned_digest,
                )
            )
        hadolint_findings = run_hadolint(dockerfiles, repo_root, args.hadolint_mode)
        if args.hadolint_mode == "advisory":
            for hf in hadolint_findings:
                print(f"::warning file={hf['file']},line={hf['line']}::{hf['ruleId']}: {hf['message']}")
        elif args.hadolint_mode == "blocking":
            findings.extend(hadolint_findings)

    k8s_files: list[pathlib.Path] = []
    if args.check_k8s_helm:
        k8s_files = discover_k8s_helm_files(repo_root, args.helm_chart_dir)
        for kf in k8s_files:
            rel = normalize_path(str(kf.relative_to(repo_root)))
            content = kf.read_text(encoding="utf-8", errors="replace")
            findings.extend(check_k8s_helm_content(content, rel))

    baselined, unapproved = apply_baseline(findings, baseline_entries)
    print(
        f"[SUMMARY] Infra scan ({len(dockerfiles)} Dockerfile(s), {len(k8s_files)} K8s/Helm file(s)): "
        f"baselined={len(baselined)} | unapproved={len(unapproved)}"
    )

    if unapproved:
        for v in unapproved:
            print(
                f"::error file={v['file']},line={v['line']}::[{v['ruleId']}] {v['message']}",
                file=sys.stderr,
            )
        return 1

    print("[PASS] Infrastructure safety checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
