#!/usr/bin/env python3
"""
DustBowl Games - Commit Message Hygiene & Anti-Slop Linter

Validates commit messages against:
- Conventional Commits format (feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)
- Subject line length <= 72 chars and no trailing period
- Zero AI buzzwords, AI watermarks, or em/en-dashes
- Safe bypass for Merge commits and Revert commits
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys

CC_RE = re.compile(
    r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)"
    r"(\([a-zA-Z0-9_\-./]+\))?(!)?: (.+)$"
)

BYPASS_PREFIXES = (
    "Merge branch ",
    "Merge remote-tracking branch ",
    "Merge pull request #",
    'Revert "',
)

FORBIDDEN_BUZZWORDS = re.compile(
    r"\b(?:delve|seamless(?:ly)?|tapestry|testament|robust(?:ly)?|leverage|"
    r"cutting-edge|revolutionary|elevate|game-changer|plethora|multifaceted|"
    r"holistic|synergy|paradigm|groundbreaking|harness\s+the\s+power|embark\s+on)\b",
    re.IGNORECASE,
)

FORBIDDEN_AI_WATERMARKS = re.compile(
    r"(?:generated\s+by\s+(?:ai|claude|chatgpt|copilot|gemini|cursor)|"
    r"co-authored-by:\s*(?:assistant|claude|chatgpt|copilot|gemini)|"
    r"\bai-generated\b|\bas\s+an\s+ai\b)",
    re.IGNORECASE,
)

DISALLOWED_DASH_RE = re.compile("[\u2013\u2014]")


def validate_commit_message(message: str, sha: str = "") -> list[str]:
    prefix = f"{sha[:8]}: " if sha else ""
    lines = [
        line.strip()
        for line in message.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not lines:
        return [f"{prefix}empty commit message"]

    subj = lines[0]
    if subj.startswith(BYPASS_PREFIXES):
        return []

    errors: list[str] = []
    if not CC_RE.match(subj):
        errors.append(f"{prefix}invalid Conventional Commit subject: {subj}")
    if len(subj) > 72:
        errors.append(f"{prefix}subject exceeds 72 chars ({len(subj)}): {subj}")
    if subj.endswith("."):
        errors.append(f"{prefix}subject must not end with a period: {subj}")

    full_body = "\n".join(lines)
    m_buzz = FORBIDDEN_BUZZWORDS.search(full_body)
    if m_buzz:
        errors.append(f'{prefix}forbidden buzzword "{m_buzz.group(0)}"')

    m_wm = FORBIDDEN_AI_WATERMARKS.search(full_body)
    if m_wm:
        errors.append(f'{prefix}forbidden AI watermark "{m_wm.group(0)}"')

    if DISALLOWED_DASH_RE.search(full_body):
        errors.append(f"{prefix}disallowed em-dash or en-dash in commit message")

    return errors


def read_commits_in_range(repo_root: pathlib.Path, rev_range: str) -> list[tuple[str, str]]:
    proc = subprocess.run(
        ["git", "log", rev_range, "--pretty=format:%H%x00%B%x00"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    chunks = proc.stdout.split("\x00")
    commits: list[tuple[str, str]] = []
    for i in range(0, len(chunks) - 1, 2):
        sha = chunks[i].strip()
        body = chunks[i + 1].strip()
        if sha:
            commits.append((sha, body))
    return commits


def read_last_commit(repo_root: pathlib.Path) -> list[tuple[str, str]]:
    sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).strip()
    body = subprocess.check_output(
        ["git", "log", "-1", "--pretty=format:%B"],
        cwd=repo_root,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).strip()
    return [(sha, body)]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify commit message hygiene")
    parser.add_argument("msg_file", nargs="?", help="Optional commit message file path")
    parser.add_argument("--repo-root", default=os.environ.get("GITHUB_WORKSPACE") or os.getcwd())
    parser.add_argument("--range", dest="rev_range", default="", help="Git revision range base..head")
    parser.add_argument("--last", action="store_true", help="Inspect HEAD commit")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = pathlib.Path(args.repo_root).resolve()

    if args.msg_file:
        msg_path = pathlib.Path(args.msg_file)
        if not msg_path.is_absolute():
            msg_path = (pathlib.Path.cwd() / msg_path).resolve()
        if not msg_path.is_file():
            print(f"[FAIL] Commit message file not found: {msg_path}", file=sys.stderr)
            return 1
        content = msg_path.read_text(encoding="utf-8", errors="replace")
        errs = validate_commit_message(content)
        commits_checked = 1
    else:
        if not repo_root.is_dir():
            print(f"[FAIL] Repository root does not exist: {repo_root}", file=sys.stderr)
            return 1
        try:
            if args.rev_range:
                commits = read_commits_in_range(repo_root, args.rev_range)
            else:
                commits = read_last_commit(repo_root)
        except subprocess.CalledProcessError as exc:
            print(f"[FAIL] git log failed: {exc}", file=sys.stderr)
            return 1

        errs = []
        for sha, body in commits:
            errs.extend(validate_commit_message(body, sha=sha))
        commits_checked = len(commits)

    if errs:
        print("[FAIL] Commit lint violations:", file=sys.stderr)
        for err in errs:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(f"[PASS] {commits_checked} commit(s) passed Conventional Commits & anti-slop check.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
