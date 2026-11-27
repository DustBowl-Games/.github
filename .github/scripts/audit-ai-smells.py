#!/usr/bin/env python3
"""
DustBowl Games - Diff-Scoped & Full-Repo Anti-AI-Slop & Cleanliness Gate

Checks added lines (default in PRs) or all files (--all) for:
- AI_NARRATION_CHATTER: Conversational assistant filler left in code/docs
- AI_WATERMARK: Assistant attribution/watermark text
- AI_BUZZWORD: Corporate/AI filler vocabulary
- UNGROUNDED_STUB: TODO/FIXME/HACK/XXX without issue link/ID, NotImplemented stubs, Lorem ipsum
- EMPTY_CATCH: Empty catch { } blocks in C#/JS/TS
- EMPTY_HELPER: Empty static helper classes in C#
- INLINE_STYLE: Static inline style="..." in Razor/HTML (preserves dynamic background-image:/@ width:)
- DISALLOWED_DASH: Em-dash (U+2014) and en-dash (U+2013) in code/config (and Markdown unless --allow-markdown-dashes)
- TRAILING_WHITESPACE: Trailing spaces or tabs
- EXCESSIVE_BLANK_LINES: >=3 consecutive blank lines in .py (PEP 8 safe), >=2 in other text files
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
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
}

TEXT_EXTENSIONS = {
    ".cs", ".razor", ".html", ".cshtml", ".css", ".scss",
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".py", ".ps1", ".psm1", ".sh", ".bash",
    ".yml", ".yaml", ".json", ".jsonc", ".toml", ".xml", ".props", ".targets", ".csproj", ".sln",
    ".md", ".mdx", ".txt", ".sql", ".Dockerfile",
}

DASH_EXTENSIONS = {
    ".cs", ".razor", ".html", ".cshtml", ".css", ".scss",
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".py", ".ps1", ".psm1", ".sh", ".bash",
    ".yml", ".yaml", ".json", ".jsonc", ".toml", ".xml", ".props", ".targets", ".csproj",
}

MARKDOWN_EXTENSIONS = {".md", ".mdx"}
CATCH_EXTENSIONS = {".cs", ".js", ".mjs", ".ts", ".tsx", ".jsx"}
STYLE_EXTENSIONS = {".razor", ".html", ".cshtml"}

TEST_OR_RULE_EXEMPT_RE = re.compile(
    r"(?:^|/)(?:tests/(?:ci/)?.*\.(?:test\.(?:mjs|js|ts)|py)|scripts/test_[^/]+\.py|"
    r".*Tests\.cs|\.github/scripts/(?:audit-|verify-)[^/]+\.(?:py|mjs)|"
    r"\.semgrep/antislop-rules\.yml)$",
    re.IGNORECASE,
)

BASELINE_OR_ALLOWLIST_RE = re.compile(
    r"^(?:config/.*(?:baseline|allowlist).*\.json|\.github/.*baseline.*\.json)$",
    re.IGNORECASE,
)

AI_NARRATION_RE = re.compile(
    r"(?:here\s+is\s+the\s+updated|here's\s+the\s+updated|as\s+requested|"
    r"hope\s+this\s+helps|let\s+me\s+know\s+if\s+you|i\s+have\s+updated|"
    r"(?://|#)\s*\.\.\.\s*(?:rest\s+of\s+)?existing\s+code)",
    re.IGNORECASE,
)

AI_WATERMARK_RE = re.compile(
    r"(?:generated\s+by\s+(?:ai|claude|chatgpt|copilot|gemini|cursor)|"
    r"co-authored-by:\s*(?:assistant|claude|chatgpt|copilot|gemini)|"
    r"\bai-generated\b|\bas\s+an\s+ai\b)",
    re.IGNORECASE,
)

AI_BUZZWORD_RE = re.compile(
    r"\b(?:delve|seamless(?:ly)?|tapestry|testament|robust(?:ly)?|leverage|"
    r"cutting-edge|revolutionary|elevate|game-changer|plethora|multifaceted|"
    r"holistic|synergy|paradigm|groundbreaking|harness\s+the\s+power|embark\s+on)\b",
    re.IGNORECASE,
)

UNGROUNDED_MARKER_RE = re.compile(r"\b(?:TODO|FIXME|HACK|XXX)\b")
GROUNDED_REF_RE = re.compile(r"(?:#\d+|GH-\d+|https?://)", re.IGNORECASE)
UNGROUNDED_PHRASE_RE = re.compile(
    r"(?:throw\s+new\s+NotImplementedException|raise\s+NotImplementedError|"
    r"\bLorem\s+ipsum\b|\bplaceholder\s+text\b|\bcoming\s+soon\b|\bsample\s+text\b)",
    re.IGNORECASE,
)

EMPTY_CATCH_RE = re.compile(r"\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}", re.MULTILINE)
EMPTY_HELPER_RE = re.compile(
    r"\b(?:public|internal|private|protected)?\s*static\s+class\s+[A-Za-z_][A-Za-z0-9_]*\s*\{\s*\}",
    re.MULTILINE,
)

INLINE_STYLE_ATTR_RE = re.compile(r"""\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE)
DISALLOWED_DASH_RE = re.compile("[\u2013\u2014]")


def normalize_path(rel_path: str) -> str:
    norm = rel_path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    return norm


def normalize_fingerprint(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()[:160]


def is_ignored_rel(rel_path: str) -> bool:
    parts = normalize_path(rel_path).split("/")
    return any(part in IGNORED_DIRS for part in parts[:-1])


def is_exempt_baseline_path(rel_path: str, extra_exempt_rels: set[str] | None = None) -> bool:
    norm = normalize_path(rel_path)
    if BASELINE_OR_ALLOWLIST_RE.search(norm):
        return True
    if extra_exempt_rels and norm in extra_exempt_rels:
        return True
    return False


def is_text_path(rel_path: str) -> bool:
    name = pathlib.PurePosixPath(normalize_path(rel_path)).name
    if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        return True
    if name in {".trivyignore", ".gitleaksignore", ".semgrepignore", ".gitignore", ".editorconfig"}:
        return True
    suffix = pathlib.PurePosixPath(name).suffix.lower()
    return suffix in TEXT_EXTENSIONS


def is_dash_target(rel_path: str, allow_markdown_dashes: bool) -> bool:
    suffix = pathlib.PurePosixPath(normalize_path(rel_path)).suffix.lower()
    if suffix in DASH_EXTENSIONS:
        return True
    if not allow_markdown_dashes and suffix in MARKDOWN_EXTENSIONS:
        return True
    return False


def is_allowed_inline_style(style_val: str) -> bool:
    lower = style_val.lower()
    if "background-image:" in lower:
        return True
    if "@" in style_val and "width:" in lower:
        return True
    return False


def _strip_markup_comments(text: str) -> str:
    cleaned = re.sub(r"@\*[\s\S]*?\*@", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
    cleaned = re.sub(r"<!--[\s\S]*?-->", lambda m: re.sub(r"[^\n]", " ", m.group(0)), cleaned)
    return cleaned


def audit_lines_block(
    lines: list[tuple[int, str]],
    rel_path: str,
    *,
    allow_markdown_dashes: bool = False,
    exempt_paths: set[str] | None = None,
) -> list[dict]:
    norm_file = normalize_path(rel_path)
    if not is_text_path(norm_file) or is_exempt_baseline_path(norm_file, exempt_paths):
        return []

    findings: list[dict] = []
    suffix = pathlib.PurePosixPath(norm_file).suffix.lower()
    exempt_content = bool(TEST_OR_RULE_EXEMPT_RE.search(norm_file))
    check_dash = is_dash_target(norm_file, allow_markdown_dashes)

    # Line-by-line checks
    blank_run = 0
    blank_start = 0
    blank_threshold = 3 if suffix == ".py" else 2

    for line_no, raw in lines:
        if raw.endswith((" ", "\t")):
            findings.append({
                "file": norm_file,
                "line": line_no,
                "ruleId": "TRAILING_WHITESPACE",
                "fingerprint": f"trailing-ws:line:{line_no}",
                "message": "Trailing whitespace detected.",
            })

        if raw.strip() == "":
            if blank_run == 0:
                blank_start = line_no
            blank_run += 1
        else:
            if blank_run >= blank_threshold:
                findings.append({
                    "file": norm_file,
                    "line": blank_start,
                    "ruleId": "EXCESSIVE_BLANK_LINES",
                    "fingerprint": f"blank-run:{blank_run}",
                    "message": f"Excessive consecutive blank lines ({blank_run}; max {blank_threshold - 1}).",
                })
            blank_run = 0

        if check_dash and DISALLOWED_DASH_RE.search(raw):
            findings.append({
                "file": norm_file,
                "line": line_no,
                "ruleId": "DISALLOWED_DASH",
                "fingerprint": normalize_fingerprint(raw),
                "message": "Disallowed em-dash or en-dash character detected.",
            })

        if not exempt_content:
            m_nar = AI_NARRATION_RE.search(raw)
            if m_nar:
                findings.append({
                    "file": norm_file,
                    "line": line_no,
                    "ruleId": "AI_NARRATION_CHATTER",
                    "fingerprint": normalize_fingerprint(raw),
                    "message": f'Conversational AI narration phrase "{m_nar.group(0)}" found.',
                })

            m_wm = AI_WATERMARK_RE.search(raw)
            if m_wm:
                findings.append({
                    "file": norm_file,
                    "line": line_no,
                    "ruleId": "AI_WATERMARK",
                    "fingerprint": normalize_fingerprint(raw),
                    "message": f'AI attribution/watermark "{m_wm.group(0)}" found.',
                })

            m_bz = AI_BUZZWORD_RE.search(raw)
            if m_bz:
                findings.append({
                    "file": norm_file,
                    "line": line_no,
                    "ruleId": "AI_BUZZWORD",
                    "fingerprint": normalize_fingerprint(raw),
                    "message": f'AI/corporate buzzword "{m_bz.group(0)}" found.',
                })

            if UNGROUNDED_MARKER_RE.search(raw) and not GROUNDED_REF_RE.search(raw):
                findings.append({
                    "file": norm_file,
                    "line": line_no,
                    "ruleId": "UNGROUNDED_STUB",
                    "fingerprint": normalize_fingerprint(raw),
                    "message": "TODO/FIXME/HACK/XXX marker must reference an issue (#123, GH-123, or URL).",
                })
            elif UNGROUNDED_PHRASE_RE.search(raw):
                findings.append({
                    "file": norm_file,
                    "line": line_no,
                    "ruleId": "UNGROUNDED_STUB",
                    "fingerprint": normalize_fingerprint(raw),
                    "message": "Stub or placeholder text detected.",
                })

    if blank_run >= blank_threshold:
        findings.append({
            "file": norm_file,
            "line": blank_start,
            "ruleId": "EXCESSIVE_BLANK_LINES",
            "fingerprint": f"blank-run:{blank_run}",
            "message": f"Excessive consecutive blank lines ({blank_run}; max {blank_threshold - 1}).",
        })

    # Multi-line structural checks over joined block
    joined = "\n".join(text for _, text in lines)
    first_line = lines[0][0] if lines else 1

    if suffix in CATCH_EXTENSIONS and not exempt_content:
        for m in EMPTY_CATCH_RE.finditer(joined):
            offset_lines = joined[:m.start()].count("\n")
            line_no = lines[offset_lines][0] if offset_lines < len(lines) else first_line
            findings.append({
                "file": norm_file,
                "line": line_no,
                "ruleId": "EMPTY_CATCH",
                "fingerprint": normalize_fingerprint(m.group(0)),
                "message": "Empty catch block swallows exceptions silently.",
            })

    if suffix == ".cs" and not exempt_content:
        for m in EMPTY_HELPER_RE.finditer(joined):
            offset_lines = joined[:m.start()].count("\n")
            line_no = lines[offset_lines][0] if offset_lines < len(lines) else first_line
            findings.append({
                "file": norm_file,
                "line": line_no,
                "ruleId": "EMPTY_HELPER",
                "fingerprint": normalize_fingerprint(m.group(0)),
                "message": "Empty static helper class detected.",
            })

    if suffix in STYLE_EXTENSIONS and not exempt_content:
        cleaned_markup = _strip_markup_comments(joined)
        for m in INLINE_STYLE_ATTR_RE.finditer(cleaned_markup):
            style_val = m.group(1) if m.group(1) is not None else (m.group(2) or "")
            if not is_allowed_inline_style(style_val):
                offset_lines = cleaned_markup[:m.start()].count("\n")
                line_no = lines[offset_lines][0] if offset_lines < len(lines) else first_line
                findings.append({
                    "file": norm_file,
                    "line": line_no,
                    "ruleId": "INLINE_STYLE",
                    "fingerprint": normalize_fingerprint(m.group(0)),
                    "message": "Static inline style= attribute found; move styling to CSS classes.",
                })

    return findings


def audit_content(
    content: str,
    rel_path: str,
    *,
    allow_markdown_dashes: bool = False,
    exempt_paths: set[str] | None = None,
) -> list[dict]:
    if "\x00" in content:
        return []
    raw_lines = content.splitlines()
    lines = [(idx + 1, raw) for idx, raw in enumerate(raw_lines)]
    return audit_lines_block(
        lines,
        rel_path,
        allow_markdown_dashes=allow_markdown_dashes,
        exempt_paths=exempt_paths,
    )


def audit_diff_text(
    diff_text: str,
    *,
    allow_markdown_dashes: bool = False,
    exempt_paths: set[str] | None = None,
) -> list[dict]:
    findings: list[dict] = []
    current_file: str | None = None
    current_line = 0
    hunk_lines: list[tuple[int, str]] = []

    def flush_hunk() -> None:
        nonlocal hunk_lines
        if current_file and hunk_lines and not is_ignored_rel(current_file):
            findings.extend(
                audit_lines_block(
                    hunk_lines,
                    current_file,
                    allow_markdown_dashes=allow_markdown_dashes,
                    exempt_paths=exempt_paths,
                )
            )
        hunk_lines = []

    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            flush_hunk()
            target = raw[4:].strip()
            current_file = None if target == "/dev/null" else normalize_path(target.removeprefix("b/"))
            continue
        if raw.startswith("--- "):
            flush_hunk()
            continue
        if raw.startswith("@@ "):
            flush_hunk()
            m = re.search(r"\+(\d+)", raw)
            current_line = int(m.group(1)) if m else 1
            continue
        if not current_file:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            hunk_lines.append((current_line, raw[1:]))
            current_line += 1
        elif raw.startswith(" "):
            flush_hunk()
            current_line += 1

    flush_hunk()
    return findings


def discover_repo_files(repo_root: pathlib.Path) -> list[pathlib.Path]:
    found: list[pathlib.Path] = []
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS)
        for fname in sorted(files):
            p = pathlib.Path(root) / fname
            rel = normalize_path(str(p.relative_to(repo_root)))
            if not is_ignored_rel(rel) and is_text_path(rel):
                found.append(p)
    return found


def resolve_git_diff(repo_root: pathlib.Path, base_arg: str, head_arg: str) -> str:
    base_sha = base_arg or os.environ.get("GITHUB_BASE_SHA", "")
    head_sha = head_arg or os.environ.get("GITHUB_HEAD_SHA", "")
    rev_range = ""
    if base_sha and head_sha:
        rev_range = f"{base_sha}...{head_sha}"
    else:
        base_ref = os.environ.get("GITHUB_BASE_REF", "main")
        for candidate in (f"origin/{base_ref}", base_ref):
            chk = subprocess.run(
                ["git", "rev-parse", "--verify", candidate],
                cwd=repo_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if chk.returncode == 0:
                rev_range = f"{candidate}...HEAD"
                break
        if not rev_range:
            chk_prev = subprocess.run(
                ["git", "rev-parse", "--verify", "HEAD~1"],
                cwd=repo_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if chk_prev.returncode == 0:
                rev_range = "HEAD~1..HEAD"
            else:
                return ""

    proc = subprocess.run(
        ["git", "diff", "-U0", rev_range],
        cwd=repo_root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git diff -U0 {rev_range} failed: {proc.stderr.strip()}")
    return proc.stdout


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
        for key in ("ai_smells_baseline", "entries", "legacyAuditBaseline", "baseline"):
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


def build_baseline_payload(findings: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str, str], dict] = {}
    for f in findings:
        key = (f["file"], f["ruleId"], f["fingerprint"])
        if key not in grouped:
            grouped[key] = {
                "file": f["file"],
                "ruleId": f["ruleId"],
                "fingerprint": f["fingerprint"],
                "status": "baselined-preexisting",
                "count": 0,
            }
        grouped[key]["count"] += 1
    out: list[dict] = []
    for entry in grouped.values():
        if entry["count"] == 1:
            entry = {k: v for k, v in entry.items() if k != "count"}
        out.append(entry)
    return out


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DustBowl Anti-AI-Slop & Cleanliness Gate")
    parser.add_argument("--repo-root", default=os.environ.get("GITHUB_WORKSPACE") or os.getcwd())
    parser.add_argument("--all", action="store_true", default=False)
    parser.add_argument("--baseline", default="")
    parser.add_argument("--print-baseline", action="store_true", default=False)
    parser.add_argument("--allow-markdown-dashes", action="store_true", default=False)
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = pathlib.Path(args.repo_root).resolve()
    if not repo_root.is_dir():
        print(f"[FAIL] Repository root does not exist: {repo_root}", file=sys.stderr)
        return 1

    extra_exempt_rels: set[str] = set()
    baseline_entries: list[dict] = []
    if args.baseline:
        bpath = pathlib.Path(args.baseline)
        if not bpath.is_absolute():
            bpath = (repo_root / bpath).resolve()
        else:
            bpath = bpath.resolve()
        try:
            extra_exempt_rels.add(normalize_path(str(bpath.relative_to(repo_root))))
        except ValueError:
            pass
        try:
            baseline_entries = load_baseline(bpath)
        except Exception as exc:
            print(f"[FAIL] Could not load baseline: {exc}", file=sys.stderr)
            return 1

    if args.all or args.print_baseline:
        findings: list[dict] = []
        for fpath in discover_repo_files(repo_root):
            rel = normalize_path(str(fpath.relative_to(repo_root)))
            content = fpath.read_text(encoding="utf-8", errors="replace")
            findings.extend(
                audit_content(
                    content,
                    rel,
                    allow_markdown_dashes=args.allow_markdown_dashes,
                    exempt_paths=extra_exempt_rels,
                )
            )
    else:
        try:
            diff_text = resolve_git_diff(repo_root, args.base, args.head)
        except Exception as exc:
            print(f"[FAIL] {exc}", file=sys.stderr)
            return 1
        findings = audit_diff_text(
            diff_text,
            allow_markdown_dashes=args.allow_markdown_dashes,
            exempt_paths=extra_exempt_rels,
        )

    if args.print_baseline:
        print(json.dumps({"ai_smells_baseline": build_baseline_payload(findings)}, indent=2, ensure_ascii=True))
        return 0

    baselined, unapproved = apply_baseline(findings, baseline_entries)
    mode = "full" if args.all else "diff"
    print(
        f"[SUMMARY] Anti-slop & cleanliness ({mode}): "
        f"baselined={len(baselined)} | unapproved={len(unapproved)}"
    )

    if unapproved:
        for v in unapproved:
            print(
                f"::error file={v['file']},line={v['line']}::[{v['ruleId']}] {v['message']}",
                file=sys.stderr,
            )
        return 1

    print("[PASS] No new AI slop, disallowed dashes, or cleanliness violations detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
