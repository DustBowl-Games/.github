import copy
import importlib.util
import pathlib
import re
import unittest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
AUDIT_WORKFLOWS_PATH = ROOT / ".github" / "scripts" / "audit-workflows.py"

SPEC = importlib.util.spec_from_file_location("audit_workflows", AUDIT_WORKFLOWS_PATH)
assert SPEC and SPEC.loader
audit_workflows = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_workflows)

PAID_ACTIONS = (
    "gitleaks/gitleaks-action",
    "github/codeql-action",
    "actions/dependency-review-action",
    "sonarsource/",
    "snyk/",
)
SHA_USES_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
PINNED_SETUP_NODE = "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"


def load_yaml(path: pathlib.Path):
    with open(path, encoding="utf-8") as fp:
        return yaml.safe_load(fp)


def get_triggers(doc):
    return doc.get(True, doc.get("on", {}))


def _find_semgrep_step_issues(step: dict) -> list[str]:
    issues: list[str] = []
    env = step.get("env") or {}
    for bad_key in (
        "SEMGREP_BASELINE_COMMIT",
        "SEMGREP_BASELINE_REF",
        "SEMGREP_CONFIG",
        "SEMGREP_BLOCKING",
    ):
        if bad_key in env:
            issues.append(f"colliding semgrep envvar {bad_key} exported")

    expected_env = {
        "GATE_SEMGREP_CONFIG": "${{ inputs.semgrep_config }}",
        "GATE_SEMGREP_BLOCKING": "${{ inputs.semgrep_blocking }}",
        "GATE_SEMGREP_BASELINE_COMMIT": "${{ inputs.semgrep_baseline_commit }}",
    }
    for key, expected_val in expected_env.items():
        if env.get(key) != expected_val:
            issues.append(f"missing or mismatched envvar {key}")

    run_script = step.get("run") or ""
    if re.search(r"\$\{?SEMGREP_(?:CONFIG|BLOCKING|BASELINE_COMMIT|BASELINE_REF)\b", run_script):
        issues.append("run script reads colliding SEMGREP_* envvar")

    for gate_var in (
        "GATE_SEMGREP_CONFIG",
        "GATE_SEMGREP_BLOCKING",
        "GATE_SEMGREP_BASELINE_COMMIT",
    ):
        if not re.search(rf"\$\{{?{gate_var}\b", run_script):
            issues.append(f"run script does not reference {gate_var}")

    if re.search(r"scan_args=\([^\n]*(?:--quiet\b|(?<!\S)-q(?!\S))", run_script):
        issues.append("scan_args must not pass --quiet or -q to semgrep")

    unset_commit_line = None
    unset_ref_line = None
    semgrep_invocations: list[tuple[int, str]] = []
    for idx, raw_line in enumerate(run_script.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^unset\b", stripped):
            tokens = stripped.split()[1:]
            if "SEMGREP_BASELINE_COMMIT" in tokens:
                unset_commit_line = idx
            if "SEMGREP_BASELINE_REF" in tokens:
                unset_ref_line = idx
            continue
        if "semgrep-venv/bin/pip" in stripped or "merge-semgrep-rules.py" in stripped:
            continue
        if re.search(r'(?:^|["/\s])semgrep(?:\s|$|")', stripped):
            semgrep_invocations.append((idx, stripped))
            if re.search(r"(?:^|\s)(?:--quiet|-q)(?:\s|$)", stripped):
                issues.append(f"semgrep invocation on line {idx} passes --quiet/-q")

    if unset_commit_line is None or unset_ref_line is None:
        issues.append("missing unset SEMGREP_BASELINE_COMMIT SEMGREP_BASELINE_REF before semgrep")
    elif not semgrep_invocations:
        issues.append("missing semgrep CLI invocation")
    else:
        first_semgrep_line = semgrep_invocations[0][0]
        if unset_commit_line > first_semgrep_line or unset_ref_line > first_semgrep_line:
            issues.append("unset of SEMGREP_BASELINE_* must precede semgrep invocation")

    return issues


def _split_doc_sections(doc_text: str) -> list[tuple[str, str]]:
    sections: list[tuple[str, str]] = []
    current_heading = ""
    current_lines: list[str] = []
    for line in doc_text.splitlines():
        if line.startswith("## "):
            if current_heading:
                sections.append((current_heading, "\n".join(current_lines)))
            current_heading = line
            current_lines = [line]
        elif current_heading:
            current_lines.append(line)
    if current_heading:
        sections.append((current_heading, "\n".join(current_lines)))
    return sections


def _find_doc_parity_issues(
    workflows_dir: pathlib.Path,
    doc_text: str,
    extra_workflows: dict[str, dict] | None = None,
) -> list[str]:
    issues: list[str] = []
    sections = _split_doc_sections(doc_text)
    docs_by_name: dict[str, dict] = {
        wf.name: load_yaml(wf) for wf in sorted(workflows_dir.glob("_*.yml"))
    }
    if extra_workflows:
        docs_by_name.update(extra_workflows)

    for wf_name, doc in sorted(docs_by_name.items()):
        matching = [
            body
            for heading, body in sections
            if re.search(rf"\(`?{re.escape(wf_name)}`?\)", heading)
        ]
        if not matching:
            issues.append(f"{wf_name}: missing section in docs/reusable-workflows.md")
            continue
        section_body = "\n".join(matching)
        wf_call = get_triggers(doc).get("workflow_call", {}) or {}
        for group_name in ("inputs", "outputs", "secrets"):
            entries = wf_call.get(group_name) or {}
            for key in entries:
                if not re.search(rf"`{re.escape(key)}`", section_body):
                    issues.append(
                        f"{wf_name}: undocumented workflow_call {group_name[:-1]} '{key}'"
                    )
    return issues


class WorkflowContractTests(unittest.TestCase):
    def test_all_workflows_valid_yaml_and_zero_paid_actions(self):
        wf_files = sorted(WORKFLOWS.glob("*.yml"))
        self.assertGreater(len(wf_files), 0)
        for wf in wf_files:
            with self.subTest(workflow=wf.name):
                doc = load_yaml(wf)
                self.assertIn("jobs", doc)
                raw = wf.read_text(encoding="utf-8")
                for paid in PAID_ACTIONS:
                    self.assertNotIn(paid, raw, f"{wf.name} references paid action {paid}")

    def test_reusable_workflows_accept_runner_labels_and_timeouts(self):
        for wf in sorted(WORKFLOWS.glob("_*.yml")):
            with self.subTest(workflow=wf.name):
                doc = load_yaml(wf)
                triggers = get_triggers(doc)
                self.assertIn("workflow_call", triggers)
                inputs = triggers["workflow_call"].get("inputs", {})
                self.assertIn("runner_labels", inputs)
                for job_id, job in doc["jobs"].items():
                    self.assertEqual(job["runs-on"], "${{ fromJSON(inputs.runner_labels) }}")
                    self.assertIn("timeout-minutes", job, f"{wf.name}:{job_id} missing timeout-minutes")

    def test_all_external_uses_are_sha_pinned_and_setup_node_pinned_to_v4_4_0(self):
        for wf in sorted(WORKFLOWS.glob("*.yml")):
            doc = load_yaml(wf)
            for job_id, job in doc["jobs"].items():
                for idx, step in enumerate(job.get("steps", [])):
                    uses = step.get("uses")
                    if not uses or uses.startswith("./"):
                        continue
                    with self.subTest(workflow=wf.name, job=job_id, step=idx, uses=uses):
                        self.assertRegex(uses, SHA_USES_RE, f"{wf.name} has unpinned action {uses}")
                        if uses.startswith("actions/setup-node@"):
                            self.assertEqual(uses, PINNED_SETUP_NODE)

    def test_all_workflows_pass_audit_workflows_hygiene_checks(self):
        findings = audit_workflows.audit_workflows_dir(ROOT, WORKFLOWS, skip_actionlint=True)
        self.assertEqual(findings, [])

    @staticmethod
    def _make_container_workflow(*, wf_defaults=None, job_defaults=None, steps=None):
        job = {
            "runs-on": "ubuntu-latest",
            "container": {"image": "mcr.microsoft.com/dotnet/sdk:10.0"},
            "timeout-minutes": 10,
            "steps": steps if steps is not None else [],
        }
        if job_defaults is not None:
            job["defaults"] = job_defaults
        doc = {
            True: {"push": {"branches": ["main"]}},
            "permissions": {"contents": "read"},
            "jobs": {"build": job},
        }
        if wf_defaults is not None:
            doc["defaults"] = wf_defaults
        return doc

    def test_repo_container_jobs_declare_bash_defaults_or_step_shell(self):
        container_jobs = []
        for wf in sorted(WORKFLOWS.glob("*.yml")):
            doc = load_yaml(wf)
            wf_shell = doc.get("defaults", {}).get("run", {}).get("shell", "")
            for job_id, job in doc["jobs"].items():
                if not job.get("container"):
                    continue
                container_jobs.append((wf.name, job_id))
                job_shell = job.get("defaults", {}).get("run", {}).get("shell", "")
                effective_default = (job_shell or wf_shell or "").strip().lower()
                with self.subTest(workflow=wf.name, job=job_id):
                    if effective_default != "bash":
                        for idx, step in enumerate(job.get("steps", [])):
                            if "run" in step:
                                self.assertEqual(
                                    (step.get("shell") or "").strip().lower(),
                                    "bash",
                                    f"{wf.name}:{job_id} step {idx} must declare bash shell",
                                )
        self.assertGreater(len(container_jobs), 0)

    def test_container_job_with_bash_defaults_or_step_shell_passes(self):
        bash_script = (
            "set -euo pipefail\n"
            "arr=(a b)\n"
            "arr+=(c)\n"
            'if [[ -n "${arr[0]}" ]]; then\n'
            '  lower="${MY_VAR,,}"\n'
            '  echo "$lower ${#arr[@]}"\n'
            "fi\n"
        )
        cases = [
            (
                "job_defaults_bash",
                self._make_container_workflow(
                    job_defaults={"run": {"shell": "bash"}},
                    steps=[{"run": bash_script}],
                ),
            ),
            (
                "workflow_defaults_bash",
                self._make_container_workflow(
                    wf_defaults={"run": {"shell": "bash"}},
                    steps=[{"run": bash_script}],
                ),
            ),
            (
                "step_shell_bash",
                self._make_container_workflow(
                    steps=[{"shell": "bash", "run": bash_script}],
                ),
            ),
            (
                "step_shell_bash_flags",
                self._make_container_workflow(
                    steps=[{"shell": "bash -e {0}", "run": bash_script}],
                ),
            ),
            (
                "posix_sh_and_comments_only",
                self._make_container_workflow(
                    steps=[
                        {
                            "run": (
                                "# set -o pipefail\n"
                                "echo ok # [[ -n \"$HOME\" ]]\n"
                                'if [ -n "${HOME:-}" ]; then\n'
                                '  echo "ready"\n'
                                "fi\n"
                            )
                        }
                    ],
                ),
            ),
            (
                "non_sh_shell_pwsh",
                self._make_container_workflow(
                    steps=[{"shell": "pwsh", "run": "Write-Output 'ok'"}],
                ),
            ),
        ]
        for label, doc in cases:
            with self.subTest(case=label):
                findings = audit_workflows.audit_workflow_doc(doc, ".github/workflows/container.yml")
                self.assertEqual(findings, [])

    def test_container_job_with_bashisms_without_bash_shell_fails(self):
        bad_scripts = [
            ("set_o_pipefail", "set -o pipefail\necho hi"),
            ("set_euo_pipefail", "set -euo pipefail\necho hi"),
            ("set_e_o_pipefail", "set -e -o pipefail\necho hi"),
            ("bash_array_assign", "args=(a b)\necho ok"),
            ("bash_array_append", "args+=(c)\necho ok"),
            ("bash_array_length", 'echo "${#arr[@]}"'),
            ("bash_array_index", 'echo "${arr[0]}"'),
            ("double_bracket_test", 'if [[ -n "${HOME:-}" ]]; then echo ok; fi'),
            ("case_expansion_lower", 'val="${INPUT_VAL,,}"'),
            ("case_expansion_upper", 'val="${INPUT_VAL^^}"'),
            ("source_builtin", "source ./env.sh"),
            ("here_string", 'cat <<< "hello"'),
            ("process_substitution", "diff <(echo a) <(echo b)"),
            ("shopt_builtin", "shopt -s nullglob"),
            ("declare_builtin", "declare -a items"),
            ("function_keyword", "function helper {\n  echo ok\n}"),
            ("ampersand_redirect", "echo ok &> /dev/null"),
        ]
        for label, script in bad_scripts:
            with self.subTest(case=label):
                doc = self._make_container_workflow(steps=[{"run": script}])
                findings = audit_workflows.audit_workflow_doc(doc, ".github/workflows/bad-container.yml")
                self.assertEqual([f["ruleId"] for f in findings], ["WF_CONTAINER_BASH_SHELL"])

        for bad_shell in ("sh", "/bin/sh", "/usr/bin/sh", "dash"):
            with self.subTest(override_shell=bad_shell):
                doc = self._make_container_workflow(
                    job_defaults={"run": {"shell": "bash"}},
                    steps=[{"shell": bad_shell, "run": "set -o pipefail\necho fail"}],
                )
                findings = audit_workflows.audit_workflow_doc(doc, ".github/workflows/override-sh.yml")
                self.assertEqual([f["ruleId"] for f in findings], ["WF_CONTAINER_BASH_SHELL"])

    @staticmethod
    def _get_security_gate_semgrep_step():
        doc = load_yaml(WORKFLOWS / "_security-gate.yml")
        steps = doc["jobs"]["security-gate"]["steps"]
        for step in steps:
            if step.get("name") == "Run Semgrep OSS SAST":
                return doc, step
        raise AssertionError("Run Semgrep OSS SAST step not found")

    def test_security_gate_semgrep_step_is_env_safe_and_verbose(self):
        doc, step = self._get_security_gate_semgrep_step()
        inputs = get_triggers(doc)["workflow_call"]["inputs"]
        for preserved_input in (
            "run_semgrep",
            "semgrep_config",
            "semgrep_blocking",
            "semgrep_baseline_commit",
        ):
            self.assertIn(preserved_input, inputs)
        self.assertIn('pip" install --quiet semgrep pyyaml', step["run"])
        self.assertEqual(_find_semgrep_step_issues(step), [])

    def test_semgrep_step_contract_rejects_env_leaks_missing_unset_and_quiet(self):
        _, valid_step = self._get_security_gate_semgrep_step()

        leak_baseline_commit = copy.deepcopy(valid_step)
        leak_baseline_commit["env"]["SEMGREP_BASELINE_COMMIT"] = "${{ inputs.semgrep_baseline_commit }}"
        self.assertTrue(_find_semgrep_step_issues(leak_baseline_commit))

        leak_baseline_ref = copy.deepcopy(valid_step)
        leak_baseline_ref["env"]["SEMGREP_BASELINE_REF"] = "main"
        self.assertTrue(_find_semgrep_step_issues(leak_baseline_ref))

        leak_cfg_and_blocking = copy.deepcopy(valid_step)
        leak_cfg_and_blocking["env"].pop("GATE_SEMGREP_CONFIG", None)
        leak_cfg_and_blocking["env"].pop("GATE_SEMGREP_BLOCKING", None)
        leak_cfg_and_blocking["env"]["SEMGREP_CONFIG"] = "${{ inputs.semgrep_config }}"
        leak_cfg_and_blocking["env"]["SEMGREP_BLOCKING"] = "${{ inputs.semgrep_blocking }}"
        leak_cfg_and_blocking["run"] = (
            leak_cfg_and_blocking["run"]
            .replace("GATE_SEMGREP_CONFIG", "SEMGREP_CONFIG")
            .replace("GATE_SEMGREP_BLOCKING", "SEMGREP_BLOCKING")
        )
        self.assertTrue(_find_semgrep_step_issues(leak_cfg_and_blocking))

        missing_unset = copy.deepcopy(valid_step)
        missing_unset["run"] = missing_unset["run"].replace(
            "unset SEMGREP_BASELINE_COMMIT SEMGREP_BASELINE_REF\n", ""
        )
        self.assertTrue(_find_semgrep_step_issues(missing_unset))

        quiet_in_scan_args = copy.deepcopy(valid_step)
        quiet_in_scan_args["run"] = quiet_in_scan_args["run"].replace(
            'scan_args=(scan --metrics=off "${cfg_args[@]}" --exclude ".org-ci")',
            'scan_args=(scan --metrics=off "${cfg_args[@]}" --exclude ".org-ci" --quiet)',
        )
        self.assertTrue(_find_semgrep_step_issues(quiet_in_scan_args))

        quiet_on_semgrep_call = copy.deepcopy(valid_step)
        quiet_on_semgrep_call["run"] = quiet_on_semgrep_call["run"].replace(
            '"$RUNNER_TEMP/semgrep-venv/bin/semgrep" "${scan_args[@]}" .',
            '"$RUNNER_TEMP/semgrep-venv/bin/semgrep" "${scan_args[@]}" --quiet .',
        )
        self.assertTrue(_find_semgrep_step_issues(quiet_on_semgrep_call))

    def test_reusable_workflows_doc_covers_all_workflow_call_inputs(self):
        doc_text = (ROOT / "docs" / "reusable-workflows.md").read_text(encoding="utf-8")
        self.assertEqual(_find_doc_parity_issues(WORKFLOWS, doc_text), [])

    def test_reusable_workflows_doc_parity_rejects_undocumented_input(self):
        doc_text = (ROOT / "docs" / "reusable-workflows.md").read_text(encoding="utf-8")
        synthetic_wf = {
            True: {
                "workflow_call": {
                    "inputs": {
                        "runner_labels": {"type": "string", "required": False},
                        "undocumented_secret_knob": {"type": "boolean", "required": False},
                    }
                }
            }
        }
        issues = _find_doc_parity_issues(
            WORKFLOWS,
            doc_text,
            extra_workflows={"_release-notes.yml": synthetic_wf},
        )
        self.assertEqual(
            issues,
            ["_release-notes.yml: undocumented workflow_call input 'undocumented_secret_knob'"],
        )


if __name__ == "__main__":
    unittest.main()
