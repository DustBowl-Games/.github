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


if __name__ == "__main__":
    unittest.main()
