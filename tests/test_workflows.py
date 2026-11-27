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


if __name__ == "__main__":
    unittest.main()
