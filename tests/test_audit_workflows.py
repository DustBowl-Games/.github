import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / ".github" / "scripts" / "audit-workflows.py"

SPEC = importlib.util.spec_from_file_location("audit_workflows", SCRIPT_PATH)
assert SPEC and SPEC.loader
audit_workflows = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_workflows)

PINNED_CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
PINNED_SETUP_NODE = "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"


def make_clean_pr_workflow():
    return {
        True: {"pull_request": {"branches": ["main"]}, "push": {"branches": ["main"]}},
        "permissions": {"contents": "read"},
        "jobs": {
            "build": {
                "runs-on": (
                    "${{ (github.event_name == 'pull_request' && "
                    "github.event.pull_request.head.repo.full_name != github.repository) "
                    "&& 'ubuntu-latest' || fromJSON('[\"self-hosted\",\"Linux\",\"X64\"]') }}"
                ),
                "timeout-minutes": 10,
                "steps": [
                    {"uses": PINNED_CHECKOUT, "with": {"persist-credentials": False}},
                    {"uses": PINNED_SETUP_NODE, "with": {"node-version": "22"}},
                    {"env": {"TITLE": "${{ github.event.pull_request.title }}"}, "run": 'echo "$TITLE"'},
                ],
            },
            "shared": {
                "uses": "DustBowl-Games/.github/.github/workflows/_security-gate.yml@main",
                "permissions": {"contents": "read"},
            },
            "push_only": {
                "if": "github.event_name == 'push'",
                "runs-on": ["self-hosted", "Linux", "X64"],
                "timeout-minutes": 10,
                "steps": [{"uses": "./.github/actions/local"}],
            },
        },
    }


class AuditWorkflowsTests(unittest.TestCase):
    def test_clean_pr_workflow_with_fork_routing_and_org_reusable_passes(self):
        findings = audit_workflows.audit_workflow_doc(make_clean_pr_workflow(), ".github/workflows/ci.yml")
        self.assertEqual(findings, [])

    def test_blocks_unpinned_uses_missing_permissions_timeout_and_persist_credentials(self):
        bad = {
            True: {"push": {"branches": ["main"]}},
            "jobs": {
                "bad_job": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"uses": "actions/checkout@v4"},
                    ],
                }
            },
        }
        findings = audit_workflows.audit_workflow_doc(bad, ".github/workflows/bad.yml")
        rules = {f["ruleId"] for f in findings}
        self.assertIn("WF_SHA_PINNED_USES", rules)
        self.assertIn("WF_EXPLICIT_PERMISSIONS", rules)
        self.assertIn("WF_PERSIST_CREDENTIALS_FALSE", rules)
        self.assertIn("WF_TIMEOUT_MINUTES", rules)

    def test_blocks_fork_pr_self_hosted_and_script_injection_and_pr_target_checkout(self):
        bad = {
            True: {"pull_request_target": {}},
            "permissions": {"contents": "read"},
            "jobs": {
                "unsafe": {
                    "runs-on": ["self-hosted", "Linux"],
                    "timeout-minutes": 10,
                    "steps": [
                        {
                            "uses": PINNED_CHECKOUT,
                            "with": {
                                "persist-credentials": False,
                                "ref": "${{ github.event.pull_request.head.sha }}",
                            },
                        },
                        {"run": "echo ${{ github.event.pull_request.title }}"},
                        {"run": "echo ${{ github.head_ref }}"},
                    ],
                }
            },
        }
        findings = audit_workflows.audit_workflow_doc(bad, ".github/workflows/unsafe.yml")
        rules = {f["ruleId"] for f in findings}
        self.assertIn("WF_FORK_PR_RUNNER_ISOLATION", rules)
        self.assertIn("WF_NO_PULL_REQUEST_TARGET_HEAD_CHECKOUT", rules)
        self.assertIn("WF_NO_SCRIPT_INJECTION", rules)

    def test_blocks_paid_actions(self):
        for action in (
            "gitleaks/gitleaks-action@0000000000000000000000000000000000000000",
            "github/codeql-action/analyze@0000000000000000000000000000000000000000",
            "actions/dependency-review-action@0000000000000000000000000000000000000000",
            "sonarsource/sonarcloud-github-action@0000000000000000000000000000000000000000",
            "snyk/actions@0000000000000000000000000000000000000000",
        ):
            with self.subTest(action=action):
                doc = {
                    True: {"push": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "runs-on": "ubuntu-latest",
                            "timeout-minutes": 5,
                            "steps": [{"uses": action}],
                        }
                    },
                }
                findings = audit_workflows.audit_workflow_doc(doc, ".github/workflows/paid.yml")
                self.assertEqual([f["ruleId"] for f in findings], ["WF_NO_PAID_ACTIONS"])

    def test_baseline_suppression_is_count_bounded(self):
        bad = {
            True: {"push": {}},
            "permissions": {"contents": "read"},
            "jobs": {
                "j": {
                    "runs-on": "ubuntu-latest",
                    "timeout-minutes": 5,
                    "steps": [{"uses": "actions/checkout@v4", "with": {"persist-credentials": False}}],
                }
            },
        }
        findings = audit_workflows.audit_workflow_doc(bad, ".github/workflows/legacy.yml")
        baseline = [{"file": ".github/workflows/legacy.yml", "ruleId": "WF_SHA_PINNED_USES", "count": 1}]
        baselined, unapproved = audit_workflows.apply_baseline(findings, baseline)
        self.assertEqual(len(baselined), 1)
        self.assertEqual(unapproved, [])

    def test_actionlint_subprocess_error_is_surfaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            wf = root / ".github" / "workflows" / "ci.yml"
            wf.parent.mkdir(parents=True)
            wf.write_text("name: test\n", encoding="utf-8")

            fake_proc = mock.Mock(
                returncode=1,
                stdout=f"{wf}:3:1: syntax error in expression\n",
                stderr="",
            )
            with mock.patch.object(audit_workflows.subprocess, "run", return_value=fake_proc):
                findings = audit_workflows.run_actionlint([wf], root, actionlint_bin="/fake/actionlint")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["ruleId"], "WF_ACTIONLINT")
            self.assertIn("syntax error", findings[0]["message"])

    def test_missing_actionlint_without_skip_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            wf_dir = root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "ci.yml").write_text(
                "on: [push]\npermissions:\n  contents: read\njobs:\n  j:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - run: echo ok\n",
                encoding="utf-8",
            )
            with mock.patch.object(audit_workflows.shutil, "which", return_value=None):
                rc = audit_workflows.main(["--repo-root", str(root)])
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
