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
                "with": {
                    "runner_labels": (
                        "${{ (github.event_name == 'pull_request' && "
                        "github.event.pull_request.head.repo.full_name != github.repository) "
                        "&& '[\"ubuntu-latest\"]' || '[\"self-hosted\",\"Linux\",\"X64\"]' }}"
                    )
                },
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

    def test_blocks_refs_pull_checkout_under_pull_request_target(self):
        bad = {
            True: {"pull_request_target": {}},
            "permissions": {"contents": "read"},
            "jobs": {
                "unsafe": {
                    "runs-on": "ubuntu-latest",
                    "timeout-minutes": 10,
                    "steps": [
                        {
                            "uses": PINNED_CHECKOUT,
                            "with": {
                                "persist-credentials": False,
                                "ref": "refs/pull/${{ github.event.pull_request.number }}/merge",
                            },
                        },
                    ],
                }
            },
        }
        findings = audit_workflows.audit_workflow_doc(bad, ".github/workflows/pr-target.yml")
        self.assertEqual([f["ruleId"] for f in findings], ["WF_NO_PULL_REQUEST_TARGET_HEAD_CHECKOUT"])

    def test_baseline_count_zero_grants_zero_waivers_and_rejects_invalid_count(self):
        finding = {
            "file": ".github/workflows/ci.yml",
            "job": "j",
            "ruleId": "WF_SHA_PINNED_USES",
            "fingerprint": "actions/checkout@v4",
            "message": "unpinned",
        }
        baselined, unapproved = audit_workflows.apply_baseline([finding], [{**finding, "count": 0}])
        self.assertEqual(baselined, [])
        self.assertEqual(len(unapproved), 1)

        for bad_count in ("999", -1, 1.5, True):
            with self.subTest(bad_count=bad_count):
                with self.assertRaises(ValueError):
                    audit_workflows.apply_baseline([finding], [{**finding, "count": bad_count}])

    def test_blocks_fork_pr_isolation_bypasses_and_case_insensitive_self_hosted(self):
        base_step = [{"uses": PINNED_CHECKOUT, "with": {"persist-credentials": False}}]
        unsafe_docs = [
            (
                "or_pull_request_if",
                {
                    True: {"pull_request": {}, "push": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "if": "github.event_name == 'push' || github.event_name == 'pull_request'",
                            "runs-on": ["self-hosted", "Linux"],
                            "timeout-minutes": 5,
                            "steps": base_step,
                        }
                    },
                },
            ),
            (
                "always_or_push",
                {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "if": "always() || github.event_name == 'push'",
                            "runs-on": ["self-hosted", "Linux"],
                            "timeout-minutes": 5,
                            "steps": base_step,
                        }
                    },
                },
            ),
            (
                "inverted_ternary",
                {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "runs-on": "${{ (github.event.pull_request.head.repo.full_name != github.repository) && 'self-hosted' || 'ubuntu-latest' }}",
                            "timeout-minutes": 5,
                            "steps": base_step,
                        }
                    },
                },
            ),
            (
                "and_false",
                {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "runs-on": "${{ (github.event.pull_request.head.repo.fork && false) && 'ubuntu-latest' || 'self-hosted' }}",
                            "timeout-minutes": 5,
                            "steps": base_step,
                        }
                    },
                },
            ),
            (
                "negated_fork",
                {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "runs-on": "${{ !(github.event.pull_request.head.repo.fork) && 'ubuntu-latest' || 'self-hosted' }}",
                            "timeout-minutes": 5,
                            "steps": base_step,
                        }
                    },
                },
            ),
            (
                "negated_full_name",
                {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "runs-on": "${{ !(github.event.pull_request.head.repo.full_name != github.repository) && 'ubuntu-latest' || 'self-hosted' }}",
                            "timeout-minutes": 5,
                            "steps": base_step,
                        }
                    },
                },
            ),
            (
                "reusable_missing_runner_labels",
                {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "uses": "DustBowl-Games/.github/.github/workflows/_security-gate.yml@main",
                        }
                    },
                },
            ),
            (
                "case_insensitive_self_hosted",
                {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "runs-on": ["Self-Hosted", "Linux"],
                            "timeout-minutes": 5,
                            "steps": base_step,
                        }
                    },
                },
            ),
            (
                "fork_pred_after_or",
                {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "runs-on": "${{ (github.actor == 'x' && 'ubuntu-latest') || (github.event.pull_request.head.repo.fork && 'self-hosted') }}",
                            "timeout-minutes": 5,
                            "steps": base_step,
                        }
                    },
                },
            ),
            (
                "event_name_neq_pr_in_before_or",
                {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "runs-on": "${{ (github.event_name != 'pull_request' && github.event.pull_request.head.repo.fork) && 'ubuntu-latest' || 'self-hosted' }}",
                            "timeout-minutes": 5,
                            "steps": base_step,
                        }
                    },
                },
            ),
            (
                "same_repo_eq_in_before_or",
                {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "runs-on": "${{ (github.event.pull_request.head.repo.fork && github.event.pull_request.head.repo.full_name == github.repository) && 'ubuntu-latest' || 'self-hosted' }}",
                            "timeout-minutes": 5,
                            "steps": base_step,
                        }
                    },
                },
            ),
        ]
        for label, doc in unsafe_docs:
            with self.subTest(case=label):
                findings = audit_workflows.audit_workflow_doc(doc, ".github/workflows/bad.yml")
                self.assertIn("WF_FORK_PR_RUNNER_ISOLATION", [f["ruleId"] for f in findings], findings)

        non_pr_reusable = {
            True: {"pull_request": {}, "push": {}},
            "permissions": {"contents": "read"},
            "jobs": {
                "release": {
                    "if": "github.event_name == 'push'",
                    "uses": "DustBowl-Games/.github/.github/workflows/_release-notes.yml@main",
                }
            },
        }
        self.assertEqual(audit_workflows.audit_workflow_doc(non_pr_reusable, ".github/workflows/rel.yml"), [])

        safe_full_name_routing = {
            True: {"pull_request": {}},
            "permissions": {"contents": "read"},
            "jobs": {
                "j": {
                    "runs-on": "${{ !(github.event.pull_request.draft) && github.event.pull_request.head.repo.full_name != github.repository && 'ubuntu-latest' || 'self-hosted' }}",
                    "timeout-minutes": 5,
                    "steps": base_step,
                }
            },
        }
        self.assertEqual(audit_workflows.audit_workflow_doc(safe_full_name_routing, ".github/workflows/ok.yml"), [])

    def test_blocks_uppercase_format_and_bracket_script_injection(self):
        for expr in (
            "${{ GITHUB.EVENT.PULL_REQUEST.TITLE }}",
            "${{ format('{0}', github.event.pull_request.title) }}",
            "${{ format('can''t {0}', github.event.pull_request.title) }}",
            "${{ format('can''t } {0}', github.event.pull_request.title) }}",
            "${{ github['event']['pull_request']['title'] }}",
        ):
            with self.subTest(expr=expr):
                doc = {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "runs-on": "ubuntu-latest",
                            "timeout-minutes": 5,
                            "steps": [{"run": f'echo "{expr}"'}],
                        }
                    },
                }
                findings = audit_workflows.audit_workflow_doc(doc, ".github/workflows/inj.yml")
                self.assertEqual([f["ruleId"] for f in findings], ["WF_NO_SCRIPT_INJECTION"])

        for safe_expr in (
            "${{ format('{0}', github.repository) }}",
            "${{ format('can''t {0}', github.repository) }}",
            "${{ github.event_name }}",
            "${{ github['event_name'] }}",
        ):
            with self.subTest(safe_expr=safe_expr):
                safe_doc = {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "runs-on": "ubuntu-latest",
                            "timeout-minutes": 5,
                            "steps": [{"run": f'echo "{safe_expr}"'}],
                        }
                    },
                }
                self.assertEqual(audit_workflows.audit_workflow_doc(safe_doc, ".github/workflows/safe.yml"), [])

    def test_blocks_bracket_head_ref_event_subscript_and_tojson_script_injection(self):
        for expr in (
            "${{ github.event['pull_request']['title'] }}",
            "${{ github['head_ref'] }}",
            "${{ toJSON(github.event) }}",
            "${{ github['event']['comment']['body'] }}",
        ):
            with self.subTest(expr=expr):
                doc = {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "runs-on": "ubuntu-latest",
                            "timeout-minutes": 5,
                            "steps": [{"run": f'echo "{expr}"'}],
                        }
                    },
                }
                findings = audit_workflows.audit_workflow_doc(doc, ".github/workflows/inj2.yml")
                self.assertEqual([f["ruleId"] for f in findings], ["WF_NO_SCRIPT_INJECTION"])

    def test_rejects_falsy_and_inverted_fork_comparisons_while_allowing_truthy_variants(self):
        base_step = [{"uses": PINNED_CHECKOUT, "with": {"persist-credentials": False}}]
        unsafe_runs_on = (
            "${{ github.event.pull_request.head.repo.fork == 0 && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ github.event.pull_request.head.repo.fork == 'false' && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ github.event.pull_request.head.repo.fork == null && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ github.event.pull_request.head.repo.fork != 1 && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ github.event.pull_request.head.repo.fork != 'true' && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ false == github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ 0 == github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ 'false' == github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ null == github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ true != github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ 1 != github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ 'true' != github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}",
        )
        for runs_on in unsafe_runs_on:
            with self.subTest(unsafe_runs_on=runs_on):
                doc = {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "runs-on": runs_on,
                            "timeout-minutes": 5,
                            "steps": base_step,
                        }
                    },
                }
                findings = audit_workflows.audit_workflow_doc(doc, ".github/workflows/fork-bad.yml")
                self.assertEqual([f["ruleId"] for f in findings], ["WF_FORK_PR_RUNNER_ISOLATION"])

        safe_runs_on = (
            "${{ github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ github.event.pull_request.head.repo.fork == true && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ true == github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ github.event.pull_request.head.repo.fork != false && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ false != github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}",
        )
        for runs_on in safe_runs_on:
            with self.subTest(safe_runs_on=runs_on):
                doc = {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "runs-on": runs_on,
                            "timeout-minutes": 5,
                            "steps": base_step,
                        }
                    },
                }
                self.assertEqual(audit_workflows.audit_workflow_doc(doc, ".github/workflows/fork-ok.yml"), [])

    def test_blocks_r3_fork_isolation_bypasses_and_custom_runners_while_allowing_hosted_runners(self):
        base_step = [{"uses": PINNED_CHECKOUT, "with": {"persist-credentials": False}}]
        unsafe_runs_on_cases = (
            ("fork_eq_str_true", "${{ github.event.pull_request.head.repo.fork == 'true' && 'ubuntu-latest' || 'self-hosted' }}"),
            ("str_true_eq_fork", "${{ 'true' == github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}"),
            ("fork_eq_dbl_true", '${{ github.event.pull_request.head.repo.fork == "true" && \'ubuntu-latest\' || \'self-hosted\' }}'),
            ("nested_paren_neg_fork", "${{ !((1 == 1) && github.event.pull_request.head.repo.fork) && 'ubuntu-latest' || 'self-hosted' }}"),
            ("nested_paren_neg_full_name", "${{ !((1 == 1) && github.event.pull_request.head.repo.full_name != github.repository) && 'ubuntu-latest' || 'self-hosted' }}"),
            ("and_zero", "${{ (github.event.pull_request.head.repo.fork && 0) && 'ubuntu-latest' || 'self-hosted' }}"),
            ("zero_and", "${{ (0 && github.event.pull_request.head.repo.fork) && 'ubuntu-latest' || 'self-hosted' }}"),
            ("and_null", "${{ (github.event.pull_request.head.repo.fork && null) && 'ubuntu-latest' || 'self-hosted' }}"),
            ("and_empty_sq", "${{ (github.event.pull_request.head.repo.fork && '') && 'ubuntu-latest' || 'self-hosted' }}"),
            ("and_empty_dq", '${{ (github.event.pull_request.head.repo.fork && "") && \'ubuntu-latest\' || \'self-hosted\' }}'),
            ("fork_neq_fork", "${{ github.event.pull_request.head.repo.fork != github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}"),
            ("full_name_neq_self", "${{ github.event.pull_request.head.repo.full_name != github.event.pull_request.head.repo.full_name && 'ubuntu-latest' || 'self-hosted' }}"),
            ("custom_runner_str", "DB-Runner01"),
            ("custom_runner_list", ["DB-Runner01"]),
            ("dustbowl_linux", "dustbowl-linux"),
        )
        for label, runs_on in unsafe_runs_on_cases:
            for trig in ("pull_request", "pull_request_target"):
                with self.subTest(case=label, trigger=trig):
                    doc = {
                        True: {trig: {}},
                        "permissions": {"contents": "read"},
                        "jobs": {
                            "j": {
                                "runs-on": runs_on,
                                "timeout-minutes": 5,
                                "steps": base_step,
                            }
                        },
                    }
                    findings = audit_workflows.audit_workflow_doc(doc, ".github/workflows/r3-bad.yml")
                    self.assertEqual([f["ruleId"] for f in findings], ["WF_FORK_PR_RUNNER_ISOLATION"])

        safe_runs_on_cases = (
            "ubuntu-latest",
            "ubuntu-24.04",
            "ubuntu-22.04",
            "windows-latest",
            "windows-2022",
            "macos-latest",
            "macos-14",
            ["ubuntu-latest"],
            ["windows-latest"],
            ["macos-14"],
            "${{ !((github.event.pull_request.draft)) && github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}",
            "${{ github.event.pull_request.comments != 0 && github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}",
        )
        for runs_on in safe_runs_on_cases:
            with self.subTest(safe_runs_on=runs_on):
                self.assertTrue(audit_workflows.is_fork_isolated_runs_on(runs_on))
                doc = {
                    True: {"pull_request": {}},
                    "permissions": {"contents": "read"},
                    "jobs": {
                        "j": {
                            "runs-on": runs_on,
                            "timeout-minutes": 5,
                            "steps": base_step,
                        }
                    },
                }
                self.assertEqual(audit_workflows.audit_workflow_doc(doc, ".github/workflows/r3-ok.yml"), [])


if __name__ == "__main__":
    unittest.main()
