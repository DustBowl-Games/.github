import importlib.util
import pathlib
import tempfile
import unittest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / ".github" / "scripts" / "merge-semgrep-rules.py"
SECURITY_GATE_PATH = ROOT / ".github" / "workflows" / "_security-gate.yml"
ORG_RULES_PATH = ROOT / ".semgrep" / "antislop-rules.yml"

SPEC = importlib.util.spec_from_file_location("merge_semgrep_rules", SCRIPT_PATH)
assert SPEC and SPEC.loader
merge_semgrep_rules = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(merge_semgrep_rules)


class MergeSemgrepRulesTests(unittest.TestCase):
    def test_strips_overlapping_org_rules_and_preserves_unique_org_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            org = root / "org.yml"
            caller = root / "caller.yml"
            out = root / "out" / "merged.yml"

            org.write_text(
                yaml.safe_dump({
                    "rules": [
                        {"id": "rule-a", "languages": ["csharp"], "message": "org a", "severity": "ERROR", "pattern": "a()"},
                        {"id": "rule-b", "languages": ["csharp"], "message": "org b", "severity": "ERROR", "pattern": "b()"},
                        {"id": "rule-c", "languages": ["csharp"], "message": "org c", "severity": "WARNING", "pattern": "c()"},
                    ]
                }),
                encoding="utf-8",
            )
            caller.write_text(
                yaml.safe_dump({
                    "rules": [
                        {"id": "rule-b", "languages": ["csharp"], "message": "caller b", "severity": "WARNING", "pattern": "b2()"},
                        {"id": "caller-only", "languages": ["csharp"], "message": "caller only", "severity": "ERROR", "pattern": "x()"},
                    ]
                }),
                encoding="utf-8",
            )

            rc = merge_semgrep_rules.main([
                "--repo-root", str(root),
                "--org", "org.yml",
                "--caller", "caller.yml",
                "--out", "out/merged.yml",
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())
            merged = yaml.safe_load(out.read_text(encoding="utf-8"))
            self.assertEqual([r["id"] for r in merged["rules"]], ["rule-a", "rule-c"])

    def test_removes_out_file_and_exits_zero_when_all_org_rules_overridden(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            org = root / "org.yml"
            caller = root / "caller.yml"
            out = root / "merged.yml"
            out.write_text("stale: true\n", encoding="utf-8")

            org.write_text(
                yaml.safe_dump({"rules": [{"id": "rule-a", "message": "org", "severity": "ERROR", "languages": ["python"], "pattern": "x"}]}),
                encoding="utf-8",
            )
            caller.write_text(
                yaml.safe_dump({"rules": [{"id": "rule-a", "message": "caller", "severity": "WARNING", "languages": ["python"], "pattern": "y"}]}),
                encoding="utf-8",
            )

            rc = merge_semgrep_rules.main(["--org", str(org), "--caller", str(caller), "--out", str(out)])
            self.assertEqual(rc, 0)
            self.assertFalse(out.exists())

    def test_merges_real_org_antislop_rules_with_partial_caller_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            caller = root / "caller.yml"
            out = root / "merged-org.yml"

            org_doc = yaml.safe_load(ORG_RULES_PATH.read_text(encoding="utf-8"))
            org_ids = [r["id"] for r in org_doc["rules"]]
            self.assertGreaterEqual(len(org_ids), 2)

            caller.write_text(
                yaml.safe_dump({
                    "rules": [
                        {"id": org_ids[0], "languages": ["csharp"], "message": "override", "severity": "WARNING", "pattern": "foo()"},
                    ]
                }),
                encoding="utf-8",
            )

            rc = merge_semgrep_rules.main(["--org", str(ORG_RULES_PATH), "--caller", str(caller), "--out", str(out)])
            self.assertEqual(rc, 0)
            merged = yaml.safe_load(out.read_text(encoding="utf-8"))
            merged_ids = [r["id"] for r in merged["rules"]]
            self.assertNotIn(org_ids[0], merged_ids)
            self.assertEqual(merged_ids, org_ids[1:])

    def test_rejects_missing_or_invalid_yaml_or_bad_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            org = root / "org.yml"
            caller = root / "caller.yml"
            out = root / "merged.yml"

            # Missing caller file
            org.write_text("rules: []\n", encoding="utf-8")
            rc_missing = merge_semgrep_rules.main(["--org", str(org), "--caller", str(caller), "--out", str(out)])
            self.assertEqual(rc_missing, 1)

            # Invalid YAML syntax
            caller.write_text("rules:\n  - id: [unclosed\n", encoding="utf-8")
            rc_bad_yaml = merge_semgrep_rules.main(["--org", str(org), "--caller", str(caller), "--out", str(out)])
            self.assertEqual(rc_bad_yaml, 1)

            # Invalid schema (rules is a string instead of list)
            caller.write_text("rules: not-a-list\n", encoding="utf-8")
            rc_bad_schema = merge_semgrep_rules.main(["--org", str(org), "--caller", str(caller), "--out", str(out)])
            self.assertEqual(rc_bad_schema, 1)

    def test_security_gate_wires_merge_script_and_pyyaml(self):
        wf_text = SECURITY_GATE_PATH.read_text(encoding="utf-8")
        self.assertIn(".github/scripts/merge-semgrep-rules.py", wf_text)
        self.assertRegex(wf_text, r'pip"?\s+install\s+--quiet\s+semgrep\s+pyyaml')
        self.assertNotIn("python\" -c '", wf_text)


if __name__ == "__main__":
    unittest.main()
