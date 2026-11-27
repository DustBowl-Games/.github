import importlib.util
import pathlib
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


if __name__ == "__main__":
    unittest.main()
