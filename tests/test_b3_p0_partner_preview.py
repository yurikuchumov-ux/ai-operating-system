"""Deterministic contract tests for the Issue #68 Partner Preview.

The Preview is deliberately non-authoritative.  These tests validate only its
static no-publication workflow contract and hostile-data packaging behavior;
they do not treat provider output or an Actions conclusion as trusted evidence.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from tools import p0_partner_preview as preview


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/p0-partner-preview.yml"
RUNBOOK_PATH = REPO_ROOT / "docs/p0-partner-preview-runbook.md"
SCHEMA_PATH = REPO_ROOT / "contracts/schemas/task.v1.schema.json"
CLAUDE_PIN = "anthropics/claude-code-action@6902c227aaa9536481b99d56f3014bbbad6c6da8"
CHECKOUT_PIN = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
UPLOAD_PIN = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
DOWNLOAD_PIN = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"


def _task(allowed_paths=None, context_paths=None):
    allowed_paths = allowed_paths or ["src/delete.txt", "src/edit.txt", "src/new.txt"]
    parameters = {"component": "preview-test", "value": 0}
    if context_paths:
        parameters["preview_context_paths"] = context_paths
    return {
        "schema_version": "1.0.0",
        "task_id": "yurikuchumov-ux/ai-operating-system#68",
        "repository": "yurikuchumov-ux/ai-operating-system",
        "issue_number": 68,
        "objective": "Create a bounded untrusted preview fixture.",
        "change_policy": {
            "change_required": True,
            "policy_exception_id": None,
            "no_change": {
                "allowed": False,
                "reason_codes": [],
                "required_evidence_types": [],
            },
        },
        "base_ref": "main",
        "base_sha": "d4f10b714de3afae84d48dfcd3daa6405092a973",
        "branch": "agent/issue-68-partner-preview",
        "allowed_paths": allowed_paths,
        "denied_paths": [".git/**", ".claude/**", "forbidden/**"],
        "risk_class": "L3",
        "executor": {
            "adapter": "human-supervised-claude-code",
            "version": "test",
            "max_attempts": 1,
            "timeout_seconds": 60,
        },
        "acceptance_criteria": [
            {
                "id": "AC-PREVIEW",
                "predicate_id": "process.exit_code.equals",
                "parameters": parameters,
                "required": True,
                "linked_checks": ["preview-tests"],
            }
        ],
        "required_checks": [
            {
                "id": "preview-tests",
                "command_id": "repo.contracts.b3.tests",
                "required": True,
                "expected_postconditions": [
                    {
                        "predicate_id": "process.exit_code.equals",
                        "parameters": {"value": 0},
                    }
                ],
            }
        ],
        "review_policy": {
            "reviewer_class": "independent-engineering",
            "policy_id": "review-independence.v1",
            "forbidden_lineage_overlaps": ["agent_runtime_id"],
            "minimum_distinct_human_operators": 1,
        },
        "external_side_effects": "forbidden",
        "created_by": "test:preview",
        "created_at": "2026-07-23T08:45:00Z",
    }


def _write(path: Path, data: bytes, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


class PreviewFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="p0-partner-preview-test-"))
        self.baseline = self.root / "baseline"
        self.baseline.mkdir()
        _write(self.baseline / "src/edit.txt", b"old\n")
        _write(self.baseline / "src/delete.txt", b"delete me\n")
        _write(self.baseline / "docs/context.md", b"context\n")
        self.task_path = self.root / "task.json"
        self.task_path.write_text(
            json.dumps(_task(context_paths=["docs/context.md"])),
            encoding="utf-8",
        )

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def prepare(self):
        output = self.root / "provider-input"
        preview._prepare(
            task_path=self.task_path,
            schema_path=SCHEMA_PATH,
            baseline=self.baseline,
            output=output,
        )
        return output

    def snapshot(self, provider_input, name="candidate.snapshot.json"):
        output = self.root / name
        preview._snapshot(
            task_path=provider_input / "TASK.json",
            schema_path=SCHEMA_PATH,
            candidate=provider_input / "candidate",
            output=output,
            forbid_env=[],
        )
        return output

    def package(self, snapshot, name="package"):
        output = self.root / name
        preview._package(
            task_path=self.task_path,
            schema_path=SCHEMA_PATH,
            baseline=self.baseline,
            snapshot_path=snapshot,
            output=output,
            provenance={
                "run_attempt": "1",
                "run_id": "123",
                "workflow_sha": "a" * 40,
            },
        )
        return output

    def assert_error(self, code, callable_):
        with self.assertRaises(preview.PreviewError) as raised:
            callable_()
        self.assertEqual(code, raised.exception.code)

    def test_edit_add_delete_produces_exact_untrusted_package(self):
        provider_input = self.prepare()
        candidate = provider_input / "candidate"
        _write(candidate / "src/edit.txt", b"new\n")
        (candidate / "src/delete.txt").unlink()
        _write(candidate / "src/new.txt", b"added\n")

        output = self.package(self.snapshot(provider_input))
        self.assertEqual(
            sorted(preview.FIXED_OUTPUT_FILES),
            sorted(path.name for path in output.iterdir()),
        )
        for path in output.iterdir():
            self.assertTrue(path.is_file())
            self.assertFalse(path.is_symlink())
            self.assertEqual(0o644, stat.S_IMODE(path.stat().st_mode))

        manifest = json.loads((output / "UNTRUSTED-PREVIEW.json").read_text())
        self.assertEqual(preview.LABEL, manifest["label"])
        self.assertTrue(manifest["claims"]["scope_of_serialized_snapshot_checked"])
        for false_claim in (
            "correctness",
            "execution_verified",
            "provenance_verified",
            "security_verified",
            "tests_run",
        ):
            self.assertFalse(manifest["claims"][false_claim])
        self.assertEqual(
            [("delete", "src/delete.txt"), ("edit", "src/edit.txt"), ("add", "src/new.txt")],
            [(item["operation"], item["path"]) for item in manifest["changes"]],
        )
        patch = (output / "changes.patch").read_text()
        self.assertIn("deleted file mode 100644", patch)
        self.assertIn("-old", patch)
        self.assertIn("+new", patch)
        self.assertIn("new file mode 100644", patch)
        summary = (output / "summary.md").read_text()
        self.assertIn(preview.SAFETY_STATEMENT, summary)
        self.assertIn("secretless, read-only CI", summary)

    def test_outputs_are_byte_deterministic(self):
        provider_input = self.prepare()
        _write(provider_input / "candidate/src/edit.txt", b"deterministic\n")
        snapshot = self.snapshot(provider_input)
        first = self.package(snapshot, "package-one")
        second = self.package(snapshot, "package-two")
        for name in preview.FIXED_OUTPUT_FILES:
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())

    @unittest.skipUnless(shutil.which("git"), "git unavailable")
    def test_patch_is_independently_applicable_without_byte_normalization(self):
        cases = (
            b"changed without newline",
            b"\xef\xbb\xbfchanged with BOM\r\n",
            b"",
        )
        for index, replacement in enumerate(cases):
            case_root = self.root / "apply-case-{}".format(index)
            baseline = case_root / "baseline"
            baseline.mkdir(parents=True)
            _write(baseline / "src/edit.txt", b"old without newline")
            _write(baseline / "src/delete.txt", b"delete\r\n")
            task_path = case_root / "task.json"
            task_path.write_text(json.dumps(_task()), encoding="utf-8")
            provider_input = case_root / "provider-input"
            preview._prepare(
                task_path=task_path,
                schema_path=SCHEMA_PATH,
                baseline=baseline,
                output=provider_input,
            )
            _write(provider_input / "candidate/src/edit.txt", replacement)
            (provider_input / "candidate/src/delete.txt").unlink()
            _write(provider_input / "candidate/src/new.txt", b"new\r\n")
            snapshot = case_root / "candidate.json"
            preview._snapshot(
                task_path=provider_input / "TASK.json",
                schema_path=SCHEMA_PATH,
                candidate=provider_input / "candidate",
                output=snapshot,
                forbid_env=[],
            )
            package = case_root / "package"
            preview._package(
                task_path=task_path,
                schema_path=SCHEMA_PATH,
                baseline=baseline,
                snapshot_path=snapshot,
                output=package,
                provenance={},
            )
            checkout = case_root / "checkout"
            shutil.copytree(baseline, checkout)
            subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
            patch = package / "changes.patch"
            subprocess.run(
                ["git", "apply", "--check", str(patch)],
                cwd=checkout,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "apply", str(patch)],
                cwd=checkout,
                check=True,
                capture_output=True,
            )
            self.assertEqual(replacement, (checkout / "src/edit.txt").read_bytes())
            self.assertEqual(b"new\r\n", (checkout / "src/new.txt").read_bytes())
            self.assertFalse((checkout / "src/delete.txt").exists())

    def test_empty_diff_fails_without_partial_output(self):
        provider_input = self.prepare()
        snapshot = self.snapshot(provider_input)
        output = self.root / "must-not-exist"
        self.assert_error(
            "E_EMPTY_DIFF",
            lambda: preview._package(
                task_path=self.task_path,
                schema_path=SCHEMA_PATH,
                baseline=self.baseline,
                snapshot_path=snapshot,
                output=output,
                provenance={},
            ),
        )
        self.assertFalse(output.exists())

    def test_out_of_scope_file_fails(self):
        provider_input = self.prepare()
        _write(provider_input / "candidate/other.txt", b"no\n")
        self.assert_error("E_SCOPE", lambda: self.snapshot(provider_input))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_symlink_leaf_fails(self):
        provider_input = self.prepare()
        target = provider_input / "candidate/src/edit.txt"
        target.unlink()
        target.symlink_to(self.baseline / "src/edit.txt")
        self.assert_error("E_SYMLINK", lambda: self.snapshot(provider_input))

    @unittest.skipUnless(hasattr(os, "link"), "hardlink unavailable")
    def test_hardlink_fails(self):
        provider_input = self.prepare()
        source = provider_input / "candidate/src/edit.txt"
        linked = self.root / "linked.txt"
        os.link(source, linked)
        self.assert_error("E_HARDLINK", lambda: self.snapshot(provider_input))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO unavailable")
    def test_fifo_fails(self):
        provider_input = self.prepare()
        os.mkfifo(provider_input / "candidate/fifo")
        self.assert_error("E_SPECIAL", lambda: self.snapshot(provider_input))

    def test_invalid_utf8_and_nul_fail(self):
        for index, data in enumerate((b"\xff", b"before\x00after")):
            provider_input = self.prepare() if index == 0 else self.root / "provider-input-2"
            if index == 1:
                preview._prepare(
                    task_path=self.task_path,
                    schema_path=SCHEMA_PATH,
                    baseline=self.baseline,
                    output=provider_input,
                )
            _write(provider_input / "candidate/src/edit.txt", data)
            self.assert_error("E_TEXT_ONLY", lambda p=provider_input: self.snapshot(p, "s{}.json".format(index)))

    def test_file_size_limit_is_enforced(self):
        provider_input = self.prepare()
        _write(
            provider_input / "candidate/src/edit.txt",
            b"x" * (preview.MAX_FILE_BYTES + 1),
        )
        self.assert_error("E_LIMIT", lambda: self.snapshot(provider_input))

    def test_exact_one_mib_file_is_accepted(self):
        provider_input = self.prepare()
        exact = b"x" * preview.MAX_FILE_BYTES
        _write(provider_input / "candidate/src/edit.txt", exact)
        output = self.package(self.snapshot(provider_input))
        manifest = json.loads((output / "UNTRUSTED-PREVIEW.json").read_text())
        edit = next(item for item in manifest["changes"] if item["path"] == "src/edit.txt")
        self.assertEqual(preview.MAX_FILE_BYTES, edit["new_size"])

    def test_existing_mode_change_and_new_executable_fail(self):
        provider_input = self.prepare()
        candidate = provider_input / "candidate"
        _write(candidate / "src/edit.txt", b"changed\n", mode=0o755)
        self.assert_error("E_MODE", lambda: self.package(self.snapshot(provider_input)))

        second_root = self.root / "provider-input-two"
        preview._prepare(
            task_path=self.task_path,
            schema_path=SCHEMA_PATH,
            baseline=self.baseline,
            output=second_root,
        )
        _write(second_root / "candidate/src/new.txt", b"new\n", mode=0o755)
        self.assert_error(
            "E_MODE", lambda: self.package(self.snapshot(second_root, "mode2.json"), "mode-package")
        )

    def test_token_markers_and_exact_environment_secret_fail(self):
        provider_input = self.prepare()
        _write(provider_input / "candidate/src/edit.txt", b"github_pat_stolen")
        self.assert_error("E_SECRET", lambda: self.snapshot(provider_input))

        second_root = self.root / "provider-input-secret"
        preview._prepare(
            task_path=self.task_path,
            schema_path=SCHEMA_PATH,
            baseline=self.baseline,
            output=second_root,
        )
        secret = "sixteen-byte-secret-value"
        _write(second_root / "candidate/src/edit.txt", secret.encode())
        old = os.environ.get("PREVIEW_TEST_SECRET")
        os.environ["PREVIEW_TEST_SECRET"] = secret
        try:
            self.assert_error(
                "E_SECRET",
                lambda: preview._snapshot(
                    task_path=second_root / "TASK.json",
                    schema_path=SCHEMA_PATH,
                    candidate=second_root / "candidate",
                    output=self.root / "secret.json",
                    forbid_env=["PREVIEW_TEST_SECRET"],
                ),
            )
        finally:
            if old is None:
                os.environ.pop("PREVIEW_TEST_SECRET", None)
            else:
                os.environ["PREVIEW_TEST_SECRET"] = old

    def test_snapshot_requires_exact_allowed_entry_set(self):
        provider_input = self.prepare()
        _write(provider_input / "candidate/src/edit.txt", b"changed\n")
        snapshot = self.snapshot(provider_input)
        document = json.loads(snapshot.read_text())
        document["entries"].pop()
        hostile = self.root / "hostile.json"
        hostile.write_text(json.dumps(document), encoding="utf-8")
        self.assert_error("E_SCOPE", lambda: self.package(hostile))

    def test_duplicate_json_keys_fail(self):
        hostile = self.root / "duplicate.json"
        hostile.write_text(
            '{"format":"x","format":"y","entries":[]}',
            encoding="utf-8",
        )
        self.assert_error("E_DUPLICATE", lambda: self.package(hostile))

    def test_control_and_noncanonical_task_paths_fail(self):
        for path, code in (
            (".git/config", "E_CONTROL_PATH"),
            ("src/../evil.txt", "E_PATH"),
            ("src/*.txt", "E_PATH"),
            ("src/space name.txt", "E_PATH"),
        ):
            task = self.root / ("task-" + str(abs(hash(path))) + ".json")
            task.write_text(json.dumps(_task(allowed_paths=[path])), encoding="utf-8")
            self.assert_error(
                code,
                lambda p=task: preview._load_task(p, SCHEMA_PATH),
            )


class PreviewWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.workflow = yaml.load(cls.text, Loader=yaml.BaseLoader)
        cls.jobs = cls.workflow["jobs"]

    def test_manual_trigger_and_exact_three_job_graph(self):
        self.assertEqual(["workflow_dispatch"], list(self.workflow["on"]))
        self.assertEqual(["prepare", "author", "package"], list(self.jobs))
        self.assertNotIn("needs", self.jobs["prepare"])
        self.assertEqual("prepare", self.jobs["author"]["needs"])
        self.assertEqual("author", self.jobs["package"]["needs"])
        self.assertNotIn("strategy", self.text)

    def test_permissions_are_fail_closed(self):
        self.assertEqual({}, self.workflow["permissions"])
        self.assertEqual({"contents": "read"}, self.jobs["prepare"]["permissions"])
        self.assertEqual({}, self.jobs["author"]["permissions"])
        self.assertEqual({"contents": "read"}, self.jobs["package"]["permissions"])
        self.assertNotIn("id-token", self.text)
        self.assertNotIn("write-all", self.text)

    def test_fixed_hosted_runner_and_global_concurrency(self):
        for job in self.jobs.values():
            self.assertEqual("ubuntu-24.04", job["runs-on"])
            self.assertNotIn("self-hosted", json.dumps(job))
        self.assertEqual(
            "p0-partner-untrusted-preview", self.workflow["concurrency"]["group"]
        )
        self.assertEqual("false", self.workflow["concurrency"]["cancel-in-progress"])
        self.assertNotIn("actions/cache@", self.text)

    def test_every_external_action_is_full_sha_pinned(self):
        allowed = {CHECKOUT_PIN, UPLOAD_PIN, DOWNLOAD_PIN, CLAUDE_PIN}
        observed = []
        for job in self.jobs.values():
            for step in job["steps"]:
                if "uses" in step:
                    observed.append(step["uses"])
        self.assertTrue(observed)
        self.assertEqual(set(observed), allowed)
        for action in observed:
            self.assertRegex(action, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")

    def test_author_has_no_checkout_and_only_author_references_oauth(self):
        author_text = json.dumps(self.jobs["author"], sort_keys=True)
        self.assertNotIn("actions/checkout@", author_text)
        for name, job in self.jobs.items():
            contains_oauth = "secrets.CLAUDE_CODE_OAUTH_TOKEN" in json.dumps(job)
            self.assertEqual(name == "author", contains_oauth)
        self.assertEqual(2, author_text.count("secrets.CLAUDE_CODE_OAUTH_TOKEN"))
        self.assertNotIn("OPENAI_API_KEY", self.text)
        self.assertNotIn("ANTHROPIC_API_KEY", self.text)

    def test_claude_inputs_are_bounded_and_debug_gate_precedes_oauth(self):
        steps = self.jobs["author"]["steps"]
        claude_index = next(index for index, step in enumerate(steps) if step.get("uses") == CLAUDE_PIN)
        debug_index = next(index for index, step in enumerate(steps) if "debug" in step["name"].lower())
        warning_index = next(index for index, step in enumerate(steps) if "warning" in step["name"].lower())
        self.assertLess(debug_index, claude_index)
        self.assertLess(warning_index, claude_index)
        inputs = steps[claude_index]["with"]
        self.assertEqual("${{ github.token }}", inputs["github_token"])
        self.assertEqual("${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}", inputs["claude_code_oauth_token"])
        self.assertEqual("", inputs["anthropic_api_key"])
        self.assertEqual("false", inputs["use_bedrock"])
        self.assertEqual("false", inputs["use_vertex"])
        self.assertEqual("", inputs["settings"])
        self.assertEqual("", inputs["plugins"])
        self.assertEqual("", inputs["plugin_marketplaces"])
        self.assertEqual("", inputs["additional_permissions"])
        self.assertEqual("false", inputs["show_full_output"])
        args = shlex.split(inputs["claude_args"])
        self.assertEqual(1, args.count("--tools"))
        self.assertEqual(1, args.count("--disallowedTools"))
        self.assertEqual(1, args.count("--max-turns"))
        self.assertEqual("Read,Edit,Write,Glob,Grep", args[args.index("--tools") + 1])
        denied = set(args[args.index("--disallowedTools") + 1].split(","))
        self.assertTrue(
            {"Bash", "WebFetch", "WebSearch", "Task", "NotebookEdit", "mcp__github__*"}.issubset(denied)
        )
        for forbidden in ("--mcp-config", "--add-dir", "--dangerously-skip-permissions"):
            self.assertNotIn(forbidden, args)

    def test_provider_outputs_never_control_workflow_structure(self):
        for job in self.jobs.values():
            for step in job["steps"]:
                for field in ("if", "uses", "shell"):
                    self.assertNotIn("steps.claude.outputs", str(step.get(field, "")))
        self.assertNotIn("continue-on-error", self.text)
        self.assertNotIn("pull_request_target", self.workflow["on"])
        self.assertNotIn("workflow_run", self.workflow["on"])
        self.assertNotIn("repository_dispatch", self.workflow["on"])
        self.assertNotIn("schedule", self.workflow["on"])

    def test_artifacts_bind_run_and_attempt_and_final_retention_is_one_day(self):
        artifact_steps = [
            step
            for job in self.jobs.values()
            for step in job["steps"]
            if step.get("uses") in {UPLOAD_PIN, DOWNLOAD_PIN}
        ]
        for step in artifact_steps:
            name = step["with"]["name"]
            self.assertIn("${{ github.run_id }}", name)
            self.assertIn("${{ github.run_attempt }}", name)
            if step.get("uses") == UPLOAD_PIN:
                self.assertEqual("1", step["with"]["retention-days"])
        final = self.jobs["package"]["steps"][-1]
        self.assertEqual(UPLOAD_PIN, final["uses"])
        self.assertEqual(
            "UNTRUSTED-PREVIEW-${{ github.run_id }}-${{ github.run_attempt }}",
            final["with"]["name"],
        )

    def test_preview_owned_names_and_fixed_warning_are_prominent(self):
        self.assertIn("UNTRUSTED PREVIEW", self.workflow["name"])
        for job in self.jobs.values():
            self.assertIn("UNTRUSTED PREVIEW", job["name"])
            for step in job["steps"]:
                self.assertIn("UNTRUSTED PREVIEW", step["name"])
        self.assertIn("# UNTRUSTED PREVIEW", self.text)
        self.assertIn(preview.SAFETY_STATEMENT.split(".")[0], RUNBOOK_PATH.read_text())

    def test_no_publication_job_or_trigger_exists(self):
        forbidden_job_names = {
            "publish",
            "publisher",
            "finalize",
            "finalizer",
            "deploy",
            "merge",
        }
        self.assertTrue(forbidden_job_names.isdisjoint(self.jobs))
        self.assertEqual(["workflow_dispatch"], list(self.workflow["on"]))


class PreviewRunbookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_records_task_and_reviews(self):
        self.assertIn("950b7ffd2ea36970ba01b140958416f9b0621535", self.text)
        self.assertIn("7ccb5fd10bc264aa20cc0b3cac56aec985f90010be6a1f5fc2bbb3f5e8f15b46", self.text)
        self.assertIn("32ffe7e8a75af4417f6ac7a416a917fb04ad56d7129d39ce44e8cb10d8067004", self.text)
        self.assertIn("832891fd2c35b1310d87f4099af169e508196a782f20790066a65c9f2228cce8", self.text)
        self.assertIn("REQUEST_CHANGES", self.text)

    def test_secretless_first_ci_and_stop_controls_are_explicit(self):
        for phrase in (
            "permissions: {}",
            "без `id-token: write`",
            "без self-hosted runner",
            "Срочный local/manual режим — доступен без merge",
            "workflow существует в default branch",
            "Никогда не merge Preview workflow автоматически",
            "P0_PARTNER_PREVIEW_ENABLED=false",
            "отзывает отдельный OAuth credential",
            "Debug rerun",
        ):
            self.assertIn(phrase, self.text)

    def test_trust_overclaims_are_rejected(self):
        for phrase in (
            "не подтверждает корректность",
            "не является OS sandbox",
            "Patch может быть ошибочным",
            "не делает AI-код безопасным",
            "PR #69 остаётся Draft и unmerged",
        ):
            self.assertIn(phrase, self.text)


if __name__ == "__main__":
    unittest.main()
