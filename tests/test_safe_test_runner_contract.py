"""Static text contracts only; do not import or execute candidate code.

No YAML dependency: assertions deliberately constrain this workflow's explicit
layout as well as its security-sensitive values. These are regression checks,
not a general YAML/shell verifier or proof of runtime containment.
IMPLEMENTATION-001: authored for independent review, NOT RUN by Builder.
"""

from pathlib import Path
from collections import Counter
import hashlib
import re
import stat
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/safe-test-runner.yml"
# Identity only, never execution approval. Updating workflow and digest together
# cannot self-authorize a change; the governance review gates still apply.
APPROVED_SAFE_RUNNER_CANONICAL_SHA256 = (
    "f080bc0e6f1bf4de4bb0d858ea77013b52e0571ec977ae68fc5c78e36e6fe024"
)
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
IMAGE_DIGEST = "a66d3a463d0be3cc537c269b0d3418746dda512417a975559a0eaa8a6406baaf"
IMAGE = "docker.io/library/python@sha256:" + IMAGE_DIGEST


# Exact source expressions and multiplicities: no YAML run-key recognition needed.
ALLOWED_EXPRESSIONS = {
    "${{ github.ref }}": 1,
    "${{ inputs.candidate_sha }}": 1,
    "${{ steps.preflight.outputs.image }}": 2,
    "${{ steps.preflight.outputs.platform }}": 1,
    "${{ steps.preflight.outputs.python_version }}": 1,
    "${{ steps.preflight.outputs.candidate_sha }}": 1,
}


def require_expression_allowlist(text):
    expressions = re.findall(r"\$\{\{.*?\}\}", text, re.S)
    if text.count("${{") != len(expressions):
        raise AssertionError("Unterminated expression")
    if Counter(expressions) != Counter(ALLOWED_EXPRESSIONS):
        raise AssertionError("Unapproved, missing, or additional expression")


EXPECTED_INSPECTION = (
    "          if ! image_os=$(inspect_field '{{json .Os}}') ||\n"
    "             ! image_arch=$(inspect_field '{{json .Architecture}}') ||\n"
    "             ! image_entrypoint=$(inspect_field '{{json .Config.Entrypoint}}') ||\n"
    "             ! image_cmd=$(inspect_field '{{json .Config.Cmd}}') ||\n"
    "             ! image_user=$(inspect_field '{{json .Config.User}}') ||\n"
    "             ! image_workdir=$(inspect_field '{{json .Config.WorkingDir}}') ||\n"
    "             ! image_volumes=$(inspect_field '{{json .Config.Volumes}}') ||\n"
    "             ! image_healthcheck=$(inspect_field '{{json (index .Config \"Healthcheck\")}}') ||\n"
    "             ! image_env=$(inspect_field '{{range .Config.Env}}{{println .}}{{end}}'); then\n"
    "            printf '%s\\n' 'FAIL: image metadata inspection unavailable.'\n"
    "            exit 1\n"
    "          fi\n"
)

EXPECTED_METADATA = (
    "          if [[ \"$image_os\" != '\"linux\"' || \"$image_arch\" != '\"amd64\"' ||\n"
    "                ( \"$image_entrypoint\" != 'null' && \"$image_entrypoint\" != '[]' ) ||\n"
    "                \"$image_cmd\" != '[\"python3\"]' || \"$image_user\" != '\"\"' ||\n"
    "                \"$image_workdir\" != '\"\"' || \"$image_healthcheck\" != 'null' ||\n"
    "                ( \"$image_volumes\" != 'null' && \"$image_volumes\" != '{}' ) ]]; then\n"
    "            printf '%s\\n' 'FAIL: unexpected image metadata.'\n"
    "            exit 1\n"
    "          fi\n"
)

EXPECTED_ENV = (
    "          version_entries=0\n"
    "          while IFS= read -r entry; do\n"
    "            if [[ \"$entry\" != *=* ]]; then\n"
    "              printf '%s\\n' 'FAIL: malformed image environment.'\n"
    "              exit 1\n"
    "            fi\n"
    "            env_name=${entry%%=*}\n"
    "            case \"${env_name^^}\" in\n"
    "              GITHUB_*|ACTIONS_*|AWS_*|AZURE_*|GOOGLE_*|SSH_*|DOCKER_AUTH_CONFIG|*TOKEN*|*SECRET*|*PASSWORD*|*CREDENTIAL*|*API_KEY*|*PRIVATE_KEY*)\n"
    "                printf '%s\\n' 'FAIL: credential-like image environment.'\n"
    "                exit 1\n"
    "                ;;\n"
    "            esac\n"
    "            if [[ \"$env_name\" == 'PYTHON_VERSION' ]]; then\n"
    "              if [[ \"$entry\" != \"PYTHON_VERSION=$SAFE_TEST_PYTHON_VERSION\" ]]; then\n"
    "                printf '%s\\n' 'FAIL: unexpected image Python version.'\n"
    "                exit 1\n"
    "              fi\n"
    "              version_entries=$((version_entries + 1))\n"
    "            fi\n"
    "          done <<< \"$image_env\"\n"
    "          if [[ \"$version_entries\" -ne 1 ]]; then\n"
    "            printf '%s\\n' 'FAIL: missing or duplicate image Python version.'\n"
    "            exit 1\n"
    "          fi\n"
)


def require_metadata_contract(text):
    # Fixed expected literals; never derive these from the workflow under test.
    for expected in (EXPECTED_INSPECTION, EXPECTED_METADATA, EXPECTED_ENV):
        if text.count(expected) != 1:
            raise AssertionError("Critical metadata control changed")


def run_bodies(text):
    """Collect every indentation-based run value, including inline/folded ones.

    This workflow uses block mappings, not YAML flow mappings or aliases.
    Include defaults.run conservatively as well. Expressions in adjacent
    env/with mappings are outside the collected values.
    """
    bodies = []
    current = None
    key_indent = None
    for line in text.splitlines():
        if current is not None:
            if not line.strip() or len(line) - len(line.lstrip(" ")) > key_indent:
                current.append(line)
                continue
            bodies.append("\n".join(current))
            current = None
        match = re.match(r'''^( *)(- )?(?:run|'run'|"run"):[ \t]*(.*)$''', line)
        if match:
            key_indent = len(match[1]) + (2 if match[2] else 0)
            current = [match[3]]
    if current is not None:
        bodies.append("\n".join(current))
    return bodies


def require_expression_free_runs(text):
    bodies = run_bodies(text)
    if not bodies:
        raise AssertionError("No run values found")
    if any("${{" in body for body in bodies):
        raise AssertionError("GitHub expression inside run value")


def require_container_name(docker):
    if re.findall(r'--name\s+(\S+)', docker) != ['"$CONTAINER_NAME"']:
        raise AssertionError("Expected exactly one fixed container name")


class SafeRunnerGoldenIdentityTests(unittest.TestCase):
    def test_safe_runner_workflow_matches_approved_golden_identity(self):
        # N-03/N-04: whole-file identity covers insertions between blocks and
        # inline/flow YAML changes even when structural regexes miss them.
        # Existing structural contracts remain defense-in-depth.
        try:
            metadata = WORKFLOW.lstat()
        except OSError:
            self.fail("Workflow unavailable")
        self.assertTrue(stat.S_ISREG(metadata.st_mode), "Workflow must be a regular file")
        try:
            raw = WORKFLOW.read_bytes()
        except OSError:
            self.fail("Workflow unreadable")
        canonical = raw.replace(b"\r\n", b"\n")
        self.assertFalse(b"\r" in canonical, "Workflow contains bare CR")
        self.assertEqual(
            hashlib.sha256(canonical).hexdigest(),
            APPROVED_SAFE_RUNNER_CANONICAL_SHA256,
        )


class SafeTestRunnerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.trigger = cls.text.split("on:\n", 1)[1].split("\npermissions:", 1)[0]
        cls.preflight = cls.text.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0]
        cls.checkout = cls.text.split("        with:\n", 1)[1].split("\n      - name:", 1)[0]
        cls.execution = cls.text.split("      - name: Future contained critical suite\n", 1)[1]
        cls.preparation = cls.text.split("      - name: Prepare admitted image\n", 1)[1].split("      - name: Checkout exact candidate as data", 1)[0]
        cls.docker = cls.execution.split("10m docker run \\\n", 1)[1].split('> "$RESULT_FILE"', 1)[0]

    def test_manual_trigger_only(self):
        self.assertEqual(re.findall(r"^  ([\w]+):", self.trigger, re.M), ["workflow_dispatch"])

    def test_no_push_trigger(self):
        self.assertNotRegex(self.text, r"(?m)^\s*push:")

    def test_no_pull_request_trigger(self):
        self.assertNotRegex(self.text, r"(?m)^\s*pull_request:")

    def test_no_pull_request_target_trigger(self):
        self.assertNotRegex(self.text, r"(?m)^\s*pull_request_target:")

    def test_no_workflow_run_trigger(self):
        self.assertNotRegex(self.text, r"(?m)^\s*workflow_run:")

    def test_no_schedule_trigger(self):
        self.assertNotRegex(self.text, r"(?m)^\s*schedule:")

    def test_no_repository_dispatch_trigger(self):
        self.assertNotRegex(self.text, r"(?m)^\s*repository_dispatch:")

    def test_candidate_only_required_string_input(self):
        self.assertEqual(re.findall(r"^      (\w+):", self.trigger, re.M), ["candidate_sha"])
        self.assertIn("        required: true\n        type: string", self.trigger)
        self.assertNotIn("default:", self.trigger)

    def test_no_command_input(self):
        self.assertNotRegex(self.trigger, r"(?m)^\s*command:")

    def test_no_image_input(self):
        self.assertNotRegex(self.trigger, r"(?m)^\s*image:")

    def test_no_secret_input(self):
        self.assertNotRegex(self.trigger, r"(?m)^\s*secret:")

    def test_only_contents_read_permission(self):
        self.assertEqual(self.text.split("\npermissions:\n", 1)[1].split("\njobs:", 1)[0].strip(), "contents: read")
        self.assertEqual(len(re.findall(r"(?m)^\s*permissions:", self.text)), 1)

    def test_no_write_permissions(self):
        self.assertNotRegex(self.text, r":\s*write\b|write-all")

    def test_no_secrets_expressions(self):
        self.assertNotRegex(self.text, r"\bsecrets\s*[.\[]")

    def test_no_github_environment(self):
        self.assertNotRegex(self.text, r"(?m)^\s*environment:")

    def test_exact_checkout_pin(self):
        self.assertIn(f"        uses: {CHECKOUT} # v7.0.1\n", self.text)

    def test_no_mutable_checkout(self):
        self.assertEqual(re.findall(r"actions/checkout@([^\s]+)", self.text), [CHECKOUT.split("@")[1]])

    def test_no_persisted_credentials(self):
        self.assertIn("          persist-credentials: false\n", self.checkout)

    def test_no_submodules(self):
        self.assertIn("          submodules: false\n", self.checkout)

    def test_no_lfs(self):
        self.assertIn("          lfs: false\n", self.checkout)

    def test_fixed_candidate_path(self):
        self.assertIn("          path: candidate\n", self.checkout)

    def test_minimal_fetch_and_same_repository(self):
        self.assertIn("          fetch-depth: 1\n", self.checkout)
        self.assertNotRegex(self.checkout, r"(?m)^\s*(repository|token|ssh-key):")

    def test_sha_validation_exits_before_export(self):
        self.assertIn('if [[ ! "$CANDIDATE_SHA" =~ ^[0-9a-f]{40}$ ]]; then\n'
                      "            printf '%s\\n' 'FAIL: invalid candidate SHA.'\n"
                      "            exit 1\n          fi", self.preflight)
        self.assertLess(self.preflight.index("^[0-9a-f]{40}$"), self.preflight.index('>> "$GITHUB_OUTPUT"'))

    def test_input_passed_as_environment_data(self):
        self.assertEqual(self.text.count("${{ inputs.candidate_sha }}"), 1)
        self.assertIn("          CANDIDATE_SHA: ${{ inputs.candidate_sha }}\n", self.text)
        self.assertNotIn("${{", self.preflight)

    def test_checkout_uses_validated_sha(self):
        self.assertIn("          ref: ${{ steps.preflight.outputs.candidate_sha }}\n", self.checkout)
        self.assertIn("printf 'candidate_sha=%s\\nimage=%s\\n'", self.preflight)

    def test_main_ref_guard_fails_first(self):
        self.assertTrue(self.preflight.startswith('          if [[ "$WORKFLOW_SOURCE_REF" != \'refs/heads/main\' ]]; then\n'))
        guard = self.preflight.split("          fi", 1)[0]
        self.assertIn("            exit 1", guard)
        self.assertIn("WORKFLOW_SOURCE_REF: ${{ github.ref }}", self.text)

    def test_image_is_trusted_admitted_literal(self):
        self.assertIn(f'readonly SAFE_TEST_IMAGE="{IMAGE}"', self.preflight)
        self.assertEqual(self.text.count("readonly SAFE_TEST_IMAGE="), 1)

    def test_disabled_execution_exits(self):
        self.assertIn('if [[ "$SAFE_TEST_EXECUTION_ENABLED" != \'true\' ]]; then\n'
                      "            printf '%s\\n' 'STATICALLY ADMITTED; EXECUTION INTENTIONALLY DISABLED'\n"
                      "            exit 1\n          fi", self.preflight)

    def test_exact_image_contract_fails_closed(self):
        self.assertIn(f'if [[ "$SAFE_TEST_IMAGE" != \'{IMAGE}\' ]] ||\n'
                      '             [[ "$SAFE_TEST_PLATFORM" != \'linux/amd64\' ]] ||\n'
                      '             [[ "$SAFE_TEST_PYTHON_VERSION" != \'3.14.8\' ]]; then\n'
                      "            printf '%s\\n' 'FAIL: image admission contract mismatch.'\n"
                      "            exit 1\n          fi", self.preflight)
        self.assertNotRegex(self.text, r"python:(latest|3[\w.-]*)")

    def test_admission_precedes_checkout_pull_and_run(self):
        positions = [self.text.index(value) for value in (
            "id: preflight", "@sha256:", "EXECUTION INTENTIONALLY DISABLED",
            '>> "$GITHUB_OUTPUT"', "docker pull", "docker image inspect", f"uses: {CHECKOUT}", "10m docker run")]
        self.assertEqual(positions, sorted(positions))
        self.assertNotRegex(self.text, r"(?m)^\s*(if|continue-on-error|needs):")

    def test_container_has_no_network(self):
        self.assertEqual(re.findall(r"--network\s+(\S+)", self.docker), ["none"])

    def test_container_root_readonly(self):
        self.assertIn("--read-only \\\n", self.docker)

    def test_all_capabilities_dropped(self):
        self.assertIn("--cap-drop ALL \\\n", self.docker)
        self.assertNotIn("--cap-add", self.text)

    def test_no_new_privileges(self):
        self.assertIn("--security-opt no-new-privileges \\\n", self.docker)

    def test_numeric_nonroot_user(self):
        self.assertEqual(re.findall(r"--user\s+(\S+)", self.docker), ["65534:65534"])

    def test_pid_limit(self):
        self.assertEqual(re.findall(r"--pids-limit\s+(\S+)", self.docker), ["128"])

    def test_memory_and_swap_limit(self):
        self.assertEqual(re.findall(r"--memory\s+(\S+)", self.docker), ["1g"])
        self.assertIn("--memory-swap 1g \\\n", self.docker)

    def test_cpu_limit(self):
        self.assertEqual(re.findall(r"--cpus\s+(\S+)", self.docker), ["2"])

    def test_bounded_tmpfs(self):
        self.assertEqual(re.findall(r"--tmpfs\s+(\S+)", self.docker),
                         ["/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777",
                          "/dev/shm:rw,noexec,nosuid,nodev,size=16m,mode=1777"])

    def test_only_candidate_bind_readonly(self):
        self.assertEqual(re.findall(r'--mount\s+"([^"]+)"', self.docker),
                         ["type=bind,source=${GITHUB_WORKSPACE}/candidate,target=/candidate,readonly"])
        docker_options = self.docker.split('"$SAFE_TEST_IMAGE"', 1)[0]
        self.assertNotRegex(docker_options, r"--volume\b|(?:^|\s)-v(?:\s|=)|--volumes-from")

    def test_no_docker_socket(self):
        self.assertNotIn("docker.sock", self.text)

    def test_no_privileged_mode(self):
        self.assertNotIn("--privileged", self.text)

    def test_no_host_network(self):
        self.assertNotRegex(self.text, r"--network[= ]host|--net[= ]host")

    def test_no_host_pid_or_ipc(self):
        self.assertNotRegex(self.text, r"--(?:pid|ipc)[= ]host")

    def test_no_devices(self):
        self.assertNotIn("--device", self.text)

    def test_no_host_data_mounts(self):
        self.assertNotRegex(self.docker, r"/github|/home/runner|\.ssh|\.aws|source=/[,\"]")
        self.assertEqual(self.docker.count("${GITHUB_WORKSPACE}"), 1)

    def test_only_fixed_environment_passed_to_container(self):
        self.assertEqual(re.findall(r"--env\s+(\S+)", self.docker), ["PYTHONDONTWRITEBYTECODE=1"])
        self.assertNotRegex(self.docker, r"GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN|--env-file|(?:^|\s)-e\s")

    def test_fixed_test_command_and_entrypoint(self):
        self.assertIn('--entrypoint "" \\\n', self.docker)
        self.assertIn('"$SAFE_TEST_IMAGE" python -B -m unittest tests.test_integrity_gate -v \\\n', self.docker)
        self.assertIn("--workdir /candidate \\\n", self.docker)

    def test_exactly_71_tests_required(self):
        self.assertIn("/^Ran 71 tests in [0-9]+([.][0-9]+)?s$/ { summaries++ }", self.execution)
        self.assertIn("passed == 71 && summaries == 1 && successes == 1 && rejected == 0", self.execution)

    def test_zero_skips_failures_and_errors(self):
        self.assertIn("(FAIL|ERROR|skipped|expected failure|unexpected success)", self.execution)
        self.assertIn("/^FAILED|^OK \\(/ { rejected++ }", self.execution)
        self.assertIn("candidate-reported test summary (UNVERIFIED): tests=71 failures=0 errors=0 skips=0", self.execution)

    def test_nonzero_exit_fails(self):
        self.assertIn('> "$RESULT_FILE" 2>&1 || exit_code=$?', self.execution)
        self.assertIn('if [[ "$exit_code" -ne 0 ]]; then\n'
                      "            printf '%s\\n' 'contract/result signal: FAIL (nonzero exit or timeout)'\n"
                      '            exit "$exit_code"\n          fi', self.execution)

    def test_summary_rejection_fails(self):
        self.assertIn("if ! LC_ALL=C awk '", self.execution)
        self.assertIn("END { exit !(passed == 71", self.execution)
        self.assertIn("' \"$RESULT_FILE\"; then\n"
                      "            printf '%s\\n' 'contract/result signal: FAIL (missing or inconsistent candidate-reported output)'\n"
                      "            exit 1\n          fi", self.execution)

    def test_job_and_container_timeouts(self):
        self.assertEqual(re.findall(r"timeout-minutes:\s*(\d+)", self.text), ["15"])
        self.assertIn("timeout --signal=TERM --kill-after=10s 10m docker run", self.execution)

    def test_no_retry(self):
        self.assertNotRegex(self.text, r"(?i)\bretry\b|\bretries\b|\buntil\b|\bwhile\b(?=\s*\[)")
        self.assertEqual(self.text.count("docker run"), 1)

    def test_no_upload_artifact(self):
        self.assertNotIn("upload-artifact", self.text)

    def test_only_allowed_action(self):
        self.assertEqual(re.findall(r"(?m)^\s*uses:\s*(\S+)", self.text), [CHECKOUT])

    def test_no_package_installation(self):
        self.assertNotRegex(self.text, r"\b(?:pip\d*|npm|apt(?:-get)?|yarn|pnpm)\b")

    def test_no_candidate_execution_on_host(self):
        # The only interpreter command is an argument to the fixed Docker call.
        self.assertEqual(self.text.count("python -B -m unittest tests.test_integrity_gate -v"), 1)
        self.assertNotRegex(self.text, r"(?m)^\s*(?:python\d*|bash|sh|pwsh|node|make)\s")
        self.assertNotRegex(self.text, r"(?m)^\s*(?:source\s|\.\s|eval\s|exec\s|cd\s|\./)")
        self.assertNotRegex(self.text, r"docker\s+(?:build|compose)|uses:\s*\./|working-directory:")
        self.assertEqual(re.findall(r"\$\{\{\s*inputs\.(\w+)\s*\}\}", self.text), ["candidate_sha"])

    def test_no_raw_output_or_environment_logging(self):
        self.assertNotRegex(self.text, r"set\s+-[^\n]*x|\bprintenv\b|(?m:^\s*env\s*$)")
        self.assertNotRegex(self.execution, r"\b(?:cat|tee|tail|head)\s")
        self.assertIn('> "$RESULT_FILE" 2>&1', self.execution)

    def test_ephemeral_github_host_and_cleanup(self):
        self.assertEqual(re.findall(r"runs-on:\s*(\S+)", self.text), ["ubuntu-24.04"])
        self.assertIn("--rm \\\n", self.docker)
        self.assertIn("trap cleanup EXIT", self.execution)
        self.assertIn('docker rm --force "$CONTAINER_NAME"', self.execution)

    def test_image_not_reselected_at_execution(self):
        self.assertEqual(self.text.count("SAFE_TEST_IMAGE: ${{ steps.preflight.outputs.image }}"), 2)
        self.assertIn("--pull never \\\n", self.docker)
        self.assertEqual(self.text.count("docker pull"), 1)

    def test_shell_fails_closed(self):
        self.assertIn("shell: bash --noprofile --norc -euo pipefail {0}", self.text)
        self.assertNotRegex(self.text, r"set\s+\+e|continue-on-error|always\(\)")

    def test_all_run_values_are_expression_free(self):
        require_expression_free_runs(self.text)
        self.assertEqual(len(run_bodies(self.text)), 4)  # Three scripts plus defaults.run.

    def test_reject_event_input_expression_in_every_script(self):
        marker = "        run: |\n"
        parts = self.text.split(marker)
        self.assertEqual(len(parts), 4)
        for index in range(1, len(parts)):
            mutated = parts.copy()
            mutated[index] = "          echo '${{ github.event.inputs.candidate_sha }}'\n" + mutated[index]
            with self.subTest(script=index), self.assertRaises(AssertionError):
                require_expression_free_runs(marker.join(mutated))

    def test_reject_github_token_expression(self):
        with self.assertRaises(AssertionError):
            require_expression_free_runs("steps:\n  - run: echo '${{ github.token }}'\n")

    def test_reject_env_malicious_expression(self):
        with self.assertRaises(AssertionError):
            require_expression_free_runs("steps:\n  - run: >-\n      echo '${{ env.MALICIOUS }}'\n")

    def test_reject_other_expression_contexts(self):
        for expression in ("inputs.command", "secrets.VALUE", "steps.other.outputs.value"):
            with self.subTest(expression=expression), self.assertRaises(AssertionError):
                require_expression_free_runs("steps:\n  - run: |\n      echo '${{ " + expression + " }}'\n")

    def test_expression_detector_respects_run_boundaries(self):
        require_expression_free_runs(
            "steps:\n  - name: example\n    run: |\n      echo safe\n"
            "    env:\n      VALUE: ${{ inputs.candidate_sha }}\n"
            "  - uses: example\n    with:\n      ref: ${{ github.ref }}\n")

    def test_docker_daemon_logging_disabled(self):
        self.assertEqual(re.findall(r"--log-driver\s+(\S+)", self.docker), ["none"])

    def test_output_file_hard_and_soft_quota(self):
        self.assertIn("readonly OUTPUT_LIMIT_BYTES=1048576\n", self.execution)
        self.assertIn('prlimit --fsize="${OUTPUT_LIMIT_BYTES}:${OUTPUT_LIMIT_BYTES}" \\\n'
                      "            timeout --signal=TERM --kill-after=10s 10m docker run", self.execution)

    def test_output_quota_boundary_fails_before_summary(self):
        guard = 'if [[ ! "$output_bytes" =~ ^[0-9]+$ ]] || (( output_bytes >= OUTPUT_LIMIT_BYTES )); then'
        self.assertIn('output_bytes=$(stat --format=%s -- "$RESULT_FILE")', self.execution)
        self.assertIn(guard + "\n"
                      "            printf '%s\\n' 'contract/result signal: FAIL (output quota reached or invalid size)'\n"
                      "            exit 1\n          fi", self.execution)
        self.assertLess(self.execution.index(guard), self.execution.index("if ! LC_ALL=C awk"))

    def test_output_capture_has_no_pipeline_or_status_mask(self):
        invocation = self.execution.split("          prlimit ", 1)[1].split("          printf 'exit code:", 1)[0]
        self.assertIn('> "$RESULT_FILE" 2>&1 || exit_code=$?', invocation)
        self.assertNotIn("|", invocation.replace("|| exit_code=$?", ""))
        self.assertNotIn("|| true", invocation)

    def test_container_name_is_required(self):
        require_container_name(self.docker)
        self.assertIn('readonly CONTAINER_NAME="safe-test-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"', self.execution)

    def test_missing_container_name_is_rejected(self):
        mutated = self.docker.replace('--name "$CONTAINER_NAME"', "")
        with self.assertRaises(AssertionError):
            require_container_name(mutated)

    def test_container_init_required(self):
        self.assertIn("--init \\\n", self.docker)

    def test_cleanup_removes_then_verifies_absence(self):
        cleanup = self.execution.split("          cleanup() {\n", 1)[1].split("          }\n", 1)[0]
        self.assertIn('timeout --kill-after=5s 10s docker rm --force "$CONTAINER_NAME"', cleanup)
        self.assertIn('if remaining=$(timeout --kill-after=5s 10s docker container ls --all \\\n'
                      '              --filter "name=^/${CONTAINER_NAME}$" --format \'{{.ID}}\' 2>/dev/null); then', cleanup)
        self.assertLess(cleanup.index("docker rm --force"), cleanup.index("docker container ls --all"))
        self.assertIn('if [[ -n "$remaining" ]]; then\n                cleanup_failed=1\n              fi\n'
                      '            else\n              cleanup_failed=1\n            fi', cleanup)

    def test_cleanup_preserves_failure_and_propagates_cleanup_failure(self):
        cleanup = self.execution.split("          cleanup() {\n", 1)[1].split("          }\n", 1)[0]
        self.assertTrue(cleanup.startswith("            local original_exit=$?\n            trap - EXIT\n"))
        self.assertIn('if [[ "$original_exit" -ne 0 ]]; then\n              exit "$original_exit"\n'
                      '            fi\n            exit "$cleanup_failed"', cleanup)
        self.assertIn("trap cleanup EXIT", self.execution)
        self.assertIn("trap 'exit 1' INT TERM", self.execution)
        self.assertLess(self.execution.index("trap cleanup EXIT"), self.execution.index("          prlimit "))

    def test_summary_is_explicitly_unverified_without_approval(self):
        self.assertIn("candidate-reported test summary (UNVERIFIED):", self.execution)
        self.assertIn("contract/result signal only: NO technical approval; NO security approval", self.execution)
        self.assertNotIn("'test summary:", self.execution)

    def test_image_digest_is_exact_and_complete(self):
        self.assertEqual(re.findall(r"@sha256:([0-9a-f]+)", self.preflight), [IMAGE_DIGEST, IMAGE_DIGEST])

    def test_image_registry_is_exact(self):
        self.assertEqual(re.findall(r'SAFE_TEST_IMAGE="([^/]+)/', self.preflight), ["docker.io"])

    def test_image_repository_is_exact(self):
        self.assertEqual(re.findall(r'docker.io/([^@]+)@sha256:', self.preflight), ["library/python", "library/python"])

    def test_platform_constant_and_equality(self):
        self.assertIn('readonly SAFE_TEST_PLATFORM="linux/amd64"', self.preflight)
        self.assertIn('[[ "$SAFE_TEST_PLATFORM" != \'linux/amd64\' ]]', self.preflight)

    def test_python_version_constant_and_equality(self):
        self.assertIn('readonly SAFE_TEST_PYTHON_VERSION="3.14.8"', self.preflight)
        self.assertIn('[[ "$SAFE_TEST_PYTHON_VERSION" != \'3.14.8\' ]]', self.preflight)

    def test_no_image_tags(self):
        self.assertNotRegex(self.text, r"(?:library/)?python:[A-Za-z0-9]")
        self.assertNotIn("__UNSET_REQUIRES_IMAGE_ADMISSION__", self.text)

    def test_execution_gate_is_explicitly_enabled(self):
        self.assertEqual(re.findall(r"readonly SAFE_TEST_EXECUTION_ENABLED=(\S+)", self.text), ["true"])
        self.assertNotIn("SAFE_TEST_EXECUTION_ENABLED=false", self.text)

    def test_admission_does_not_enable_execution(self):
        self.assertLess(self.preflight.index("SAFE_TEST_EXECUTION_ENABLED\" != 'true'"),
                        self.preflight.index('>> "$GITHUB_OUTPUT"'))
        self.assertNotRegex(self.text, r"(?m)^\s*(if|continue-on-error):")

    def test_pull_uses_trusted_exact_image_and_platform(self):
        self.assertIn('if ! docker pull --quiet --platform "$SAFE_TEST_PLATFORM" "$SAFE_TEST_IMAGE" > /dev/null 2>&1; then\n'
                      "            printf '%s\\n' 'FAIL: admitted image unavailable.'\n"
                      "            exit 1\n          fi", self.preparation)
        self.assertIn("SAFE_TEST_PLATFORM: ${{ steps.preflight.outputs.platform }}", self.preparation)
        self.assertIn("SAFE_TEST_IMAGE: ${{ steps.preflight.outputs.image }}", self.preparation)

    def test_pull_precedes_checkout(self):
        self.assertLess(self.text.index("docker pull"), self.text.index(f"uses: {CHECKOUT}"))

    def test_inspection_precedes_checkout(self):
        self.assertLess(self.text.index("docker image inspect"), self.text.index(f"uses: {CHECKOUT}"))
        self.assertLess(self.text.index('if [[ "$version_entries" -ne 1 ]]'), self.text.index(f"uses: {CHECKOUT}"))

    def test_metadata_os_is_linux(self):
        self.assertIn("image_os=$(inspect_field '{{json .Os}}')", self.preparation)
        self.assertIn('"$image_os" != \'"linux"\'', self.preparation)

    def test_metadata_arch_is_amd64(self):
        self.assertIn("image_arch=$(inspect_field '{{json .Architecture}}')", self.preparation)
        self.assertIn('"$image_arch" != \'"amd64"\'', self.preparation)

    def test_metadata_entrypoint_empty_only(self):
        self.assertIn("image_entrypoint=$(inspect_field '{{json .Config.Entrypoint}}')", self.preparation)
        self.assertIn('( "$image_entrypoint" != \'null\' && "$image_entrypoint" != \'[]\' )', self.preparation)

    def test_metadata_cmd_exact_python3(self):
        self.assertIn("image_cmd=$(inspect_field '{{json .Config.Cmd}}')", self.preparation)
        self.assertIn('"$image_cmd" != \'["python3"]\'', self.preparation)

    def test_metadata_user_empty(self):
        self.assertIn("image_user=$(inspect_field '{{json .Config.User}}')", self.preparation)
        self.assertIn('"$image_user" != \'""\'', self.preparation)

    def test_metadata_workdir_empty(self):
        self.assertIn("image_workdir=$(inspect_field '{{json .Config.WorkingDir}}')", self.preparation)
        self.assertIn('"$image_workdir" != \'""\'', self.preparation)

    def test_metadata_volumes_forbidden(self):
        self.assertIn("image_volumes=$(inspect_field '{{json .Config.Volumes}}')", self.preparation)
        self.assertIn('( "$image_volumes" != \'null\' && "$image_volumes" != \'{}\' ) ]]; then\n'
                      "            printf '%s\\n' 'FAIL: unexpected image metadata.'\n"
                      "            exit 1\n          fi", self.preparation)

    def test_image_env_python_version_exactly_once(self):
        self.assertIn('if [[ "$entry" != "PYTHON_VERSION=$SAFE_TEST_PYTHON_VERSION" ]]; then\n'
                      "                printf '%s\\n' 'FAIL: unexpected image Python version.'\n"
                      "                exit 1", self.preparation)
        self.assertIn('version_entries=$((version_entries + 1))', self.preparation)
        self.assertIn('if [[ "$version_entries" -ne 1 ]]; then\n'
                      "            printf '%s\\n' 'FAIL: missing or duplicate image Python version.'\n"
                      "            exit 1", self.preparation)
        self.assertIn("SAFE_TEST_PYTHON_VERSION: ${{ steps.preflight.outputs.python_version }}", self.preparation)

    def test_credential_like_image_env_fails(self):
        self.assertIn('case "${env_name^^}" in', self.preparation)
        self.assertIn('GITHUB_*|ACTIONS_*|AWS_*|AZURE_*|GOOGLE_*|SSH_*|DOCKER_AUTH_CONFIG|*TOKEN*|*SECRET*|*PASSWORD*|*CREDENTIAL*|*API_KEY*|*PRIVATE_KEY*)\n'
                      "                printf '%s\\n' 'FAIL: credential-like image environment.'\n"
                      "                exit 1", self.preparation)
        self.assertNotRegex(self.preparation, r"(?:printf|echo)[^\n]*\$(?:image_env|entry)")

    def test_inspect_failure_fails_closed(self):
        self.assertIn('docker image inspect --format "$1" "$SAFE_TEST_IMAGE" 2>/dev/null', self.preparation)
        self.assertIn("if ! image_os=$(inspect_field", self.preparation)
        self.assertEqual(self.preparation.count("! image_"), 9)
        self.assertIn("! image_env=$(inspect_field '{{range .Config.Env}}{{println .}}{{end}}'); then\n"
                      "            printf '%s\\n' 'FAIL: image metadata inspection unavailable.'\n"
                      "            exit 1", self.preparation)

    def test_runtime_image_and_platform_are_fixed(self):
        self.assertIn('"$SAFE_TEST_IMAGE" python -B -m unittest tests.test_integrity_gate -v', self.docker)
        self.assertEqual(re.findall(r"--platform\s+(\S+)", self.docker), ["linux/amd64"])
        self.assertIn("--pull never", self.docker)

    def test_candidate_cannot_supply_image_or_platform(self):
        self.assertNotIn("inputs.", self.preparation)
        self.assertNotIn("/candidate", self.preparation)
        self.assertNotIn("GITHUB_WORKSPACE", self.preparation)
        self.assertNotRegex(self.trigger, r"(?m)^\s*(image|registry|repository|platform|python_version):")

    def test_no_registry_login_or_build(self):
        self.assertNotRegex(self.text, r"docker\s+(?:login|build)|--password|--config\s")

    def test_global_expression_allowlist(self):
        require_expression_allowlist(self.text)

    def test_unapproved_expressions_rejected_in_alternative_yaml(self):
        for expression in ("github.token", "github.event.inputs.candidate_sha", "secrets.X",
                           "vars.X", "env.MALICIOUS", "inputs.command"):
            token = "${{ " + expression + " }}"
            for snippet in ("run : |\n  echo '" + token + "'\n",
                            "-   run: echo '" + token + "'\n",
                            "- { run: '" + token + "' }\n",
                            "env:\n  EXTRA: '" + token + "'\n"):
                for position in (0, len(self.text) // 2, len(self.text)):
                    mutated = self.text[:position] + snippet + self.text[position:]
                    with self.subTest(expression=expression, snippet=snippet, position=position):
                        with self.assertRaises(AssertionError):
                            require_expression_allowlist(mutated)

    def test_allowed_expression_replacement_rejected(self):
        for original in ALLOWED_EXPRESSIONS:
            mutated = self.text.replace(original, "${{ github.token }}", 1)
            with self.subTest(original=original), self.assertRaises(AssertionError):
                require_expression_allowlist(mutated)

    def test_additional_allowed_expression_also_rejected(self):
        with self.assertRaises(AssertionError):
            require_expression_allowlist(self.text + "\n- { run: '${{ inputs.candidate_sha }}' }\n")

    def test_unterminated_expression_rejected(self):
        with self.assertRaises(AssertionError):
            require_expression_allowlist(self.text + "\nrun: '${{ github.token'\n")

    def test_cleanup_masks_signals_before_removal(self):
        cleanup = self.execution.split("          cleanup() {\n", 1)[1].split("          }\n", 1)[0]
        self.assertTrue(cleanup.startswith("            local original_exit=$?\n"
                                          "            trap - EXIT\n"
                                          "            trap '' INT TERM\n"))
        self.assertLess(cleanup.index("trap '' INT TERM"), cleanup.index("docker rm --force"))
        self.assertLess(cleanup.index("docker rm --force"), cleanup.index("docker container ls --all"))
        self.assertIn('exit "$original_exit"', cleanup)
        self.assertIn('exit "$cleanup_failed"', cleanup)

    def test_metadata_complete_logical_contract(self):
        require_metadata_contract(self.preparation)

    def test_each_inspection_or_to_and_mutation_rejected(self):
        for match in re.finditer(r"\|\|", EXPECTED_INSPECTION):
            changed = EXPECTED_INSPECTION[:match.start()] + "&&" + EXPECTED_INSPECTION[match.end():]
            with self.subTest(offset=match.start()), self.assertRaises(AssertionError):
                require_metadata_contract(self.preparation.replace(EXPECTED_INSPECTION, changed, 1))

    def test_each_metadata_operator_mutation_rejected(self):
        for match in re.finditer(r"\|\||&&|!=", EXPECTED_METADATA):
            replacement = {"||": "&&", "&&": "||", "!=": "=="}[match.group()]
            changed = EXPECTED_METADATA[:match.start()] + replacement + EXPECTED_METADATA[match.end():]
            with self.subTest(offset=match.start()), self.assertRaises(AssertionError):
                require_metadata_contract(self.preparation.replace(EXPECTED_METADATA, changed, 1))

    def test_env_condition_and_failure_mutations_rejected(self):
        for before, after in (("!=", "=="), ("==", "!="), ("-ne 1", "-eq 1"),
                              ("version_entries + 1", "version_entries + 0"),
                              ("GITHUB_*|ACTIONS_*", "ACTIONS_*"), ("exit 1", "exit 0")):
            self.assertIn(before, EXPECTED_ENV)
            changed = EXPECTED_ENV.replace(before, after, 1)
            with self.subTest(before=before), self.assertRaises(AssertionError):
                require_metadata_contract(self.preparation.replace(EXPECTED_ENV, changed, 1))

    def test_healthcheck_read_and_null_required_before_checkout(self):
        self.assertIn('! image_healthcheck=$(inspect_field \'{{json (index .Config "Healthcheck")}}\') ||', self.preparation)
        self.assertIn('"$image_healthcheck" != \'null\' ||', self.preparation)
        require_metadata_contract(self.preparation)
        self.assertLess(self.text.index('! image_healthcheck='), self.text.index(f"uses: {CHECKOUT}"))

    def test_healthcheck_presence_acceptance_mutation_rejected(self):
        for replacement in ('"$image_healthcheck" == \'null\'', '"$image_healthcheck" != \'{}\''):
            mutated = self.preparation.replace('"$image_healthcheck" != \'null\'', replacement, 1)
            with self.subTest(replacement=replacement), self.assertRaises(AssertionError):
                require_metadata_contract(mutated)

    def test_healthcheck_inspection_removal_rejected(self):
        line = next(line for line in EXPECTED_INSPECTION.splitlines(keepends=True) if "image_healthcheck=" in line)
        with self.assertRaises(AssertionError):
            require_metadata_contract(self.preparation.replace(line, "", 1))

    def test_shared_memory_is_bounded_and_restricted(self):
        self.assertIn("--tmpfs /dev/shm:rw,noexec,nosuid,nodev,size=16m,mode=1777 \\\n", self.docker)


if __name__ == "__main__":
    unittest.main()
