param([switch]$DryRun, [switch]$ProbePlan)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Plan only. Future privileged use requires the SAME native launch/profile audit,
# admin staging, protected copy, flush/readback, approved SHA, absolute execution.
# Never elevate directly from the repository. No probe action executes here.
if (($DryRun -and $ProbePlan) -or (-not $DryRun -and -not $ProbePlan)) {
    Write-Output 'BLOCKED_REAL_MUTATION_NOT_IMPLEMENTED'
    exit 2
}
$targets = @(
 'runtime-write', 'runtime-replace', 'python-replace', 'authority-write',
 'authority-delete-replace', 'secrets-read', 'secrets-replace', 'captures-write-delete',
 'task-modify-delete', 'task-policy-demand-disabled', 'canary-task-DACL-Run-RunEx',
 'dangerous-OpenProcess', 'token-duplicate-impersonate', 'protected-import-config',
 'inbox-hardlink-reparse', 'inbox-retained-writer', 'inbox-post-capture-mutation',
 'owner-rights-no-WRITE_DAC', 'capture-no-DELETE_CHILD', 'hostile-inbox-corpus',
 'builder-DLL-decoy-not-loaded', 'synthetic-mid-capture-termination',
 'activation-write-denied', 'expired-window-rejected', 'effective-principal-root-access',
 'protected-file-create-denied', 'protected-directory-create-denied',
 'protected-hardlink-denied-or-not-admitted', 'protected-ancestor-rename-delete-denied',
 'runtime-profile-access-denied', 'protected-folder-task-registration-denied',
 'effective-LSA-group-rights', 'old-activation-rollback-rejected',
 'builder-migration', 'admin-session-no-agents', 'runtime-SID-nonadmin',
 'batch-Scheduler-start', 'protected-interpreter-modules', 'isolated-sys-path',
 'exact-Scheduler-semantic-XML-SD', 'synthetic-exact-capture', 'durable-CAPTURED',
 'SQLite-auxiliary-lifecycle', 'DPAPI-synthetic-future-only', 'tampered-capture-rejected',
 'poison-file-continues', 'noninteractive', 'exit-before-hard-limit',
 'independent-manifest-reproduction', 'fresh-operational-data'
)
foreach ($target in $targets) {
    [pscustomobject]@{
        probe = $target
        mode = 'PLAN_ONLY_NOT_EXECUTED'
        identity_first = 'SID,elevation,integrity,groups,deny-only,privileges,session'
        prerequisites = 'target-exists;authorized-positive-control;no-netonly'
        pass_rule = 'specific-expected-code;missing-disabled-unrelated-sharing-is-not-PASS'
        cleanup = 'close-handles;preserve-protected-evidence;no-automatic-delete'
    } | ConvertTo-Json -Compress
}
