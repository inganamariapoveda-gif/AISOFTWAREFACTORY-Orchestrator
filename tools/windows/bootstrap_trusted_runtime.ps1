param(
    [switch]$Preflight,
    [switch]$DryRun,
    [string]$ManifestPath,
    [string]$ApprovedSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# CODE_EXISTS != WINDOWS_MUTATION_AUTHORIZED. No mutation mode exists.
# Future elevated execution MUST start with absolute system cmd.exe /d,
# native environment/profile admission BEFORE CLR/PowerShell, then admin staging,
# flush/readback and approved SHA of the PROTECTED copy. Never elevate this repo file.
if (($Preflight -and $DryRun) -or (-not $Preflight -and -not $DryRun)) {
    Write-Output 'BLOCKED_REAL_MUTATION_NOT_IMPLEMENTED'
    exit 2
}
try {
    if (-not $ManifestPath) { throw 'missing' }
    $item = Get-Item -LiteralPath $ManifestPath
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 4194304) { throw 'invalid' }
    $raw = [IO.File]::ReadAllBytes($item.FullName)
    $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $document = $utf8.GetString($raw) | ConvertFrom-Json
    if ($document.installable -eq $false) {
        Write-Output 'NOT_INSTALLABLE_TEMPLATE'
        exit 2
    }
    if ($ApprovedSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'missing' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actual = ([BitConverter]::ToString($sha.ComputeHash($raw))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($actual -cne $ApprovedSha256) { throw 'mismatch' }
    # Hash match alone is never installation authority. Complete native launch
    # audit, source provenance, SID/ACL/LSA/task admission remain external gates.
    Write-Output 'BLOCKED_REAL_MUTATION_NOT_IMPLEMENTED'
    Write-Output 'DRY_RUN_PLAN: GATE1_1A; MIGRATION_STOP; GATE1_1B; GATE2_VALIDATION; GATE3_OPERATION'
    exit 2
} catch {
    Write-Output 'BLOCKED_PREFLIGHT_INPUT'
    exit 2
}
