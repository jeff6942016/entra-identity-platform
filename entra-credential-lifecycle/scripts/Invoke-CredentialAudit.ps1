#requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Audit the credential posture of every application registration in an Entra
    tenant, read-only, and report which ones still rely on a standing client secret.

.DESCRIPTION
    Connects to Microsoft Graph with read scopes only, enumerates every application
    registration, flattens its credentials (client secrets, certificates, federated
    identity credentials) with age and expiry, and gives each application a
    deterministic posture verdict. A standing client secret is ranked high, a
    certificate low, and workload identity federation with no standing credential is
    the goal state. Writes a per-credential CSV and a per-application HTML report.

.PARAMETER OutputDir
    Where to write credential-report.csv and credential-report.html. Defaults to ../output.

.PARAMETER PolicyPath
    The credential policy JSON. Defaults to ../policy/credential-policy.json.

.EXAMPLE
    ./Invoke-CredentialAudit.ps1
#>
[CmdletBinding()]
param(
    [string] $OutputDir  = (Join-Path $PSScriptRoot '..' 'output'),
    [string] $PolicyPath = (Join-Path $PSScriptRoot '..' 'policy' 'credential-policy.json')
)

$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'CredentialLifecycle.psm1') -Force

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
$policy = Get-Content -Path $PolicyPath -Raw | ConvertFrom-Json

$ctx = Connect-CredGraph
Write-Host ("Connected to tenant {0} as {1}" -f $ctx.TenantId, $ctx.Account) -ForegroundColor Green

$audit = Get-AppCredentials -Policy $policy

$csvPath  = Join-Path $OutputDir 'credential-report.csv'
$htmlPath = Join-Path $OutputDir 'credential-report.html'
Export-CredentialReport -Audit $audit -CsvPath $csvPath -HtmlPath $htmlPath -TenantId $ctx.TenantId

# Console summary, worst posture first.
$order = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }
Write-Host ''
Write-Host 'Credential posture summary:' -ForegroundColor Cyan
$audit.Apps | Group-Object PostureTier |
    Sort-Object { $order[$_.Name] } -Descending |
    ForEach-Object { Write-Host ("  {0,-8} {1}" -f $_.Name, $_.Count) }

$standing = @($audit.Apps | Where-Object { $_.SecretCount -gt 0 }).Count
$expired  = @($audit.Credentials | Where-Object { $_.Status -eq 'Expired' }).Count

Write-Host ''
Write-Host ("Audited {0} application registrations, {1} credentials." -f @($audit.Apps).Count, @($audit.Credentials).Count) -ForegroundColor Green
Write-Host ("  Apps with a standing client secret: {0}" -f $standing)
Write-Host ("  Expired credentials still attached: {0}" -f $expired)
Write-Host ("  CSV:  {0}" -f $csvPath)
Write-Host ("  HTML: {0}" -f $htmlPath)
