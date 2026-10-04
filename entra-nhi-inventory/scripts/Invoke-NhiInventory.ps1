#requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Discover and risk-rank every non-human identity (service principal and app
    registration) in a Microsoft Entra tenant, read-only.

.DESCRIPTION
    Connects to Microsoft Graph with read scopes only, enumerates all service
    principals (following pagination), gathers posture evidence for each (granted
    application permissions, credential type and age, owners, federation, origin,
    dormancy), applies a deterministic tiered risk policy, and writes a CSV plus a
    self-contained HTML report.

    The scanner never requests a write scope, so it is itself a minimal,
    least-privilege non-human identity that cannot change what it inventories.

.PARAMETER OutputDir
    Where to write inventory.csv and inventory.html. Defaults to ../output.

.PARAMETER PolicyPath
    The risk policy JSON. Defaults to ../policy/high-privilege-app-roles.json.

.PARAMETER IncludeMicrosoftFirstParty
    Include Microsoft first-party apps. Off by default so the report covers only the
    identities the tenant is accountable for.

.PARAMETER SkipSignInActivity
    Skip the beta sign-in-activity lookup (faster, and avoids per-identity beta calls
    in tenants where the report is unavailable). Dormancy is then reported as unknown.

.EXAMPLE
    ./Invoke-NhiInventory.ps1

.EXAMPLE
    ./Invoke-NhiInventory.ps1 -IncludeMicrosoftFirstParty -OutputDir C:\temp\nhi
#>
[CmdletBinding()]
param(
    [string] $OutputDir  = (Join-Path $PSScriptRoot '..' 'output'),
    [string] $PolicyPath = (Join-Path $PSScriptRoot '..' 'policy' 'high-privilege-app-roles.json'),
    [switch] $IncludeMicrosoftFirstParty,
    [switch] $SkipSignInActivity
)

$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'NhiInventory.psm1') -Force

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
$policy = Get-Content -Path $PolicyPath -Raw | ConvertFrom-Json

$ctx = Connect-NhiGraph
Write-Host ("Connected to tenant {0} as {1}" -f $ctx.TenantId, $ctx.Account) -ForegroundColor Green

$inventory = Get-NhiInventory -TenantId $ctx.TenantId `
    -IncludeMicrosoftFirstParty:$IncludeMicrosoftFirstParty `
    -SkipSignInActivity:$SkipSignInActivity

# Score each identity and attach the verdict.
foreach ($nhi in $inventory) {
    $risk = Get-NhiRisk -Nhi $nhi -Policy $policy
    $nhi | Add-Member -NotePropertyName RiskTier    -NotePropertyValue $risk.RiskTier    -Force
    $nhi | Add-Member -NotePropertyName RiskReasons -NotePropertyValue $risk.RiskReasons -Force
}

$csvPath  = Join-Path $OutputDir 'inventory.csv'
$htmlPath = Join-Path $OutputDir 'inventory.html'
Export-NhiReport -Inventory $inventory -CsvPath $csvPath -HtmlPath $htmlPath -TenantId $ctx.TenantId

# Console summary, worst first.
$order = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }
Write-Host ''
Write-Host 'Risk summary:' -ForegroundColor Cyan
$inventory | Group-Object RiskTier |
    Sort-Object { $order[$_.Name] } -Descending |
    ForEach-Object { Write-Host ("  {0,-8} {1}" -f $_.Name, $_.Count) }

Write-Host ''
Write-Host ("Inventoried {0} non-human identities." -f @($inventory).Count) -ForegroundColor Green
Write-Host ("  CSV:  {0}" -f $csvPath)
Write-Host ("  HTML: {0}" -f $htmlPath)
