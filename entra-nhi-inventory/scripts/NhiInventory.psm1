#requires -Modules Microsoft.Graph.Authentication
<#
    NhiInventory.psm1

    Read-only helper module for the Entra non-human identity (NHI) inventory.
    Imported by Invoke-NhiInventory.ps1. Nothing here writes to the tenant: every
    Graph call is a GET and the connection requests read scopes only, so the
    scanner is itself a minimal, least-privilege non-human identity that cannot
    change what it inventories.
#>

$ErrorActionPreference = 'Stop'

# Microsoft Graph's own service principal appId (the usual resource behind app-role grants).
$script:GraphAppId = '00000003-0000-0000-c000-000000000000'
# Microsoft's home tenant. Any app owned by this tenant is a Microsoft first-party app.
$script:MicrosoftTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'

# appRoleId GUID -> permission value, cached per resource SP so a resource's roles
# are resolved from Graph only once.
$script:AppRoleCache = @{}

$script:TierNames = @('info', 'low', 'medium', 'high', 'critical')
$script:TierRank  = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }

function Connect-NhiGraph {
    <#
        Connect to Microsoft Graph with the least scopes the inventory needs:
          Application.Read.All  read app registrations and service principals
          Directory.Read.All    read owners and directory objects
          AuditLog.Read.All     read service-principal sign-in activity (dormancy)
        No write scope is ever requested, so the scanner structurally cannot
        modify the identities it inspects.
    #>
    param(
        [string[]] $Scopes = @('Application.Read.All', 'Directory.Read.All', 'AuditLog.Read.All')
    )
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        Connect-MgGraph -Scopes $Scopes -NoWelcome | Out-Null
        $ctx = Get-MgContext
    }
    return $ctx
}

function Get-GraphAllPages {
    <# GET a Graph collection, following @odata.nextLink until the collection is exhausted. #>
    param(
        [Parameter(Mandatory)] [string] $Uri
    )
    $items = @()
    $next = $Uri
    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
        if ($resp.value) { $items += $resp.value }
        $next = $resp.'@odata.nextLink'
    }
    return $items
}

function Get-ResourceAppRoleMap {
    <# Build/return a {appRoleId -> value} map for a resource service principal (e.g. Microsoft Graph). #>
    param(
        [Parameter(Mandatory)] [string] $ResourceSpId
    )
    if (-not $script:AppRoleCache.ContainsKey($ResourceSpId)) {
        $map = @{}
        try {
            $sp = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
                -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/' + $ResourceSpId + '?$select=appRoles,displayName')
            foreach ($r in $sp.appRoles) { $map[$r.id] = $r.value }
        } catch {
            # If the resource SP cannot be read, leave the map empty; callers fall back to the GUID.
        }
        $script:AppRoleCache[$ResourceSpId] = $map
    }
    return $script:AppRoleCache[$ResourceSpId]
}

function Resolve-GrantedRoles {
    <# Turn appRoleAssignments (GUIDs) into readable permission values where possible. #>
    param(
        [Parameter()] [AllowNull()] $Assignments
    )
    $names = @()
    foreach ($a in @($Assignments)) {
        if (-not $a) { continue }
        $map = Get-ResourceAppRoleMap -ResourceSpId $a.resourceId
        $value = if ($map.ContainsKey($a.appRoleId)) { $map[$a.appRoleId] } else { $a.appRoleId }
        $names += $value
    }
    return @($names | Sort-Object -Unique)
}

function Get-CredentialFacts {
    <# Summarise passwordCredentials (secrets) and keyCredentials (certs): counts, expiry, age. #>
    param(
        [Parameter()] [AllowNull()] $PasswordCredentials,
        [Parameter()] [AllowNull()] $KeyCredentials
    )
    $now = (Get-Date).ToUniversalTime()
    $secrets = @($PasswordCredentials | Where-Object { $_ })
    $certs   = @($KeyCredentials | Where-Object { $_ })

    $hasExpired = $false
    $oldestStart = $null
    foreach ($c in ($secrets + $certs)) {
        if ($c.endDateTime -and ([datetime]$c.endDateTime) -lt $now) { $hasExpired = $true }
        if ($c.startDateTime) {
            $start = [datetime]$c.startDateTime
            if ($null -eq $oldestStart -or $start -lt $oldestStart) { $oldestStart = $start }
        }
    }
    $maxAgeDays = if ($oldestStart) { [int]([math]::Round(($now - $oldestStart).TotalDays)) } else { $null }

    return [pscustomobject]@{
        SecretCount             = $secrets.Count
        CertCount               = $certs.Count
        HasExpiredCredential    = $hasExpired
        OldestCredentialAgeDays = $maxAgeDays
    }
}

function Get-LastSignInDays {
    <#
        Service-principal sign-in activity is a BETA report and is unavailable in many
        tenants. Returns whole days since the most recent sign-in, or $null when the
        report cannot be read, so dormancy is reported as "unknown" rather than
        wrongly as "active".
    #>
    param(
        [Parameter(Mandatory)] [string] $AppId
    )
    try {
        $filter = [uri]::EscapeDataString("appId eq '$AppId'")
        $resp = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
            -Uri ('https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?$filter=' + $filter)
        $row = @($resp.value)[0]
        if (-not $row) { return $null }

        $dates = @()
        foreach ($prop in $row.PSObject.Properties) {
            $val = $prop.Value
            if ($val -and ($val.PSObject.Properties.Name -contains 'lastSignInDateTime') -and $val.lastSignInDateTime) {
                $dates += [datetime]$val.lastSignInDateTime
            }
        }
        if ($dates.Count -eq 0) { return $null }
        $last = ($dates | Sort-Object -Descending)[0]
        return [int]([math]::Round(((Get-Date).ToUniversalTime() - $last).TotalDays))
    } catch {
        return $null
    }
}

function Get-NhiOrigin {
    <# Classify where the identity comes from, which changes how its privilege should be read. #>
    param(
        [AllowEmptyString()] [AllowNull()] [string] $AppOwnerOrganizationId,
        [Parameter(Mandatory)] [string] $TenantId,
        [AllowEmptyString()] [AllowNull()] [string] $ServicePrincipalType
    )
    if ($ServicePrincipalType -eq 'ManagedIdentity') { return 'ManagedIdentity' }
    if ($AppOwnerOrganizationId -eq $script:MicrosoftTenantId) { return 'MicrosoftFirstParty' }
    if ($AppOwnerOrganizationId -eq $TenantId) { return 'InTenant' }
    if ([string]::IsNullOrEmpty($AppOwnerOrganizationId)) { return 'Unknown' }
    return 'ThirdParty'
}

function Get-NhiInventory {
    <#
        Enumerate every service principal in the tenant and gather, for each, the
        evidence a security reviewer needs: granted application permissions, credential
        posture, owners, federation, origin, enabled state, and sign-in dormancy.
        Microsoft first-party apps are excluded by default, because a hygiene inventory
        is about the identities the tenant is accountable for, not the hundreds of
        pre-consented Microsoft apps.
    #>
    param(
        [Parameter(Mandatory)] [string] $TenantId,
        [switch] $IncludeMicrosoftFirstParty,
        [switch] $SkipSignInActivity
    )

    Write-Host 'Enumerating service principals...' -ForegroundColor Cyan
    $spSelect = 'id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,passwordCredentials,keyCredentials'
    $sps = Get-GraphAllPages -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals?$select=' + $spSelect + '&$top=100')
    Write-Host ("  found {0} service principals" -f $sps.Count) -ForegroundColor DarkGray

    Write-Host 'Enumerating application registrations...' -ForegroundColor Cyan
    $apps = Get-GraphAllPages -Uri 'https://graph.microsoft.com/v1.0/applications?$select=id,appId&$top=100'
    $appObjByAppId = @{}
    foreach ($a in $apps) { $appObjByAppId[$a.appId] = $a.id }
    Write-Host ("  found {0} application registrations" -f $apps.Count) -ForegroundColor DarkGray

    $results = @()
    $i = 0
    foreach ($sp in $sps) {
        $i++
        $origin = Get-NhiOrigin -AppOwnerOrganizationId ([string]$sp.appOwnerOrganizationId) -TenantId $TenantId -ServicePrincipalType ([string]$sp.servicePrincipalType)
        if ($origin -eq 'MicrosoftFirstParty' -and -not $IncludeMicrosoftFirstParty) { continue }

        Write-Progress -Activity 'Gathering NHI evidence' -Status $sp.displayName -PercentComplete (($i / [math]::Max($sps.Count, 1)) * 100)

        # Granted application permissions (app-role assignments on this SP).
        $assignments = Get-GraphAllPages -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/' + $sp.id + '/appRoleAssignments?$select=appRoleId,resourceId,resourceDisplayName')
        $grantedRoles = Resolve-GrantedRoles -Assignments $assignments

        # Owners (accountability).
        $owners = Get-GraphAllPages -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/' + $sp.id + '/owners?$select=id,userPrincipalName,displayName')

        # Credentials come off the SP; federation lives on the application object (if one exists in-tenant).
        $cred = Get-CredentialFacts -PasswordCredentials $sp.passwordCredentials -KeyCredentials $sp.keyCredentials
        $fedCount = 0
        if ($appObjByAppId.ContainsKey($sp.appId)) {
            $fed = Get-GraphAllPages -Uri ('https://graph.microsoft.com/v1.0/applications/' + $appObjByAppId[$sp.appId] + '/federatedIdentityCredentials')
            $fedCount = @($fed).Count
        }

        $signIn = if ($SkipSignInActivity) { $null } else { Get-LastSignInDays -AppId $sp.appId }

        $results += [pscustomobject]@{
            DisplayName              = $sp.displayName
            AppId                    = $sp.appId
            ObjectId                 = $sp.id
            ServicePrincipalType     = [string]$sp.servicePrincipalType
            Origin                   = $origin
            Enabled                  = [bool]$sp.accountEnabled
            GrantedRoles             = $grantedRoles
            GrantedRoleCount         = $grantedRoles.Count
            OwnerCount               = @($owners).Count
            SecretCount              = $cred.SecretCount
            CertCount                = $cred.CertCount
            FederatedCredentialCount = $fedCount
            HasExpiredCredential     = $cred.HasExpiredCredential
            OldestCredentialAgeDays  = $cred.OldestCredentialAgeDays
            DaysSinceSignIn          = $signIn
        }
    }
    Write-Progress -Activity 'Gathering NHI evidence' -Completed
    return $results
}

function Get-NhiRisk {
    <#
        Deterministic, tiered risk verdict for one NHI. Each rule can only raise the
        tier, never lower it, so the final verdict is the worst thing true about the
        identity. The privileged-permission watchlist is data (policy JSON); the
        structural rules (ownership, standing secrets, dormancy, cleanup) are here.
    #>
    param(
        [Parameter(Mandatory)] $Nhi,
        [Parameter(Mandatory)] $Policy
    )
    $cur = 0
    $reasons = @()

    # Rule 1: privileged application permissions held (from the policy watchlist).
    foreach ($role in @($Nhi.GrantedRoles)) {
        $tier = $Policy.appRoleTiers.$role
        if ($tier) {
            $reasons += ("holds {0} ({1})" -f $role, $tier)
            if ($script:TierRank[$tier] -gt $cur) { $cur = $script:TierRank[$tier] }
        }
    }

    # Rule 2: no accountable owner on an in-tenant app identity.
    if ($Nhi.OwnerCount -eq 0 -and $Nhi.Origin -eq 'InTenant' -and $Nhi.ServicePrincipalType -eq 'Application') {
        $reasons += 'no accountable owner'
        if ($script:TierRank['high'] -gt $cur) { $cur = $script:TierRank['high'] }
    }

    # Rule 3: a standing client secret is a long-lived bearer credential with no user and
    # no MFA. Only an *enabled* identity can authenticate, so the active-exposure verdict
    # applies to enabled identities; a secret on a disabled identity is caught as cleanup
    # by Rule 6 instead.
    if ($Nhi.SecretCount -gt 0 -and $Nhi.Enabled) {
        $note = if ($Nhi.FederatedCredentialCount -gt 0) {
            "standing client secret present despite federation ({0})" -f $Nhi.SecretCount
        } else {
            "{0} standing client secret(s)" -f $Nhi.SecretCount
        }
        $reasons += $note
        if ($script:TierRank['high'] -gt $cur) { $cur = $script:TierRank['high'] }
    }

    # Rule 4: dormant but still credentialed (an unused identity that can still be used).
    # Dormancy is an exposure only while the identity can still authenticate.
    $dormantDays = [int]$Policy.thresholds.dormantDays
    if ($Nhi.Enabled -and $null -ne $Nhi.DaysSinceSignIn -and $Nhi.DaysSinceSignIn -ge $dormantDays -and ($Nhi.SecretCount + $Nhi.CertCount) -gt 0) {
        $reasons += ("dormant {0}d but still credentialed" -f $Nhi.DaysSinceSignIn)
        if ($script:TierRank['high'] -gt $cur) { $cur = $script:TierRank['high'] }
    }

    # Rule 5: expired credential still attached (hygiene / stale object).
    if ($Nhi.HasExpiredCredential) {
        $reasons += 'expired credential still attached'
        if ($script:TierRank['medium'] -gt $cur) { $cur = $script:TierRank['medium'] }
    }

    # Rule 6: disabled identity that still holds credentials (should be cleaned up).
    if (-not $Nhi.Enabled -and ($Nhi.SecretCount + $Nhi.CertCount) -gt 0) {
        $reasons += 'disabled but still credentialed'
        if ($script:TierRank['medium'] -gt $cur) { $cur = $script:TierRank['medium'] }
    }

    if ($reasons.Count -eq 0) { $reasons = @('no risk rule triggered') }

    return [pscustomobject]@{
        RiskTier    = $script:TierNames[$cur]
        RiskReasons = ($reasons -join '; ')
    }
}

function Export-NhiReport {
    <# Write the inventory to a CSV (for pivoting) and a self-contained HTML report (for reading). #>
    param(
        [Parameter(Mandatory)] $Inventory,
        [Parameter(Mandatory)] [string] $CsvPath,
        [Parameter(Mandatory)] [string] $HtmlPath,
        [Parameter(Mandatory)] [string] $TenantId
    )

    $byRisk = @{ Expression = { $script:TierRank[$_.RiskTier] }; Descending = $true }
    $byName = @{ Expression = 'DisplayName'; Descending = $false }

    $flat = $Inventory | Select-Object `
        DisplayName, AppId, ObjectId, ServicePrincipalType, Origin, Enabled, RiskTier,
        @{ n = 'GrantedRoles'; e = { ($_.GrantedRoles -join ', ') } },
        OwnerCount, SecretCount, CertCount, FederatedCredentialCount,
        HasExpiredCredential, OldestCredentialAgeDays, DaysSinceSignIn, RiskReasons

    $flat | Sort-Object -Property $byRisk, $byName | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

    # Summary counts by tier.
    $counts = @{}
    foreach ($t in $script:TierNames) { $counts[$t] = 0 }
    foreach ($row in $Inventory) { $counts[$row.RiskTier]++ }

    $tierColor = @{ critical = '#C0392B'; high = '#E67E22'; medium = '#F1C40F'; low = '#3498DB'; info = '#7F8C8D' }

    $cards = ''
    foreach ($t in ($script:TierNames | Sort-Object { $script:TierRank[$_] } -Descending)) {
        $cards += ('<div class="card" style="border-top:4px solid {0}"><div class="n">{1}</div><div class="l">{2}</div></div>' -f $tierColor[$t], $counts[$t], $t.ToUpper())
    }

    $rows = ''
    foreach ($row in ($Inventory | Sort-Object -Property $byRisk, $byName)) {
        $name    = [System.Net.WebUtility]::HtmlEncode([string]$row.DisplayName)
        $roles   = [System.Net.WebUtility]::HtmlEncode(($row.GrantedRoles -join ', '))
        $reasons = [System.Net.WebUtility]::HtmlEncode([string]$row.RiskReasons)
        $dorm    = if ($null -eq $row.DaysSinceSignIn) { 'unknown' } else { "$($row.DaysSinceSignIn)d" }
        $color   = $tierColor[$row.RiskTier]
        $rows += @"
<tr>
  <td><span class="pill" style="background:$color">$($row.RiskTier)</span></td>
  <td>$name</td>
  <td>$($row.Origin)</td>
  <td>$($row.ServicePrincipalType)</td>
  <td class="c">$($row.SecretCount)</td>
  <td class="c">$($row.CertCount)</td>
  <td class="c">$($row.FederatedCredentialCount)</td>
  <td class="c">$($row.OwnerCount)</td>
  <td class="c">$dorm</td>
  <td>$roles</td>
  <td>$reasons</td>
</tr>
"@
    }

    $generated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC'
    $total = @($Inventory).Count

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra NHI Inventory</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 2rem; background:#fff; color:#1a1a1a; }
  @media (prefers-color-scheme: dark) { body { background:#14171a; color:#e6e6e6; } th, td { border-color:#333 !important; } }
  h1 { font-size: 1.4rem; margin-bottom: .2rem; }
  .meta { color:#888; font-size:.85rem; margin-bottom:1.2rem; }
  .cards { display:flex; gap:.6rem; flex-wrap:wrap; margin-bottom:1.4rem; }
  .card { min-width:90px; padding:.6rem .9rem; border-radius:8px; background:rgba(127,127,127,.08); }
  .card .n { font-size:1.6rem; font-weight:700; }
  .card .l { font-size:.7rem; letter-spacing:.05em; color:#888; }
  table { border-collapse: collapse; width:100%; font-size:.82rem; }
  th, td { border:1px solid #e3e3e3; padding:.4rem .5rem; text-align:left; vertical-align:top; }
  th { background:rgba(127,127,127,.1); position:sticky; top:0; }
  td.c { text-align:center; }
  .pill { color:#fff; padding:.1rem .5rem; border-radius:999px; font-size:.72rem; font-weight:600; text-transform:uppercase; }
</style>
</head>
<body>
  <h1>Entra Non-Human Identity Inventory</h1>
  <div class="meta">Tenant $TenantId &middot; $total identities &middot; generated $generated &middot; read-only scan</div>
  <div class="cards">$cards</div>
  <table>
    <thead><tr>
      <th>Risk</th><th>Display name</th><th>Origin</th><th>Type</th>
      <th>Secrets</th><th>Certs</th><th>Fed</th><th>Owners</th><th>Last sign-in</th>
      <th>Granted application permissions</th><th>Why</th>
    </tr></thead>
    <tbody>$rows</tbody>
  </table>
</body>
</html>
"@

    $html | Out-File -FilePath $HtmlPath -Encoding UTF8
}

Export-ModuleMember -Function Connect-NhiGraph, Get-NhiInventory, Get-NhiRisk, Export-NhiReport
