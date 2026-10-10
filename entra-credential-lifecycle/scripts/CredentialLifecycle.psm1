#requires -Modules Microsoft.Graph.Authentication
<#
    CredentialLifecycle.psm1

    Read-only helper module for the Entra credential-lifecycle audit. Imported by
    Invoke-CredentialAudit.ps1. Every Graph call is a GET and the connection requests
    read scopes only, so the audit cannot change the credentials it inspects.

    It enumerates every application registration and reports, per credential, the
    type (client secret, certificate, or federated), its validity window, age, and
    days to expiry, then gives each application a deterministic posture verdict: a
    standing client secret is the thing to eliminate, a certificate is better, and
    workload identity federation (no standing credential at all) is the goal state.
#>

$ErrorActionPreference = 'Stop'

$script:TierNames = @('info', 'low', 'medium', 'high', 'critical')
$script:TierRank  = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }

function Connect-CredGraph {
    <#
        Connect read-only. Application.Read.All reads app registrations and their
        credentials; Directory.Read.All reads related directory objects. No write
        scope is requested, so the audit cannot rotate, add, or remove a credential.
    #>
    param(
        [string[]] $Scopes = @('Application.Read.All', 'Directory.Read.All')
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

function Get-CredentialStatus {
    <# Status of one secret/certificate from its validity window. #>
    param(
        [Parameter()] [AllowNull()] $EndDateTime,
        [Parameter(Mandatory)] [int] $ExpiringSoonDays
    )
    if (-not $EndDateTime) { return 'NoExpiry' }
    $now = (Get-Date).ToUniversalTime()
    $end = [datetime]$EndDateTime
    if ($end -lt $now) { return 'Expired' }
    if (($end - $now).TotalDays -le $ExpiringSoonDays) { return 'ExpiringSoon' }
    return 'Valid'
}

function Get-AppCredentials {
    <#
        Enumerate every application registration and flatten its credentials into one
        row per credential, plus a per-application posture summary. Applications live
        only in the tenant that owns them, so there is no Microsoft first-party noise
        to filter here.
    #>
    param(
        [Parameter(Mandatory)] $Policy
    )
    $expiringSoonDays = [int]$Policy.thresholds.expiringSoonDays

    Write-Host 'Enumerating application registrations...' -ForegroundColor Cyan
    $select = 'id,appId,displayName,passwordCredentials,keyCredentials'
    $apps = Get-GraphAllPages -Uri ('https://graph.microsoft.com/v1.0/applications?$select=' + $select + '&$top=100')
    Write-Host ("  found {0} application registrations" -f $apps.Count) -ForegroundColor DarkGray

    $rows = @()      # one row per credential
    $apps_out = @()  # one row per application (posture)
    $now = (Get-Date).ToUniversalTime()
    $i = 0
    foreach ($app in $apps) {
        $i++
        Write-Progress -Activity 'Reading credentials' -Status $app.displayName -PercentComplete (($i / [math]::Max($apps.Count, 1)) * 100)

        $secrets = @($app.passwordCredentials | Where-Object { $_ })
        $certs   = @($app.keyCredentials | Where-Object { $_ })
        $fed     = @(Get-GraphAllPages -Uri ('https://graph.microsoft.com/v1.0/applications/' + $app.id + '/federatedIdentityCredentials'))

        foreach ($s in $secrets) {
            $rows += [pscustomobject]@{
                AppDisplayName = $app.displayName; AppId = $app.appId; CredentialType = 'ClientSecret'
                Name = $s.displayName; KeyId = $s.keyId
                StartDateTime = $s.startDateTime; EndDateTime = $s.endDateTime
                AgeDays = (& { if ($s.startDateTime) { [int]([math]::Round(($now - [datetime]$s.startDateTime).TotalDays)) } else { $null } })
                DaysToExpiry = (& { if ($s.endDateTime) { [int]([math]::Round((([datetime]$s.endDateTime) - $now).TotalDays)) } else { $null } })
                Status = (Get-CredentialStatus -EndDateTime $s.endDateTime -ExpiringSoonDays $expiringSoonDays)
            }
        }
        foreach ($c in $certs) {
            $rows += [pscustomobject]@{
                AppDisplayName = $app.displayName; AppId = $app.appId; CredentialType = 'Certificate'
                Name = $c.displayName; KeyId = $c.keyId
                StartDateTime = $c.startDateTime; EndDateTime = $c.endDateTime
                AgeDays = (& { if ($c.startDateTime) { [int]([math]::Round(($now - [datetime]$c.startDateTime).TotalDays)) } else { $null } })
                DaysToExpiry = (& { if ($c.endDateTime) { [int]([math]::Round((([datetime]$c.endDateTime) - $now).TotalDays)) } else { $null } })
                Status = (Get-CredentialStatus -EndDateTime $c.endDateTime -ExpiringSoonDays $expiringSoonDays)
            }
        }
        foreach ($f in $fed) {
            $rows += [pscustomobject]@{
                AppDisplayName = $app.displayName; AppId = $app.appId; CredentialType = 'Federated'
                Name = $f.name; KeyId = $f.subject
                StartDateTime = $null; EndDateTime = $null; AgeDays = $null; DaysToExpiry = $null
                Status = 'Federated'
            }
        }

        $apps_out += (Get-AppPosture -App $app -Secrets $secrets -Certs $certs -FederatedCount $fed.Count -Policy $policy)
    }
    Write-Progress -Activity 'Reading credentials' -Completed
    return [pscustomobject]@{ Credentials = $rows; Apps = $apps_out }
}

function Get-AppPosture {
    <#
        Deterministic credential-posture verdict for one application. Each rule can
        only raise the tier, never lower it, so the verdict is the worst thing true
        about how the app authenticates.
    #>
    param(
        [Parameter(Mandatory)] $App,
        [Parameter()] [AllowNull()] $Secrets,
        [Parameter()] [AllowNull()] $Certs,
        [Parameter(Mandatory)] [int] $FederatedCount,
        [Parameter(Mandatory)] $Policy
    )
    $now = (Get-Date).ToUniversalTime()
    $expiringSoonDays = [int]$Policy.thresholds.expiringSoonDays
    $maxSecretDays    = [int]$Policy.thresholds.maxSecretValidityDays

    $secrets = @($Secrets | Where-Object { $_ })
    $certs   = @($Certs | Where-Object { $_ })

    $validSecrets = @($secrets | Where-Object { -not $_.endDateTime -or ([datetime]$_.endDateTime) -gt $now })
    $validCerts   = @($certs   | Where-Object { -not $_.endDateTime -or ([datetime]$_.endDateTime) -gt $now })
    $anyExpired   = @(($secrets + $certs) | Where-Object { $_.endDateTime -and ([datetime]$_.endDateTime) -lt $now }).Count -gt 0
    $expiringSoon = @(($validSecrets + $validCerts) | Where-Object { $_.endDateTime -and ((([datetime]$_.endDateTime) - $now).TotalDays -le $expiringSoonDays) }).Count -gt 0
    $longLived    = @($validSecrets | Where-Object { $_.startDateTime -and $_.endDateTime -and ((([datetime]$_.endDateTime) - [datetime]$_.startDateTime).TotalDays -gt $maxSecretDays) }).Count -gt 0

    $cur = 0
    $reasons = @()

    if ($validSecrets.Count -gt 0) {
        $msg = if ($longLived) { "{0} standing client secret(s), at least one long-lived" -f $validSecrets.Count }
               else { "{0} standing client secret(s)" -f $validSecrets.Count }
        $reasons += $msg
        if ($script:TierRank['high'] -gt $cur) { $cur = $script:TierRank['high'] }
    }
    elseif ($validCerts.Count -gt 0) {
        # A certificate is still a standing credential, so this stays low. If federation
        # is already configured, the certificate is now redundant and should be removed
        # to reach the no-standing-credential end state, so say so rather than "no federation".
        if ($FederatedCount -gt 0) {
            $reasons += ("certificate still present alongside federation, remove it to finish ({0})" -f $validCerts.Count)
        } else {
            $reasons += ("certificate credential, no federation ({0})" -f $validCerts.Count)
        }
        if ($script:TierRank['low'] -gt $cur) { $cur = $script:TierRank['low'] }
    }
    elseif ($FederatedCount -gt 0) {
        $reasons += ("federated, no standing credential ({0})" -f $FederatedCount)
        # info
    }
    else {
        # No valid secret, no valid cert, no federation. Only say "no credential" when
        # there is truly nothing; if expired credentials remain, the overlay below
        # explains it rather than claiming the app has no credential at all.
        if (($secrets.Count + $certs.Count) -eq 0) {
            $reasons += 'no credential configured'
        }
    }

    if ($anyExpired) {
        $reasons += 'expired credential still attached'
        if ($script:TierRank['medium'] -gt $cur) { $cur = $script:TierRank['medium'] }
    }
    if ($expiringSoon) {
        $reasons += ("credential expiring within {0} days" -f $expiringSoonDays)
        if ($script:TierRank['medium'] -gt $cur) { $cur = $script:TierRank['medium'] }
    }

    return [pscustomobject]@{
        AppDisplayName  = $App.displayName
        AppId           = $App.appId
        SecretCount     = $validSecrets.Count
        CertCount       = $validCerts.Count
        FederatedCount  = $FederatedCount
        PostureTier     = $script:TierNames[$cur]
        Why             = ($reasons -join '; ')
    }
}

function Export-CredentialReport {
    <# Write per-credential detail to CSV and a per-application posture report to HTML. #>
    param(
        [Parameter(Mandatory)] $Audit,
        [Parameter(Mandatory)] [string] $CsvPath,
        [Parameter(Mandatory)] [string] $HtmlPath,
        [Parameter(Mandatory)] [string] $TenantId
    )

    $Audit.Credentials |
        Sort-Object AppDisplayName, CredentialType |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

    $counts = @{}
    foreach ($t in $script:TierNames) { $counts[$t] = 0 }
    foreach ($a in $Audit.Apps) { $counts[$a.PostureTier]++ }

    $tierColor = @{ critical = '#C0392B'; high = '#E67E22'; medium = '#F1C40F'; low = '#3498DB'; info = '#7F8C8D' }

    $cards = ''
    foreach ($t in ($script:TierNames | Sort-Object { $script:TierRank[$_] } -Descending)) {
        $cards += ('<div class="card" style="border-top:4px solid {0}"><div class="n">{1}</div><div class="l">{2}</div></div>' -f $tierColor[$t], $counts[$t], $t.ToUpper())
    }

    $byTier = @{ Expression = { $script:TierRank[$_.PostureTier] }; Descending = $true }
    $byName = @{ Expression = 'AppDisplayName'; Descending = $false }

    $rows = ''
    foreach ($a in ($Audit.Apps | Sort-Object -Property $byTier, $byName)) {
        $name = [System.Net.WebUtility]::HtmlEncode([string]$a.AppDisplayName)
        $why  = [System.Net.WebUtility]::HtmlEncode([string]$a.Why)
        $color = $tierColor[$a.PostureTier]
        $rows += @"
<tr>
  <td><span class="pill" style="background:$color">$($a.PostureTier)</span></td>
  <td>$name</td>
  <td class="c">$($a.SecretCount)</td>
  <td class="c">$($a.CertCount)</td>
  <td class="c">$($a.FederatedCount)</td>
  <td>$why</td>
</tr>
"@
    }

    $generated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC'
    $total = @($Audit.Apps).Count

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra Credential Lifecycle</title>
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
  <h1>Entra Credential Lifecycle</h1>
  <div class="meta">Tenant $TenantId &middot; $total application registrations &middot; generated $generated &middot; read-only scan</div>
  <div class="cards">$cards</div>
  <table>
    <thead><tr>
      <th>Posture</th><th>Application</th><th>Secrets</th><th>Certs</th><th>Fed</th><th>Why</th>
    </tr></thead>
    <tbody>$rows</tbody>
  </table>
</body>
</html>
"@

    $html | Out-File -FilePath $HtmlPath -Encoding UTF8
}

Export-ModuleMember -Function Connect-CredGraph, Get-AppCredentials, Get-AppPosture, Export-CredentialReport
