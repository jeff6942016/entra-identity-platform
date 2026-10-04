# Validating the detection: seed a risky app

A detection is only trustworthy if you have watched it fire. This note plants a
deliberately risky non-human identity, confirms the inventory flags it at the
expected tier, then removes it. Everything here is done in a lab tenant you own.

The point is not to break anything. It is to prove that each risk rule in
`policy/high-privilege-app-roles.json` and `scripts/NhiInventory.psm1` actually
triggers on a real object, so a clean report means "clean", not "blind".

## What a convincing test covers

Seed one app that trips several rules at once, so a single run exercises the
privileged-permission rule, the standing-secret rule, and the no-owner rule.

| Rule under test | How to trip it |
| :--- | :--- |
| Privileged application permission (critical) | Grant the app `Application.ReadWrite.All` on Microsoft Graph and admin-consent it |
| Standing client secret (high) | Add a client secret to the app |
| No accountable owner (high) | Leave the app with no owner assigned |

## Steps

1. Create a throwaway app registration, for example `nhi-redteam-canary`.
2. Under **API permissions**, add Microsoft Graph application permission
   `Application.ReadWrite.All`, then **Grant admin consent**. This is the single
   most dangerous Graph permission a non-human identity can hold: it can add
   credentials to any other app or service principal and impersonate it, so the
   policy ranks it `critical`.
3. Under **Certificates & secrets**, add a client secret. Do not store the value
   anywhere; the inventory only reads that a secret exists and when it expires.
4. Leave **Owners** empty.
5. Run the inventory:

   ```powershell
   ./scripts/Invoke-NhiInventory.ps1
   ```

6. Open `output/inventory.html` (or sort `output/inventory.csv` by `RiskTier`).
   `nhi-redteam-canary` should appear at the top as **critical**, with a `Why`
   value naming all three findings, for example:

   `holds Application.ReadWrite.All (critical); no accountable owner; 1 standing client secret(s)`

## Expected result

| Identity | Risk tier | Why |
| :--- | :--- | :--- |
| nhi-redteam-canary | critical | holds Application.ReadWrite.All (critical); no accountable owner; 1 standing client secret(s) |

If the canary does not appear, the most common causes are: admin consent was not
granted (the app-role assignment never lands on the service principal, so there is
nothing to read), or the app is being filtered as Microsoft first-party (it should
be classified `InTenant`). Re-run with `-IncludeMicrosoftFirstParty` only to rule
the second out; an in-tenant canary should never need it.

## Clean up

Delete the `nhi-redteam-canary` app registration. Re-run the inventory and confirm
it no longer appears, which also demonstrates that remediation closes the finding.
