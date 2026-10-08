# Eliminate the standing secret: GitHub Actions workload identity federation

This sets up the end state of the credential lifecycle: an application that
authenticates to Microsoft Graph from CI with no client secret and no certificate
stored anywhere. GitHub mints a short-lived OIDC token on each run, Entra trusts it
through a federated identity credential scoped to one repo and branch, and the token
is exchanged for a Graph token. Nothing long-lived is ever stored.

This is the same federation technique applied to `nhi-auditor` in the separate
agentic-ai-iam project (project 03); here it is done as the deliberate endpoint of a
credential-lifecycle walk, with the standing secret removed afterward to prove it.

## 1. Add the federated credential on the app

In the Entra admin center, App registrations, open the demo app, then
Certificates & secrets, Federated credentials, Add credential.

- Scenario: GitHub Actions deploying Azure resources
- Organization: `jeff6942016`
- Repository: `entra-identity-platform`
- Entity type: Branch
- Branch: `main`
- Name: `github-main`

That produces a trust whose subject is
`repo:jeff6942016/entra-identity-platform:ref:refs/heads/main`. Only an OIDC token
from that exact repo and branch is accepted, so the trust is scoped, not open to the
whole organization.

## 2. Give the app the Graph permission it needs

The workflow reads applications, so grant the app the Microsoft Graph application
permission `Application.Read.All` under API permissions, then Grant admin consent.
Keep this minimal: the federated identity should hold only the scopes its job needs.

## 3. Store the client and tenant IDs as repository variables

These are identifiers, not secrets, which is the point. In the GitHub repo,
Settings, Secrets and variables, Actions, Variables tab, add:

- `AZURE_CLIENT_ID`: the app's Application (client) ID
- `AZURE_TENANT_ID`: the tenant ID

No secret is stored. If you ever find yourself adding a client secret here, the
lifecycle is not finished.

## 4. Run the workflow and confirm

Commit `cred-federation.yml` to `.github/workflows/`, then run it from the Actions
tab (Run workflow). The `azure/login` step succeeds using only the OIDC token, and
the Graph call returns a result. Capture the successful run as evidence.

## 5. Remove the standing secret

Back on the app, Certificates & secrets, delete the client secret (and the
certificate, if one was added during the earlier phase). Re-run the credential audit
and confirm the app now reports as federated with zero secrets. That is the lifecycle
closed: detected, upgraded, and finally eliminated.

## How this fails in production

- A federation subject scoped too broadly (any branch, any environment, or a
  reusable-workflow `job_workflow_ref` that many repos call) widens the trust far
  beyond one pipeline. Keep the subject as narrow as the job allows.
- Federation removes the credential for app-to-app and CI auth, but a human still
  needs a path; do not delete a secret that an interactive or on-prem caller still
  depends on without moving that caller first.
- The OIDC token is short-lived, so an idle or self-hosted runner that cannot reach
  the token endpoint will fail closed, which is correct but worth expecting.
