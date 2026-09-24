# Entra Identity Platform

Five hands-on labs that together cover the identity and access management lifecycle in Microsoft Entra ID and Azure: **build** the hybrid identity foundation, **operate** it with lifecycle automation, and **govern** access three ways, right-sizing what identities can do, governing how access is requested and recertified, and enforcing just-in-time privilege for administrators.

![Microsoft Entra ID](https://img.shields.io/badge/Microsoft_Entra_ID-P2-0067b8?logo=microsoftazure&logoColor=white)
![Azure RBAC](https://img.shields.io/badge/Azure_RBAC-Least_Privilege-0078D4?logo=microsoftazure&logoColor=white)
![Graph PowerShell](https://img.shields.io/badge/Microsoft_Graph-PowerShell_SDK-5391FE?logo=powershell&logoColor=white)
![PIM](https://img.shields.io/badge/PIM-Just_in_Time-5C2D91)
![Identity Governance](https://img.shields.io/badge/Identity_Governance-Entitlement_Mgmt_%7C_Access_Reviews-107C10)
![Focus](https://img.shields.io/badge/Focus-Identity_%26_Access_Management-success)

---

## Overview

This repository collects five self-contained labs that map to how an IAM team actually works: you stand up an identity environment, you run it day to day, and you govern what people can access and how they get it. Each lab is built and evidenced against a live tenant, and each has its own detailed README with steps, screenshots, and an honest troubleshooting record.

The labs are grouped here so the through-line is visible. Individually they are five tasks. Together they are a demonstration of the identity lifecycle from on-premises foundation through automated operations to entitlement governance, privileged access, and access recertification.

## The lifecycle

```mermaid
flowchart LR
    BUILD["<b>BUILD</b><br/>Hybrid identity foundation<br/>hybrid-identity-cloud-sync"]
    OPERATE["<b>OPERATE</b><br/>Lifecycle automation (JML)<br/>entra-iam-toolkit"]
    CIEM["<b>GOVERN</b><br/>Entitlement right-sizing (CIEM)<br/>azure-ciem-least-privilege"]
    IG["<b>GOVERN</b><br/>Access governance<br/>entra-identity-governance"]
    PIM["<b>GOVERN</b><br/>Privileged access (PIM)<br/>entra-pim-privileged-access"]

    BUILD --> OPERATE --> CIEM
    OPERATE --> IG
    OPERATE --> PIM

    style BUILD fill:#e6f0fa,stroke:#0067b8,stroke-width:2px,color:#0a2540
    style OPERATE fill:#eef4ff,stroke:#5391FE,stroke-width:2px,color:#0a2540
    style CIEM fill:#f2ecf7,stroke:#5C2D91,stroke-width:2px,color:#2a1440
    style IG fill:#f2ecf7,stroke:#5C2D91,stroke-width:2px,color:#2a1440
    style PIM fill:#f2ecf7,stroke:#5C2D91,stroke-width:2px,color:#2a1440
```

## The labs

| Lab | Stage | What it demonstrates |
|-----|-------|----------------------|
| [hybrid-identity-cloud-sync](./hybrid-identity-cloud-sync) | Build | On-prem Active Directory to Entra ID via Entra Cloud Sync and password hash sync, plus a full root-cause analysis of a sync-agent fault |
| [entra-iam-toolkit](./entra-iam-toolkit) | Operate | Joiner-mover-leaver automation, access reporting, and audit export with the Microsoft Graph PowerShell SDK |
| [azure-ciem-least-privilege](./azure-ciem-least-privilege) | Govern | Detecting four over-provisioning findings from Activity logs and remediating them to least privilege with PIM, scope reduction, access reviews, and a custom role |
| [entra-identity-governance](./entra-identity-governance) | Govern | Entitlement management (catalogs, access packages, approval, terms of use) and access reviews with auto-apply, plus governed external-user lifecycle |
| [entra-pim-privileged-access](./entra-pim-privileged-access) | Govern | Just-in-time privileged access across Entra roles, groups, and Azure resources, with approval, Conditional Access step-up, PIM alerts, and privileged access reviews |

---

### Build: Hybrid identity foundation

[`hybrid-identity-cloud-sync`](./hybrid-identity-cloud-sync)

Stands up the on-premises foundation that most enterprises actually run: a Windows Server domain controller for a new forest, an OU-scoped provisioning boundary, verified-domain UPN alignment so synced identities are sign-in ready, and the Entra Cloud Sync provisioning agent with password hash sync configured. The environment is fully built and correctly configured. The sync itself surfaced an agent-connectivity fault, which is diagnosed here layer by layer (DNS, connectivity, TLS, certificate trust, permissions, host security) and isolated through the agent's own trace log to an environmental WebSocket failure rather than any misconfiguration. The build and the diagnosis are both intended deliverables.

**Skills:** Windows Server AD DS, Entra Cloud Sync, password hash sync, UPN and verified-domain configuration, OU-scoped provisioning, gMSA, structured root-cause analysis.

[Details →](./hybrid-identity-cloud-sync)

### Operate: Identity lifecycle automation

[`entra-iam-toolkit`](./entra-iam-toolkit)

A set of Microsoft Graph PowerShell scripts that run the joiner-mover-leaver lifecycle as repeatable automation instead of portal clicks: bulk provisioning, idempotent group assignment, desired-state reconciliation that strips privilege creep, a "who has access to what" report, enterprise offboarding that disables rather than deletes, and audit-log export so the toolkit produces the evidence of its own operations. Includes a documented debugging trail of five real failures, several of which first presented as false success.

**Skills:** Graph PowerShell SDK, JML automation, least-privilege remediation, idempotent and honest-failure scripting, governance reporting, audit evidence.

[Details →](./entra-iam-toolkit)

### Govern: Entitlement right-sizing (CIEM)

[`azure-ciem-least-privilege`](./azure-ciem-least-privilege)

The entitlement plane: not who someone is, but what they can do to cloud resources and whether that access is right-sized. The lab seeds four realistic over-provisioning states, proves each is over-provisioned by correlating granted permissions against actual usage in KQL, then walks each down to least privilege using PIM just-in-time access, scope reduction, an access review with auto-apply, and a purpose-built custom role. It also names the boundary of native Azure CIEM honestly rather than overclaiming a dedicated engine.

**Skills:** Azure RBAC scope hierarchy, standing vs just-in-time access, PIM for Azure resources, access reviews, custom role authoring, KQL entitlement detection.

[Details →](./azure-ciem-least-privilege)

### Govern: Access governance and recertification

[`entra-identity-governance`](./entra-identity-governance)

The request-and-recertify plane: how access is granted through self-service with approval and a time-bound expiry, and how it is periodically re-attested and automatically removed. The lab builds entitlement management end to end (a catalog, an access package with a manager-approval policy and required justification, terms of use enforced through Conditional Access) and a governed external-user path (connected organization plus an auto-cleanup lifecycle for guests). It then runs a full access review with decision helpers and auto-apply, so a denied user's access is actually removed. Built and evidenced in a P2 trial tenant, with honest licensing findings on the P2 versus Entra ID Governance SKU boundary.

**Skills:** entitlement management, catalogs and access packages, approval workflows with justification, terms of use via Conditional Access, connected organizations and external-user lifecycle, access reviews with decision helpers and auto-apply.

[Details →](./entra-identity-governance)

### Govern: Privileged access (PIM)

[`entra-pim-privileged-access`](./entra-pim-privileged-access)

The privileged-access plane: turning standing admin rights into just-in-time access so no one holds privilege they are not actively using. The lab makes roles eligible rather than active across all three PIM surfaces (Entra directory roles, PIM for Groups, and Azure resource roles), then hardens the activation path with a named-approver workflow and a Conditional Access authentication context that forces step-up MFA at the moment of elevation. It closes on the monitoring side with PIM alerts for privilege hygiene and an access review that recertifies who should stay eligible, with auto-apply removing those who should not. Includes a documented troubleshooting trail of a Conditional Access authentication-context activation loop.

**Skills:** PIM for Entra roles, groups, and Azure resources, eligible vs active assignments, JIT activation with approval, Conditional Access authentication context step-up, PIM alerts and remediation, privileged access reviews, PIM audit analysis.

[Details →](./entra-pim-privileged-access)

---

## Skills demonstrated across the platform

- **Hybrid identity:** on-prem AD to Entra ID synchronization, Cloud Sync, password hash sync, UPN routing
- **Identity lifecycle (JML):** automated provisioning, group and access management, desired-state reconciliation, enterprise offboarding
- **Access governance:** entitlement management, access packages with approval, terms of use, connected organizations and external-user lifecycle
- **Privileged access:** PIM across Entra roles, groups, and Azure resources, eligible-vs-active just-in-time activation with MFA, justification, and approval, Conditional Access authentication context step-up, break-glass reasoning
- **Recertification and least privilege:** access reviews with auto-apply, least-privilege enforcement, custom RBAC roles, privilege-creep detection
- **Detection and evidence:** KQL over Azure Activity and directory logs, audit export, access reporting
- **Engineering rigour:** idempotency, graceful licensing degradation, honest failure handling, and structured root-cause analysis

## Tech stack

Microsoft Entra ID (P2), Windows Server AD DS, Microsoft Entra Cloud Sync, Microsoft Graph PowerShell SDK, Azure RBAC, Azure Privileged Identity Management, Microsoft Entra entitlement management and access reviews, Conditional Access, Azure Monitor and Log Analytics (KQL), Azure CLI, PowerShell 7+.

## About

Built by Jeffrey Lam-Ping-Fong, a fourth-year Honours Bachelor of Information Technology student specializing in cybersecurity, with a focus on identity and access management.

- LinkedIn: https://www.linkedin.com/in/jeffrey-lam-ping-fong-07a649321
