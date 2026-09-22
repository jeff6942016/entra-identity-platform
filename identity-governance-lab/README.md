# Microsoft Entra Identity Governance Lab

![Microsoft Entra ID](https://img.shields.io/badge/Microsoft_Entra_ID-0078D4?style=flat&logo=microsoftazure&logoColor=white)
![License](https://img.shields.io/badge/License-P2-512BD4?style=flat)
![SC-300](https://img.shields.io/badge/SC--300-Identity_Governance-107C10?style=flat)
![Identity Governance](https://img.shields.io/badge/Identity_Governance-Entitlement_Management_%7C_Access_Reviews-5C2D91?style=flat)

Entitlement management and access reviews built end to end in a Microsoft Entra ID P2 trial tenant, demonstrating self-service access with approval, time-bound assignments, governed external access, and access recertification with automatic remediation.

This lab covers the **Plan and automate identity governance** domain of SC-300 and the "govern" stage of my broader Entra identity platform work.

---

## The concept in one line

Identity governance answers three questions continuously: **who should have access, are they using it appropriately, and how is it removed when they no longer need it.** This lab implements all three across the joiner-mover-leaver (JML) lifecycle, anchored to the principle of least privilege and Zero Trust's "verify explicitly."

| Governance question | Control in this lab | JML stage |
|---|---|---|
| Who should get access, and who approves it? | Access packages + approval policy | Joiner / Mover |
| Is the access still appropriate? | Access reviews (recertification) | Mover |
| How is access removed? | Assignment expiry + external-user lifecycle + auto-apply | Leaver |

---

## What this lab demonstrates

| Capability | SC-300 objective |
|---|---|
| Catalogs and delegated catalog ownership | Create and configure catalogs |
| Access packages with resource roles | Create and configure access packages |
| Single-stage approval with justification | Manage access requests |
| Time-bound assignments with expiry | Plan entitlements |
| Terms of use enforced via Conditional Access | Implement and manage terms of use |
| Connected organizations + external-user lifecycle | Manage the lifecycle of external users |
| Access review with decision helpers and auto-apply | Plan, implement, and manage access reviews |

**Licensing:** everything here runs on Microsoft Entra ID P2. Notes on the P2 vs Entra ID Governance SKU boundary are in [Licensing findings](#licensing-findings).

---

## Architecture

```mermaid
flowchart TD
    subgraph Sources
        INT[Internal users]
        EXT[External users via connected org]
    end

    CAT[Catalog: Finance Access]
    AP[Access package: Finance App Access]
    POL[Request policies:<br/>Initial Policy + External Users]

    INT -->|request| AP
    EXT -->|request| AP
    CAT --> AP
    AP --> POL

    POL -->|requestor justification| APPR{Approval<br/>Manager, fallback approver}
    APPR -->|denied| END1[No access granted]
    APPR -->|approved| ASSIGN[Time-bound assignment<br/>expires in 30 days]

    ASSIGN --> GRP[Group + app role granted]
    GRP --> TOU[Conditional Access:<br/>Require Terms of Use]

    GRP --> REVIEW[Access review<br/>weekly, group owner]
    REVIEW -->|decision helper flags inactivity| DECIDE{Reviewer decision}
    DECIDE -->|deny| AUTO[Auto-apply removes access]
    DECIDE -->|approve| KEEP[Access retained]

    ASSIGN -.->|external user loses last assignment| LIFECYCLE[External lifecycle:<br/>block sign-in, remove after 30 days]
```

---

## Phase 0: Environment and test cast

**Concept:** Governance controls act on identities, so the test cast is modeled to mirror separation of duties. The requester, approver, and reviewer are deliberately different accounts. No single identity both requests and approves its own access.

<details>
<summary>Screenshots: test users and group owner</summary>

Test identities: a requester, an approver, a resource owner (reviewer), and a B2B guest for the external path.

![Test users](screenshots/01_user-list.png)

`SG-Finance-App-Users` given a dedicated owner so the access review routes to a resource owner, not to me directly.

![Group owner](screenshots/02_group-owner.png)

</details>

---

## Phase 1: Catalog

**Concept:** A catalog is the delegation boundary of entitlement management. It lets a resource owner govern their own resources without holding a tenant-wide admin role, which is least privilege applied to administration itself. Enabling external users at creation is what later allows guests to be governed through it.

<details>
<summary>Screenshot: catalog overview</summary>

![Catalog overview](screenshots/03_catalog.png)

</details>

---

## Phase 2: Access package with approval

**Concept:** The access package separates two things that are easy to conflate: **what access you receive** (resource roles) and **who may request it and how it is approved** (the policy). Approval with required justification creates the audit trail; the 30-day expiry means the entitlement is time-bound rather than standing privilege. Both are core least-privilege ideas.

<details>
<summary>Screenshots: request scope, approval, requestor info, lifecycle</summary>

**Who can request:**

![Request scope](screenshots/05_request_access.png)

**Approval:** single-stage, Manager as approver with a named fallback, requestor and approver justification required, 14-day decision deadline.

![Approval configuration](screenshots/04_request-just_approval.png)

**Requestor information:** a custom "Business justification for access?" question captured for the audit trail.

![Requestor information](screenshots/06_question.png)

**Lifecycle:** assignments expire after 30 days, and access reviews are required on the assignment.

![Lifecycle settings](screenshots/07_lifecycle.png)

</details>

> **Understanding note:** "Manager as approver" depends on the requester having a manager attribute set. My test user had none, so approval fell through to the named fallback. In production the manager attribute must be populated and maintained, or approvals stall silently.

---

## Phase 3: Terms of use

**Concept:** Terms of use is the compliance-consent gate. It is authored under Identity Governance but enforced through a Conditional Access grant control, which shows the governance plane and the access plane are wired together rather than separate. Acceptance is recorded, which is what an auditor looks for.

<details>
<summary>Screenshots: ToU object and Conditional Access policy</summary>

![Terms of use object](screenshots/10_ToU_Object.png)

The ToU referenced as a grant control in a CA policy targeting the finance group, with the break-glass account excluded.

![Conditional Access policy](screenshots/09_conditional_access_policy.png)

</details>

---

## Phase 4: External users

**Concept:** Guests are the higher-risk half of governance because they are outside the org's control. A connected organization defines which external partner is trusted to request access, and the external-user lifecycle automatically removes a guest once they lose their last assignment. That closes the orphaned-guest gap, which is one of the most common access-audit findings.

<details>
<summary>Screenshots: connected org, package policies, external-user lifecycle</summary>

**Connected organization** defines the trusted external partner.

![Connected organization](screenshots/11_connected_org.png)

A second request policy (`External Users`) scopes external requests separately from internal ones.

![Package policies](screenshots/12_access_package_policies.png)

**External-user lifecycle:** a governed guest is blocked from sign-in and removed 30 days after losing their last access-package assignment.

![External-user lifecycle](screenshots/13_ext-user_lifecycle.png)

</details>

---

## Phase 5: Request flow end to end

**Concept:** This is the joiner/mover path in action. Self-service request with approval turns access from a manual help-desk ticket into a governed workflow: the user gets access faster, the org keeps control and a full evidence trail, and the entitlement carries its own expiry. Configured is not the same as proven, so the cycle was actually run.

<details>
<summary>Screenshots: request submitted, approval pending, assignment delivered</summary>

**Requester submits** through the My Access portal.

![Request submitted](screenshots/14_user-request.png)

**Approver sees the pending request** and approves or denies with justification.

![Approval pending](screenshots/15_user-approve.png)

**Assignment delivered** after approval, with the 30-day expiry visible (end date 10/22/2026).

![Assignment delivered](screenshots/16_req-user_access.png)

</details>

---

## Phase 6: Access review cycle (the governance report)

**Concept:** Access reviews are recertification, the periodic "does this person still need this?" control. It is what catches privilege creep over time and satisfies SOC 2 and PCI access-review requirements. Two pieces make it real rather than cosmetic: **decision helpers** surface inactivity so a reviewer is not eyeballing hundreds of users, and **auto-apply** turns the decision into enforced removal. That auto-removal is the leaver/cleanup stage of the lifecycle.

<details>
<summary>Screenshots: review config, settings, reviewer decision before and after</summary>

**Review configuration:** scoped to `SG-Finance-App-Users`, reviewer is the group owner, weekly recurrence.

![Review configuration](screenshots/17_access-review1_half1.png)

**Review settings:** auto-apply to the resource, remove access if reviewers do not respond, decision helpers on 30 days of sign-in inactivity, justification required.

![Review settings](screenshots/18_access-review1_half2.png)

**Reviewer view (before):** decision helper recommends **Deny**, reason "Inactive user," signed in as the group owner.

![Review pending](screenshots/19_before_access-review.png)

**Reviewer decision (after):** access denied, recorded against Owner User. Auto-apply then removes the membership.

![Review decided](screenshots/20_after_access-review.png)

</details>

---

## Licensing findings

Confirmed live in the P2 trial tenant before building:

| Feature | Available on P2 trial |
|---|---|
| Entitlement management (catalogs, access packages) | Yes |
| Access reviews | Yes |
| Connected organizations | Yes |
| Terms of use | Yes |
| Lifecycle Workflows | No (requires Entra ID Governance SKU) |
| Access-package custom extensions | No (Governance SKU) |

Two boundaries worth noting:

- **Access packages are not reviewable from the global Access reviews blade.** That blade only offers Teams + Groups and Applications. Access-package assignment reviews are configured from the package's own policy lifecycle instead.
- **Reviewing guest users under governance now requires a linked Azure subscription** (change effective January 15, 2026, billed per unique guest). Reviews here were kept scoped to internal users to avoid that cost.

---

## Lessons learned

- **Manager-as-approver has a dependency.** With no manager attribute set, approval only works because a fallback approver was configured.
- **Two review types start differently.** A group review from the global blade instantiates quickly; a package-policy review is scheduled and can take up to a day, and its frequency (quarterly vs weekly) changes how soon the first instance appears.
- **Decision helpers are what make reviews scale.** The "Inactive user" flag came from last-sign-in data, which is how a reviewer handles hundreds of accounts.
- **Auto-apply is the difference between a report and a control.** Without it a review only produces a list of decisions; with it, denied access is actually removed.
- **Terms of use spans two planes.** Authored in governance, enforced only once wired into a Conditional Access grant control.
