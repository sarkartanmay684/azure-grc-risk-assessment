# Lab Walkthrough — Build and Evidence Collection

How the assessed environment was built and how each finding in the [risk register](../artifacts/risk-register.csv) was evidenced. Every screenshot has been redacted; see the [sanitisation note](../README.md#sanitisation-note).

This is a record of what was done and what was observed, not a set of instructions to follow.

---

## Part 1 — Building the environment

### 1.1 Resource group

A dedicated resource group, `GRC-Lab`, was created to contain every lab resource so the assessment scope had a clean boundary and teardown was a single operation.

- Subscription: Azure for Students Starter
- Name: `GRC-Lab`
- Region: Central India — chosen for proximity and lower compute cost

![Create a resource](../screenshots/01-portal-create-a-resource.png)
![Resource group configuration](../screenshots/02-resource-group-configuration.png)
![Resource group created](../screenshots/03-resource-group-review-create.png)

### 1.2 Virtual machine

| Setting | Value | Reasoning |
|---|---|---|
| Name | `GRC-Windows-VM01` | Single workload; the entire assessment scope |
| Image | Windows 11 Pro 25H2, x64 Gen 2 | Client OS, deliberately left at defaults so the assessment reflects an unhardened baseline |
| Size | Standard B2als_v2 (2 vCPU, 4 GiB) | Cheapest size that runs the OS comfortably for a short-lived lab |
| OS disk | Standard SSD | Cost; no performance requirement |
| Availability zone | Zone 1 | Default |

![Create VM](../screenshots/04-create-resource-virtual-machine.png)
![Marketplace search](../screenshots/05-marketplace-search-virtual-machine.png)
![VM basics](../screenshots/06-vm-basics-subscription-rg-name-region.png)
![Image and size](../screenshots/07-vm-image-and-size-selection.png)
![Size options](../screenshots/08-vm-size-options.png)
![Size selected](../screenshots/09-vm-size-selected-b2als-v2.png)

### 1.3 Administrator account and inbound access

A local administrator account, `azureadmin`, was created with password authentication. Public inbound ports were set to **Allow selected ports → RDP (3389)**.

This is the decision that produces the two Critical findings later in the assessment. It was made deliberately: the exercise calls for an environment with a realistic misconfiguration to assess, and RDP exposed to the internet is among the most common findings in real cloud estates.

![Admin account and inbound ports](../screenshots/10-vm-admin-account-and-inbound-ports-rdp.png)

### 1.4 Disks and networking

Disk and network settings were left at Azure defaults, which auto-created a virtual network, subnet, public IP and network security group.

- VNet: `GRC-Windows-VM01-vnet`, subnet `default`
- Public IP: enabled (new)
- NSG: `GRC-Windows-VM01-nsg`, Basic, attached at NIC level

![Disks](../screenshots/11-vm-disks-os-disk-standard-ssd.png)
![Disks configuration](../screenshots/12-vm-disks-configuration.png)
![Disks defaults](../screenshots/13-vm-disks-defaults.png)
![Networking](../screenshots/14-vm-networking-vnet-subnet-public-ip.png)
![Networking NSG](../screenshots/15-vm-networking-nsg-and-inbound-rdp.png)

Two defaults matter for the assessment and are picked up later: the public IP is enabled without a Bastion host in front of it, and the NSG binds to the network interface rather than the subnet.

### 1.5 Deployment and first connection

![Review and create](../screenshots/16-vm-review-and-create-validation.png)
![Deployment submitted](../screenshots/17-vm-deployment-submitted.png)
![Deployment in progress](../screenshots/18-vm-deployment-in-progress.png)
![Deployment complete](../screenshots/19-vm-deployment-complete.png)
![VM overview](../screenshots/20-vm-overview-after-deployment.png)
![Connect blade](../screenshots/21-vm-connect-rdp-blade.png)
![Download RDP file](../screenshots/22-download-rdp-file.png)
![RDP prompt](../screenshots/23-rdp-connection-prompt.png)
![Session established](../screenshots/24-rdp-session-established.png)

---

## Part 2 — Asset identification

> *What are we protecting?* Assets are not only hardware. Anything that holds value, grants access, or confers privilege belongs in the inventory — accounts, network paths and cloud permissions included.

Nine assets were catalogued with confidentiality, integrity and availability ratings in [`asset-inventory.csv`](../artifacts/asset-inventory.csv).

### 2.1 Operating system

Confirmed from **Settings → Operating System**: Windows 11 Pro, 25H2, sourced from image `microsoftwindowsdesktop / windows-11 / win11-25h2-pro`.

![Operating system settings](../screenshots/25-vm-settings-operating-system.png)
![Operating system blade](../screenshots/26-operating-system-blade.png)

### 2.2 Network exposure

**Networking → Network settings** confirmed a public IPv4 address bound to the NIC, private address `10.1.0.4`, and no DNS name.

![Network settings](../screenshots/27-vm-networking-network-settings.png)

### 2.3 Open ports

The inbound rule set on `GRC-Windows-VM01-nsg`:

| Priority | Name | Port | Protocol | Source | Destination | Action |
|---|---|---|---|---|---|---|
| 300 | RDP | 3389 | TCP | **Any** | Any | Allow |
| 65000 | AllowVnetInBound | Any | Any | VirtualNetwork | VirtualNetwork | Allow |
| 65001 | AllowAzureLoadBalancerInBound | Any | Any | AzureLoadBalancer | Any | Allow |
| 65500 | DenyAllInBound | Any | Any | Any | Any | Deny |

![NSG inbound rules](../screenshots/28-nsg-inbound-rules-rdp-open.png)

Three observations from this one screen:

1. Rule 300 permits RDP from **any source address on the internet**. Azure marks the rule with a warning icon of its own accord. → **R-01**
2. The NSG header reads *"Impacts 0 subnets, 1 network interface"* and effective security rules is 0. The NSG protects the NIC only; there is no subnet-level control behind it. → **R-06**
3. Outbound rule 65001 `AllowInternetOutBound` permits unrestricted egress to the internet. → **R-07**

### 2.4 Privileged accounts

`Get-LocalUser` was run through **Operations → Run command → RunPowerShellScript**, which enumerates local accounts without needing an interactive session:

```
Name               Enabled  Description
----               -------  -----------
azureadmin         True     Built-in account for administering the computer/domain
DefaultAccount     False    A user account managed by the system
Guest              False    Built-in account for guest access to the computer/domain
WDAGUtilityAccount False    A user account managed and used by the system for Windows Defender Application Guard
```

![Run command](../screenshots/29-run-command-list.png)
![Get-LocalUser output](../screenshots/30-get-localuser-output.png)

`azureadmin` is the only enabled account on the host — every administrative action traces to one shared identity, so there is no individual accountability in the audit trail.

### 2.5 Public exposure and platform security posture

The VM overview confirmed internet reachability and surfaced several platform settings relevant to the register:

| Setting | State | Register entry |
|---|---|---|
| Public IP | Enabled | R-01 |
| Security type | Trusted launch | — |
| Secure Boot | Enabled | — |
| vTPM | Enabled | — |
| Integrity monitoring | **Disabled** | R-09 |
| Encryption at host | **Disabled** | R-09 |
| Azure Disk Encryption | **Not enabled** | R-09 |
| Health monitoring | **Not enabled** | R-04 |
| Backup + disaster recovery | **Not configured** | R-08 |
| Extensions | **None** | R-03 |

![Public exposure](../screenshots/31-vm-overview-public-exposure.png)
![Properties and networking](../screenshots/32-vm-overview-properties-networking.png)
![Security and extensions](../screenshots/33-vm-overview-security-and-extensions.png)

Worth noting for accuracy: Azure managed disks are encrypted at rest by default with platform-managed keys, so "Azure Disk Encryption: Not enabled" does not mean the disk is plaintext. The residual gap is customer key ownership and the absence of attestation alerting — which is why R-09 is scored Low rather than inflated for effect.

---

## Part 3 — Vulnerability identification

> A vulnerability is a weakness, not an attack. Nothing here required exploitation — if a configuration *can* be abused, it is documented as a vulnerability.

### 3.1 Network security group review

![NSG rules reviewed](../screenshots/34-nsg-rules-review-vulnerability.png)

RDP (TCP/3389) allowed inbound from source `Any` with action `Allow`. Confirmed as the primary vulnerability underpinning R-01.

### 3.2 Authentication method

Connecting over RDP prompts for a username and password and nothing else. There is no second factor, no conditional access evaluation, and no device compliance check between the internet and a local administrator session.

![RDP credential prompt](../screenshots/35-rdp-credential-prompt.png)
![VM desktop session](../screenshots/36-vm-desktop-session.png)

### 3.3 OS-level account confirmation

**Computer Management → Local Users and Groups** corroborated the Run Command output from inside the OS, and the Administrators group properties confirmed `azureadmin` as its only member.

![Computer Management](../screenshots/37-computer-management-opened.png)
![Local Users and Groups](../screenshots/38-local-users-and-groups.png)
![Local users list](../screenshots/39-local-users-list-azureadmin.png)
![Administrators group membership](../screenshots/40-administrators-group-membership.png)

Evidencing the same fact from two independent sources — the control plane and the guest OS — is what makes the finding defensible in an audit.

### 3.4 Monitoring coverage

**Azure-side.** Monitor (formerly Insights) returns platform metrics — VM Network Bytes, Disk Bytes, Logical Disk IOPS — because those come from the hypervisor at no cost. But *Network Dropped Packets*, *Network Errors*, *Max Logical Disk Used %*, *Logical Disk Latency* and *Top 5 processes* all return **"No metrics detected — configure detailed metrics."**

![Monitoring entry](../screenshots/41-monitoring-insights-entry.png)
![Monitor overview](../screenshots/42-monitor-insights-overview.png)
![Performance charts](../screenshots/43-monitor-performance-charts.png)
![Metrics partially available](../screenshots/44-monitor-metrics-partial.png)
![Detailed metrics not configured](../screenshots/45-monitor-detailed-metrics-not-configured.png)
![Monitor session view](../screenshots/46-monitor-vm-session-view.png)

This partial coverage is worth naming precisely, because it is the kind of thing that produces false assurance: charts are drawn, so monitoring *appears* to be on. What is missing is guest-level telemetry, any log collection, and any alert rule. Nothing about this VM would ever notify a human.

**OS-side.** Event Viewer → Windows Logs → Security confirmed the host is generating audit records — 1,414 events at the time of review.

![Event Viewer](../screenshots/47-event-viewer-launch.png)
![Security log](../screenshots/48-event-viewer-security-log-4625.png)

### 3.5 What the Security log actually contained

The log was not merely present. It contained a pattern:

| Time (local) | Event ID | Result | Task category |
|---|---|---|---|
| 03:23:19 | 4625 | Audit Failure | Logon |
| 03:24:54 | 4625 | Audit Failure | Logon |
| 03:26:28 | 4625 | Audit Failure | Logon |
| 03:28:01 | 4625 | Audit Failure | Logon |
| 03:29:37 | 4625 | Audit Failure | Logon |
| 03:31:11 | 4625 | Audit Failure | Logon |

Event 4625 is *"An account failed to log on."* Every entry carried `Subject → Security ID: NULL SID` and `User: N/A`, meaning the logon failed before any account context was established — the signature of an authentication attempt against a service rather than a mistyped password at a console.

The intervals are 95, 94, 93, 96 and 94 seconds. That regularity does not come from a person.

**What this justifies.** R-01's likelihood is scored 5 rather than 4 because the exposure produced observable activity within hours on a host with no DNS name and no reason for anyone to know it existed. Internet-facing RDP is not a risk that *might* materialise; on this VM it began immediately.

**What this does not justify.** The `Source Network Address` field in each event's Details tab was not captured. Without it, these attempts cannot be attributed to an external source with certainty — a stuck local RDP client could in principle produce a similar pattern. The finding is therefore recorded as *consistent with* automated authentication attempts, and capturing the source addresses is the first item under [known limitations](../README.md#known-limitations).

Assuming default OS configuration otherwise: Windows Defender and Windows Firewall are enabled at their defaults, with no Group Policy hardening, no CIS Benchmark applied, and no additional host-based security tooling installed.

---

## Assessment boundary

No exploitation, credential attack, or penetration testing was performed at any stage. Every finding derives from configuration review and native platform and OS logging — the evidence standard a GRC or internal-audit function works to.
