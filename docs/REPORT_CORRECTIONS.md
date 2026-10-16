# Report corrections — align the write-up with the built system

Apply these to the Word document. Each item gives the location, what it currently
says, and what to change it to. They remove the mismatches between the proposal and
the system that was actually built and tested.

## 1. VirtualBox → VMware Workstation  (the lab was built on VMware, not VirtualBox)

Change every mention of VirtualBox to **VMware Workstation 17**. Known locations:

| Section | Current | Change to |
|---|---|---|
| 1.3.2 Specific Objective iv | "using Kali Linux in VirtualBox" | "using Kali Linux in **VMware Workstation**" |
| 3.3.2 Non-Functional Reqs | "deployable on a single host machine running VirtualBox" | "...running **VMware Workstation**" |
| 3.4.1 Hardware Requirements | "supports VirtualBox internal network adapters" | "supports **VMware host-only / NAT** network adapters" |
| 3.5.2 Test Environment | "within the VirtualBox environment" | "within the **VMware Workstation** environment" |
| 4.1 / 4.4.1 (Chapter 4) | "five-VM VirtualBox test environment" | "five-VM **VMware Workstation** test environment" |

Also in 3.4.2 Software Requirements, "Platform software includes VMware Workstation"
is already correct — just make sure VirtualBox does not reappear elsewhere.

## 2. Datasets — NSL-KDD is the training set; CICIDS2017 is referenced

The build trained on **NSL-KDD** (KDDTrain+/KDDTest+). CICIDS2017 was not used for
training because of its size on the lab VM. Update the claims so they match.

- **2.2.4** and **Abstract/Keywords**: keep both datasets named in the literature,
  but state clearly: *"NSL-KDD is used to train and evaluate the benchmark models;
  CICIDS2017 is reviewed as a complementary modern benchmark and is recommended for
  future retraining on higher-volume flow data."*
- Remove any sentence claiming the two datasets are *combined / feature-aligned* for
  training (they share almost no features, so that claim is not defensible). Replace
  with the single-dataset statement above. In the build, each dataset stands alone.
- If you prefer to still show CICIDS2017 results, that is a Phase-5/future-work item;
  do not claim it as done.

## 3. Windows endpoint — add it to scope (it was built)

A Wazuh agent was installed on the Windows host, giving 3 live agents
(2× Ubuntu + 1× Windows) plus the Cowrie honeypot agent. The proposal's scope
(1.4) says Linux-only. Either:
- **(recommended)** widen 1.4: "The SIEM layer monitors Linux endpoints **and a
  Windows host**, demonstrating cross-platform collection," and mention Windows
  Event Log collection as a strength; or
- keep Windows out of scope and present it only as supplementary evidence.
Pick one and be consistent in Chapters 4 and 5.

## 4. ML output on the dashboard — now literally true

The proposal says ML classification results appear on the Wazuh Dashboard. With the
integration built (`wazuh/` rules + the verdict re-ingestion), this is now accurate:
ML verdicts are written to a log that Wazuh re-ingests under rule group `isiem_ml`,
so they show on the dashboard beside rule-based alerts. Keep the claim; it is backed
by the deployment steps in `DEPLOY.md`.

## 5. Behavioural analytics — make the title's promise explicit

The title says "Behavioural Analytics". Add a short paragraph (end of 2.2.3 or in
Chapter 4/5) explaining the live engine reasons about an **actor (source IP) over a
sliding time window**, counting behaviours (failed logins, hosts/ports touched,
honeypot hits, off-hours logins, beacon regularity) rather than scoring single
packets — this is what distinguishes the live layer from the offline benchmark and
justifies "behavioural analytics".

## 6. Seven categories — confirm coverage

The live classifier covers all seven proposal categories plus Honeypot Interaction:
brute force/credential stuffing, port scanning/recon, lateral movement, privilege
escalation, data exfiltration, C2 beaconing, suspicious authentication. The mapping
is in `ml/classifier.py` and each rule traces to a signature from Chapter 2.3 — cite
that in Chapter 4's detection-logic discussion.
