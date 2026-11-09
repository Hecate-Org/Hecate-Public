# Hecate-Public

> **The Version-Controlled Threat Hunting & Detection Engineering Workspace.**
> Living repository holding peer-reviewed hunts, Sigma rules, multi-engine SIEM queries, and grounded research dossiers.

[![Ecosystem: Hecate](https://img.shields.io/badge/ecosystem-Hecate-blue.svg)](https://github.com/Hecate-Org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Format: LOCK](https://img.shields.io/badge/pattern-LOCK-green.svg)](https://github.com/Hecate-Org/Hecate-Core/blob/main/docs/lock-pattern.md)

---

## 🧭 Overview

**Hecate-Public** (`Hecate-Workspace`) is the central content catalog of the Hecate threat hunting platform. Generated detection bundles, behavioral threat hypotheses, and Sigma rules drafted autonomously by [Hecate-Runner](https://github.com/Hecate-Org/Hecate-Runner) are submitted here via automated pull requests for human review, verification, and automated promotion into production SIEMs.

It enforces strict content hygiene:
- **LOCK Pattern Format:** Every hunt follows **Learn, Observe, Check, Keep** structure.
- **Audited Provenance:** Every claim is grounded against primary CTI sources or research dossiers.
- **Automated Promotion Gates:** `promotion-policy.yaml` blocks credentials and restricted TLP material while enforcing review approvals.

---

## 📂 Catalog Structure

| Directory | Contents & Purpose |
| :--- | :--- |
| **`hunts/`** | Threat hunt records in LOCK markdown format (`H-XXXX.md`). |
| **`queries/`** | Synthesized Sigma rules and transpiled native SIEM queries (`Splunk .spl`, `Elastic .eql`, `CrowdStrike .cql`, `Logscale .leql`). |
| **`research/`** | Model-assisted deep research dossiers grounding hunts (`R-XXXX.md`). |
| **`knowledge/`** | Organization telemetry mapping, logsource definitions, and ATT&CK matrix references. |

---

## 🚀 Getting Started for Developers & Analysts

### 1. Prerequisites & Side-by-Side Setup
Check out this repository alongside `Hecate-Core` and `Hecate-Runner`:

```bash
mkdir -p ~/betas && cd ~/betas

git clone https://github.com/Hecate-Org/Hecate-Core.git
git clone https://github.com/Hecate-Org/Hecate-Runner.git
git clone https://github.com/Hecate-Org/Hecate-Public.git Hecate-Workspace
```

### 2. Configure Local Environment
Copy the environment template:

```bash
cd ~/betas/Hecate-Workspace
cp .env.example .env
export HECATE_WORKSPACE="$PWD"
```

The selected workspace supplies `knowledge/hunting-knowledge.md` and
`knowledge/environment.md`. Core contains the readers; Runner uses the workspace
configured for its execution. Keeping the repositories beside one another does
not make Core's knowledge directory the source of truth for Public.

The public environment profile is an **unverified adopter template**. Fill its
telemetry contract with your actual sources, fields, coverage, retention and
verification evidence before relying on hunt results. Credentials belong in `.env`;
private environment details and findings belong in your controlled workspace.

Agents load bounded, stage-specific guidance blocks, rather than the whole
reference. Compact guidance is enabled by default and can be disabled with
`HECATE_HUNTING_KNOWLEDGE=false`; essential evidence rules and execution approvals
still apply. An unchanged template or missing profile never establishes telemetry
availability. Existing hunts can be reviewed and run through Runner's `sweep`
commands without enabling new-hunt generation.

### 3. Inspect & Navigate the Hunt Catalog

```bash
# List all hunts and their promotion status
uv run --directory ../Hecate-Core hecate-agent hunt list

# Launch the interactive terminal monitor
uv run --directory ../Hecate-Core hecate-agent monitor

# Generate a new research topic
uv run --directory ../Hecate-Core hecate-agent research new --topic "CVE-2026-4444 Edge Appliance Exploitation"
```

---

## 🛡️ Promotion Workflow & Security

- **Safe by Default:** Automated drafts enter in `status: planning`. No detection logic executes unattended against production environments.
- **Sanitization:** Credentials, local runtime caches (`.cursors/`, `.*_cursor_state.json`), and private logs are strictly excluded via `.gitignore`.
- **Policy Enforcement:** CI runs `promotion-policy.yaml` to validate syntax, verify Sigma rules, audit technique grounding, and confirm review approvals before merging.

See [license scope](LICENSES.md) for what the MIT license covers.
