# Hecate Public

A fresh public workspace for threat hunting with [Hecate](https://github.com/Hecate-Org/Hecate-Core).

## Get started

Use an installed `hecate-agent` command, then run:

```bash
cd Hecate-Public
cp .env.example .env
export HECATE_WORKSPACE="$PWD"
hecate-agent hunt list --output json
hecate-agent monitor
```

The workspace starts with an empty hunt catalog. Configure local AI and search credentials in the ignored `.env` file before running grounded research:

```bash
hecate-agent research new --topic "Your research topic"
hecate-agent hunt new --help
```

Use the CLI to create, validate, and manage research, hunts, and investigations.

## Contents

| Directory | Purpose |
| --- | --- |
| `hunts/` | Hunt records in LOCK format |
| `research/` | Research supporting hunt hypotheses |
| `queries/` | Detection and hunting queries |
| `detections/` | Detection rules |
| `investigations/` | Exploratory investigations |
| `knowledge/` | Hunting guidance and telemetry context |

This repository is public. Review new content before publishing it. Credentials, local runtime state, evidence, and query results belong in local or private storage.

The Runner retains its local hunt history in `Hecate-Workspace` and publishes new planning-hunt bundles here through the `hecate-publisher` GitHub App. A separate public publication queue prevents replay of the former private queue.

The promotion workflow validates content and applies `promotion-policy.yaml`. Restricted TLP material and credentials are blocked before upload. Unmarked source material is allowed; quality issues that require review still need a qualified approval on the current commit.
