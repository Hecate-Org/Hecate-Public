# Hecate-Public

The shared Hecate catalog contains hunt definitions, candidate Sigma rules,
native query artifacts, research and starter knowledge. Presence in this catalog
or a merged PR does not prove live detection coverage in your environment.

## Repository responsibilities

[Core](https://github.com/Hecate-Org/Hecate-Core) supplies functional code and the
`hecate-agent` CLI. [Runner](https://github.com/Hecate-Org/Hecate-Runner) supplies
scheduling, integrations, execution approvals and the `hecate-runner` CLI. This
repository supplies content. Your enterprise-specific component should be a
private workspace seeded with the content you want to use.

| Directory | Contents |
| --- | --- |
| `hunts/` | LOCK-format hunt records (`H-XXXX.md`) |
| `queries/` | Sigma YAML and native `.spl`, `.kql`, `.eql`, `.cql`, `.leql`, `.s1ql` artifacts |
| `research/` | Research dossiers (`R-XXXX.md`) |
| `knowledge/` | Starter environment contract and hunting guidance |
| `scripts/` and `.github/workflows/` | Content review and promotion checks |

`.cql` is the CrowdStrike LogScale query format; `.leql` is Rapid7 LEQL.

## Install and browse

Python 3.11+, Git and uv are required for this source setup. `.github`, Core,
Runner and Public can be sibling directories; `.github` is optional to clone.

```bash
mkdir hecate-dev
cd hecate-dev
git clone https://github.com/Hecate-Org/Hecate-Core.git
git clone https://github.com/Hecate-Org/Hecate-Runner.git
git clone https://github.com/Hecate-Org/Hecate-Public.git
uv venv .venv
source .venv/bin/activate
uv pip install -e './Hecate-Core[all,dev]' -e './Hecate-Runner[dev]'
export HECATE_WORKSPACE="$PWD/Hecate-Public"
export HECATE_BIN="$PWD/.venv/bin/hecate-agent"
cd Hecate-Public
hecate-runner demo
hecate-agent hunt list
```

This setup uses one development environment for both packages. The demo is
isolated and needs no keys. It does not add a new hunt to Public. For persistent
shell setup, see [Runner onboarding](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/ONBOARDING.md).

## Select knowledge, credentials and output locations

Export `HECATE_WORKSPACE` before running either application. Both use that
workspace's `.env`; a cwd `.env` can override it, and existing environment
variables take precedence. No `.env` symlink is created automatically.

Copy `.env.example` to `.env` only if a file does not already exist, then supply
only the keys required by the features you enable. Nothing supplies working API
keys for adopters. Keep `.env`, `.hecate/`, logs, evidence and private findings
out of public commits.

The selected workspace supplies `knowledge/environment.md` and
`knowledge/hunting-knowledge.md`. The public environment file is an **unverified
template**: complete its actual sources, fields, coverage, retention and evidence
before live use. Compact stage-specific guidance is enabled by default;
`HECATE_HUNTING_KNOWLEDGE=false` disables that optional guidance without removing
evidence requirements or execution gates.

For enterprise use, copy reviewed catalog content into a private workspace, set
`HECATE_WORKSPACE` to it, and keep your real environment profile and results
there. Applications do not automatically merge Public with a second workspace.

## Run catalog hunts without generating new H files

Configure a query provider and approval policy in your private workspace. Replace
`H-0001` with an existing ID:

```bash
hecate-agent hunt list
hecate-agent context --hunt H-0001 --format json
hecate-agent hunt update H-0001 --status active
hecate-runner sweep stage --hunt-id H-0001 --days 1
hecate-runner sweep pending
hecate-runner sweep approve <SWEEP-ID>
```

`HECATE_RUNNER_QUERY_PROVIDER=mock` performs no live SIEM search. Keep
`HECATE_AUTO_HUNT_APPROVAL_REQUIRED=true` while establishing verified mappings.
For continuous scheduling, configure `HECATE_AUTO_HUNT_EXECUTION_ENABLED` and run
`hecate-runner sweep daemon`. CTI intake, research and new-hunt generation are
separate; you do not need to run `hecate-runner daemon`. Optional finding triage,
pivots and rule tuning may use model calls.

## Publication and validation boundaries

Generated hunts start in planning. Publication, query deployment, active-hunt
execution and BAS each have their own opt-ins. GitHub promotion checks do not
configure or enable a production SIEM alert.

Public snapshots require exact-snapshot privacy/redistribution review before
upload. Synthetic replay, local BAS rule matches, smoke checks, native search
matches and correlated fired-alert evidence are reported separately. Review
[BAS boundaries](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/BAS_AUTOMATION.md)
and [community/publication controls](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/COMMUNITY_RELEASES.md).

See [LICENSE](LICENSE), [LICENSES.md](LICENSES.md) and the source attribution on
imported content before redistributing it.


## GitHub Actions deployment settings

Review `.github/workflows/siem-*.yml` before configuring repository secrets.
These workflows use GitHub secrets/variables rather than the local `.env`.
The current deploy workflow can push saved queries on relevant `main` updates
when its endpoint/token are configured; local Runner dry-run flags do not govern
that separate workflow. Missing endpoint/token or an explicit workflow dry-run
selects its preview path. Review permissions, workflow triggers and destination
namespaces before enabling live credentials.

Runner includes community-release tooling, but this checkout does not contain
`catalog/catalog.yaml` or a community-release workflow. A reviewed explicit
catalog and publication workflow must be added before following that optional
release path; ordinary hunt/query content is not automatically a release bundle.
