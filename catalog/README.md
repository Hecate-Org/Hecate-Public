# Experimental Linux hunting catalog

Version 0.1.0 contains four original, low-specificity hunting building blocks:
whoami identity discovery, uname system discovery, ps process discovery, and
Base64 decoding. They identify observable mechanics also used by administrators.
They are not production alerts or claims of compromise.

Every rule has two positive and two negative synthetic process fixtures. Live
validation, when attached, runs only the existing pinned read-only Linux BAS
controls and verifies independent process observation plus local Sigma matching.
That does not establish SIEM ingestion, deployed-rule behavior, alert delivery,
or a production false-positive rate. Native queries remain schema-dependent
templates even after syntax validation.

Only catalog/catalog.yaml selects release content. Hunts, research reports,
sessions, workspace configuration and raw BAS traces are excluded. See
LICENSES.md for original-content licensing and third-party restrictions.

Use hecate-runner release build --catalog <repository> --output <new-private-dir>
for a local fixture-tested build. Use hecate-runner release verify --catalog
<repository> --output <private-evidence.json> only with the existing isolated BAS
lab configured. Add --evidence <private-evidence.json> when building to include
its sanitized validation summary. No build or validation command publishes data.
