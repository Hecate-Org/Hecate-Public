# Hunting guidance

Use LOCK to connect research to a testable behavioral hypothesis:

1. Learn: gather grounded research and identify the relevant adversary behavior.
2. Observe: state a falsifiable hypothesis and map it to available telemetry.
3. Check: validate query syntax and run an authorized, bounded test.
4. Keep: record the result, limitations, and lessons learned.

Search prior hunts with `hecate-agent similar` before generating new hypotheses. Use `hecate-agent research new` before AI-generated hypotheses and create hunt records through `hecate-agent hunt new`.

Prefer behavioral detection over stand-alone indicators. Distinguish source assertions, analyst inferences, and observed evidence. Bound queries by time and scope, start with counts and small result limits, and document likely false positives.

Do not invent execution results. An untested rule remains a candidate until the relevant schema and behavior have been validated.
