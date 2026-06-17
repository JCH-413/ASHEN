# Architecture Decision Records

Each ADR records one significant, non-obvious design decision — its context, the
decision, and its consequences. Numbers map to the architecture-review candidate
they came from, so gaps are meaningful (no 0004 yet — that candidate is unbuilt).

| ADR | Decision |
|-----|----------|
| [0001](0001-exploit-type-seam.md) | An Exploit Type seam — `ExploitRunner` + explicit registry |
| [0002](0002-process-module.md) | A deep `process` module owns external-process lifecycle |
| [0003](0003-authorisation-seam.md) | Authorisation enforced at one seam (`require_action`) |
| [0005](0005-scan-lifecycle.md) | A Scan lifecycle module owns transitions and extraction |
