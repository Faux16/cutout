# Ethical Use & Coordinated Disclosure

Cutout is a security research framework for **authorized testing of agentic AI systems**.
It exists to help defenders find and fix a class of vulnerabilities — indirect prompt
injection, tool-call abuse, agent persistence, and lateral movement across agent chains —
that current tooling does not exercise. Understanding these attacks is a precondition for
defending against them; every offensive technique in this project is paired with detection
and mitigation guidance.

## Authorized use only

Use Cutout **only** against:

- The bundled `range/` (its intended target — a deliberately-vulnerable stack you run locally).
- Systems you own.
- Systems you have **explicit, written authorization** to test.

Running Cutout against systems you do not own or have permission to test may be illegal and
is not a use this project supports.

## Scope

- Cutout ships with, and is developed against, its own vulnerable range so that no third-party
  system is needed to demonstrate or learn any technique.
- The default provider is a deterministic offline mock. The framework makes no external calls
  unless a user explicitly configures a target they are authorized to test.

## Coordinated disclosure

Findings produced with Cutout against real products are handled under coordinated disclosure:

- Report privately to the affected vendor first.
- Allow a reasonable remediation window (default 90 days) before public detail.
- Request CVEs where applicable.
- Publish write-ups only after a fix ships or the window lapses.

## Defensive contribution

Each technique in the taxonomy (`taxonomy/matrix.yaml`) carries an intended detection and
mitigation note. The project's public output includes defensive guidance for builders of
agentic systems, not only offensive tooling.
