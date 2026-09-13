# Cutout

**A security research framework for authorized testing of agentic AI systems.**

Cutout maps, exercises, and helps remediate a class of vulnerabilities in deployed
multi-agent systems — indirect prompt injection, tool-call abuse, agent persistence, and
lateral movement across MCP servers and agent-to-agent chains — that model-level testing
tools do not reach. It ships with a deliberately-vulnerable range so every technique can be
learned and demonstrated locally, offline, against a target built for the purpose.

> ⚠️ **Authorized use only.** Use Cutout against the bundled range, systems you own, or
> systems you have explicit written permission to test. See [ETHICS.md](ETHICS.md).

This is independent security research. Every offensive technique is paired with detection and
mitigation guidance; see the taxonomy at [`taxonomy/matrix.yaml`](taxonomy/matrix.yaml) and
the plan in [PROJECT_PLAN.md](PROJECT_PLAN.md).

## Status

Early development. See [PROJECT_PLAN.md](PROJECT_PLAN.md) for roadmap and
[CLAUDE.md](CLAUDE.md) for architecture.
