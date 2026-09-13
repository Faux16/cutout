"""Networked range: the vulnerable stack exposed as HTTP services (docker/uvicorn).

Same tool-server / corpus / orchestrator logic as the in-process range, wrapped in
FastAPI apps so it becomes a real, network-addressable target. Requires the ``range``
optional dependencies (``pip install -e '.[range]'``).
"""
