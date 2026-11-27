"""oauth service — the networked MCP 2026-07-28 auth surface (CUT-EXEC-005 / CUT-CRED-004).

An honest authorization server, an attacker-controlled one, and three resource servers (a
hardened ``notes-api``, a vulnerable ``customer-records`` with no audience validation, and a
``customer-records-strict`` control). `standin` replays a token across audiences here; `shellgame`
runs the authorization-server mix-up. See :func:`cutout_range.service.apps.oauth_app`.
"""

from __future__ import annotations

from cutout_range.service.apps import oauth_app

app = oauth_app()
