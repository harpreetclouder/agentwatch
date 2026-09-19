# VEYRA Security Plane

This directory is part of the VEYRA security control plane.

Agents must NOT modify:
- config.json
- policies/
- veyra.sqlite
- security state
- event / decision history

Local MVP note: a process with OS privileges can still bypass user-space controls.
Production deployments should place this plane outside the agent trust boundary.
