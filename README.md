# AgentShield

A hackathon security gateway between an AI agent and tools or resources.
Do not trust the AI agent: AgentShield enforces security outside the agent.

This monorepo contains only placeholders. No dependencies are installed.

## Team responsibilities

- **backend-core:** API, policy engine, budget, audit (`backend/app/`, `backend/policy.yaml`).
- **guardrails:** PII, secrets, semantic security (`backend/app/guardrails/`).
- **frontend:** Dashboard and simulator (`frontend/`).
- **tests-demo:** Tests, mock tools, demo scenarios (`tests/`, `backend/app/tools/`, `demo/`).

Planned stack: Python, FastAPI, Pydantic, PyYAML, pytest; Next.js, TypeScript,
Tailwind; in-memory audit storage.

Agree on shared contracts in `backend/app/models.py` before connecting workstreams.
See [architecture notes](docs/architecture.md). Empty folders include `.gitkeep`
so Git preserves them. Run instructions will be added when implementation begins.
