# AgentShield architecture

Planned flow: User → AI Agent → AgentShield → Tools / APIs / Files / Databases.

Do not trust the AI agent. AgentShield enforces security outside the agent.

Planned decisions: `ALLOW`, `BLOCK`, `REDACT`, `REQUIRE_APPROVAL`.

Backend core owns the API, policy engine, budgets, and audit. Guardrails owns
PII, secrets, and semantic security. Frontend owns the dashboard and simulator.
Tests-demo owns tests, fake tool adapters, and demo scenarios.

This repository contains placeholders only; no behavior is implemented.
