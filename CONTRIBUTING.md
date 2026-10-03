# Working together on AgentShield

We have four workstreams. Use your assigned branch and keep changes inside your
ownership area so everyone can work in parallel.

## Branch ownership

| Branch | Owner | Responsibilities | Files and folders |
| --- | --- | --- | --- |
| `backend-core` | Person 1 | FastAPI, `/intercept`, shared models, policy engine, decision logic, budget, audit | `backend/app/main.py`, `models.py`, `engine.py`, `policy.py`, `budget.py`, `audit.py`, `backend/policy.yaml`, `backend/requirements.txt` |
| `guardrails` | Person 2 | PII and secret detection, redaction helpers, prompt-injection and semantic risk detection | `backend/app/guardrails/` |
| `frontend-core` | Person 3 | Dashboard, action simulator, statistics display, audit log UI, result cards | `frontend/` |
| `test-demo` | Person 4 | pytest tests, mock tools and agent, fake demo data, attack scenarios, final demo flow | `tests/`, `backend/app/tools/`, `demo/` |

In the backend row, the Python filenames all refer to `backend/app/`.
Shared documentation and root configuration need coordination when edits overlap.

`frontend-core` and `test-demo` are the repository branch names for the frontend
and tests-demo workstreams. `warden-core` integrates all four workstreams and is
the current demo/test deployment branch. It does not change file ownership.

## Boundaries and shared contracts

- Guardrails **detect risks** and provide findings and redaction helpers.
- The backend policy engine **decides what to do**: `ALLOW`, `BLOCK`, `REDACT`, or `REQUIRE_APPROVAL`.
- The frontend **shows the result**; it does not enforce security.
- Tests-demo **proves it works** with fake tools, data, and scenarios.

Do not trust the AI agent. AgentShield enforces security outside the agent.

Do not change another branch's files unless necessary. If a change crosses a
boundary, explain the need to the owner and coordinate the edit before proceeding.
For example, a guardrail developer should coordinate an engine integration with
Person 1 instead of independently changing `engine.py`.

The shared request/response API contract belongs in `backend/app/models.py`.
Before changing fields, types, defaults, or response shapes, coordinate with
Person 1 and everyone consuming the contract. Agree on the change and update
affected frontend, guardrail interfaces, tests, and demo payloads together.
Person 1's ownership does not remove this coordination requirement.

## Start working

1. Choose your assigned branch from the table above.
2. Start new work from the latest `warden-core`. If your branch already exists,
   switch to it and merge `origin/warden-core` before starting new changes.
3. Read the existing API and guardrail interfaces and `docs/CONTRACTS.md` before
   connecting workstreams. Coordinate any contract changes with their consumers.
4. Implement in your ownership area and keep commits focused.
5. Open a pull request into `warden-core` with what changed, how to verify it, and any
   dependencies on another branch. Coordinate integration order with affected owners.

For a new branch:

```bash
git fetch origin
git switch -c backend-core origin/warden-core  # only if your branch does not exist
```

For an existing local branch, use `git switch backend-core` (with your branch name).
Then fetch and merge `origin/warden-core` into that branch; preserve your work and
coordinate any conflicts with the owners of affected files.

## Keep main demoable

The integration flow is team branches → `warden-core` → verified release → `main`.
Every integration and release must preserve the demo flow.

Before merging, verify the affected behavior, run available relevant tests, and
check that the agreed demo still runs. Include verification steps in the pull
request. Coordinate dependent changes so `main` is not left with incompatible
contracts or a broken frontend/backend connection.

Mock tools must use fake data only. Keep the hackathon scope small; add dependencies
and infrastructure only when needed for the agreed MVP.
