# AI Control Layer — HackYeah Submission

**Project title:** AI Control Layer  
**Team name:** TODO — add the registered team name.

## Team members

- Ivan Shevchuk
- Timofii Vasin
- Illia Liudohovskyi

## Project description

AI Control Layer is a security gateway between AI agents and the models and tools they use. It checks OpenAI-compatible requests against a shared YAML policy, detects prompt injection and sensitive data, controls tool permissions and arguments, enforces usage budgets, and requires human approval for irreversible actions. An information-flow guard checks whether protected tool data is reused in outgoing actions. Decisions are recorded in an HMAC-chained audit log and explained in a browser dashboard. The reproducible banking demo uses synthetic records, a scripted assistant, and simulated email and payment tools. It runs offline with a labelled rules classifier; an OpenRouter key enables the implemented remote AI security judge.

## Links

- **Repository:** [GitHub repository](https://github.com/ivanshevchuk0/HackYeah-) — submission code is on `main`.
- **Hosted demo:** TODO — add the confirmed public demo URL.
- **Demo video:** TODO — add a link if a video is submitted.
- **Local demo:** http://localhost:8080/ after following the [README setup instructions](README.md#quickstart).

## Review instructions

Follow the [README](README.md) to start `make run-offline HOST=127.0.0.1`, configure the dashboard admin token, and explore the demo cards. `make demo` runs the scripted walkthrough; `python3 -m pytest -q` runs the offline test suite. The offline classifier is not an LLM, and the demo tools do not send real email or move real funds.
