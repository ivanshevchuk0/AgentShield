# AgentShield. Run every target from the repository root.
# Server command matches the image:
#   uvicorn --factory app.main:create_app --app-dir backend --host 0.0.0.0 --port 8080

PYTHON ?= python3
HOST ?= 0.0.0.0
PORT ?= 8080
COMPOSE ?= docker compose

# Export assignments from .env when the file exists. One shell line, no override of the recipe.
LOAD_ENV = set -a; [ -f .env ] && . ./.env; set +a;

.PHONY: help install run test demo docker verify-audit

help:
	@echo "targets: install run test demo docker verify-audit"

install:
	$(PYTHON) -m pip install -r backend/requirements.txt

run:
	@$(LOAD_ENV) $(PYTHON) -m uvicorn --factory app.main:create_app --app-dir backend --host $(HOST) --port $(PORT)

test:
	$(PYTHON) -m pytest -q

demo:
	@$(LOAD_ENV) bash demo/run_demo.sh

# ./data is the audit volume. Mode 0777 lets the image user (uid 1000, or the
# host uid passed below) create audit.jsonl on Linux as well as Docker Desktop.
docker:
	mkdir -p data
	chmod a+rwx data
	UID="$$(id -u)" GID="$$(id -g)" $(COMPOSE) up --build

# Verify the HMAC audit chain with backend/app/audit.py. Exit 0 only when at
# least one chain was checked and every checked chain is intact.
# Key: AGENTSHIELD_AUDIT_KEY, otherwise <data-dir>/audit.key (same order as Gateway).
# Dir: AGENTSHIELD_DATA_DIR if set, otherwise data/ and backend/data/.
verify-audit:
	@$(LOAD_ENV) tmp=$$(mktemp); printf '%s\n' \
	'import os, sys' \
	'from pathlib import Path' \
	'from app.audit import AuditLog' \
	'def main():' \
	'    env_dir = os.environ.get("AGENTSHIELD_DATA_DIR", "").strip()' \
	'    if env_dir:' \
	'        directories = [Path(env_dir)]' \
	'    else:' \
	'        directories = [Path("data"), Path("backend/data")]' \
	'    checked = 0' \
	'    failed = 0' \
	'    for directory in directories:' \
	'        log_path = directory / "audit.jsonl"' \
	'        if not log_path.is_file():' \
	'            continue' \
	'        checked += 1' \
	'        env_key = os.environ.get("AGENTSHIELD_AUDIT_KEY", "").strip()' \
	'        key_file = directory / "audit.key"' \
	'        if env_key:' \
	'            raw = env_key' \
	'            source = "AGENTSHIELD_AUDIT_KEY"' \
	'        elif key_file.is_file():' \
	'            raw = key_file.read_text(encoding="utf-8").strip()' \
	'            source = str(key_file)' \
	'        else:' \
	'            print("FAIL", log_path, "no HMAC key; set AGENTSHIELD_AUDIT_KEY or add", key_file)' \
	'            failed += 1' \
	'            continue' \
	'        if not raw:' \
	'            print("FAIL", log_path, "audit key is empty")' \
	'            failed += 1' \
	'            continue' \
	'        try:' \
	'            log = AuditLog(directory, raw.encode())' \
	'        except ValueError as exc:' \
	'            print("FAIL", log_path, exc)' \
	'            failed += 1' \
	'            continue' \
	'        result = log.verify()' \
	'        status = "OK" if result.get("ok") else "FAIL"' \
	'        print(status, log_path, result, "key=" + source)' \
	'        if not result.get("ok"):' \
	'            failed += 1' \
	'    if checked == 0:' \
	'        if env_dir:' \
	'            print("FAIL no audit log at", str(Path(env_dir) / "audit.jsonl"))' \
	'        else:' \
	'            print("FAIL no audit log at data/audit.jsonl or backend/data/audit.jsonl")' \
	'        return 1' \
	'    return 1 if failed else 0' \
	'raise SystemExit(main())' \
	> "$$tmp"; PYTHONPATH=backend $(PYTHON) "$$tmp"; rc=$$?; rm -f "$$tmp"; exit $$rc
