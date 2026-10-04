"""Write an explicitly labelled offline demo policy without changing the shipped one."""
from pathlib import Path
import argparse
import yaml


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="data/offline-policy.yaml")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    policy = yaml.safe_load((root / "backend/policy.yaml").read_text())
    policy["semantic"].update(backend="heuristic", model="offline/heuristic", fallback_model="")
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("# Offline deterministic heuristic judge; this is not an LLM.\n" + yaml.safe_dump(policy, sort_keys=False))
    print(f"Offline heuristic policy: {destination}")


if __name__ == "__main__":
    main()
