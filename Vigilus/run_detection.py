import yaml
from pathlib import Path

from core.db import init_db
from core.detect import run_detection

CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main():
    print("[*] Initializing database (if needed)...")
    init_db()

    config = load_config()
    run_detection(config=config, batch_size=200)


if __name__ == "__main__":
    main()
