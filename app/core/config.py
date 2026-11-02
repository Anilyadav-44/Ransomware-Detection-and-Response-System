import yaml
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent.parent
CONFIG_FILE = BASE_DIR / "config.yaml"


def load_config():
    """Load RDRS configuration from config.yaml."""
    if not CONFIG_FILE.exists():
        raise FileNotFoundError(f"Configuration file not found: {CONFIG_FILE}")

    with open(CONFIG_FILE, "r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


if __name__ == "__main__":
    config = load_config()
    print("RDRS configuration loaded successfully.")
    print(config)
