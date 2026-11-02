
import logging
from pathlib import Path

from app.core.config import load_config


def setup_logger():
    """Configure RDRS logging to save events in a log file."""

    config = load_config()

    log_directory = Path(config["logging"]["log_directory"])
    log_directory.mkdir(parents=True, exist_ok=True)

    log_file = log_directory / "rdrs.log"
    log_level = config["logging"].get("log_level", "INFO").upper()

    logger = logging.getLogger("RDRS")
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    if not logger.handlers:
        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s"
        )

        file_handler = logging.FileHandler(
            log_file,
            encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
