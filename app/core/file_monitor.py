
import json
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from app.core.config import load_config
from app.core.entropy import calculate_entropy
from app.core.logger import setup_logger
from app.detectors.detection_engine import DetectionEngine, FileEvent


DASHBOARD_EVENT_URL = "http://127.0.0.1:5000/api/events"


def send_dashboard_event(event_data):
    """Send monitoring results to the local dashboard."""

    try:
        payload = json.dumps(event_data).encode("utf-8")

        request = Request(
            DASHBOARD_EVENT_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urlopen(request, timeout=2) as response:
            return response.status == 201

    except (URLError, TimeoutError, OSError) as error:
        print(f"[INFO] Dashboard unavailable: {error}")
        return False


class RDRSFileHandler(FileSystemEventHandler):

    def __init__(self, engine, threshold):
        self.engine = engine
        self.threshold = threshold
        self.logger = setup_logger()

    def analyze_file(self, file_path, event_type):
        path = Path(file_path)

        if not path.is_file():
            return

        try:
            data = path.read_bytes()

            if not data:
                print(f"[INFO] Empty file: {path.name}")
                self.logger.info(
                    "Empty file detected: %s",
                    path.name
                )
                return

            entropy = calculate_entropy(data)

            event = FileEvent(
                event_type=event_type,
                file_path=str(path.resolve()),
                entropy=entropy,
                timestamp=time.time()
            )

            self.engine.add_event(event)
            result = self.engine.analyze()

            high_entropy = entropy >= self.threshold
            ransomware_burst = result["ransomware_burst"]

            # Combine the engine's severity with the current file's
            # entropy and event type.
            engine_severity = result["severity"]

            if engine_severity == "CRITICAL":
                severity = "CRITICAL"

            elif high_entropy or engine_severity == "HIGH":
                severity = "HIGH"

            elif (
                engine_severity == "MEDIUM"
                or event_type in ("renamed", "extension_changed")
            ):
                severity = "MEDIUM"

            else:
                severity = "LOW"

            if severity == "CRITICAL":
                status = "RANSOMWARE-LIKE ACTIVITY DETECTED"

            elif severity == "HIGH":
                status = "HIGH ENTROPY FILE - REVIEW REQUIRED"

            elif severity == "MEDIUM":
                status = "FILE NAME OR EXTENSION CHANGED"

            else:
                status = "NORMAL"

            dashboard_event = {
                "file": path.name,
                "file_path": str(path.resolve()),
                "event_type": event_type,
                "entropy": round(entropy, 2),
                "severity": severity,
                "high_entropy": high_entropy,
                "ransomware_burst": ransomware_burst,
                "modifications": result["modifications"],
                "renames": result["renames"],
                "extension_changes": result["extension_changes"],
                "high_entropy_files": result["high_entropy_files"],
                "average_entropy": result["average_entropy"],
                "modification_burst": result["modification_burst"],
                "rename_burst": result["rename_burst"],
                "high_entropy_burst": result["high_entropy_burst"],
                "suspicious_signals": result["suspicious_signals"]
            }

            send_dashboard_event(dashboard_event)

            self.logger.info(
                "File event: %s | File: %s | Entropy: %.2f bits | Severity: %s",
                event_type,
                path.name,
                entropy,
                severity
            )

            print("\n========== RDRS EVENT ==========")
            print(f"File: {path.name}")
            print(f"Event: {event_type}")
            print(f"Entropy: {entropy:.2f} bits")
            print(f"Severity: {severity}")
            print(f"Modifications: {result['modifications']}")
            print(f"Renames: {result['renames']}")
            print(f"Extension changes: {result['extension_changes']}")
            print(f"High entropy files: {result['high_entropy_files']}")
            print(f"Average entropy: {result['average_entropy']}")
            print(f"Modification burst: {result['modification_burst']}")
            print(f"Rename burst: {result['rename_burst']}")
            print(f"High entropy burst: {result['high_entropy_burst']}")
            print(f"Suspicious signals: {result['suspicious_signals']}")
            print(f"Status: {status}")
            print("================================\n")

            if ransomware_burst:
                self.logger.warning(
                    "Ransomware-like activity detected | File: %s",
                    path.name
                )

            elif high_entropy:
                self.logger.warning(
                    "High entropy file detected | File: %s | Entropy: %.2f",
                    path.name,
                    entropy
                )

        except Exception as error:
            print(f"[ERROR] Could not analyze {path}: {error}")

            self.logger.exception(
                "Could not analyze file: %s",
                path
            )

    def on_created(self, event):
        if not event.is_directory:
            self.analyze_file(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self.analyze_file(event.src_path, "modified")

    def on_moved(self, event):
        if not event.is_directory:
            old_path = Path(event.src_path)
            new_path = Path(event.dest_path)

            if old_path.suffix.lower() != new_path.suffix.lower():
                self.analyze_file(
                    event.dest_path,
                    "extension_changed"
                )

            else:
                self.analyze_file(
                    event.dest_path,
                    "renamed"
                )


def main():
    config = load_config()
    logger = setup_logger()

    watch_directory = Path(
        config["monitoring"]["watch_directory"]
    )

    if not watch_directory.is_absolute():
        watch_directory = (
            Path(__file__).resolve().parents[2]
            / watch_directory
        )

    threshold = config["detection"]["entropy_threshold"]

    engine = DetectionEngine(
        window_seconds=60,
        modification_threshold=5,
        rename_threshold=3,
        entropy_threshold=threshold
    )

    watch_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    handler = RDRSFileHandler(engine, threshold)

    observer = Observer()

    observer.schedule(
        handler,
        str(watch_directory),
        recursive=True
    )

    observer.start()

    print("========================================")
    print(" RDRS File Monitoring Started")
    print("========================================")
    print(f"Monitoring: {watch_directory.resolve()}")
    print(f"Entropy threshold: {threshold}")
    print("Improved detection engine: ENABLED")
    print("Severity classification: ENABLED")
    print("Dashboard integration: ENABLED")
    print("File logging: ENABLED")
    print("Press CTRL+C to stop.")
    print("========================================")

    logger.info(
        "RDRS monitoring started | Directory: %s",
        watch_directory.resolve()
    )

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping RDRS...")
        logger.info("RDRS monitoring stopped")

    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()
