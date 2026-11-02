
import time
from collections import deque
from dataclasses import dataclass


@dataclass
class FileEvent:
    event_type: str
    file_path: str
    entropy: float = 0.0
    timestamp: float = 0.0


class DetectionEngine:
    """Detect suspicious file activity and ransomware-like patterns."""

    def __init__(
        self,
        window_seconds=60,
        modification_threshold=20,
        rename_threshold=10,
        entropy_threshold=4.0,
    ):
        self.window_seconds = window_seconds
        self.modification_threshold = modification_threshold
        self.rename_threshold = rename_threshold
        self.entropy_threshold = entropy_threshold
        self.events = deque()

    def add_event(self, event):
        """Add an event and maintain the detection time window."""

        if event.timestamp == 0:
            event.timestamp = time.time()

        self.events.append(event)
        self._remove_old_events()

    def _remove_old_events(self):
        """Remove events older than the configured time window."""

        current_time = time.time()

        while (
            self.events
            and current_time - self.events[0].timestamp
            > self.window_seconds
        ):
            self.events.popleft()

    def analyze(self):
        """Analyze recent events and return detection information."""

        self._remove_old_events()

        modifications = sum(
            event.event_type == "modified"
            for event in self.events
        )

        renames = sum(
            event.event_type == "renamed"
            for event in self.events
        )

        extension_changes = sum(
            event.event_type == "extension_changed"
            for event in self.events
        )

        high_entropy_events = [
            event for event in self.events
            if event.entropy >= self.entropy_threshold
        ]

        average_entropy = (
            sum(event.entropy for event in self.events)
            / len(self.events)
            if self.events else 0.0
        )

        unique_modified_files = len({
            event.file_path
            for event in self.events
            if event.event_type == "modified"
        })

        unique_renamed_files = len({
            event.file_path
            for event in self.events
            if event.event_type in ("renamed", "extension_changed")
        })

        modification_burst = (
            modifications >= self.modification_threshold
            and unique_modified_files >= 3
        )

        rename_burst = (
            renames + extension_changes >= self.rename_threshold
            and unique_renamed_files >= 3
        )

        high_entropy_burst = (
            len(high_entropy_events) >= 5
            and average_entropy >= self.entropy_threshold
        )

        ransomware_burst = (
            modification_burst
            or rename_burst
            or high_entropy_burst
        )

        suspicious_signals = sum([
            modification_burst,
            rename_burst,
            high_entropy_burst,
        ])

        if ransomware_burst and suspicious_signals >= 2:
            severity = "CRITICAL"
        elif ransomware_burst or high_entropy_burst:
            severity = "HIGH"
        elif renames > 0 or extension_changes > 0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "modifications": modifications,
            "renames": renames,
            "extension_changes": extension_changes,
            "high_entropy_files": len(high_entropy_events),
            "average_entropy": round(average_entropy, 2),
            "unique_modified_files": unique_modified_files,
            "unique_renamed_files": unique_renamed_files,
            "modification_burst": modification_burst,
            "rename_burst": rename_burst,
            "high_entropy_burst": high_entropy_burst,
            "suspicious_signals": suspicious_signals,
            "severity": severity,
            "ransomware_burst": ransomware_burst,
        }


if __name__ == "__main__":
    engine = DetectionEngine(
        window_seconds=60,
        modification_threshold=5,
        rename_threshold=3,
        entropy_threshold=4.0,
    )

    now = time.time()

    for i in range(5):
        engine.add_event(
            FileEvent(
                event_type="modified",
                file_path=f"data/test_{i}.txt",
                entropy=5.5,
                timestamp=now,
            )
        )

    result = engine.analyze()

    print("=" * 45)
    print("RDRS IMPROVED DETECTION ENGINE")
    print("=" * 45)

    for key, value in result.items():
        print(f"{key.replace('_', ' ').title()}: {value}")

    print("=" * 45)
