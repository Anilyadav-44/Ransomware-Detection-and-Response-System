import unittest
import time

from app.detectors.detection_engine import DetectionEngine, FileEvent


class TestDetectionEngine(unittest.TestCase):

    def test_no_events_no_ransomware_burst(self):
        engine = DetectionEngine()
        result = engine.analyze()

        self.assertFalse(result["ransomware_burst"])

    def test_modification_burst_detected(self):
        engine = DetectionEngine(
            modification_threshold=5,
            rename_threshold=3
        )

        now = time.time()

        for i in range(5):
            engine.add_event(
                FileEvent(
                    event_type="modified",
                    file_path=f"file_{i}.txt",
                    entropy=2.0,
                    timestamp=now
                )
            )

        result = engine.analyze()

        self.assertTrue(result["ransomware_burst"])
        self.assertEqual(result["modifications"], 5)

    def test_rename_burst_detected(self):
        engine = DetectionEngine(rename_threshold=3)

        now = time.time()

        for i in range(3):
            engine.add_event(
                FileEvent(
                    event_type="renamed",
                    file_path=f"file_{i}.locked",
                    entropy=2.0,
                    timestamp=now
                )
            )

        result = engine.analyze()

        self.assertTrue(result["ransomware_burst"])
        self.assertEqual(result["renames"], 3)

    def test_high_entropy_files_counted(self):
        engine = DetectionEngine(entropy_threshold=4.0)

        now = time.time()

        engine.add_event(
            FileEvent(
                event_type="modified",
                file_path="suspicious.bin",
                entropy=5.5,
                timestamp=now
            )
        )

        result = engine.analyze()

        self.assertEqual(result["high_entropy_files"], 1)

    def test_extension_changes_detected(self):
        engine = DetectionEngine(rename_threshold=3)

        now = time.time()

        for i in range(3):
            engine.add_event(
                FileEvent(
                    event_type="extension_changed",
                    file_path=f"file_{i}.locked",
                    entropy=2.0,
                    timestamp=now
                )
            )

        result = engine.analyze()

        self.assertTrue(result["ransomware_burst"])
        self.assertEqual(result["extension_changes"], 3)


if __name__ == "__main__":
    unittest.main()