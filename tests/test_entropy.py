import unittest

from app.core.entropy import calculate_entropy


class TestEntropy(unittest.TestCase):

    def test_empty_data(self):
        self.assertEqual(calculate_entropy(b""), 0.0)

    def test_identical_bytes(self):
        self.assertEqual(calculate_entropy(b"aaaaaa"), 0.0)

    def test_two_equally_frequent_bytes(self):
        result = calculate_entropy(b"abababab")
        self.assertAlmostEqual(result, 1.0)

    def test_entropy_is_positive_for_varied_data(self):
        result = calculate_entropy(b"Hello RDRS")
        self.assertGreater(result, 0.0)

    def test_entropy_does_not_exceed_eight_bits(self):
        result = calculate_entropy(bytes(range(256)))
        self.assertLessEqual(result, 8.0)


if __name__ == "__main__":
    unittest.main()