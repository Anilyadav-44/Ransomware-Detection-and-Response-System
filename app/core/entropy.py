
import math
from collections import Counter


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of file bytes."""

    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


if __name__ == "__main__":
    samples = [
        b"hello world",
        b"normal_filename.txt",
        b"a8F$k92Lm!xP7@qZ"
    ]

    for sample in samples:
        print(f"Data: {sample}")
        print(f"Entropy: {calculate_entropy(sample):.2f} bits")
        print("-" * 40)
