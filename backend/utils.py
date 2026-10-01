import math


def calculate_entropy(data: str) -> float:
    """Calculates Shannon entropy: H(X) = -sum(p(x) * log2(p(x)))"""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for char in set(data):
        p_x = data.count(char) / length
        entropy -= p_x * math.log2(p_x)
    return entropy


def evaluate_risk(query_length: int, entropy: float):
    """Assigns a 0-100 risk score and severity classification."""
    score = 0
    indicators = []

    if query_length > 45:
        score += 15
        indicators.append("Long query length (>45)")
    if entropy > 3.8:
        score += 20
        indicators.append(f"High entropy ({entropy:.2f} > 3.8)")

    if score <= 29:
        severity = "Low"
    elif score <= 59:
        severity = "Medium"
    elif score <= 79:
        severity = "High"
    else:
        severity = "Critical"

    return score, severity, indicators
