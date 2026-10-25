
"""Generate synthetic honey tokens for controlled security experiments."""

import secrets
import string


def generate_canary(length: int = 24) -> str:
    """Generate a random synthetic canary with a recognizable prefix."""
    alphabet = string.ascii_letters + string.digits
    random_part = "".join(
        secrets.choice(alphabet) for _ in range(length)
    )
    return f"HS-CANARY-{random_part}"


def contains_canary(text: str, canaries: set[str]) -> bool:
    """Return True if any registered canary occurs in the text."""
    return any(canary in text for canary in canaries)


