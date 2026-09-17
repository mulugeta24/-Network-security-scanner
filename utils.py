"""Small presentation helpers used by the command-line interface."""

from collections import Counter
from typing import Any


def summarize_results(results: list[dict[str, Any]]) -> dict[str, int]:
    """Count each supported scan status."""
    counts = Counter(result["status"] for result in results)
    return {status: counts.get(status, 0) for status in ("open", "closed", "timeout", "error")}
