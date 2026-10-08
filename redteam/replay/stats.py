"""Statistical utilities for episode result analysis.

Currently provides the Wilson score interval for binomial proportions.
"""

from __future__ import annotations

import math


def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Compute the Wilson score 95% confidence interval for a proportion.

    Parameters
    ----------
    k:
        Number of successes (0 <= k <= n).
    n:
        Total number of trials (n >= 1).
    z:
        Z-score for the desired confidence level (default 1.96 for 95%).

    Returns
    -------
    (low, high):
        Lower and upper bounds of the Wilson score interval, both in [0, 1].

    Raises
    ------
    ValueError:
        If n <= 0 or if k is outside [0, n].

    Notes
    -----
    Formula (Wilson 1927)::

        p      = k / n
        d      = 1 + z² / n
        center = (p + z² / (2n)) / d
        margin = z * sqrt(p·(1-p)/n + z² / (4n²)) / d
        low    = max(0.0, center - margin)
        high   = min(1.0, center + margin)

    The standard Wilson score interval naturally evaluates at k=0 (yielding
    low=0.0, high=z²/(n+z²)) and at k=n (yielding low=n/(n+z²), high=1.0)
    without special-casing.
    """
    if n <= 0:
        raise ValueError("n must be >= 1")
    if k < 0 or k > n:
        raise ValueError(f"k must satisfy 0 <= k <= n; got k={k}, n={n}")

    p = k / n
    z2 = z * z
    d = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / d
    margin = (z * math.sqrt(p * (1.0 - p) / n + z2 / (4.0 * n * n))) / d
    low = max(0.0, center - margin)
    high = min(1.0, center + margin)
    return low, high
