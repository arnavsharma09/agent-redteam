"""Tests for redteam.replay.stats.wilson_interval (A1d, task 11)."""

from __future__ import annotations

import pytest

from redteam.replay.stats import wilson_interval


class TestWilsonInterval:
    """Known-value tests for Wilson score 95% CI."""

    def test_4_of_5_approx_expected(self) -> None:
        """4/5 -> approximately [0.376, 0.964] (tolerance 0.002)."""
        lo, hi = wilson_interval(4, 5)
        assert abs(lo - 0.376) < 0.002, f"low={lo:.4f} expected ~0.376"
        assert abs(hi - 0.964) < 0.002, f"high={hi:.4f} expected ~0.964"

    def test_0_of_10_low_exactly_zero(self) -> None:
        """0/10 -> low bound exactly 0.0."""
        lo, hi = wilson_interval(0, 10)
        assert lo == 0.0

    def test_10_of_10_high_exactly_one(self) -> None:
        """10/10 -> high bound exactly 1.0."""
        lo, hi = wilson_interval(10, 10)
        assert hi == 1.0

    def test_n_zero_raises_value_error(self) -> None:
        """n=0 raises ValueError."""
        with pytest.raises(ValueError, match="n must be"):
            wilson_interval(0, 0)

    def test_bounds_always_in_unit_interval(self) -> None:
        """lo >= 0 and hi <= 1 for any valid k, n."""
        for n in range(1, 20):
            for k in range(n + 1):
                lo, hi = wilson_interval(k, n)
                assert 0.0 <= lo <= hi <= 1.0, f"k={k}, n={n}: [{lo}, {hi}]"

    def test_midpoint_50_percent(self) -> None:
        """Interval is symmetric around 0.5 for k=n/2 (n even)."""
        lo, hi = wilson_interval(5, 10)
        assert abs((lo + hi) / 2 - 0.5) < 0.01

    def test_low_le_high(self) -> None:
        """lo <= hi always."""
        lo, hi = wilson_interval(3, 7)
        assert lo <= hi

    def test_k_zero_upper_bounds(self) -> None:
        """k=0 produces accurate Wilson upper bounds (tolerance 0.0005)."""
        # 0/10 -> upper 0.2775
        lo, hi = wilson_interval(0, 10)
        assert lo == 0.0
        assert abs(hi - 0.2775) < 0.0005, f"hi={hi:.4f} expected ~0.2775"

        # 0/100 -> upper 0.0370
        lo, hi = wilson_interval(0, 100)
        assert lo == 0.0
        assert abs(hi - 0.0370) < 0.0005, f"hi={hi:.4f} expected ~0.0370"

        # 0/250 -> upper 0.0151
        lo, hi = wilson_interval(0, 250)
        assert lo == 0.0
        assert abs(hi - 0.0151) < 0.0005, f"hi={hi:.4f} expected ~0.0151"

    def test_k_equals_n_lower_bounds_symmetric(self) -> None:
        """k=n produces symmetric Wilson lower bounds (tolerance 0.0005)."""
        # 10/10 -> lower 0.7225
        lo, hi = wilson_interval(10, 10)
        assert hi == 1.0
        assert abs(lo - 0.7225) < 0.0005, f"lo={lo:.4f} expected ~0.7225"

        # 250/250 -> lower 0.9849
        lo, hi = wilson_interval(250, 250)
        assert hi == 1.0
        assert abs(lo - 0.9849) < 0.0005, f"lo={lo:.4f} expected ~0.9849"

    def test_nonzero_k_known_values(self) -> None:
        """Nonzero k matches known Wilson values (tolerance 0.0005)."""
        # 16/100 -> [0.1010, 0.2442]
        lo, hi = wilson_interval(16, 100)
        assert abs(lo - 0.1010) < 0.0005, f"lo={lo:.4f} expected ~0.1010"
        assert abs(hi - 0.2442) < 0.0005, f"hi={hi:.4f} expected ~0.2442"

        # 45/250 -> [0.1374, 0.2324]
        lo, hi = wilson_interval(45, 250)
        assert abs(lo - 0.1374) < 0.0005, f"lo={lo:.4f} expected ~0.1374"
        assert abs(hi - 0.2324) < 0.0005, f"hi={hi:.4f} expected ~0.2324"

        # 5/100 -> [0.0215, 0.1118]
        lo, hi = wilson_interval(5, 100)
        assert abs(lo - 0.0215) < 0.0005, f"lo={lo:.4f} expected ~0.0215"
        assert abs(hi - 0.1118) < 0.0005, f"hi={hi:.4f} expected ~0.1118"

    def test_invalid_k_and_n_raise_value_error(self) -> None:
        """Invalid inputs raise ValueError."""
        with pytest.raises(ValueError, match="n must be"):
            wilson_interval(0, -5)
        with pytest.raises(ValueError, match="k must satisfy"):
            wilson_interval(-1, 10)
        with pytest.raises(ValueError, match="k must satisfy"):
            wilson_interval(11, 10)
