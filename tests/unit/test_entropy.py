# FILE: tests/unit/test_entropy.py
"""Unit tests for entropy computation module."""

from __future__ import annotations

import math

from forensiq.features.entropy import (
    _shannon_entropy,
    compute_name_entropy,
    compute_path_depth,
    compute_path_entropy,
)


class TestShannonEntropy:
    """Tests for the internal _shannon_entropy function."""

    def test_empty_string_returns_zero(self) -> None:
        assert _shannon_entropy("") == 0.0

    def test_single_char_returns_zero(self) -> None:
        assert _shannon_entropy("a") == 0.0
        assert _shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars_max_entropy(self) -> None:
        # "ab" -> each appears 50% -> H = 1.0 bit
        assert abs(_shannon_entropy("ab") - 1.0) < 1e-9

    def test_uniform_distribution_maximizes_entropy(self) -> None:
        # All 8 distinct chars -> H = log2(8) = 3.0
        text = "abcdefgh"
        assert abs(_shannon_entropy(text) - 3.0) < 1e-9

    def test_known_entropy_value(self) -> None:
        # "aaab": p(a)=3/4, p(b)=1/4
        # H = -(3/4)*log2(3/4) - (1/4)*log2(1/4)
        # Implementation rounds to 6 decimal places, so use 1e-5 tolerance
        expected = -(3 / 4) * math.log2(3 / 4) - (1 / 4) * math.log2(1 / 4)
        assert abs(_shannon_entropy("aaab") - expected) < 1e-5


class TestComputeNameEntropy:
    """Tests for compute_name_entropy."""

    def test_strips_extension(self) -> None:
        # svchost -> no extension stripped; entropy of "svchost"
        e1 = compute_name_entropy("svchost.exe")
        e2 = compute_name_entropy("svchost")
        assert abs(e1 - e2) < 1e-9

    def test_lowercases_before_computing(self) -> None:
        assert compute_name_entropy("SVCHOST.EXE") == compute_name_entropy("svchost.exe")

    def test_random_name_has_high_entropy(self) -> None:
        # Random-looking name should have higher entropy than "svchost"
        random_entropy = compute_name_entropy("a3xq9bz7.exe")
        svchost_entropy = compute_name_entropy("svchost.exe")
        assert random_entropy > svchost_entropy

    def test_empty_name(self) -> None:
        assert compute_name_entropy("") == 0.0

    def test_extension_only(self) -> None:
        # ".exe": os.path.splitext(".exe") -> (".exe", "") — stem is ".exe", not empty
        # So entropy of ".xe" characters is computed, not 0.0
        # This is correct behavior: ".exe" is not a pure extension in Python path handling
        result = compute_name_entropy(".exe")
        assert result > 0.0  # has some entropy (3 distinct chars: '.', 'x', 'e')


class TestComputePathDepth:
    """Tests for compute_path_depth."""

    def test_system32_path(self) -> None:
        path = r"\Device\HarddiskVolume2\Windows\System32\svchost.exe"
        depth = compute_path_depth(path)
        # After stripping drive prefix and splitting: Windows, System32, svchost.exe
        assert depth >= 3

    def test_empty_path(self) -> None:
        assert compute_path_depth("") == 0

    def test_forward_slashes_normalized(self) -> None:
        d1 = compute_path_depth(r"\Windows\System32\svchost.exe")
        d2 = compute_path_depth("/Windows/System32/svchost.exe")
        assert d1 == d2

    def test_deeper_path_returns_higher_depth(self) -> None:
        shallow = compute_path_depth(r"\Windows\svchost.exe")
        deep = compute_path_depth(r"\Users\victim\AppData\Local\Temp\payload.exe")
        assert deep > shallow

    def test_temp_path_depth(self) -> None:
        path = r"\Users\victim\AppData\Local\Temp\payload.exe"
        depth = compute_path_depth(path)
        assert depth >= 5


class TestComputePathEntropy:
    """Tests for compute_path_entropy."""

    def test_empty_path_returns_zero(self) -> None:
        assert compute_path_entropy("") == 0.0

    def test_entropy_is_nonnegative(self) -> None:
        path = r"\Windows\System32\svchost.exe"
        assert compute_path_entropy(path) >= 0.0

    def test_longer_path_may_have_higher_entropy(self) -> None:
        short_path = r"\Windows\a.exe"
        long_path = r"\Users\victim\AppData\Local\Temp\xqz9a3.exe"
        assert compute_path_entropy(long_path) >= compute_path_entropy(short_path)

    def test_windows_drive_letter_stripped(self) -> None:
        """compute_path_depth strips C:/ drive letter before counting components."""
        depth = compute_path_depth("C:\\Windows\\System32\\svchost.exe")
        assert depth >= 3
