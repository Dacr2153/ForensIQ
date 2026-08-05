# FILE: tests/unit/test_live_memory.py
"""Unit tests for live memory acquisition — /proc/kcore and LiME paths."""

from __future__ import annotations

import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Importability ──────────────────────────────────────────────────────────────


class TestLiveMemoryImports:
    """All public symbols are importable."""

    def test_module_importable(self) -> None:
        from forensiq.acquisition import live_memory

        assert live_memory is not None

    def test_kcore_path_constant(self) -> None:
        from forensiq.acquisition.live_memory import KCORE_PATH

        assert str(KCORE_PATH) == "/proc/kcore"

    def test_lime_format_constant(self) -> None:
        from forensiq.acquisition.live_memory import LIME_FORMAT

        assert LIME_FORMAT == "lime"

    def test_live_memory_error_is_exception(self) -> None:
        from forensiq.acquisition.live_memory import LiveMemoryError

        assert issubclass(LiveMemoryError, Exception)

    def test_check_live_requirements_callable(self) -> None:
        from forensiq.acquisition.live_memory import check_live_requirements

        assert callable(check_live_requirements)

    def test_get_kcore_path_callable(self) -> None:
        from forensiq.acquisition.live_memory import get_kcore_path

        assert callable(get_kcore_path)

    def test_find_lime_module_callable(self) -> None:
        from forensiq.acquisition.live_memory import find_lime_module

        assert callable(find_lime_module)

    def test_acquire_lime_dump_callable(self) -> None:
        from forensiq.acquisition.live_memory import acquire_lime_dump

        assert callable(acquire_lime_dump)

    def test_build_lime_from_source_callable(self) -> None:
        from forensiq.acquisition.live_memory import build_lime_from_source

        assert callable(build_lime_from_source)

    def test_check_lime_build_requirements_callable(self) -> None:
        from forensiq.acquisition.live_memory import check_lime_build_requirements

        assert callable(check_lime_build_requirements)

    def test_lime_repo_url_constant(self) -> None:
        from forensiq.acquisition.live_memory import LIME_REPO_URL

        assert "504ensicsLabs/LiME" in LIME_REPO_URL
        assert LIME_REPO_URL.startswith("https://")

    def test_get_kernel_info_callable(self) -> None:
        from forensiq.acquisition.live_memory import get_kernel_info

        assert callable(get_kernel_info)


# ── get_volatility_version() ───────────────────────────────────────────────────


class TestGetVolatilityVersion:
    """Version detection works across Volatility 2.x/3.0 flag conventions."""

    def test_returns_framework_version_from_stdout(self) -> None:
        from forensiq.acquisition.volatility_runner import VolatilityRunner

        result = MagicMock()
        result.stdout = "Volatility 3 Framework 2.28.0\n"
        result.stderr = ""
        with (
            patch(
                "forensiq.acquisition.volatility_runner.subprocess.run",
                return_value=result,
            ) as mock_run,
            patch("forensiq.config.settings.shutil.which", return_value="/usr/bin/vol"),
        ):
            runner = VolatilityRunner(dump_path=Path("test.dump"), is_linux=True)
            version = runner.get_volatility_version()

        assert version == "Volatility 3 Framework 2.28.0"
        assert mock_run.call_args_list[0].args[0] == ["/usr/bin/vol", "--version"]

    def test_falls_back_to_dash_v_when_version_flag_unsupported(self) -> None:
        """vol 2.28 rejects --version; the -v fallback must be used."""
        from forensiq.acquisition.volatility_runner import VolatilityRunner

        unsupported = MagicMock()
        unsupported.stdout = ""
        unsupported.stderr = "vol: error: unrecognized arguments: --version"

        supported = MagicMock()
        supported.stdout = "Volatility 3 Framework 2.28.0\n"
        supported.stderr = ""

        with (
            patch(
                "forensiq.acquisition.volatility_runner.subprocess.run",
                side_effect=[unsupported, supported],
            ) as mock_run,
            patch("forensiq.config.settings.shutil.which", return_value="/usr/bin/vol"),
        ):
            runner = VolatilityRunner(dump_path=Path("test.dump"), is_linux=True)
            version = runner.get_volatility_version()

        assert version == "Volatility 3 Framework 2.28.0"
        flags = [call.args[0][-1] for call in mock_run.call_args_list]
        assert flags == ["--version", "-v"]

    def test_returns_empty_string_on_errors(self) -> None:
        from forensiq.acquisition.volatility_runner import VolatilityRunner

        with (
            patch(
                "forensiq.acquisition.volatility_runner.subprocess.run",
                side_effect=FileNotFoundError("vol"),
            ),
            patch("forensiq.config.settings.shutil.which", return_value="/usr/bin/vol"),
        ):
            runner = VolatilityRunner(dump_path=Path("test.dump"), is_linux=True)
            version = runner.get_volatility_version()

        assert version == ""


# ── get_kernel_info() ─────────────────────────────────────────────────────────


class TestGetKernelInfo:
    """Tests for kernel introspection helper."""

    def test_returns_dict_with_required_keys(self) -> None:
        from forensiq.acquisition.live_memory import get_kernel_info

        info = get_kernel_info()
        assert "release" in info
        assert "version" in info
        assert "is_hardened" in info
        assert "kcore_compiled_in" in info

    def test_release_matches_uname(self) -> None:
        from forensiq.acquisition.live_memory import get_kernel_info

        info = get_kernel_info()
        assert info["release"] == os.uname().release

    def test_hardened_detected_on_this_system(self) -> None:
        """linux-hardened is active on this machine."""
        from forensiq.acquisition.live_memory import get_kernel_info

        info = get_kernel_info()
        # The test machine runs linux-hardened — this should be "true"
        if "hardened" in os.uname().release.lower():
            assert info["is_hardened"] == "true"

    def test_kcore_compiled_in_is_false_on_hardened(self) -> None:
        """linux-hardened disables CONFIG_PROC_KCORE."""
        from forensiq.acquisition.live_memory import get_kernel_info

        info = get_kernel_info()
        if "hardened" in os.uname().release.lower():
            # On this system we know it's disabled
            assert info["kcore_compiled_in"] in ("false", "unknown")

    def test_version_is_nonempty_string(self) -> None:
        from forensiq.acquisition.live_memory import get_kernel_info

        info = get_kernel_info()
        assert isinstance(info["version"], str)
        assert len(info["version"]) > 0


# ── find_lime_module() ────────────────────────────────────────────────────────


class TestFindLimeModule:
    """Tests for LiME module auto-discovery."""

    def test_returns_none_when_no_module_found(self) -> None:
        from forensiq.acquisition.live_memory import find_lime_module

        # On this test system lime.ko is not installed
        result = find_lime_module()
        # Result is either None or a valid file path
        assert result is None or result.is_file()

    def test_returns_hint_path_when_file_exists(self, tmp_path: Path) -> None:
        from forensiq.acquisition.live_memory import find_lime_module

        fake_lime = tmp_path / "lime.ko"
        fake_lime.write_bytes(b"\x7fELF")  # ELF magic bytes
        result = find_lime_module(hint=fake_lime)
        assert result == fake_lime

    def test_hint_nonexistent_falls_through_to_search(self) -> None:
        from forensiq.acquisition.live_memory import find_lime_module

        nonexistent = Path("/nonexistent/path/lime.ko")
        result = find_lime_module(hint=nonexistent)
        # Falls through to search paths — likely None on this system
        assert result is None or result.is_file()

    def test_hint_none_searches_standard_paths(self) -> None:
        from forensiq.acquisition.live_memory import find_lime_module

        result = find_lime_module(hint=None)
        assert result is None or isinstance(result, Path)


# ── check_live_requirements() ─────────────────────────────────────────────────


class TestCheckLiveRequirements:
    """Tests for the pre-flight requirements checker."""

    def test_returns_dict(self) -> None:
        from forensiq.acquisition.live_memory import check_live_requirements

        result = check_live_requirements()
        assert isinstance(result, dict)

    def test_required_keys_present(self) -> None:
        from forensiq.acquisition.live_memory import check_live_requirements

        result = check_live_requirements()
        required = {
            "is_linux",
            "kcore_exists",
            "kcore_readable",
            "has_root",
            "kcore_size_ok",
            "lime_available",
            "lime_module_path",
            "kernel_release",
            "kernel_hardened",
            "kcore_compiled_in",
            "ready",
            "error",
        }
        assert required.issubset(result.keys())

    def test_is_linux_true_on_linux(self) -> None:
        from forensiq.acquisition.live_memory import check_live_requirements

        result = check_live_requirements()
        assert result["is_linux"] is True

    def test_kernel_release_nonempty(self) -> None:
        from forensiq.acquisition.live_memory import check_live_requirements

        result = check_live_requirements()
        assert isinstance(result["kernel_release"], str)
        assert len(result["kernel_release"]) > 0

    def test_hardened_kernel_detected(self) -> None:
        from forensiq.acquisition.live_memory import check_live_requirements

        result = check_live_requirements()
        if "hardened" in os.uname().release.lower():
            assert result["kernel_hardened"] is True

    def test_kcore_not_found_on_hardened(self) -> None:
        """On linux-hardened, /proc/kcore should not exist."""
        from forensiq.acquisition.live_memory import check_live_requirements

        result = check_live_requirements()
        if "hardened" in os.uname().release.lower():
            assert result["kcore_exists"] is False
            assert result["ready"] is False

    def test_error_mentions_hardened_when_applicable(self) -> None:
        from forensiq.acquisition.live_memory import check_live_requirements

        result = check_live_requirements()
        if "hardened" in os.uname().release.lower() and not result["kcore_exists"]:
            assert "hardened" in result["error"].lower() or "lime" in result["error"].lower()

    def test_lime_available_false_when_no_module(self) -> None:
        from forensiq.acquisition.live_memory import check_live_requirements

        with patch("forensiq.acquisition.live_memory.find_lime_module", return_value=None):
            result = check_live_requirements()
        assert result["lime_available"] is False
        assert result["lime_module_path"] is None

    def test_lime_available_true_when_module_found(self, tmp_path: Path) -> None:
        from forensiq.acquisition.live_memory import check_live_requirements

        fake_module = tmp_path / "lime.ko"
        fake_module.write_bytes(b"\x7fELF")
        with patch("forensiq.acquisition.live_memory.find_lime_module", return_value=fake_module):
            result = check_live_requirements()
        assert result["lime_available"] is True
        assert result["lime_module_path"] == str(fake_module)

    def test_lime_hint_passed_to_finder(self, tmp_path: Path) -> None:
        from forensiq.acquisition.live_memory import check_live_requirements

        hint = tmp_path / "custom_lime.ko"
        with patch("forensiq.acquisition.live_memory.find_lime_module") as mock_find:
            mock_find.return_value = None
            check_live_requirements(lime_hint=hint)
        mock_find.assert_called_once_with(hint=hint)

    def test_not_linux_returns_early(self) -> None:
        from forensiq.acquisition.live_memory import check_live_requirements

        fake_uname = MagicMock()
        fake_uname.sysname = "Darwin"
        with patch("os.name", "posix"), patch("os.uname", return_value=fake_uname):
            result = check_live_requirements()
        assert result["is_linux"] is False
        assert result["ready"] is False
        assert "linux" in result["error"].lower()


# ── acquire_lime_dump() ───────────────────────────────────────────────────────


class TestAcquireLimeDump:
    """Tests for LiME acquisition function."""

    def test_raises_permission_error_when_not_root(self, tmp_path: Path) -> None:
        from forensiq.acquisition.live_memory import acquire_lime_dump

        fake_module = tmp_path / "lime.ko"
        fake_module.write_bytes(b"\x7fELF")

        with patch("os.geteuid", return_value=1000):
            with pytest.raises(PermissionError, match="root"):
                acquire_lime_dump(
                    output_path=tmp_path / "dump.lime",
                    lime_module=fake_module,
                )

    def test_raises_live_memory_error_when_module_missing(self, tmp_path: Path) -> None:
        from forensiq.acquisition.live_memory import LiveMemoryError, acquire_lime_dump

        missing = tmp_path / "nonexistent.ko"

        with patch("os.geteuid", return_value=0):
            with pytest.raises(LiveMemoryError, match="not found"):
                acquire_lime_dump(
                    output_path=tmp_path / "dump.lime",
                    lime_module=missing,
                )

    def test_raises_live_memory_error_when_insmod_not_found(self, tmp_path: Path) -> None:
        from forensiq.acquisition.live_memory import LiveMemoryError, acquire_lime_dump

        fake_module = tmp_path / "lime.ko"
        fake_module.write_bytes(b"\x7fELF")

        with patch("os.geteuid", return_value=0):
            with patch("subprocess.run", side_effect=FileNotFoundError("insmod")):
                with pytest.raises(LiveMemoryError, match="insmod"):
                    acquire_lime_dump(
                        output_path=tmp_path / "dump.lime",
                        lime_module=fake_module,
                    )

    def test_raises_live_memory_error_on_insmod_failure(self, tmp_path: Path) -> None:
        from forensiq.acquisition.live_memory import LiveMemoryError, acquire_lime_dump

        fake_module = tmp_path / "lime.ko"
        fake_module.write_bytes(b"\x7fELF")

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Operation not permitted"

        with patch("os.geteuid", return_value=0):
            with patch("subprocess.run", return_value=mock_result):
                with pytest.raises(LiveMemoryError):
                    acquire_lime_dump(
                        output_path=tmp_path / "dump.lime",
                        lime_module=fake_module,
                    )

    def test_module_signing_error_message(self, tmp_path: Path) -> None:
        from forensiq.acquisition.live_memory import LiveMemoryError, acquire_lime_dump

        fake_module = tmp_path / "lime.ko"
        fake_module.write_bytes(b"\x7fELF")

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Required key not available"

        with patch("os.geteuid", return_value=0):
            with patch("subprocess.run", return_value=mock_result):
                with pytest.raises(LiveMemoryError, match="signing"):
                    acquire_lime_dump(
                        output_path=tmp_path / "dump.lime",
                        lime_module=fake_module,
                    )

    def test_successful_acquisition_writes_dump(self, tmp_path: Path) -> None:
        from forensiq.acquisition.live_memory import acquire_lime_dump

        fake_module = tmp_path / "lime.ko"
        fake_module.write_bytes(b"\x7fELF")
        dump_path = tmp_path / "memory.lime"

        # Simulate insmod success + LiME writing the dump file
        mock_insmod = MagicMock(returncode=0, stderr="")

        def _write_dump_on_insmod(*args, **kwargs):
            # Write fake dump data when insmod is called
            dump_path.write_bytes(b"LiME" + b"\x00" * 1024)
            return mock_insmod

        with patch("os.geteuid", return_value=0):
            with patch("subprocess.run") as mock_run:
                # First call = insmod (writes file), second call = rmmod
                mock_run.side_effect = _write_dump_on_insmod
                result = acquire_lime_dump(
                    output_path=dump_path,
                    lime_module=fake_module,
                    timeout=10,
                )

        assert result == dump_path
        assert dump_path.exists()

    def test_insmod_parameters_are_separate_args(self, tmp_path: Path) -> None:
        """insmod must receive path= and format= as separate argv elements.

        Passing them joined in one string causes 'Invalid parameters' error.
        """
        from forensiq.acquisition.live_memory import acquire_lime_dump

        fake_module = tmp_path / "lime.ko"
        fake_module.write_bytes(b"\x7fELF")
        dump_path = tmp_path / "memory.lime"

        captured_cmd: list[list[str]] = []

        def _side_effect(cmd, *args, **kwargs):
            captured_cmd.append(list(cmd))
            dump_path.write_bytes(b"LiME" + b"\x00" * 1024)
            return MagicMock(returncode=0, stderr="")

        with patch("os.geteuid", return_value=0):
            with patch("subprocess.run", side_effect=_side_effect):
                acquire_lime_dump(
                    output_path=dump_path,
                    lime_module=fake_module,
                    timeout=10,
                )

        # First call must be insmod; parameters must be individual args
        insmod_call = next(c for c in captured_cmd if c[0] == "insmod")
        assert len(insmod_call) == 4, (
            f"insmod should have 4 args (insmod, module, path=, format=), got: {insmod_call}"
        )
        assert insmod_call[1] == str(fake_module)
        assert insmod_call[2].startswith("path=")
        assert insmod_call[3].startswith("format=")

    def test_rmmod_called_after_dump(self, tmp_path: Path) -> None:
        """rmmod lime is called to unload the module after acquisition."""
        from forensiq.acquisition.live_memory import acquire_lime_dump

        fake_module = tmp_path / "lime.ko"
        fake_module.write_bytes(b"\x7fELF")
        dump_path = tmp_path / "memory.lime"

        calls_made = []

        def _side_effect(cmd, *args, **kwargs):
            calls_made.append(cmd[0] if cmd else "")
            if cmd[0] == "insmod":
                dump_path.write_bytes(b"LiME" + b"\x00" * 512)
            return MagicMock(returncode=0, stderr="")

        with patch("os.geteuid", return_value=0):
            with patch("subprocess.run", side_effect=_side_effect):
                acquire_lime_dump(
                    output_path=dump_path,
                    lime_module=fake_module,
                    timeout=10,
                )

        assert "insmod" in calls_made
        assert "rmmod" in calls_made

    def test_creates_output_directory(self, tmp_path: Path) -> None:
        """acquire_lime_dump creates the output directory if it doesn't exist."""
        from forensiq.acquisition.live_memory import acquire_lime_dump

        fake_module = tmp_path / "lime.ko"
        fake_module.write_bytes(b"\x7fELF")
        nested_dir = tmp_path / "deep" / "nested" / "dir"
        dump_path = nested_dir / "memory.lime"

        def _side_effect(cmd, *args, **kwargs):
            if cmd[0] == "insmod":
                dump_path.write_bytes(b"LiME" + b"\x00" * 512)
            return MagicMock(returncode=0, stderr="")

        with patch("os.geteuid", return_value=0):
            with patch("subprocess.run", side_effect=_side_effect):
                acquire_lime_dump(
                    output_path=dump_path,
                    lime_module=fake_module,
                    timeout=10,
                )

        assert nested_dir.exists()

    def test_already_loaded_module_with_existing_dump(self, tmp_path: Path) -> None:
        """If LiME module is already loaded (EEXIST) and dump exists, return it."""
        from forensiq.acquisition.live_memory import acquire_lime_dump

        fake_module = tmp_path / "lime.ko"
        fake_module.write_bytes(b"\x7fELF")
        dump_path = tmp_path / "memory.lime"
        dump_path.write_bytes(b"LiME" + b"\x00" * 1024)  # Pre-existing dump

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "File exists"

        with patch("os.geteuid", return_value=0):
            with patch("subprocess.run", return_value=mock_result):
                result = acquire_lime_dump(
                    output_path=dump_path,
                    lime_module=fake_module,
                    timeout=10,
                )
        assert result == dump_path

    def test_rejects_invalid_lime_format(self, tmp_path: Path) -> None:
        """An unknown LiME format must be rejected before anything runs."""
        from forensiq.acquisition.live_memory import LiveMemoryError, acquire_lime_dump

        fake_module = tmp_path / "lime.ko"
        fake_module.write_bytes(b"\x7fELF")

        with patch("os.geteuid", return_value=0):
            with pytest.raises(LiveMemoryError, match="Invalid LiME format"):
                acquire_lime_dump(
                    output_path=tmp_path / "dump.lime",
                    lime_module=fake_module,
                    lime_format="malicious",
                )

    def test_sets_0600_permissions_on_dump(self, tmp_path: Path) -> None:
        """A memory dump is sensitive: it must be chmod 0600 after acquisition."""
        from forensiq.acquisition.live_memory import acquire_lime_dump

        fake_module = tmp_path / "lime.ko"
        fake_module.write_bytes(b"\x7fELF")
        dump_path = tmp_path / "memory.lime"

        def _side_effect(cmd, *args, **kwargs):
            if cmd[0] == "insmod":
                dump_path.write_bytes(b"LiME" + b"\x00" * 1024)
            return MagicMock(returncode=0, stderr="")

        with patch("os.geteuid", return_value=0):
            with patch("subprocess.run", side_effect=_side_effect):
                acquire_lime_dump(
                    output_path=dump_path,
                    lime_module=fake_module,
                    timeout=10,
                )

        assert (dump_path.stat().st_mode & 0o777) == 0o600

    def test_timeout_removes_partial_dump_and_unloads_module(
        self, tmp_path: Path
    ) -> None:
        """On timeout, any partial dump is removed and the module is unloaded."""
        from forensiq.acquisition.live_memory import LiveMemoryError, acquire_lime_dump

        fake_module = tmp_path / "lime.ko"
        fake_module.write_bytes(b"\x7fELF")
        dump_path = tmp_path / "memory.lime"

        calls_made: list[str] = []

        def _side_effect(cmd, *args, **kwargs):
            name = cmd[0] if cmd else ""
            calls_made.append(name)
            if name == "insmod":
                # Partial dump written by the kernel, but acquisition never
                # stabilises before the timeout.
                dump_path.write_bytes(b"LiME" + b"\x00" * 64)
            return MagicMock(returncode=0, stderr="")

        with patch("os.geteuid", return_value=0):
            with patch("subprocess.run", side_effect=_side_effect):
                with pytest.raises(LiveMemoryError, match="Timed out"):
                    acquire_lime_dump(
                        output_path=dump_path,
                        lime_module=fake_module,
                        timeout=0,
                    )

        assert "rmmod" in calls_made
        assert not dump_path.exists(), "partial dump must be removed on timeout"

    def test_still_growing_dump_is_not_aborted_by_timeout(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """A dump that keeps growing is never cut off by the stall timeout.

        LiME's insmod blocks for the entire acquisition, so the thread stays
        alive while the file grows.  The stall timeout must only fire when the
        file has genuinely stopped growing — even if that takes far longer than
        ``timeout`` seconds of wall-clock time.
        """
        from forensiq.acquisition.live_memory import acquire_lime_dump

        monkeypatch.setattr(
            "forensiq.acquisition.live_memory._LIME_POLL_INTERVAL", 0.02
        )
        fake_module = tmp_path / "lime.ko"
        fake_module.write_bytes(b"\x7fELF")
        dump_path = tmp_path / "memory.lime"
        chunk = b"LiME" * 1000  # 4 KiB

        def _side_effect(cmd, *args, **kwargs):
            if cmd[0] == "insmod":
                # Simulate LiME writing the full dump over ~3.6s (longer than
                # the initial thread.join(timeout=3) and far longer than the
                # 0.1s stall window).
                written = 0
                while written < 72 * len(chunk):
                    written += len(chunk)
                    dump_path.write_bytes(chunk * (written // len(chunk)))
                    time.sleep(0.05)
            return MagicMock(returncode=0, stderr="")

        start = time.monotonic()
        with patch("os.geteuid", return_value=0):
            with patch("subprocess.run", side_effect=_side_effect):
                result = acquire_lime_dump(
                    output_path=dump_path,
                    lime_module=fake_module,
                    timeout=0.1,
                )

        elapsed = time.monotonic() - start
        assert result == dump_path
        assert elapsed > 0.1, "acquisition should outlive the stall window"
        assert dump_path.exists() and dump_path.stat().st_size > 0

    def test_safe_kernel_release_sanitizes_path_separators(self) -> None:
        """Kernel releases are used in filenames; slashes must never survive."""
        from forensiq.acquisition.live_memory import _safe_kernel_release

        assert _safe_kernel_release("6.1.0-arch1-1") == "6.1.0-arch1-1"
        assert _safe_kernel_release("6.1/../etc") == "6.1-..-etc"
        assert _safe_kernel_release("a/b/c") == "a-b-c"
        assert _safe_kernel_release("") == ""


# ── check_lime_build_requirements() ──────────────────────────────────────────


class TestCheckLimeBuildRequirements:
    """Tests for the LiME build pre-flight checker."""

    def test_returns_dict_with_required_keys(self) -> None:
        from forensiq.acquisition.live_memory import check_lime_build_requirements

        result = check_lime_build_requirements()
        required = {
            "git_available",
            "make_available",
            "gcc_available",
            "headers_available",
            "headers_path",
            "can_build",
        }
        assert required.issubset(result.keys())

    def test_can_build_true_on_this_system(self) -> None:
        """This system has git, make, gcc, and linux-hardened-headers installed."""
        from forensiq.acquisition.live_memory import check_lime_build_requirements

        result = check_lime_build_requirements()
        assert result["git_available"] is True
        assert result["make_available"] is True
        assert result["gcc_available"] is True
        assert result["headers_available"] is True
        assert result["can_build"] is True

    def test_can_build_false_when_git_missing(self) -> None:
        from forensiq.acquisition.live_memory import check_lime_build_requirements

        with patch("shutil.which", side_effect=lambda x: None if x == "git" else f"/usr/bin/{x}"):
            result = check_lime_build_requirements()
        assert result["git_available"] is False
        assert result["can_build"] is False

    def test_can_build_false_when_headers_missing(self) -> None:
        from forensiq.acquisition.live_memory import check_lime_build_requirements

        with patch("pathlib.Path.is_file", return_value=False):
            result = check_lime_build_requirements()
        assert result["headers_available"] is False
        assert result["can_build"] is False

    def test_headers_path_contains_kernel_release(self) -> None:
        from forensiq.acquisition.live_memory import check_lime_build_requirements

        result = check_lime_build_requirements()
        assert os.uname().release in result["headers_path"]

    def test_can_build_reflected_in_check_live_requirements(self) -> None:
        """check_live_requirements includes lime_can_build key."""
        from forensiq.acquisition.live_memory import check_live_requirements

        result = check_live_requirements()
        assert "lime_can_build" in result
        # On this system build tools are present
        assert result["lime_can_build"] is True


# ── build_lime_from_source() ──────────────────────────────────────────────────


class TestBuildLimeFromSource:
    """Tests for automated LiME build helper."""

    def test_raises_runtime_error_when_tools_missing(self, tmp_path: Path) -> None:
        from forensiq.acquisition.live_memory import build_lime_from_source

        no_tools = {
            "git_available": False,
            "make_available": True,
            "gcc_available": True,
            "headers_available": True,
            "headers_path": "/x",
            "can_build": False,
        }
        with patch(
            "forensiq.acquisition.live_memory.check_lime_build_requirements", return_value=no_tools
        ):
            with pytest.raises(RuntimeError, match="Cannot build LiME"):
                build_lime_from_source(install_dir=tmp_path)

    def test_returns_cached_module_if_already_built(self, tmp_path: Path) -> None:
        """Returns existing lime.ko without rebuilding if already present."""
        from forensiq.acquisition.live_memory import build_lime_from_source

        release = os.uname().release
        pre_built = tmp_path / f"lime-{release}.ko"
        pre_built.write_bytes(b"\x7fELF" + b"\x00" * 100)

        messages: list[str] = []
        result = build_lime_from_source(
            install_dir=tmp_path,
            progress_callback=messages.append,
        )
        assert result == pre_built
        # Should not call git clone
        assert any("already built" in m for m in messages)

    def test_raises_live_memory_error_on_clone_failure(self, tmp_path: Path) -> None:
        from forensiq.acquisition.live_memory import LiveMemoryError, build_lime_from_source

        good_reqs = {
            "git_available": True,
            "make_available": True,
            "gcc_available": True,
            "headers_available": True,
            "headers_path": "/x",
            "can_build": True,
        }
        failed_clone = MagicMock(returncode=1, stderr="Could not resolve host: github.com")

        with patch(
            "forensiq.acquisition.live_memory.check_lime_build_requirements", return_value=good_reqs
        ):
            with patch("subprocess.run", return_value=failed_clone):
                with pytest.raises(LiveMemoryError, match="git clone failed"):
                    build_lime_from_source(install_dir=tmp_path)

    def test_raises_live_memory_error_on_make_failure(self, tmp_path: Path) -> None:
        from forensiq.acquisition.live_memory import LiveMemoryError, build_lime_from_source

        good_reqs = {
            "git_available": True,
            "make_available": True,
            "gcc_available": True,
            "headers_available": True,
            "headers_path": "/x",
            "can_build": True,
        }
        ok_clone = MagicMock(returncode=0, stderr="")
        fail_make = MagicMock(returncode=2, stderr="Error: compiler error")

        def _side_effect(cmd, *args, **kwargs):
            if cmd[0] == "git":
                clone_target = Path(cmd[-1])
                (clone_target / "src").mkdir(parents=True, exist_ok=True)
                return ok_clone
            return fail_make

        with patch(
            "forensiq.acquisition.live_memory.check_lime_build_requirements", return_value=good_reqs
        ):
            with patch("subprocess.run", side_effect=_side_effect):
                with pytest.raises(LiveMemoryError, match="make failed"):
                    build_lime_from_source(install_dir=tmp_path)

    def test_progress_callback_called(self, tmp_path: Path) -> None:
        """progress_callback receives status messages during build."""
        from forensiq.acquisition.live_memory import build_lime_from_source

        release = os.uname().release
        # Pre-built module so we skip actual git/make
        pre_built = tmp_path / f"lime-{release}.ko"
        pre_built.write_bytes(b"\x7fELF" + b"\x00" * 100)

        messages: list[str] = []
        build_lime_from_source(install_dir=tmp_path, progress_callback=messages.append)
        assert len(messages) >= 1

    def test_successful_build_copies_ko_to_install_dir(self, tmp_path: Path) -> None:
        """After a successful build, lime-<release>.ko appears in install_dir.

        Tests the lime-<release>.ko naming which LiME's Makefile produces
        on some kernels (e.g. linux-hardened).
        """
        from forensiq.acquisition.live_memory import build_lime_from_source

        good_reqs = {
            "git_available": True,
            "make_available": True,
            "gcc_available": True,
            "headers_available": True,
            "headers_path": "/x",
            "can_build": True,
        }

        ok_run = MagicMock(returncode=0, stderr="")
        release = os.uname().release

        def _fake_run(cmd, *args, **kwargs):
            cwd = Path(kwargs.get("cwd", "."))
            if cmd[0] == "git":
                clone_target = Path(cmd[-1])
                (clone_target / "src").mkdir(parents=True, exist_ok=True)
            elif cmd[0] == "make":
                # Simulate kernel-version-named output (linux-hardened style)
                (cwd / f"lime-{release}.ko").write_bytes(b"\x7fELFfakelime")
            return ok_run

        with patch(
            "forensiq.acquisition.live_memory.check_lime_build_requirements", return_value=good_reqs
        ):
            with patch("subprocess.run", side_effect=_fake_run):
                result = build_lime_from_source(install_dir=tmp_path)

        expected = tmp_path / f"lime-{release}.ko"
        assert result == expected
        assert expected.is_file()

    def test_successful_build_with_compressed_zst_ko(self, tmp_path: Path) -> None:
        """Handles lime.ko.zst output (CONFIG_MODULE_COMPRESS_ZSTD=y kernels)."""
        from forensiq.acquisition.live_memory import build_lime_from_source

        good_reqs = {
            "git_available": True,
            "make_available": True,
            "gcc_available": True,
            "headers_available": True,
            "headers_path": "/x",
            "can_build": True,
        }

        ok_run = MagicMock(returncode=0, stderr="")

        def _fake_run(cmd, *args, **kwargs):
            cwd = Path(kwargs.get("cwd", "."))
            if cmd[0] == "git":
                clone_target = Path(cmd[-1])
                (clone_target / "src").mkdir(parents=True, exist_ok=True)
            elif cmd[0] == "make":
                (cwd / "lime.ko.zst").write_bytes(b"\x7fELFfakelime.zst")
            elif cmd[0] == "zstd":
                out_flag = "-o"
                if out_flag in cmd:
                    out_path = Path(cmd[cmd.index(out_flag) + 1])
                    out_path.write_bytes(b"\x7fELFfakelime")
            return ok_run

        with patch(
            "forensiq.acquisition.live_memory.check_lime_build_requirements", return_value=good_reqs
        ):
            with patch("subprocess.run", side_effect=_fake_run):
                result = build_lime_from_source(install_dir=tmp_path)

        release = os.uname().release
        expected = tmp_path / f"lime-{release}.ko"
        assert result == expected
        assert expected.is_file()

    def test_successful_build_with_plain_lime_ko(self, tmp_path: Path) -> None:
        """Handles plain lime.ko output (no kernel module compression)."""
        from forensiq.acquisition.live_memory import build_lime_from_source

        good_reqs = {
            "git_available": True,
            "make_available": True,
            "gcc_available": True,
            "headers_available": True,
            "headers_path": "/x",
            "can_build": True,
        }

        ok_run = MagicMock(returncode=0, stderr="")

        def _fake_run(cmd, *args, **kwargs):
            cwd = Path(kwargs.get("cwd", "."))
            if cmd[0] == "git":
                clone_target = Path(cmd[-1])
                (clone_target / "src").mkdir(parents=True, exist_ok=True)
            elif cmd[0] == "make":
                (cwd / "lime.ko").write_bytes(b"\x7fELFfakelime")
            return ok_run

        with patch(
            "forensiq.acquisition.live_memory.check_lime_build_requirements", return_value=good_reqs
        ):
            with patch("subprocess.run", side_effect=_fake_run):
                result = build_lime_from_source(install_dir=tmp_path)

        release = os.uname().release
        expected = tmp_path / f"lime-{release}.ko"
        assert result == expected
        assert expected.is_file()


# ── get_kcore_path() ──────────────────────────────────────────────────────────


class TestGetKcorePath:
    """Tests for get_kcore_path() helper."""

    def test_raises_live_memory_error_when_not_ready(self) -> None:
        from forensiq.acquisition.live_memory import LiveMemoryError, get_kcore_path

        not_ready = {
            "is_linux": True,
            "kcore_exists": False,
            "kcore_readable": False,
            "has_root": False,
            "kcore_size_ok": False,
            "lime_available": False,
            "lime_module_path": None,
            "kernel_release": "6.x",
            "kernel_hardened": True,
            "kcore_compiled_in": "false",
            "ready": False,
            "error": "kcore not found",
        }
        with patch(
            "forensiq.acquisition.live_memory.check_live_requirements", return_value=not_ready
        ):
            with pytest.raises(LiveMemoryError, match="kcore not found"):
                get_kcore_path()

    def test_returns_kcore_path_when_ready(self) -> None:
        from forensiq.acquisition.live_memory import KCORE_PATH, get_kcore_path

        ready = {
            "is_linux": True,
            "kcore_exists": True,
            "kcore_readable": True,
            "has_root": True,
            "kcore_size_ok": True,
            "lime_available": False,
            "lime_module_path": None,
            "kernel_release": "6.x",
            "kernel_hardened": False,
            "kcore_compiled_in": "true",
            "ready": True,
            "error": "",
        }
        with patch("forensiq.acquisition.live_memory.check_live_requirements", return_value=ready):
            result = get_kcore_path()
        assert result == KCORE_PATH


# ── linux_isf module ──────────────────────────────────────────────────────────


class TestLinuxISFImports:
    """linux_isf module public symbols are importable."""

    def test_module_importable(self) -> None:
        from forensiq.acquisition import linux_isf

        assert linux_isf is not None

    def test_find_linux_isf_callable(self) -> None:
        from forensiq.acquisition.linux_isf import find_linux_isf

        assert callable(find_linux_isf)

    def test_build_linux_isf_callable(self) -> None:
        from forensiq.acquisition.linux_isf import build_linux_isf

        assert callable(build_linux_isf)

    def test_check_linux_isf_requirements_callable(self) -> None:
        from forensiq.acquisition.linux_isf import check_linux_isf_requirements

        assert callable(check_linux_isf_requirements)

    def test_find_system_map_callable(self) -> None:
        from forensiq.acquisition.linux_isf import find_system_map

        assert callable(find_system_map)

    # install_dwarf2json removed — ISF is now built from BTF in pure Python


class TestLinuxISFRequirements:
    """check_linux_isf_requirements() returns the expected keys."""

    def test_returns_all_required_keys(self) -> None:
        from forensiq.acquisition.linux_isf import check_linux_isf_requirements

        with patch("forensiq.acquisition.linux_isf._BTF_PATH") as mock_btf:
            mock_btf.exists.return_value = False
            result = check_linux_isf_requirements("6.0.0-test")
        expected_keys = {"btf_available", "system_map_found", "isf_cached", "can_build"}
        assert expected_keys <= set(result.keys())

    def test_can_build_false_when_btf_missing(self) -> None:
        from forensiq.acquisition.linux_isf import check_linux_isf_requirements

        with (
            patch("forensiq.acquisition.linux_isf._BTF_PATH") as mock_btf,
            patch(
                "forensiq.acquisition.linux_isf.find_system_map",
                return_value=Path("/boot/System.map"),
            ),
        ):
            mock_btf.exists.return_value = False
            result = check_linux_isf_requirements("6.0.0-test")
        assert result["can_build"] is False

    def test_can_build_true_when_btf_and_sysmap_present(self) -> None:
        from forensiq.acquisition.linux_isf import check_linux_isf_requirements

        with (
            patch("forensiq.acquisition.linux_isf._BTF_PATH") as mock_btf,
            patch(
                "forensiq.acquisition.linux_isf.find_system_map",
                return_value=Path("/boot/System.map"),
            ),
            patch("forensiq.acquisition.linux_isf.os.access", return_value=True),
        ):
            mock_btf.exists.return_value = True
            result = check_linux_isf_requirements("6.0.0-test")
        assert result["can_build"] is True

    def test_can_build_false_when_sysmap_missing(self) -> None:
        from forensiq.acquisition.linux_isf import check_linux_isf_requirements

        with (
            patch("forensiq.acquisition.linux_isf._BTF_PATH") as mock_btf,
            patch("forensiq.acquisition.linux_isf.find_system_map", return_value=None),
        ):
            mock_btf.exists.return_value = True
            result = check_linux_isf_requirements("6.0.0-test")
        assert result["can_build"] is False


class TestFindLinuxISF:
    """find_linux_isf() locates cached ISF files."""

    def test_returns_none_when_not_cached(self, tmp_path: Path) -> None:
        from forensiq.acquisition import linux_isf as m

        with (
            patch.object(m, "_VOL3_CACHE_SYMBOLS_DIR", tmp_path / "vol3"),
            patch.object(m, "_FORENSIQ_SYMBOLS_DIR", tmp_path / "forensiq"),
        ):
            result = m.find_linux_isf("99.0.0-nonexistent")
        assert result is None

    def test_finds_gzipped_isf(self, tmp_path: Path) -> None:
        import base64
        import gzip
        import json

        from forensiq.acquisition import linux_isf as m

        vol3_dir = tmp_path / "vol3"
        vol3_dir.mkdir()
        isf = vol3_dir / "linux-6.0.0-test.json.gz"
        valid = {
            "metadata": {"producer": {"version": "1.1.0"}},
            "symbols": {
                "linux_banner": {
                    "address": 0,
                    "constant_data": base64.b64encode(b"Linux version 6.0.0-test\n").decode(),
                }
            },
        }
        with gzip.open(isf, "wt", encoding="utf-8") as f:
            json.dump(valid, f)
        with (
            patch.object(m, "_VOL3_CACHE_SYMBOLS_DIR", vol3_dir),
            patch.object(m, "_FORENSIQ_SYMBOLS_DIR", tmp_path / "forensiq"),
        ):
            result = m.find_linux_isf("6.0.0-test")
        assert result == isf

    def test_finds_plain_json_isf(self, tmp_path: Path) -> None:
        import base64
        import json

        from forensiq.acquisition import linux_isf as m

        forensiq_dir = tmp_path / "forensiq"
        forensiq_dir.mkdir()
        isf = forensiq_dir / "linux-6.0.0-test.json"
        valid = {
            "metadata": {"producer": {"version": "1.1.0"}},
            "symbols": {
                "linux_banner": {
                    "address": 0,
                    "constant_data": base64.b64encode(b"Linux version 6.0.0-test\n").decode(),
                }
            },
        }
        isf.write_text(json.dumps(valid))
        with (
            patch.object(m, "_VOL3_CACHE_SYMBOLS_DIR", tmp_path / "vol3"),
            patch.object(m, "_FORENSIQ_SYMBOLS_DIR", forensiq_dir),
        ):
            result = m.find_linux_isf("6.0.0-test")
        assert result == isf


class TestBuildLinuxISF:
    """build_linux_isf() parses BTF in Python and saves a compressed ISF."""

    def test_returns_existing_isf_without_rebuilding(self, tmp_path: Path) -> None:
        import base64
        import gzip
        import json

        from forensiq.acquisition import linux_isf as m

        vol3_dir = tmp_path / "vol3"
        vol3_dir.mkdir()
        isf = vol3_dir / "linux-6.0.0-test.json.gz"
        # Must have linux_banner.constant_data AND producer version 1.1.0
        # for _isf_has_banner_data() to return True
        valid_isf = {
            "metadata": {"producer": {"name": "forensiq-btf2isf", "version": "1.1.0"}},
            "base_types": {},
            "user_types": {},
            "enums": {},
            "symbols": {
                "linux_banner": {
                    "address": 0xFFFFFFFF80000000,
                    "constant_data": base64.b64encode(b"Linux version 6.0.0-test\n").decode(),
                }
            },
        }
        with gzip.open(isf, "wt", encoding="utf-8") as f:
            json.dump(valid_isf, f)
        with (
            patch.object(m, "_VOL3_CACHE_SYMBOLS_DIR", vol3_dir),
            patch.object(m, "_FORENSIQ_SYMBOLS_DIR", tmp_path / "forensiq"),
        ):
            result = m.build_linux_isf("6.0.0-test")
        assert result == isf

    def test_raises_when_btf_missing(self, tmp_path: Path) -> None:
        from forensiq.acquisition import linux_isf as m

        with (
            patch.object(m, "_VOL3_CACHE_SYMBOLS_DIR", tmp_path / "vol3"),
            patch.object(m, "_FORENSIQ_SYMBOLS_DIR", tmp_path / "forensiq"),
            patch.object(m, "_BTF_PATH") as mock_btf,
        ):
            mock_btf.exists.return_value = False
            with pytest.raises(RuntimeError, match="BTF data not found"):
                m.build_linux_isf("6.0.0-test")

    def test_raises_when_sysmap_missing(self, tmp_path: Path) -> None:
        from forensiq.acquisition import linux_isf as m

        with (
            patch.object(m, "_VOL3_CACHE_SYMBOLS_DIR", tmp_path / "vol3"),
            patch.object(m, "_FORENSIQ_SYMBOLS_DIR", tmp_path / "forensiq"),
            patch.object(m, "_BTF_PATH") as mock_btf,
            patch("forensiq.acquisition.linux_isf.find_system_map", return_value=None),
            patch("forensiq.acquisition.linux_isf.os.access", return_value=True),
        ):
            mock_btf.exists.return_value = True
            with pytest.raises(RuntimeError, match=r"System\.map not found"):
                m.build_linux_isf("6.0.0-test")

    def test_saves_compressed_isf_on_success(self, tmp_path: Path) -> None:
        import gzip
        import json

        from forensiq.acquisition import linux_isf as m

        vol3_dir = tmp_path / "vol3"
        forensiq_dir = tmp_path / "forensiq"
        fake_isf_dict = {
            "metadata": {},
            "base_types": {},
            "user_types": {},
            "enums": {},
            "symbols": {},
        }
        mock_btf_parser = MagicMock()
        mock_btf_parser.types = {}
        mock_isf_builder = MagicMock()
        mock_isf_builder.return_value.build.return_value = fake_isf_dict
        with (
            patch.object(m, "_VOL3_CACHE_SYMBOLS_DIR", vol3_dir),
            patch.object(m, "_FORENSIQ_SYMBOLS_DIR", forensiq_dir),
            patch.object(m, "_BTF_PATH") as mock_btf_path,
            patch(
                "forensiq.acquisition.linux_isf.find_system_map",
                return_value=Path("/boot/System.map"),
            ),
            patch("forensiq.acquisition.linux_isf.os.access", return_value=True),
            patch("forensiq.acquisition.linux_isf._BTFParser", return_value=mock_btf_parser),
            patch("forensiq.acquisition.linux_isf._ISFBuilder", mock_isf_builder),
        ):
            mock_btf_path.exists.return_value = True
            mock_btf_path.read_bytes.return_value = b"fake-btf"
            mock_btf_path.stat.return_value.st_size = 8
            result = m.build_linux_isf("6.0.0-test")
        assert result.name == "linux-6.0.0-test.json.gz"
        assert result.exists()
        with gzip.open(result, "rb") as f:
            loaded = json.loads(f.read())
        assert loaded == fake_isf_dict
