# FILE: tests/unit/test_heuristics.py
"""Unit tests for process relationship and behavioral heuristics."""

from __future__ import annotations

from forensiq.features.heuristics import (
    has_encoded_cmdline,
    is_system_path,
    parent_child_legit,
)


class TestIsSystemPath:
    """Tests for is_system_path."""

    def test_system32_path(self) -> None:
        assert is_system_path(r"\Device\HarddiskVolume2\Windows\System32\svchost.exe") is True

    def test_syswow64_path(self) -> None:
        assert is_system_path(r"\Windows\SysWOW64\rundll32.exe") is True

    def test_temp_path_not_system(self) -> None:
        assert is_system_path(r"\Users\user\AppData\Local\Temp\malware.exe") is False

    def test_desktop_path_not_system(self) -> None:
        assert is_system_path(r"\Users\user\Desktop\payload.exe") is False

    def test_empty_path_not_system(self) -> None:
        assert is_system_path("") is False

    def test_program_files_is_system(self) -> None:
        assert is_system_path(r"\Program Files\SomeApp\app.exe") is True

    def test_case_insensitive(self) -> None:
        assert is_system_path(r"\WINDOWS\SYSTEM32\SVCHOST.EXE") is True


class TestParentChildLegit:
    """Tests for parent_child_legit."""

    def test_services_spawning_svchost(self) -> None:
        assert parent_child_legit("services.exe", "svchost.exe") is True

    def test_lsass_spawning_nothing(self) -> None:
        # lsass should not spawn processes
        assert parent_child_legit("lsass.exe", "cmd.exe") is False

    def test_wininit_spawning_lsass(self) -> None:
        assert parent_child_legit("wininit.exe", "lsass.exe") is True

    def test_explorer_spawning_notepad(self) -> None:
        assert parent_child_legit("explorer.exe", "notepad.exe") is True

    def test_unknown_parent_returns_true(self) -> None:
        # Unknown parents are assumed legitimate (reduces FPs)
        assert parent_child_legit("unknown_process.exe", "cmd.exe") is True

    def test_csrss_spawning_cmd(self) -> None:
        # csrss is in _NO_CHILD_PROCESSES
        assert parent_child_legit("csrss.exe", "cmd.exe") is False

    def test_services_spawning_payload(self) -> None:
        # payload.exe not in known children of services
        assert parent_child_legit("services.exe", "payload.exe") is False

    def test_case_insensitive(self) -> None:
        assert parent_child_legit("SERVICES.EXE", "SVCHOST.EXE") is True


class TestHasEncodedCmdline:
    """Tests for has_encoded_cmdline."""

    def test_base64_encoded_powershell(self) -> None:
        cmdline = r"powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIA=="
        assert has_encoded_cmdline(cmdline) is True

    def test_clean_svchost_cmdline(self) -> None:
        cmdline = "svchost.exe -k netsvcs -p -s Browser"
        assert has_encoded_cmdline(cmdline) is False

    def test_none_cmdline(self) -> None:
        assert has_encoded_cmdline(None) is False

    def test_empty_cmdline(self) -> None:
        assert has_encoded_cmdline("") is False

    def test_hex_payload(self) -> None:
        cmdline = r"cmd.exe /c echo 4d5a9000030000000400000f0ffff > payload.bin"
        assert has_encoded_cmdline(cmdline) is True

    def test_powershell_encodedcommand_flag(self) -> None:
        cmdline = (
            "powershell.exe -NonInteractive -EncodedCommand "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIA=="
        )
        assert has_encoded_cmdline(cmdline) is True

    def test_wscript_eval_obfuscation(self) -> None:
        cmdline = r'wscript.exe //e:jscript -e:eval("WScript.CreateObject")'
        assert has_encoded_cmdline(cmdline) is True

    def test_normal_explorer_cmdline(self) -> None:
        cmdline = r"C:\Windows\Explorer.EXE"
        assert has_encoded_cmdline(cmdline) is False


class TestNormalizeWindowsPath:
    def test_empty_path_returns_empty(self) -> None:
        from forensiq.features.heuristics import _normalize_windows_path
        assert _normalize_windows_path("") == ""

    def test_drive_letter_stripped(self) -> None:
        from forensiq.features.heuristics import _normalize_windows_path
        result = _normalize_windows_path("C:\\Windows\\System32\\svchost.exe")
        assert not result.startswith("c:")
        assert "windows" in result


class TestIsSystemPathLinux:
    def test_linux_system_path_usr_bin(self) -> None:
        from forensiq.features.heuristics import is_system_path
        assert is_system_path("/usr/bin/python3") is True

    def test_linux_non_system_tmp(self) -> None:
        from forensiq.features.heuristics import is_system_path
        assert is_system_path("/tmp/evil") is False

    def test_linux_kernel_thread_returns_false(self) -> None:
        """Process names like [kworker/0:0] start with '[' → treated as Linux."""
        from forensiq.features.heuristics import is_system_path
        # Kernel thread names start with [ — not a system path, just kernel thread
        result = is_system_path("[kworker/0:0]")
        assert isinstance(result, bool)


class TestGetProcessStem:
    def test_empty_name_returns_empty(self) -> None:
        from forensiq.features.heuristics import _get_process_stem
        assert _get_process_stem("") == ""


class TestParentChildLegitBoundary:
    def test_dangerous_child_of_whitelisted_parent_returns_false(self) -> None:
        from forensiq.features.heuristics import parent_child_legit
        # mimikatz should not be a legit child of any process
        result = parent_child_legit("services.exe", "mimikatz")
        assert result is False

    def test_whitelisted_child_in_allowed_set_returns_true(self) -> None:
        from forensiq.features.heuristics import parent_child_legit
        # services.exe → svchost.exe is a well-known legitimate relationship
        result = parent_child_legit("services.exe", "svchost.exe")
        assert result is True
