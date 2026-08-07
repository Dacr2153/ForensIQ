# FILE: tests/unit/test_tui_menu.py
"""Unit tests for forensiq.tui.menu helper functions."""

from __future__ import annotations

from pathlib import Path

import questionary

from forensiq.tui.menu import _ask_choice, _ask_confirm, _ask_output_dir


class _FakePrompt:
    """Factory producing a fake questionary prompt whose ask() returns/raises a
    fixed outcome."""

    def __init__(self, outcome: object) -> None:
        self._outcome = outcome

    def __call__(self, *args, **kwargs) -> _FakePrompt:  # type: ignore[no-untyped-def]
        return self

    def ask(self) -> object:
        if isinstance(self._outcome, BaseException):
            raise self._outcome
        return self._outcome


def _patch(monkeypatch, select_outcome, confirm_outcome) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(questionary, "select", _FakePrompt(select_outcome))
    monkeypatch.setattr(questionary, "confirm", _FakePrompt(confirm_outcome))


class TestAskChoice:
    def test_user_selection_maps_to_value(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        _patch(monkeypatch, "Analyze", True)
        result = _ask_choice("menu", [("Analyze", "analyze"), ("Exit", "exit")])
        assert result == "analyze"

    def test_cancel_returns_exit(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        _patch(monkeypatch, None, True)
        assert _ask_choice("menu", [("A", "a")]) == "exit"

    def test_keyboard_interrupt_returns_exit(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        _patch(monkeypatch, KeyboardInterrupt(), True)
        assert _ask_choice("menu", [("A", "a")]) == "exit"

    def test_eof_error_returns_exit(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        _patch(monkeypatch, EOFError(), True)
        assert _ask_choice("menu", [("A", "a")]) == "exit"


class TestAskConfirm:
    def test_eof_falls_back_to_default(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        _patch(monkeypatch, "Analyze", EOFError())
        assert _ask_confirm("really?", default=True) is True

    def test_none_answer_falls_back_to_default(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        _patch(monkeypatch, "Analyze", None)
        assert _ask_confirm("really?", default=False) is False


class TestAskOutputDir:
    def test_uses_provided_path(self, monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        target = tmp_path / "nested" / "dir"
        monkeypatch.setattr(
            "forensiq.tui.menu._ask_text",
            lambda *a, **k: str(target),  # type: ignore[arg-type]
        )
        assert _ask_output_dir("out?") == target.resolve()

    def test_empty_answer_uses_default(self, monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr(
            "forensiq.tui.menu._ask_text",
            lambda *a, **k: None,  # type: ignore[arg-type]
        )
        default = str(tmp_path / "reports")
        assert _ask_output_dir("out?", default=default) == Path(default)
