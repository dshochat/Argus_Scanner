"""Hermetic tests for `argus doctor` check logic (no docker / no Postgres)."""

from __future__ import annotations

import pytest

import scanner.doctor as doctor
from scanner.doctor import FAIL, OK, WARN, Check, collect_checks


def test_python_check_ok() -> None:
    assert doctor._check_python().status == OK  # test env is 3.12+


def test_api_key_warn_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert doctor._check_api_key().status == WARN


def test_api_key_ok_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert doctor._check_api_key().status == OK


def test_unknown_dast_runtime_warns() -> None:
    checks = doctor._check_dast("")
    assert checks[0].status == WARN


def test_fly_runtime_requires_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FLY_API_TOKEN", raising=False)
    statuses = {c.name: c.status for c in doctor._check_dast("fly")}
    assert statuses["FLY_API_TOKEN"] == FAIL


def test_dashboard_deps_present_and_db_unset_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARGUS_DB_URL", raising=False)
    statuses = {c.name: c.status for c in doctor._check_dashboard()}
    assert statuses["Dashboard deps"] == OK  # bundled into the base install
    assert statuses["ARGUS_DB_URL"] == WARN  # unset → warn (no Postgres ping)


def test_collect_checks_is_list_of_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_DAST_RUNTIME", "")  # avoid the docker code path
    monkeypatch.delenv("ARGUS_DB_URL", raising=False)
    checks = collect_checks()
    assert checks and all(isinstance(c, Check) for c in checks)
    assert any(c.name == "Python" for c in checks)
