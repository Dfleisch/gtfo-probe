"""Shared pytest fixtures.

Tests that need a real sandbox use the `sandbox` fixture, which *skips* (not
fails) when bubblewrap is unavailable, e.g. on a CI runner without user namespaces.
Everything else (spec, detector, db) is pure and always runs.
"""
from pathlib import Path

import pytest

from gtfo_probe import fixtures
from gtfo_probe.sandbox import Sandbox, SandboxUnavailable


@pytest.fixture(scope="session")
def sandbox():
    try:
        sb = Sandbox.detect()
        sb.preflight()
    except SandboxUnavailable as exc:
        pytest.skip(f"no working sandbox: {exc}")
    return sb


@pytest.fixture(scope="session")
def template(tmp_path_factory) -> Path:
    return fixtures.build_template(tmp_path_factory.mktemp("tpl") / "template")


@pytest.fixture
def world(template, tmp_path) -> Path:
    """A fresh private copy of the fixture world for one test."""
    return fixtures.fresh_copy(template, tmp_path / "world")
