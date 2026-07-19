"""Purser settings use the PURSER_ prefix via env_get."""

from purser.core.env import env_get


def test_reads_purser_prefix(monkeypatch):
    monkeypatch.setenv("PURSER_POLICY", "p.yaml")
    assert env_get("POLICY") == "p.yaml"


def test_default_when_unset(monkeypatch):
    monkeypatch.delenv("PURSER_POLICY", raising=False)
    assert env_get("POLICY", "fallback") == "fallback"
