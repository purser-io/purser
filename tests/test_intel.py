"""Tests for the end-user intel update channel (`purser update-intel`)."""

from __future__ import annotations

import json
import zipfile
from datetime import date, timedelta

import pytest
from typer.testing import CliRunner

from purser.cli import app
from purser.core import intel
from purser.signals import SignalContext
from purser.signals.loader_cves import LoaderCVEsSource

GOOD = """\
# test dataset
# Last refreshed: {stamp}
- cve: CVE-9999-1111
  framework: keras
  channel: keras_version
  affected: '<9.0'
  summary: test
  reference: x
"""


class FakeHTTP:
    def __init__(self, body: str):
        self.body = body
        self.urls: list[str] = []

    def urlopen(self, req, timeout=0):
        self.urls.append(req.full_url)
        body = self.body

        class R:
            def read(self):
                return body.encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        return R()


def make_keras_v3(path, version):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("metadata.json", json.dumps({"keras_version": version}))


# -- validation -------------------------------------------------------------------

def test_validate_accepts_real_vendored_dataset():
    _, text = intel.active_dataset()
    assert len(intel.validate_dataset(text)) >= 20


@pytest.mark.parametrize("bad", [
    "not: a list", "[]", "- {framework: keras}", "- just-a-string", "{{{{",
])
def test_validate_rejects_malformed(bad):
    with pytest.raises(ValueError):
        intel.validate_dataset(bad)


# -- update ------------------------------------------------------------------------

def test_update_fetches_validates_installs(monkeypatch):
    fake = FakeHTTP(GOOD.format(stamp="2026-08-01"))
    monkeypatch.setattr("purser.core.intel.urllib.request.urlopen", fake.urlopen)
    summary = intel.update()
    assert summary["entries"] == 1
    assert summary["refreshed"] == "2026-08-01"
    assert intel.user_intel_path().exists()
    assert fake.urls == [intel.DEFAULT_INTEL_URL]


def test_update_rejects_garbage_and_keeps_previous(monkeypatch):
    good = FakeHTTP(GOOD.format(stamp="2026-08-01"))
    monkeypatch.setattr("purser.core.intel.urllib.request.urlopen", good.urlopen)
    intel.update()
    before = intel.user_intel_path().read_text()

    bad = FakeHTTP("<html>404 not the dataset</html>")
    monkeypatch.setattr("purser.core.intel.urllib.request.urlopen", bad.urlopen)
    with pytest.raises(ValueError):
        intel.update()
    assert intel.user_intel_path().read_text() == before


def test_update_url_env_override(monkeypatch):
    monkeypatch.setenv("PURSER_INTEL_URL", "https://mirror.internal/cves.yaml")
    fake = FakeHTTP(GOOD.format(stamp="2026-08-01"))
    monkeypatch.setattr("purser.core.intel.urllib.request.urlopen", fake.urlopen)
    intel.update()
    assert fake.urls == ["https://mirror.internal/cves.yaml"]


# -- resolution order --------------------------------------------------------------

def test_user_file_preferred_over_vendored(monkeypatch, tmp_path):
    fake = FakeHTTP(GOOD.format(stamp="2026-08-01"))
    monkeypatch.setattr("purser.core.intel.urllib.request.urlopen", fake.urlopen)
    intel.update()

    make_keras_v3(tmp_path / "model.keras", "3.9.0")
    fs = LoaderCVEsSource().collect(SignalContext(target=tmp_path))
    got = {c["cve"] for f in fs for c in f.evidence["cves"]}
    assert got == {"CVE-9999-1111"}  # user dataset, not the vendored one


def test_env_override_beats_user_file(monkeypatch, tmp_path):
    fake = FakeHTTP(GOOD.format(stamp="2026-08-01"))
    monkeypatch.setattr("purser.core.intel.urllib.request.urlopen", fake.urlopen)
    intel.update()

    custom = tmp_path / "explicit.yaml"
    custom.write_text(GOOD.format(stamp="2026-08-01").replace(
        "CVE-9999-1111", "CVE-8888-2222"))
    monkeypatch.setenv("PURSER_LOADER_CVES", str(custom))
    make_keras_v3(tmp_path / "model.keras", "3.9.0")
    fs = LoaderCVEsSource().collect(SignalContext(target=tmp_path))
    got = {c["cve"] for f in fs for c in f.evidence["cves"]}
    assert got == {"CVE-8888-2222"}


# -- staleness ---------------------------------------------------------------------

def test_staleness_hint_on_old_dataset(monkeypatch):
    old = (date.today() - timedelta(days=200)).isoformat()
    fake = FakeHTTP(GOOD.format(stamp=old))
    monkeypatch.setattr("purser.core.intel.urllib.request.urlopen", fake.urlopen)
    intel.update()
    hint = intel.staleness_hint()
    assert hint and "update-intel" in hint


def test_no_hint_when_fresh(monkeypatch):
    fresh = date.today().isoformat()
    fake = FakeHTTP(GOOD.format(stamp=fresh))
    monkeypatch.setattr("purser.core.intel.urllib.request.urlopen", fake.urlopen)
    intel.update()
    assert intel.staleness_hint() is None


def test_staleness_never_raises(monkeypatch):
    monkeypatch.setenv("PURSER_LOADER_CVES", "/nonexistent/nope.yaml")
    assert intel.staleness_hint() is None


# -- CLI ---------------------------------------------------------------------------

def test_cli_update_intel_check(monkeypatch):
    runner = CliRunner()
    result = runner.invoke(app, ["update-intel", "--check"])
    assert result.exit_code == 0
    assert "vendored" in result.output
    assert "entries" in result.output


def test_cli_update_intel_fetch(monkeypatch):
    fake = FakeHTTP(GOOD.format(stamp="2026-08-01"))
    monkeypatch.setattr("purser.core.intel.urllib.request.urlopen", fake.urlopen)
    runner = CliRunner()
    result = runner.invoke(app, ["update-intel"])
    assert result.exit_code == 0
    assert "Updated" in result.output

    result = runner.invoke(app, ["update-intel", "--check"])
    assert "user:" in result.output


def test_cli_update_intel_rejects_bad_fetch(monkeypatch):
    fake = FakeHTTP("<html>nope</html>")
    monkeypatch.setattr("purser.core.intel.urllib.request.urlopen", fake.urlopen)
    runner = CliRunner()
    result = runner.invoke(app, ["update-intel"])
    assert result.exit_code == 3
    assert "Rejected" in result.output
