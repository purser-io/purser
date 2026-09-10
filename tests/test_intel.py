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
            # match urllib's real signature: update() reads with a size cap
            def read(self, n=-1):
                data = body.encode()
                return data if n is None or n < 0 else data[:n]

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


# -- transport hardening -----------------------------------------------------------

@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "file:///tmp/fake_intel.yaml",
    "ftp://example.invalid/loader_cves.yaml",
    "data:text/plain,- cve: X",
    "/tmp/fake_intel.yaml",          # bare path, no scheme
    "",
])
def test_check_url_rejects_non_http_schemes(url):
    """`urlopen` honours file:// and friends — an unvalidated PURSER_INTEL_URL
    would let a local file install itself as the active CVE dataset."""
    with pytest.raises(ValueError, match="unsupported intel URL scheme"):
        intel.check_url(url)


def test_check_url_accepts_https():
    assert intel.check_url("https://example.test/x.yaml").startswith("https://")


def test_plain_http_needs_explicit_opt_in(monkeypatch):
    monkeypatch.delenv("PURSER_INTEL_ALLOW_HTTP", raising=False)
    with pytest.raises(ValueError, match="plain http"):
        intel.check_url("http://mirror.internal/x.yaml")

    monkeypatch.setenv("PURSER_INTEL_ALLOW_HTTP", "1")
    assert intel.check_url("http://mirror.internal/x.yaml").startswith("http://")


def test_update_refuses_a_file_url_end_to_end(monkeypatch, tmp_path):
    """Regression: this exact URL previously installed as the active dataset."""
    local = tmp_path / "fake_intel.yaml"
    local.write_text(GOOD.format(stamp="2026-08-01"))
    monkeypatch.setenv("PURSER_INTEL_URL", local.as_uri())
    with pytest.raises(ValueError, match="unsupported intel URL scheme"):
        intel.update()


def test_oversized_response_is_refused(monkeypatch):
    fake = FakeHTTP("#" * (intel.MAX_INTEL_BYTES + 10))
    monkeypatch.setattr("purser.core.intel.urllib.request.urlopen", fake.urlopen)
    with pytest.raises(ValueError, match="exceeds"):
        intel.update(url="https://example.test/x.yaml")


def test_response_at_the_cap_is_still_accepted(monkeypatch):
    body = GOOD.format(stamp="2026-08-01")
    assert len(body.encode()) < intel.MAX_INTEL_BYTES
    fake = FakeHTTP(body)
    monkeypatch.setattr("purser.core.intel.urllib.request.urlopen", fake.urlopen)
    assert intel.update(url="https://example.test/x.yaml")["entries"] == 1
