"""The CI helper scripts decide what fails a build and what gets pinned, so
their logic is tested like product code. Nothing here touches Docker or the
network — the resolver and the Trivy reports are faked."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod   # dataclasses look their module up by name
    spec.loader.exec_module(mod)
    return mod


gate = _load("trivy_gate")
repin = _load("repin_apk")


# ---------------------------------------------------------------- trivy_gate

def _report(tmp_path, name, *vulns):
    """A minimal `trivy image --format json` report. Each vuln is
    (type, package, id, installed, fixed)."""
    results = {}
    for kind, pkg, vid, installed, fixed in vulns:
        results.setdefault(kind, []).append({
            "PkgName": pkg, "VulnerabilityID": vid, "Severity": "HIGH",
            "InstalledVersion": installed, "FixedVersion": fixed,
        })
    path = tmp_path / name
    path.write_text(json.dumps({
        # Trivy emits `"Vulnerabilities": null`-less results for clean targets.
        "Results": [{"Target": "purser:ci", "Type": "wolfi"}] + [
            {"Target": k, "Type": k, "Vulnerabilities": v} for k, v in results.items()
        ],
    }))
    return path


EXPAT = ("wolfi", "libexpat1", "CVE-1", "2.9.0-r0", "2.10.0-r0")
CERTIFI = ("python-pkg", "certifi", "GHSA-1", "2026.6.17", "2026.10.19")
FILELOCK = ("python-pkg", "filelock", "CVE-2", "3.30.3", "4.2.1")


def test_clean_head_passes_without_a_base(tmp_path):
    head = _report(tmp_path, "head.json")
    assert gate.main(["diff", "--base", str(tmp_path / "absent.json"),
                      "--head", str(head)]) == 0


def test_inherited_findings_do_not_fail_the_change(tmp_path, capsys):
    """The case that used to turn unrelated PRs red: upstream published a fix
    for something main already pins."""
    base = _report(tmp_path, "base.json", EXPAT, CERTIFI)
    head = _report(tmp_path, "head.json", EXPAT, CERTIFI)
    assert gate.main(["diff", "--base", str(base), "--head", str(head)]) == 0
    assert "already present on the base" in capsys.readouterr().out


def test_introduced_finding_fails_the_change(tmp_path, capsys):
    base = _report(tmp_path, "base.json", EXPAT)
    head = _report(tmp_path, "head.json", EXPAT, FILELOCK)
    assert gate.main(["diff", "--base", str(base), "--head", str(head)]) == 1
    out = capsys.readouterr().out
    assert "introduced by this change" in out
    assert "filelock" in out.split("introduced by this change")[1]


def test_same_advisory_at_another_version_is_still_inherited(tmp_path):
    """A PR that moves a pin without reaching the fix did not introduce the CVE."""
    base = _report(tmp_path, "base.json", EXPAT)
    moved = ("wolfi", "libexpat1", "CVE-1", "2.9.1-r0", "2.10.0-r0")
    head = _report(tmp_path, "head.json", moved)
    assert gate.main(["diff", "--base", str(base), "--head", str(head)]) == 0


def test_missing_base_report_excuses_nothing(tmp_path):
    """No baseline (the base revision did not build) must fail closed."""
    head = _report(tmp_path, "head.json", EXPAT)
    assert gate.main(["diff", "--base", str(tmp_path / "absent.json"),
                      "--head", str(head)]) == 1


def test_report_is_strict_and_counts_unscanned_as_dirty(tmp_path, capsys):
    clean = _report(tmp_path, "core.json")
    dirty = _report(tmp_path, "hf.json", CERTIFI)
    assert gate.main(["report", str(clean)]) == 0
    assert gate.main(["report", str(clean), str(dirty)]) == 1
    assert gate.main(["report", str(clean), str(tmp_path / "deep.json")]) == 1
    assert "deep: NOT SCANNED" in capsys.readouterr().out


def test_lock_upgrades_names_only_python_packages(tmp_path, capsys):
    one = _report(tmp_path, "hf.json", EXPAT, CERTIFI, FILELOCK)
    two = _report(tmp_path, "core.json", CERTIFI)
    assert gate.main(["lock-upgrades", str(one), str(two),
                      str(tmp_path / "absent.json")]) == 0
    assert capsys.readouterr().out.strip() == "certifi filelock"


def test_lock_upgrades_drops_names_unsafe_for_a_command_line(tmp_path, capsys):
    hostile = ("python-pkg", "x; rm -rf /", "CVE-3", "1", "2")
    odd_case = ("python-pkg", "Typing_Extensions", "CVE-4", "1", "2")
    path = _report(tmp_path, "r.json", hostile, odd_case)
    gate.main(["lock-upgrades", str(path)])
    assert capsys.readouterr().out.strip() == "typing-extensions"


# ----------------------------------------------------------------- repin_apk

DOCKERFILE = """\
ARG WOLFI=cgr.dev/chainguard/wolfi-base:latest@sha256:{digest}

FROM ${{WOLFI}} AS build
RUN apk add --no-cache \\
      python-3.14=3.14.1-r0 \\
      build-base=1-r1
RUN python3.14 -m venv /venv

FROM ${{WOLFI}}
LABEL org.opencontainers.image.licenses="Apache-2.0" \\
      org.opencontainers.image.title="x"
RUN apk add --no-cache \\
      python-3.14=3.14.1-r0 \\
    && mkdir -p /models
USER 10001:10001
""".format(digest="a" * 64)

VERSIONS = {"python-3.14": "3.14.2-r0", "build-base": "1-r2"}
CLOSURES = {("python-3.14",): {"libexpat1": "2.10.0-r1", "py3-pip-wheel": "26.2.2-r2"}}


def test_closure_is_what_install_added_or_upgraded():
    before = {"busybox": "1-r0", "zlib": "1-r0"}
    after = {"busybox": "1-r0", "zlib": "1-r1", "python-3.14": "3-r0", "libffi": "3-r0"}
    assert repin.closure_of(before, after, ("python-3.14",)) == {
        "zlib": "1-r1",     # already on the base, but upgraded by the install
        "libffi": "3-r0",   # pulled in
    }


def test_rewrite_pins_runtime_closure_and_leaves_build_stage_top_level():
    text, changes = repin.rewrite_text("Dockerfile", DOCKERFILE, VERSIONS, CLOSURES)
    build, runtime = text.split("FROM ${WOLFI}\n")

    assert "python-3.14=3.14.2-r0 \\\n      build-base=1-r2\n" in build
    assert "apk-closure" not in build and "libexpat1" not in build

    assert (
        "      python-3.14=3.14.2-r0 \\\n"
        f"      {repin.CLOSURE_MARKER}\n"
        "      libexpat1=2.10.0-r1 \\\n"
        "      py3-pip-wheel=26.2.2-r2 \\\n"
        "    && mkdir -p /models\n"
    ) in runtime
    # LABEL continuation lines look like `name=value` too; they must survive.
    assert 'org.opencontainers.image.licenses="Apache-2.0" \\\n' in runtime
    assert ("Dockerfile", "libexpat1", None, "2.10.0-r1") in changes
    assert ("Dockerfile", "build-base", "1-r1", "1-r2") in changes


def test_rewrite_is_idempotent():
    once, _ = repin.rewrite_text("Dockerfile", DOCKERFILE, VERSIONS, CLOSURES)
    twice, changes = repin.rewrite_text("Dockerfile", once, VERSIONS, CLOSURES)
    assert twice == once
    assert changes == []


def test_rewrite_drops_closure_pins_no_longer_installed():
    once, _ = repin.rewrite_text("Dockerfile", DOCKERFILE, VERSIONS, CLOSURES)
    shrunk = {("python-3.14",): {"libexpat1": "2.11.0-r0"}}
    text, changes = repin.rewrite_text("Dockerfile", once, VERSIONS, shrunk)
    assert "py3-pip-wheel" not in text
    assert "libexpat1=2.11.0-r0 \\\n    && mkdir" in text
    assert ("Dockerfile", "py3-pip-wheel", "26.2.2-r2", None) in changes
    assert ("Dockerfile", "libexpat1", "2.10.0-r1", "2.11.0-r0") in changes


def test_rewrite_keeps_an_unterminated_block_unterminated():
    """When `apk add` is the whole RUN (no `&& ...`), the last pin — now a
    closure pin — must be the line without a trailing backslash."""
    text = "FROM x\nRUN apk add --no-cache \\\n      python-3.14=3.14.1-r0\nUSER 1\n"
    out, _ = repin.rewrite_text("Dockerfile", text, VERSIONS, CLOSURES)
    assert out.endswith(
        "      python-3.14=3.14.2-r0 \\\n"
        f"      {repin.CLOSURE_MARKER}\n"
        "      libexpat1=2.10.0-r1 \\\n"
        "      py3-pip-wheel=26.2.2-r2\n"
        "USER 1\n"
    )


@pytest.mark.parametrize("name", repin.DOCKERFILES)
def test_committed_dockerfiles_pin_a_runtime_closure(name):
    """Guards the invariant the CI gate relies on: the image that ships has no
    floating apk dependency for the build cache to freeze at a random version."""
    root = SCRIPTS.parent
    blocks = repin.apk_blocks((root / name).read_text().splitlines())
    runtime = repin.runtime_blocks(blocks)
    assert runtime, f"{name}: no pinned `apk add` in the final stage"
    for block in runtime:
        assert block.closure, f"{name}: runtime stage has no apk-closure pins"
