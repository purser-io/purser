"""Generic archive scanner: zip-slip, zip-bomb, and recursive member scanning."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from purser.core.findings import Finding, Severity
from purser.scanners.base import Scanner

MAX_DEPTH = 3
MAX_TOTAL_UNCOMPRESSED = 4 * 1024 * 1024 * 1024  # 4 GiB — flag regardless of ratio
BOMB_RATIO = 200
BOMB_RATIO_MIN_SIZE = 100 * 1024 * 1024  # ratio trips above this absolute size


def _member_is_unsafe(name: str) -> bool:
    p = PurePosixPath(name.replace("\\", "/"))
    return p.is_absolute() or ".." in p.parts


class ArchiveScanner(Scanner):
    name = "archive"

    def __init__(self, depth: int = 0):
        self.depth = depth

    def scan(self, path: Path) -> list[Finding]:
        if zipfile.is_zipfile(path):
            return self._scan_zip(path)
        if tarfile.is_tarfile(path):
            return self._scan_tar(path)
        return []

    # -- zip ---------------------------------------------------------------
    def _scan_zip(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            total_uncompressed = sum(i.file_size for i in infos)
            total_compressed = max(1, sum(i.compress_size for i in infos))
            ratio = total_uncompressed / total_compressed
            # Two independent triggers (OR, not AND — the previous AND left a
            # gap band, e.g. a 3.9 GiB expansion or a 150x ratio, that passed):
            #   * any expansion beyond the absolute ceiling, or
            #   * a high compression ratio once past a minimum size.
            if total_uncompressed > MAX_TOTAL_UNCOMPRESSED or (
                total_uncompressed > BOMB_RATIO_MIN_SIZE and ratio > BOMB_RATIO
            ):
                findings.append(self.finding(
                    "ARCHIVE_ZIP_BOMB", Severity.HIGH,
                    "Archive expands suspiciously (possible zip bomb)",
                    f"{total_compressed} bytes expand to {total_uncompressed} bytes "
                    f"(ratio {total_uncompressed // total_compressed}x).",
                    tags=["denial-of-service"],
                ))
                return findings
            for info in infos:
                if _member_is_unsafe(info.filename):
                    findings.append(self.finding(
                        "ARCHIVE_PATH_TRAVERSAL", Severity.CRITICAL,
                        f"Archive member escapes extraction dir: `{info.filename[:120]}`",
                        "Extraction would write outside the target directory "
                        "(zip-slip attack).",
                        tags=["file-access"], evidence={"member": info.filename[:300]},
                    ))
            if self.depth < MAX_DEPTH:
                findings.extend(self._scan_members_zip(zf, infos))
        return findings

    def _scan_members_zip(self, zf: zipfile.ZipFile, infos) -> list[Finding]:
        from purser.core.dispatch import scan_bytes_as_file  # lazy: avoids cycle

        findings: list[Finding] = []
        for info in infos:
            if info.is_dir() or _member_is_unsafe(info.filename):
                continue
            if info.file_size > 2 * 1024 * 1024 * 1024:
                continue
            data = zf.read(info)
            for f in scan_bytes_as_file(data, info.filename, depth=self.depth + 1):
                f.detail = f"[{info.filename}] {f.detail}" if f.detail else f"[{info.filename}]"
                f.evidence.setdefault("member", info.filename)
                findings.append(f)
        return findings

    # -- tar ---------------------------------------------------------------
    def _scan_tar(self, path: Path) -> list[Finding]:
        from purser.core.dispatch import scan_bytes_as_file

        findings: list[Finding] = []
        with tarfile.open(path) as tf:
            for member in tf.getmembers():
                if _member_is_unsafe(member.name) or member.islnk() or member.issym():
                    if _member_is_unsafe(member.name):
                        findings.append(self.finding(
                            "ARCHIVE_PATH_TRAVERSAL", Severity.CRITICAL,
                            f"Archive member escapes extraction dir: `{member.name[:120]}`",
                            "Extraction would write outside the target directory.",
                            tags=["file-access"], evidence={"member": member.name[:300]},
                        ))
                    continue
                if not member.isfile() or member.size > 2 * 1024 * 1024 * 1024:
                    continue
                if self.depth < MAX_DEPTH:
                    fobj = tf.extractfile(member)
                    if fobj is None:
                        continue
                    data = fobj.read()
                    for f in scan_bytes_as_file(data, member.name, depth=self.depth + 1):
                        f.detail = f"[{member.name}] {f.detail}" if f.detail else f"[{member.name}]"
                        f.evidence.setdefault("member", member.name)
                        findings.append(f)
        return findings
