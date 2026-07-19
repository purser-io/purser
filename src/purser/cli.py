"""Purser CLI."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from purser import __version__
from purser.core.findings import ScanReport, Severity
from purser.core.hf import HFNotAvailable, download_repo, parse_hf_uri
from purser.core.policy import Policy, PolicyError
from purser.core.provenance import origin_db
from purser.core.scanner import EXIT_CODES, scan_target
from purser.core.signing import (
    SigningError,
    generate_keypair,
    load_trust_store,
    verify_target,
    write_signature,
)

app = typer.Typer(help="Purser — ML model security scanner with policy controls.",
                  no_args_is_help=True)
console = Console(stderr=False)

SEV_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}
VERDICT_STYLE = {
    "PASS": "bold green",
    "WARN": "bold yellow",
    "FAIL": "bold red",
    "BLOCKED": "bold white on red",
    "ERROR": "bold magenta",
}


def _load_policy(policy_path: str | None) -> Policy:
    if policy_path is None:
        return Policy.default()
    try:
        return Policy.load(policy_path)
    except (OSError, PolicyError) as exc:
        console.print(f"[bold red]Policy error:[/] {exc}")
        raise typer.Exit(3)


def _render_table(report: ScanReport) -> None:
    style = VERDICT_STYLE.get(report.verdict.value, "")
    console.print(f"\n[bold]Target:[/] {report.target}")
    if report.metadata.get("repo_id"):
        console.print(f"[bold]Repo:[/] {report.metadata['repo_id']}")
    if report.provenance_verified:
        prov = "[bold green]✓ signature-verified[/]"
    else:
        prov = report.metadata.get("provenance_source", "unknown")
    console.print(f"[bold]Policy:[/] {report.policy_name}"
                  f"    [bold]Publisher:[/] {report.publisher or '-'}"
                  f"    [bold]Origin:[/] {report.origin or 'unknown'}"
                  f" ({prov})")
    console.print(f"[bold]Files scanned:[/] {len(report.files)}"
                  f"    [bold]Duration:[/] {report.duration_seconds:.2f}s")

    findings = report.all_findings
    if findings:
        table = Table(title=None, expand=False, show_lines=False)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Rule")
        table.add_column("Finding")
        table.add_column("File", overflow="fold")
        for f in sorted(findings, key=lambda x: -int(x.severity)):
            table.add_row(
                f"[{SEV_STYLE.get(f.severity.name, '')}]{f.severity.name}[/]",
                f.rule_id,
                f.title,
                Path(f.file).name if f.file else "-",
            )
        console.print(table)
    else:
        console.print("[green]No findings.[/]")

    counts = {k: v for k, v in report.severity_counts().items() if v}
    if counts:
        console.print("[bold]Counts:[/] " + "  ".join(f"{k}={v}" for k, v in counts.items()))
    console.print(f"\n[bold]Verdict:[/] [{style}] {report.verdict.value} [/]\n")


def _to_sarif(report: ScanReport) -> dict:
    sev_to_level = {
        Severity.CRITICAL: "error", Severity.HIGH: "error",
        Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note",
    }
    rules: dict[str, dict] = {}
    results = []
    for f in report.all_findings:
        rules.setdefault(f.rule_id, {
            "id": f.rule_id,
            "shortDescription": {"text": f.title[:120]},
        })
        results.append({
            "ruleId": f.rule_id,
            "level": sev_to_level[f.severity],
            "message": {"text": f"{f.title}. {f.detail}".strip()},
            "properties": {"severity": f.severity.name, "tags": f.tags},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file or report.target},
                }
            }],
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Purser",
                "version": __version__,
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"verdict": report.verdict.value, "policy": report.policy_name},
        }],
    }


def _emit(report: ScanReport, fmt: str, output: str | None) -> None:
    if fmt == "json":
        text = json.dumps(report.to_dict(), indent=2)
    elif fmt == "sarif":
        text = json.dumps(_to_sarif(report), indent=2)
    else:
        if output:
            Path(output).write_text(json.dumps(report.to_dict(), indent=2))
        _render_table(report)
        return
    if output:
        Path(output).write_text(text)
        console.print(f"Report written to {output}")
    else:
        print(text)


@app.command()
def scan(
    target: str = typer.Argument(..., help="File, directory, or hf://org/repo to scan"),
    policy: str = typer.Option(None, "--policy", "-p", help="Path to policy YAML"),
    origin: str = typer.Option(None, "--origin", help="Explicit country of origin (ISO 3166-1 alpha-2)"),
    publisher: str = typer.Option(None, "--publisher", help="Model publisher (e.g. HF org)"),
    repo_id_opt: str = typer.Option(None, "--repo-id", help="Logical model id/name for policy matching (e.g. org/name), for local scans"),
    fmt: str = typer.Option("table", "--format", "-f", help="Output: table | json | sarif"),
    output: str = typer.Option(None, "--output", "-o", help="Write report to file"),
    revision: str = typer.Option(None, "--revision", help="HF revision when scanning hf:// targets"),
):
    """Scan a model artifact, directory, or HuggingFace repo."""
    pol = _load_policy(policy)
    hf_repo = parse_hf_uri(target)              # only hf:// triggers a download
    repo_id = hf_repo or repo_id_opt            # logical id for policy matching
    local_target = Path(target)
    if hf_repo is not None:
        try:
            console.print(f"Downloading [bold]{hf_repo}[/] from HuggingFace Hub…")
            local_target = download_repo(hf_repo, revision=revision)
        except HFNotAvailable as exc:
            console.print(f"[bold red]{exc}[/]")
            raise typer.Exit(3)
        except Exception as exc:
            console.print(f"[bold red]Download failed:[/] {exc}")
            raise typer.Exit(3)

    report = scan_target(local_target, policy=pol, origin=origin,
                         publisher=publisher, repo_id=repo_id)
    if hf_repo is not None:
        report.target = target
    _emit(report, fmt, output)
    raise typer.Exit(EXIT_CODES[report.verdict])


@app.command("policy-check")
def policy_check(policy: str = typer.Argument(..., help="Path to policy YAML")):
    """Validate a policy file and print its effective configuration."""
    pol = _load_policy(policy)
    console.print_json(json.dumps(pol.to_dict()))
    console.print("[green]Policy is valid.[/]")


@app.command()
def origins(publisher: str = typer.Argument(None, help="Look up one publisher")):
    """Show the publisher -> country origin database."""
    db = origin_db()
    if publisher:
        code = db.get(publisher.lower())
        if code:
            console.print(f"{publisher.lower()} -> {code}")
        else:
            console.print(f"[yellow]{publisher}: unknown origin[/]")
            raise typer.Exit(1)
        return
    table = Table()
    table.add_column("Publisher")
    table.add_column("Country")
    for pub, code in sorted(db.items()):
        table.add_row(pub, code)
    console.print(table)


@app.command()
def keygen(
    out: str = typer.Option("purser", "--out", "-o", help="Output filename prefix"),
):
    """Generate an Ed25519 signing keypair (<out>.key private, <out>.pub public)."""
    try:
        priv_pem, pub_pem = generate_keypair()
    except SigningError as exc:
        console.print(f"[bold red]{exc}[/]")
        raise typer.Exit(3)
    priv_path = Path(f"{out}.key")
    pub_path = Path(f"{out}.pub")
    priv_path.write_bytes(priv_pem)
    priv_path.chmod(0o600)
    pub_path.write_bytes(pub_pem)
    console.print(f"Private key: [bold]{priv_path}[/] (keep secret, chmod 600)")
    console.print(f"Public key:  [bold]{pub_path}[/] (add to trust_store.yaml)")


@app.command()
def sign(
    target: str = typer.Argument(..., help="Model file or directory to sign"),
    key: str = typer.Option(..., "--key", "-k", help="Path to the private key (PEM)"),
    key_id: str = typer.Option(..., "--key-id", help="Key id recorded in the signature"),
):
    """Sign a model artifact, producing a detached signature sidecar."""
    from datetime import datetime, timezone
    created = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        out = write_signature(Path(target), Path(key).read_bytes(), key_id,
                              created=created)
    except (SigningError, OSError) as exc:
        console.print(f"[bold red]Signing failed:[/] {exc}")
        raise typer.Exit(3)
    console.print(f"[green]Signed[/] {target} -> {out} (key_id={key_id})")


@app.command()
def verify(
    target: str = typer.Argument(..., help="Model file or directory to verify"),
    trust_store: str = typer.Option(None, "--trust-store", "-t",
                                    help="Path to trust_store.yaml"),
):
    """Verify a model's signature against the trust store."""
    store = load_trust_store(trust_store) if trust_store else load_trust_store()
    result = verify_target(Path(target), store)
    style = "bold green" if result.verified else "bold red"
    console.print(f"[{style}]{result.status.upper()}[/]: {result.reason}")
    if result.verified:
        console.print(f"  key_id:    {result.key_id}")
        console.print(f"  publisher: {result.publisher}")
        console.print(f"  origin:    {result.origin}")
    raise typer.Exit(0 if result.verified else 1)


@app.command()
def version():
    """Print version."""
    console.print(f"purser {__version__}")


def main() -> None:  # console_scripts entry point
    app()


if __name__ == "__main__":
    main()
