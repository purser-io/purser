"""Purser live demo — a HuggingFace Space.

Runs the real Purser scanner + policy engine on an uploaded model file or a
Hub repo id. The Space is a thin UI: everything security-relevant happens in
the `purser` package exactly as it does in the CLI/API/admission webhook.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import gradio as gr

from purser.core.findings import ScanReport
from purser.core.scanner import scan_target
from purser.signals import SignalContext

MAX_UPLOAD_MB = 200          # Space disk/CPU is small; keep the demo snappy
MAX_REPO_MB = 500

VERDICT_BADGE = {
    "PASS": "🟢 **PASS**",
    "WARN": "🟡 **WARN**",
    "FAIL": "🔴 **FAIL**",
    "BLOCKED": "⛔ **BLOCKED**",
    "ERROR": "🟣 **ERROR**",
}


def _render(report: ScanReport) -> tuple[str, list[list[str]], str]:
    badge = VERDICT_BADGE.get(report.verdict.value, report.verdict.value)
    head = (f"{badge} — policy `{report.policy_name}` · "
            f"{len(report.files)} file(s) · {report.duration_seconds:.2f}s")
    rows = [
        [f.severity.name, f.rule_id, f.title, Path(f.file).name if f.file else "-"]
        for f in sorted(report.all_findings, key=lambda x: -int(x.severity))
    ] or [["-", "-", "No findings", "-"]]
    return head, rows, json.dumps(report.to_dict(), indent=2)


def scan_upload(file) -> tuple[str, list[list[str]], str]:
    if file is None:
        return "Upload a model file first.", [], ""
    # Gradio stages uploads under the system temp dir; confine the scan to
    # that staging area so a crafted path can't point the scanner elsewhere
    # (same resolved-prefix guard as the REST API's scan-root confinement).
    src = Path(file).resolve()
    staging = Path(tempfile.gettempdir()).resolve()
    if staging != src and staging not in src.parents:
        return "Rejected: upload is outside the staging directory.", [], ""
    if not src.is_file():
        return "Upload not found.", [], ""
    if src.stat().st_size > MAX_UPLOAD_MB * 1024 * 1024:
        return f"File exceeds the demo's {MAX_UPLOAD_MB} MB limit.", [], ""
    return _render(scan_target(src))


def scan_repo(repo_id: str, revision: str) -> tuple[str, list[list[str]], str]:
    repo_id = (repo_id or "").strip().removeprefix("hf://")
    if not repo_id or "/" not in repo_id:
        return "Enter a repo id like `org/model`.", [], ""
    from huggingface_hub import snapshot_download

    tmp = tempfile.mkdtemp(prefix="purser-space-")
    try:
        local = snapshot_download(
            repo_id=repo_id, revision=(revision or None), cache_dir=tmp)
        size = sum(p.stat().st_size for p in Path(local).rglob("*") if p.is_file())
        if size > MAX_REPO_MB * 1024 * 1024:
            return (f"Repo exceeds the demo's {MAX_REPO_MB} MB limit — "
                    "run Purser locally for big models.", [], "")
        report = scan_target(
            local, repo_id=repo_id,
            signal_context=SignalContext(repo_id=repo_id,
                                         revision=(revision or None),
                                         source="huggingface"))
        report.target = f"hf://{repo_id}"
        return _render(report)
    except Exception as exc:
        return f"Could not fetch `{repo_id}`: {exc}", [], ""
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


FINDING_HEADERS = ["Severity", "Rule", "Finding", "File"]

with gr.Blocks(title="Purser — model supply-chain control plane") as demo:
    gr.Markdown(
        "# ⚓ Purser\n"
        "**Model supply-chain control plane** — policy, provenance, and "
        "enforcement for ML model artifacts. This demo runs the real scanner "
        "+ policy engine; models are **never loaded or executed**.\n\n"
        "[GitHub](https://github.com/purser-io/purser) · "
        "`pip install purser` · "
        "[Helm/K8s admission](https://github.com/purser-io/purser#kubernetes)")
    with gr.Tab("Scan an upload"):
        up = gr.File(label=f"Model file (≤{MAX_UPLOAD_MB} MB)", type="filepath")
        btn_u = gr.Button("Scan", variant="primary")
        out_u = gr.Markdown()
        tbl_u = gr.Dataframe(headers=FINDING_HEADERS, interactive=False)
        json_u = gr.Code(language="json", label="Full report")
        btn_u.click(scan_upload, inputs=up, outputs=[out_u, tbl_u, json_u])
    with gr.Tab("Scan a Hub repo"):
        repo = gr.Textbox(label="Repo id", placeholder="org/model")
        rev = gr.Textbox(label="Revision (optional)", placeholder="main")
        btn_r = gr.Button("Download + scan", variant="primary")
        out_r = gr.Markdown()
        tbl_r = gr.Dataframe(headers=FINDING_HEADERS, interactive=False)
        json_r = gr.Code(language="json", label="Full report")
        btn_r.click(scan_repo, inputs=[repo, rev],
                    outputs=[out_r, tbl_r, json_r])
        gr.Markdown(
            "Hub scans also ingest the Hub's **upstream scan verdicts** "
            "(picklescan / ClamAV / Protect AI / JFrog) as a corroborating "
            "signal — try `mcpotato/42-eicar-street` to see upstream "
            "findings, or `prajjwal1/bert-tiny` for a clean pass.")

if __name__ == "__main__":
    demo.launch()
