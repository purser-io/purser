# "Hugging Face already scans models. Why would we need Purser?"

Short answer: the Hub tells you what it found on files hosted on the Hub.
Purser decides whether a model is allowed into *your* environment and enforces
that decision, wherever the model came from. Purser reads the Hub's verdicts
and builds on them; it does not replace them.

Everything below about Hugging Face is taken from its own documentation or
from published research, read on **26 November 2026**. Sources are numbered and
listed at the end. Hugging Face changes quickly, so check the links before you
rely on a claim.

## What the Hub does, and does well

- **Malware scanning** with ClamAV on every pushed file under 2 GB [1].
- **Pickle import scanning**: it lists what a pickled file imports and
  highlights suspicious imports [2].
- **Secret scanning** with TruffleHog on each push [3].
- **Third-party scanners** on public repositories: Protect AI Guardian [4],
  JFrog [5], and VirusTotal hash lookups [6].
- **An API** that returns these verdicts per repository and per file [7].
- **Organisation controls** on paid plans: SSO, audit logs, resource groups,
  and on Enterprise Plus a content access policy that can restrict which
  repositories members may reach [8][9].

That is real coverage, at a scale no single team can match, and it is free on
public repositories. If every model you run comes straight from the Hub and a
warning badge is enough for you, you may not need more.

## Where the gaps are

| # | Gap | What the sources say | What Purser adds |
|---|---|---|---|
| 1 | **A flag is a warning, not a gate** | A flagged file gets a message in the web UI and the owner is advised to remove it [1]. A file the Hub marks `unsafe` still downloads: Hugging Face's own demo file returned HTTP 200 on 26 November 2026. Protect AI's "automatic threat blocking" is for Guardian customers, not for the Hub [10]. | One verdict with an exit code: `PASS`/`WARN` 0, `FAIL` 1, `BLOCKED` 2. A CI job, the GitHub Action, or the Kubernetes admission webhook stops on it. An upstream `unsafe` becomes a `HF_UPSTREAM_UNSAFE` finding that fails the scan. |
| 2 | **Only what is on the Hub** | All scanning is described for files pushed to Hub repositories. The third-party scanners are documented for *public* repositories [4][5][6]. | Scans any file or directory: a fine-tune you trained, a checkpoint in object storage, a model from a vendor, an MLflow directory. Local scans make no network calls, so they work air-gapped. |
| 3 | **The policy is yours to write** | Hugging Face's compliance guide says model risk policy and approved sources or licences are "left to you regardless of tier" [11]. Its access policy is keyed to repository and organisation, not to scan results [8]. | A YAML policy: allowed formats, publishers, model names, country of origin, required signer, severity threshold, and a known-bad denylist of hashes and publishers. See [Configuring a policy](configuring-policy.md). |
| 4 | **The pickle scanner has been bypassed repeatedly** | Hugging Face: "this is not 100% foolproof ... the safe/unsafe imports lists we have are maintained in a best-effort manner" [2]. Published bypasses of picklescan include four CVEs in March 2025 [12] and three more in December 2025 [13]. In the "nullifAI" case two malicious models went unflagged because the pickle stream was deliberately broken *after* the payload [14]. | Format is detected from content, not the file extension. Imports are classified into dangerous, known-safe and unknown, so an import missing from a denylist still surfaces. A broken stream is reported as evasion **and** whatever was parsed before the break is still classified. |
| 5 | **Code that is not a pickle** | Hugging Face treats `trust_remote_code` as out of scope: "running the repository's code is what that flag does" [15]. ClamAV "doesn't cover pickle exploits" [2], and Keras `safe_mode` has itself needed a bypass fix [16]. | Static analysis of bundled Python (`modeling_*.py`) and of the `auto_map` config that arms it; Keras Lambda and custom layers; GGUF chat templates; ONNX external-data paths; TensorFlow file and code ops; about 35 formats in total. See [What it detects](../README.md#what-it-detects). |
| 6 | **Embedded endpoints and secrets** | TruffleHog emails the pusher, and only for *verified* secrets; unverified ones "are not necessarily harmless" [3]. Nothing tells the person downloading. | The exfiltration engine reports webhooks, hard-coded addresses, credentials and encoded payloads in every file, to the person about to use the model. |
| 7 | **No verifiable provenance for the artifact** | The Hub offers GPG-signed commits, which "does **not** guarantee that your file is safe" [2]. We found no Hugging Face documentation of Sigstore or model-signing verification. | Ed25519 signatures checked against your trust store, offline Sigstore verification, and a `require_signed` policy. The same scan emits a CycloneDX ML-BOM. |
| 8 | **What you scanned may not be what you deploy** | `main` is a moving reference; Hugging Face itself recommends pinning a `revision` [15]. Unit 42 showed that a deleted or transferred author name can be re-registered and serve a different model under the same path [17]. | Approval is bound to the file's SHA-256. The admission webhook admits only workloads whose declared model digests are on the approved list, so a swapped artifact is rejected even if its name is unchanged. |

## See it in two minutes

Hugging Face publishes a demo repository of files its scanners flag. The Hub
still serves them:

```bash
curl -sIL https://huggingface.co/mcpotato/42-eicar-street/resolve/main/danger.dat | grep -i '^HTTP'
# HTTP/2 307   (redirect to storage)
# HTTP/2 200   (the flagged file is served)
```

Purser turns the same information into a decision a pipeline can act on:

```bash
pip install "purser[hf]"
purser scan hf://mcpotato/42-eicar-street ; echo "exit=$?"
# ... HF_UPSTREAM_UNSAFE (HIGH) for each flagged file, plus Purser's own findings
# Verdict: FAIL
# exit=1
```

And the same check on something the Hub has never seen:

```bash
purser scan ./my-finetune --policy policies/strict.yaml
purser scan ./my-finetune --format cyclonedx -o mlbom.json
```

## What Purser does not do

- **It is not a replacement for the Hub's scanners.** Purser has no antivirus
  engine and no VirusTotal lookup. It ingests those verdicts on `hf://` scans.
  An upstream "safe" never lowers Purser's own verdict.
- **It can be evaded too.** Every static scanner can be beaten by a novel
  technique. A clean scan is necessary, not sufficient.
- **It does not unpack 7z archives.** The "nullifAI" models were 7z-compressed
  [14]. Purser recurses into zip, tar and gzip only; a 7z file is checked as
  opaque bytes.
- **It does not yet flag an unpinned revision or a re-registered namespace.**
  Digest-bound approval limits the damage (row 8), but Purser does not warn
  that `hf://org/model` was scanned at a moving `main`. Both are on the
  [roadmap](../ROADMAP.md).
- **No live threat feed, behavioural backdoor detection or dashboard.** Those
  are commercial-platform territory; see
  [How Purser compares](../README.md#how-purser-compares).

## Sources

All read on 26 November 2026.

1. Hugging Face, Malware Scanning — <https://huggingface.co/docs/hub/security-malware>
2. Hugging Face, Pickle Scanning — <https://huggingface.co/docs/hub/security-pickle>
3. Hugging Face, Secrets Scanning — <https://huggingface.co/docs/hub/security-secrets>
4. Hugging Face, Third-party scanner: Protect AI — <https://huggingface.co/docs/hub/security-protectai>
5. Hugging Face, Third-party scanner: JFrog — <https://huggingface.co/docs/hub/security-jfrog>
6. Hugging Face blog, VirusTotal integration (22 October 2025) — <https://huggingface.co/blog/virustotal>
7. `huggingface_hub` API reference (`securityStatus`, `securityFileStatus`) — <https://huggingface.co/docs/huggingface_hub/package_reference/hf_api>
8. Hugging Face, Network Security (content access policy) — <https://huggingface.co/docs/hub/enterprise-network-security>
9. Hugging Face, Team & Enterprise plans — <https://huggingface.co/docs/hub/enterprise>
10. Hugging Face blog, Protect AI six-month report (14 April 2025) — <https://huggingface.co/blog/pai-6-month>
11. Hugging Face blog, SOC 2 / ISO 27001 AI compliance guide — <https://huggingface.co/blog/jeffboudier/soc2-iso27001-ai-compliance-guide>
12. Sonatype, four picklescan vulnerabilities, CVE-2025-1716/-1889/-1944/-1945 (11 March 2025) — <https://www.sonatype.com/blog/bypassing-picklescan-sonatype-discovers-four-vulnerabilities>
13. JFrog, three picklescan zero-days, CVE-2025-10155/-10156/-10157 (2 December 2025) — <https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/>
14. ReversingLabs, "nullifAI" (6 February 2025) — <https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face>
15. `transformers` SECURITY.md — <https://github.com/huggingface/transformers/blob/main/SECURITY.md>
16. Keras advisory GHSA-c9rc-mg46-23w3 (CVE-2025-8747) — <https://github.com/advisories/GHSA-c9rc-mg46-23w3>
17. Palo Alto Networks Unit 42, Model Namespace Reuse (3 September 2025) — <https://unit42.paloaltonetworks.com/model-namespace-reuse/>

The picklescan issues in [12] and [13] were fixed in picklescan 0.0.23 and
0.0.31, and Hugging Face removed the "nullifAI" models within a day [14]. They
are cited to show the pattern, not as open holes.
