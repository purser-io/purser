# Contributing to Purser

Thanks for helping make ML model distribution safer. Purser is an Apache-2.0
open-source project and we welcome issues and pull requests. By participating you
agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting security issues

**Do not open a public issue for vulnerabilities.** Use the private process in
[`SECURITY.md`](SECURITY.md) (GitHub → **Security → Report a vulnerability**).
Scanner-evasion reports are in scope — include an **inert** reproducer
(e.g. `os.system("true")`), never live malware.

## Development setup

Purser targets Python 3.11–3.14 and uses [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/purser-io/purser && cd purser
uv venv && uv pip install -e ".[dev,sign,hf,deep]"
uv run ruff check src tests      # lint
uv run pytest -q                 # tests — keep them green
```

If you change dependencies, regenerate the hash-pinned lockfiles and the license
inventory (CI fails if they drift):

```bash
make lock        # requirements*.lock (pinned to uv 0.11.7 — see the Makefile)
make licenses    # THIRD_PARTY_LICENSES.md
```

## Making a change

1. Branch from `main` (direct pushes to `main` are blocked by branch protection).
2. Keep changes covered by tests in `tests/`. New detection logic needs both a
   **positive** case and an **adversarial/benign** case; adversarial fixtures must
   use **inert** payloads — Purser never executes a model, and neither does its
   test suite.
3. Run `ruff check` and `pytest` locally. CI enforces both across Python
   3.11–3.14, plus Helm lint, an image build + Trivy scan, and the DCO check.
4. Add a note under [`CHANGELOG.md`](CHANGELOG.md) for any user-facing change.
5. Open a pull request and fill in the template.

## Sign your commits (DCO)

Contributions are accepted under the **Developer Certificate of Origin**
([DCO](https://developercertificate.org/)) — a per-commit statement that you have
the right to submit the change. There is **no CLA**.

Add a `Signed-off-by` line to every commit (it must match your author identity):

```bash
git commit -s -m "your message"     # signs off this commit
git rebase --signoff main           # sign off an existing branch
```

A CI check enforces this on every pull request. Example line:
`Signed-off-by: Jane Doe <jane@example.com>`.

## License

Purser is licensed under [Apache-2.0](LICENSE). Unless you state otherwise, your
contributions are submitted under the same license (inbound = outbound).
