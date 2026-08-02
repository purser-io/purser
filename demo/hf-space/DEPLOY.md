# Deploying the Purser Space

The Space is push-ready: a Gradio app whose `README.md` frontmatter is the
Space config. One-time setup (needs a HuggingFace account + a write token):

```bash
pip install huggingface_hub
hf auth login                          # or set HF_TOKEN

# create the Space (once) — pick the org/name you want public
hf repo create purser-io/purser --repo-type space --space_sdk gradio

# push the app files to it (exclude local build junk)
cd demo/hf-space
hf upload purser-io/purser . . --repo-type space --exclude "__pycache__/*" --exclude "DEPLOY.md"
```

The Space builds from `requirements.txt` (Purser comes from PyPI — no source
copy to keep in sync) and serves `app.py`. Free CPU hardware is enough.

Maintenance notes:

- **Version bumps:** `requirements.txt` floats on `purser>=0.2.1`, so a
  factory reboot of the Space picks up new releases; pin exactly if demo
  stability matters more than freshness.
- **Limits:** uploads capped at 200 MB and repos at 500 MB in `app.py` —
  Spaces run on small shared CPUs; the caps keep scans interactive.
- **No secrets needed.** Public repos only; private-repo scanning would need
  an `HF_TOKEN` Space secret and is deliberately not part of the public demo.
