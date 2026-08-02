# Purser — User Guides

Purser is the **clearance desk for ML models**: it checks model files for
hidden malicious code and leaked secrets *before* anyone loads them — without
ever running them — combines that with other evidence (signatures, the model
hub's own scan results), and gives one verdict your team's rules can enforce
in CI or Kubernetes.

Pick the guide that matches you:

| You are… | Start here |
|---|---|
| Setting Purser up in **GitLab** so model files get scanned automatically | [**DevSecOps + GitLab guide**](devsecops-gitlab.md) |
| A **data scientist / ML engineer** who downloads or uses models and wants to check they're safe | [**Data scientist guide**](data-scientists.md) |
| Writing the **rules** for which models are allowed | [**Configuring a policy**](configuring-policy.md) |
| A **platform / Kubernetes operator** deploying the service, webhook, or dashboards | [Helm chart](../deploy/helm/purser/README.md) · [README: Kubernetes](../README.md#kubernetes) |

New to the project? The top-level [README](../README.md) has the full feature
list; [SECURITY.md](../SECURITY.md) explains what Purser does and does not
protect against.

## The 30-second version

- A model file can secretly contain code that runs the moment you load it. That
  code can steal data, open a backdoor, or "phone home."
- Purser reads the file **without running it** and reports anything
  dangerous, giving a simple verdict: **PASS**, **WARN**, **FAIL**, or
  **BLOCKED**.
- The verdict can draw on more than Purser's own scan: verified signatures,
  Hugging Face's own scan results, and (opt-in) whether the model documents
  itself with a model card.
- You can add a **policy** — your team's rules — such as "only allow safe file
  types" or "block models from certain sources."
- It runs as a command-line tool, a small web service, or a container — and in
  Kubernetes it can **enforce** the verdict at deploy time, so an uncleared
  model can't reach the cluster even if it skipped the pipeline.
