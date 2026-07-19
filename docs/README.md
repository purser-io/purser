# Purser — User Guides

Purser checks machine-learning model files for **hidden malicious code and
leaked secrets** *before* anyone loads them, and lets your team set rules about
which models are allowed.

Pick the guide that matches you:

| You are… | Start here |
|---|---|
| Setting Purser up in **GitLab** so model files get scanned automatically | [**DevSecOps + GitLab guide**](devsecops-gitlab.md) |
| A **data scientist / ML engineer** who downloads or uses models and wants to check they're safe | [**Data scientist guide**](data-scientists.md) |
| Writing the **rules** for which models are allowed | [**Configuring a policy**](configuring-policy.md) |

New to the project? The top-level [README](../README.md) has the full feature
list; [SECURITY.md](../SECURITY.md) explains what Purser does and does not
protect against.

## The 30-second version

- A model file can secretly contain code that runs the moment you load it. That
  code can steal data, open a backdoor, or "phone home."
- Purser reads the file **without running it** and reports anything
  dangerous, giving a simple verdict: **PASS**, **WARN**, **FAIL**, or
  **BLOCKED**.
- You can add a **policy** — your team's rules — such as "only allow safe file
  types" or "block models from certain sources."
- It runs as a command-line tool, a small web service, or a container, so it
  fits both a laptop and a build pipeline.
