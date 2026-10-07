# Main branch protection configuration

Status: **NOT APPLIED**. Checking this JSON into Git does not protect a branch.
The current connector cannot administer branch protection; its protection read returned
`403 Resource not accessible by integration`. The branch listing reported `main` unprotected.

`main.json` is an importable repository ruleset following the
[GitHub repository ruleset API](https://docs.github.com/en/rest/repos/rules#create-a-repository-ruleset).
It targets only `refs/heads/main`, rejects deletion and force pushes, requires a PR
with resolved discussions, and requires six successful checks on an up-to-date candidate:
`native`, `container`, `browser`, `dependency-and-regression`, `secret-scan`, `codeql`.
There are no bypass actors. Its enforcement is active when imported by an administrator.

A repository administrator must import and verify this configuration in repository ruleset
settings or apply it through the authorized API. Confirm the exact reported check contexts
after the first new workflow run, and select GitHub Actions as the expected check source.
Do not merge the foundation branch until protection is actually applied and all required
gates pass. The JSON is reviewable configuration, not evidence that the setting is live.
