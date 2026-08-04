# Security Policy

## Supported Versions

Security fixes are applied to the latest commit on the default branch (`main`).

| Version | Supported |
| ------- | --------- |
| `main`  | Yes       |

## Reporting a Vulnerability

If you find a security issue in this project, please report it privately.

1. Prefer [GitHub private vulnerability reporting](https://github.com/glucero0/repo-security-report/security/advisories/new) for this repository.
2. If that is unavailable, open a [GitHub issue](https://github.com/glucero0/repo-security-report/issues) **without** including secrets, tokens, or exploit details, and ask for a private contact channel.

Please include:

- A clear description of the issue
- Steps to reproduce
- Potential impact
- Any suggested fix (optional)

You should receive an initial response within a few days. If the report is accepted, a fix will be prepared and coordinated before any public disclosure.

Do **not** open a public issue that includes proof-of-concept exploits, credentials, or personal access tokens.

## Handling Secrets

This tool expects a GitHub personal access token via `GITHUB_TOKEN` / `GH_TOKEN` or a local `.env` file.

- Never commit `.env` or real tokens
- Prefer a least-privilege token (`public_repo` for public repositories)
- Rotate any token that may have been exposed
