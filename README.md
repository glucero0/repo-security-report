# Repo Security Report

- Simple Python app that provides one command to pull open GitHub security alerts for all of your **public** repositories
- Writes a self-contained HTML report that opens in a browser

It collects:

- Dependabot alerts
- Code scanning / CodeQL alerts
- Secret scanning alerts

Every repo and alert links to the matching page on github.com. No local web server.

## Setup

1. Create a [classic PAT](https://github.com/settings/tokens) with the `public_repo` scope  
   (or a fine-grained token with Dependabot / code scanning / secret scanning alert read access).

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Set your token — either copy `.env.example` to `.env` and fill it in:

```
GITHUB_TOKEN=ghp_...
```

Or set it in the shell:

```powershell
$env:GITHUB_TOKEN = "ghp_..."
# or reuse the GitHub CLI login:
$env:GITHUB_TOKEN = (gh auth token)
```

## Usage

```powershell
python main.py
```

That writes **`report.html`** and opens it in your browser.

Useful options:

```powershell
python main.py --no-open          # write HTML without opening browser
python main.py -o my-report.html  # custom HTML path
python main.py --json report.json # also write JSON (optional)
python main.py --user octocat     # scan another user's public repos
```

## Output

- Console: progress per repo + summary counts
- `report.html`: browsable report with severity badges and GitHub links

## Tests

```powershell
python -m unittest test_report.py
```

These also run automatically on pushes to `main` and on pull requests via GitHub Actions.
