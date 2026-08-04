"""
Fetch GitHub security alerts for all of your public repositories and write
a self-contained HTML report (report.html) with links to github.com.

Collects Dependabot, code scanning, and secret scanning alerts.

Usage:
  Put GITHUB_TOKEN=ghp_... in a .env file (or set the env var)
  python main.py
  python main.py --no-open
  python main.py --json report.json
  python main.py --user someuser
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import webbrowser
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

API = "https://api.github.com"
API_VERSION = "2022-11-28"
PER_PAGE = 100
DEFAULT_HTML = "report.html"

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "moderate": 2,
    "low": 3,
    "warning": 3,
    "note": 4,
    "error": 1,
}


class GitHubClient:
    def __init__(self, token: str) -> None:
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "repo-security-report",
            }
        )

    def get(
        self, path: str, params: dict[str, Any] | None = None
    ) -> tuple[Any, requests.Response]:
        url = path if path.startswith("http") else f"{API}{path}"
        # When following Link headers, pass a full URL and do not re-apply params.
        request_params = None if path.startswith("http") else params
        response = self.session.get(url, params=request_params, timeout=60)
        if response.status_code >= 400:
            detail = ""
            try:
                detail = response.json().get("message", response.text[:200])
            except Exception:
                detail = response.text[:200]
            raise requests.HTTPError(
                f"{response.status_code} for {path}: {detail}",
                response=response,
            )
        return response.json(), response

    def paginate(self, path: str, params: dict[str, Any] | None = None) -> list[Any]:
        """Paginate using Link headers (works for page- and cursor-based APIs)."""
        params = dict(params or {})
        params.setdefault("per_page", PER_PAGE)
        items: list[Any] = []
        next_url: str | None = path

        while next_url:
            batch, response = self.get(next_url, params if next_url == path else None)
            if not isinstance(batch, list):
                raise RuntimeError(f"Expected a list from {path}, got {type(batch)}")
            items.extend(batch)
            next_url = _link_next(response.headers.get("Link"))

        return items


def _link_next(link_header: str | None) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        section = part.strip()
        if 'rel="next"' not in section:
            continue
        match = re.match(r'<([^>]+)>', section)
        if match:
            return match.group(1)
    return None


def list_public_repos(client: GitHubClient, username: str | None) -> list[dict[str, Any]]:
    if username:
        repos = client.paginate(
            f"/users/{username}/repos",
            {"type": "owner", "sort": "full_name"},
        )
        return [r for r in repos if not r.get("private") and not r.get("fork")]

    repos = client.paginate("/user/repos", {"affiliation": "owner", "sort": "full_name"})
    return [r for r in repos if not r.get("private") and not r.get("fork")]


def _alert_access_note(status: int, message: str = "") -> str | None:
    """Return a user-facing note, or None when the failure just means 'no alerts'."""
    lowered = message.lower()
    # Feature disabled / not set up is not a permission problem and not an alert.
    if status in {404, 410} and (
        "disabled" in lowered
        or "not enabled" in lowered
        or "no analysis" in lowered
        or "advanced security" in lowered
    ):
        return None
    if status in {404, 410}:
        return None
    if status == 403:
        return "no access (token missing permission)"
    if status == 422:
        return "unavailable for this repository"
    if status == 400 and "page" in lowered:
        return "pagination error talking to GitHub API"
    return f"unavailable ({status})"


def fetch_alerts(
    client: GitHubClient, owner: str, repo: str
) -> tuple[dict[str, list[Any]], dict[str, str]]:
    """Return open alerts plus per-source access notes when fetch fails."""
    base = f"/repos/{owner}/{repo}"
    results: dict[str, list[Any]] = {}
    notes: dict[str, str] = {}
    endpoints = {
        "dependabot": f"{base}/dependabot/alerts",
        "code_scanning": f"{base}/code-scanning/alerts",
        "secret_scanning": f"{base}/secret-scanning/alerts",
    }
    for key, path in endpoints.items():
        try:
            results[key] = client.paginate(path, {"state": "open"})
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            message = ""
            if exc.response is not None:
                try:
                    message = exc.response.json().get("message", "")
                except Exception:
                    message = exc.response.text[:200]
            if status and status < 500:
                results[key] = []
                note = _alert_access_note(status, message)
                if note:
                    notes[key] = note
            else:
                raise
    return results, notes


def summarize_dependabot(alert: dict[str, Any]) -> dict[str, Any]:
    vuln = alert.get("security_vulnerability") or {}
    advisory = alert.get("security_advisory") or {}
    pkg = vuln.get("package") or {}
    return {
        "number": alert.get("number"),
        "state": alert.get("state"),
        "severity": advisory.get("severity") or vuln.get("severity"),
        "package": pkg.get("name"),
        "ecosystem": pkg.get("ecosystem"),
        "vulnerable_range": vuln.get("vulnerable_version_range"),
        "ghsa_id": advisory.get("ghsa_id"),
        "summary": advisory.get("summary"),
        "html_url": alert.get("html_url"),
        "created_at": alert.get("created_at"),
    }


def summarize_code_scanning(alert: dict[str, Any]) -> dict[str, Any]:
    rule = alert.get("rule") or {}
    tool = alert.get("tool") or {}
    most_recent = alert.get("most_recent_instance") or {}
    location = most_recent.get("location") or {}
    return {
        "number": alert.get("number"),
        "state": alert.get("state"),
        "severity": rule.get("security_severity") or rule.get("severity"),
        "rule_id": rule.get("id"),
        "rule_description": rule.get("description") or rule.get("name"),
        "tool": tool.get("name"),
        "path": location.get("path"),
        "html_url": alert.get("html_url"),
        "created_at": alert.get("created_at"),
    }


def summarize_secret_scanning(alert: dict[str, Any]) -> dict[str, Any]:
    return {
        "number": alert.get("number"),
        "state": alert.get("state"),
        "secret_type": alert.get("secret_type"),
        "secret_type_display_name": alert.get("secret_type_display_name"),
        "validity": alert.get("validity"),
        "html_url": alert.get("html_url"),
        "created_at": alert.get("created_at"),
    }


def build_report(client: GitHubClient, username: str | None) -> dict[str, Any]:
    me, _ = client.get("/user")
    if not isinstance(me, dict) or not me.get("login"):
        raise SystemExit("Failed to resolve authenticated user. Check GITHUB_TOKEN.")

    owner_label = username or me["login"]
    print(f"Authenticated as {me['login']}")
    print(f"Fetching public repos for {owner_label}...")

    repos = list_public_repos(client, username)
    print(f"Found {len(repos)} public repo(s)\n")

    repo_reports: list[dict[str, Any]] = []
    totals = defaultdict(int)

    for i, repo in enumerate(repos, start=1):
        full_name = repo["full_name"]
        owner, name = full_name.split("/", 1)
        print(f"[{i}/{len(repos)}] {full_name}...", end=" ", flush=True)

        try:
            raw, access_notes = fetch_alerts(client, owner, name)
        except requests.HTTPError as exc:
            print(f"skipped ({exc})")
            continue

        dependabot = [summarize_dependabot(a) for a in raw["dependabot"]]
        code_scanning = [summarize_code_scanning(a) for a in raw["code_scanning"]]
        secret_scanning = [summarize_secret_scanning(a) for a in raw["secret_scanning"]]

        counts = {
            "dependabot": len(dependabot),
            "code_scanning": len(code_scanning),
            "secret_scanning": len(secret_scanning),
        }
        for key, value in counts.items():
            totals[key] += value
        totals["repos_scanned"] += 1

        open_total = sum(counts.values())

        def _count_label(key: str, label: str) -> str:
            if key in access_notes:
                return f"{label} ({access_notes[key]})"
            return f"{counts[key]} {label}"

        suffix = ""
        if access_notes:
            suffix = " (incomplete)"
        elif open_total == 0:
            suffix = " (clean)"

        print(
            f"{_count_label('dependabot', 'dependabot')}, "
            f"{_count_label('code_scanning', 'code-scanning')}, "
            f"{_count_label('secret_scanning', 'secret-scanning')}"
            + suffix
        )

        repo_reports.append(
            {
                "repo": full_name,
                "html_url": repo.get("html_url"),
                "security_url": f"{repo.get('html_url')}/security",
                "counts": counts,
                "access_notes": access_notes,
                "alerts": {
                    "dependabot": dependabot,
                    "code_scanning": code_scanning,
                    "secret_scanning": secret_scanning,
                },
            }
        )

    repos_with_alerts = sum(1 for r in repo_reports if sum(r["counts"].values()) > 0)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "authenticated_user": me["login"],
        "owner": owner_label,
        "totals": {
            "repos_scanned": totals["repos_scanned"],
            "repos_with_alerts": repos_with_alerts,
            "dependabot": totals["dependabot"],
            "code_scanning": totals["code_scanning"],
            "secret_scanning": totals["secret_scanning"],
            "open_alerts": totals["dependabot"]
            + totals["code_scanning"]
            + totals["secret_scanning"],
        },
        "repositories": repo_reports,
    }


def esc(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def severity_class(severity: Any) -> str:
    key = (severity or "unknown").lower()
    if key == "moderate":
        key = "medium"
    if key in {"critical", "high", "medium", "low", "warning", "note", "error"}:
        return key
    return "unknown"


def sort_by_severity(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        alerts,
        key=lambda a: SEVERITY_ORDER.get((a.get("severity") or "").lower(), 99),
    )


def link(url: Any, text: Any, css: str = "") -> str:
    if not url:
        return esc(text)
    cls = f' class="{css}"' if css else ""
    return f'<a href="{esc(url)}" target="_blank" rel="noopener"{cls}>{esc(text)}</a>'


def render_dependabot_rows(alerts: list[dict[str, Any]]) -> str:
    rows = []
    for alert in sort_by_severity(alerts):
        sev = alert.get("severity") or "unknown"
        title = alert.get("summary") or alert.get("package") or f"#{alert.get('number')}"
        pkg = alert.get("package") or "—"
        eco = alert.get("ecosystem") or ""
        pkg_label = f"{pkg} ({eco})" if eco else pkg
        rows.append(
            "<tr>"
            f'<td><span class="sev {severity_class(sev)}">{esc(sev)}</span></td>'
            f"<td>{link(alert.get('html_url'), title)}</td>"
            f"<td>{esc(pkg_label)}</td>"
            f"<td>{esc(alert.get('vulnerable_range') or '—')}</td>"
            f"<td>{esc(alert.get('ghsa_id') or '—')}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def render_code_scanning_rows(alerts: list[dict[str, Any]]) -> str:
    rows = []
    for alert in sort_by_severity(alerts):
        sev = alert.get("severity") or "unknown"
        title = alert.get("rule_description") or alert.get("rule_id") or f"#{alert.get('number')}"
        rows.append(
            "<tr>"
            f'<td><span class="sev {severity_class(sev)}">{esc(sev)}</span></td>'
            f"<td>{link(alert.get('html_url'), title)}</td>"
            f"<td>{esc(alert.get('rule_id') or '—')}</td>"
            f"<td>{esc(alert.get('tool') or '—')}</td>"
            f"<td>{esc(alert.get('path') or '—')}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def render_secret_rows(alerts: list[dict[str, Any]]) -> str:
    rows = []
    for alert in alerts:
        title = (
            alert.get("secret_type_display_name")
            or alert.get("secret_type")
            or f"#{alert.get('number')}"
        )
        rows.append(
            "<tr>"
            f"<td>{link(alert.get('html_url'), title)}</td>"
            f"<td>{esc(alert.get('secret_type') or '—')}</td>"
            f"<td>{esc(alert.get('validity') or '—')}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def render_alert_section(title: str, count: int, table_html: str) -> str:
    if count == 0:
        return ""
    return f"""
      <section class="alert-group">
        <h3>{esc(title)} <span class="count">{count}</span></h3>
        {table_html}
      </section>
    """


def render_repo_section(repo: dict[str, Any]) -> str:
    counts = repo["counts"]
    total = sum(counts.values())
    access_notes = repo.get("access_notes") or {}
    status = "has-alerts" if total else ("incomplete" if access_notes else "clean")
    if total:
        status_label = f"{total} open"
    elif access_notes:
        status_label = "incomplete"
    else:
        status_label = "clean"

    dependabot = repo["alerts"]["dependabot"]
    code_scanning = repo["alerts"]["code_scanning"]
    secret_scanning = repo["alerts"]["secret_scanning"]

    body = ""
    if access_notes:
        note_items = "".join(
            f"<li><strong>{esc(key.replace('_', ' '))}</strong>: {esc(note)}</li>"
            for key, note in access_notes.items()
        )
        body += f"""
        <div class="access-notes">
          <p>Could not check some alert sources (this is not a vulnerability list):</p>
          <ul>{note_items}</ul>
        </div>
        """
    if total == 0 and not access_notes:
        body += '<p class="clean-msg">No open security alerts.</p>'
    elif total == 0 and access_notes:
        body += '<p class="clean-msg">No readable open alerts (see access notes above).</p>'
    else:
        if dependabot:
            body += render_alert_section(
                "Dependabot",
                len(dependabot),
                f"""
                <table>
                  <thead><tr><th>Severity</th><th>Advisory</th><th>Package</th><th>Range</th><th>GHSA</th></tr></thead>
                  <tbody>{render_dependabot_rows(dependabot)}</tbody>
                </table>
                """,
            )
        if code_scanning:
            body += render_alert_section(
                "Code scanning / CodeQL",
                len(code_scanning),
                f"""
                <table>
                  <thead><tr><th>Severity</th><th>Finding</th><th>Rule</th><th>Tool</th><th>Path</th></tr></thead>
                  <tbody>{render_code_scanning_rows(code_scanning)}</tbody>
                </table>
                """,
            )
        if secret_scanning:
            body += render_alert_section(
                "Secret scanning",
                len(secret_scanning),
                f"""
                <table>
                  <thead><tr><th>Secret</th><th>Type</th><th>Validity</th></tr></thead>
                  <tbody>{render_secret_rows(secret_scanning)}</tbody>
                </table>
                """,
            )

    return f"""
    <article class="repo {status}" id="{esc(repo['repo'])}">
      <header class="repo-header">
        <div>
          <h2>{link(repo.get('html_url'), repo['repo'], 'repo-link')}</h2>
          <p class="meta">
            {link(repo.get('security_url'), 'Security tab on GitHub')}
            | Dependabot {counts['dependabot']}
            | Code scanning {counts['code_scanning']}
            | Secrets {counts['secret_scanning']}
          </p>
        </div>
        <span class="status {status}">{esc(status_label)}</span>
      </header>
      {body}
    </article>
    """


def render_html(report: dict[str, Any]) -> str:
    totals = report["totals"]
    repos = report["repositories"]
    # Show repos with alerts first, then clean ones alphabetically within groups.
    ordered = sorted(
        repos,
        key=lambda r: (0 if sum(r["counts"].values()) else 1, r["repo"].lower()),
    )
    repo_html = "\n".join(render_repo_section(r) for r in ordered)
    generated = report["generated_at"]
    try:
        generated_display = (
            datetime.fromisoformat(generated).astimezone().strftime("%Y-%m-%d %H:%M %Z")
        )
    except ValueError:
        generated_display = generated

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Security report — {esc(report['owner'])}</title>
  <style>
    :root {{
      --bg: #f4f6f8;
      --surface: #ffffff;
      --ink: #1b2330;
      --muted: #5b6775;
      --line: #d8dee6;
      --accent: #0b6e4f;
      --critical: #9f1239;
      --high: #c2410c;
      --medium: #a16207;
      --low: #1d4ed8;
      --clean: #15803d;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", system-ui, sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, #e7f2ec 0%, transparent 40%),
        linear-gradient(180deg, #eef2f6 0%, var(--bg) 100%);
      line-height: 1.5;
    }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .wrap {{ max-width: 980px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }}
    header.page {{
      margin-bottom: 1.75rem;
      padding-bottom: 1.25rem;
      border-bottom: 1px solid var(--line);
    }}
    header.page h1 {{
      margin: 0 0 0.35rem;
      font-size: 1.85rem;
      letter-spacing: -0.02em;
    }}
    header.page p {{ margin: 0.2rem 0; color: var(--muted); }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 0.75rem;
      margin: 1.25rem 0 0;
    }}
    .stat {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 0.85rem 1rem;
    }}
    .stat .label {{ display: block; color: var(--muted); font-size: 0.8rem; }}
    .stat .value {{ font-size: 1.45rem; font-weight: 700; }}
    .repo {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 1.1rem 1.2rem 1.2rem;
      margin: 1rem 0;
    }}
    .repo.has-alerts {{ border-color: #f0c7b0; }}
    .repo-header {{
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      align-items: flex-start;
    }}
    .repo-header h2 {{ margin: 0; font-size: 1.15rem; }}
    .repo-link {{ color: var(--ink); }}
    .meta {{ margin: 0.35rem 0 0; color: var(--muted); font-size: 0.9rem; }}
    .status {{
      flex-shrink: 0;
      border-radius: 999px;
      padding: 0.25rem 0.7rem;
      font-size: 0.8rem;
      font-weight: 600;
      text-transform: lowercase;
    }}
    .status.clean {{ background: #dcfce7; color: var(--clean); }}
    .status.has-alerts {{ background: #ffedd5; color: var(--high); }}
    .status.incomplete {{ background: #eef2f6; color: var(--muted); }}
    .clean-msg {{ margin: 0.9rem 0 0; color: var(--clean); }}
    .access-notes {{
      margin: 0.9rem 0 0;
      padding: 0.75rem 0.9rem;
      background: #f8fafc;
      border: 1px solid var(--line);
      border-radius: 8px;
      color: var(--muted);
      font-size: 0.9rem;
    }}
    .access-notes ul {{ margin: 0.35rem 0 0; padding-left: 1.1rem; }}
    .alert-group {{ margin-top: 1rem; }}
    .alert-group h3 {{
      margin: 0 0 0.55rem;
      font-size: 0.95rem;
      display: flex;
      align-items: center;
      gap: 0.45rem;
    }}
    .count {{
      background: #eef2f6;
      border-radius: 999px;
      padding: 0.05rem 0.5rem;
      font-size: 0.78rem;
      color: var(--muted);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.92rem;
    }}
    th, td {{
      text-align: left;
      padding: 0.55rem 0.45rem;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }}
    th {{ color: var(--muted); font-weight: 600; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; }}
    .sev {{
      display: inline-block;
      min-width: 4.5rem;
      text-align: center;
      border-radius: 6px;
      padding: 0.15rem 0.4rem;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .sev.critical {{ background: #ffe4e6; color: var(--critical); }}
    .sev.high, .sev.error {{ background: #ffedd5; color: var(--high); }}
    .sev.medium {{ background: #fef3c7; color: var(--medium); }}
    .sev.low, .sev.warning {{ background: #dbeafe; color: var(--low); }}
    .sev.note, .sev.unknown {{ background: #eef2f6; color: var(--muted); }}
    footer {{
      margin-top: 2rem;
      color: var(--muted);
      font-size: 0.85rem;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <header class="page">
      <h1>GitHub security report</h1>
      <p>Public repositories for <strong>{esc(report['owner'])}</strong></p>
      <p>Generated {esc(generated_display)} | authenticated as {esc(report['authenticated_user'])}</p>
      <div class="stats">
        <div class="stat"><span class="label">Repos scanned</span><span class="value">{totals['repos_scanned']}</span></div>
        <div class="stat"><span class="label">With alerts</span><span class="value">{totals['repos_with_alerts']}</span></div>
        <div class="stat"><span class="label">Dependabot</span><span class="value">{totals['dependabot']}</span></div>
        <div class="stat"><span class="label">Code scanning</span><span class="value">{totals['code_scanning']}</span></div>
        <div class="stat"><span class="label">Secret scanning</span><span class="value">{totals['secret_scanning']}</span></div>
        <div class="stat"><span class="label">Open alerts</span><span class="value">{totals['open_alerts']}</span></div>
      </div>
    </header>

    {repo_html if repo_html.strip() else "<p>No public repositories found.</p>"}

    <footer>
      Open any alert or repo name to view it on GitHub. Re-run <code>python main.py</code> to refresh.
    </footer>
  </div>
</body>
</html>
"""


def print_summary(report: dict[str, Any]) -> None:
    totals = report["totals"]
    print("\n" + "=" * 60)
    print("SECURITY REPORT SUMMARY")
    print("=" * 60)
    print(f"Owner:              {report['owner']}")
    print(f"Repos scanned:       {totals['repos_scanned']}")
    print(f"Repos with alerts:  {totals['repos_with_alerts']}")
    print(f"Dependabot:         {totals['dependabot']}")
    print(f"Code scanning:      {totals['code_scanning']}")
    print(f"Secret scanning:    {totals['secret_scanning']}")
    print(f"Total open alerts:  {totals['open_alerts']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch GitHub security alerts and write a self-contained HTML report."
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),
        help="GitHub PAT (default: GITHUB_TOKEN or GH_TOKEN env var)",
    )
    parser.add_argument(
        "--user",
        help="GitHub username whose public repos to scan (default: authenticated user)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=DEFAULT_HTML,
        help=f"HTML report path (default: {DEFAULT_HTML})",
    )
    parser.add_argument(
        "--json",
        help="Also write a JSON report to this path",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open the HTML report in a browser",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.token:
        print(
            "Error: set GITHUB_TOKEN (or GH_TOKEN) to a personal access token "
            "with the `security_events` or `public_repo` scope.\n"
            "Tip: $env:GITHUB_TOKEN = (gh auth token)",
            file=sys.stderr,
        )
        return 1

    client = GitHubClient(args.token)
    report = build_report(client, args.user)
    print_summary(report)

    html_path = Path(args.output)
    if html_path.suffix.lower() != ".html":
        corrected = html_path.with_suffix(".html")
        print(
            f"Note: HTML reports must use a .html extension; "
            f"writing {corrected} instead of {html_path}",
            file=sys.stderr,
        )
        html_path = corrected

    html_path.write_text(render_html(report), encoding="utf-8")
    print(f"\nWrote HTML report to {html_path.resolve()}")

    if args.json:
        json_path = Path(args.json)
        if json_path.suffix.lower() != ".json":
            json_path = json_path.with_suffix(".json")
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Wrote JSON report to {json_path.resolve()}")

    if not args.no_open:
        webbrowser.open(html_path.resolve().as_uri())
        print("Opened report in your browser.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
