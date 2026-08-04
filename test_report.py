"""Tests for severity sorting and HTML rendering accuracy."""

from __future__ import annotations

import re
import unittest
from html.parser import HTMLParser

import main


class AnchorCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text)))
            self._href = None


def link_map(html: str) -> dict[str, str]:
    parser = AnchorCollector()
    parser.feed(html)
    return {text: href for href, text in parser.links}


def tbody_severities(html: str) -> list[str]:
    match = re.search(r"<tbody>(.*?)</tbody>", html, flags=re.S)
    assert match, "expected a table body"
    return re.findall(r'class="sev [^"]+">([^<]+)</span>', match.group(1))


class SeveritySortingTests(unittest.TestCase):
    def test_sort_by_severity_orders_known_levels(self) -> None:
        alerts = [
            {"severity": "low", "number": 1},
            {"severity": "critical", "number": 2},
            {"severity": "moderate", "number": 3},
            {"severity": "high", "number": 4},
            {"severity": None, "number": 5},
            {"severity": "unknown-thing", "number": 6},
        ]

        ordered = main.sort_by_severity(alerts)

        self.assertEqual(
            [a["number"] for a in ordered],
            [2, 4, 3, 1, 5, 6],
        )

    def test_severity_class_maps_moderate_to_medium(self) -> None:
        self.assertEqual(main.severity_class("moderate"), "medium")
        self.assertEqual(main.severity_class("CRITICAL"), "critical")
        self.assertEqual(main.severity_class(None), "unknown")
        self.assertEqual(main.severity_class("weird"), "unknown")


class SummarizeAndRenderTests(unittest.TestCase):
    def test_dependabot_summary_fields_appear_in_html(self) -> None:
        raw = {
            "number": 12,
            "state": "open",
            "html_url": "https://github.com/acme/demo/security/dependabot/12",
            "created_at": "2026-01-01T00:00:00Z",
            "security_vulnerability": {
                "severity": "high",
                "vulnerable_version_range": "< 1.2.3",
                "package": {"name": "lodash", "ecosystem": "npm"},
            },
            "security_advisory": {
                "severity": "high",
                "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
                "summary": "Prototype pollution in lodash",
            },
        }
        alert = main.summarize_dependabot(raw)
        rows = main.render_dependabot_rows([alert])

        self.assertIn("Prototype pollution in lodash", rows)
        self.assertIn("lodash (npm)", rows)
        self.assertIn("&lt; 1.2.3", rows)  # escaped range
        self.assertIn("GHSA-xxxx-yyyy-zzzz", rows)
        self.assertIn('class="sev high"', rows)
        self.assertEqual(
            link_map(f"<table>{rows}</table>")["Prototype pollution in lodash"],
            "https://github.com/acme/demo/security/dependabot/12",
        )

    def test_dependabot_rows_sorted_by_severity(self) -> None:
        alerts = [
            main.summarize_dependabot(
                {
                    "number": 1,
                    "html_url": "https://example.com/1",
                    "security_vulnerability": {
                        "severity": "low",
                        "package": {"name": "a", "ecosystem": "npm"},
                    },
                    "security_advisory": {"severity": "low", "summary": "Low issue"},
                }
            ),
            main.summarize_dependabot(
                {
                    "number": 2,
                    "html_url": "https://example.com/2",
                    "security_vulnerability": {
                        "severity": "critical",
                        "package": {"name": "b", "ecosystem": "npm"},
                    },
                    "security_advisory": {
                        "severity": "critical",
                        "summary": "Critical issue",
                    },
                }
            ),
            main.summarize_dependabot(
                {
                    "number": 3,
                    "html_url": "https://example.com/3",
                    "security_vulnerability": {
                        "severity": "moderate",
                        "package": {"name": "c", "ecosystem": "npm"},
                    },
                    "security_advisory": {
                        "severity": "moderate",
                        "summary": "Moderate issue",
                    },
                }
            ),
        ]

        rows = main.render_dependabot_rows(alerts)
        self.assertEqual(tbody_severities(f"<table><tbody>{rows}</tbody></table>"), [
            "critical",
            "moderate",
            "low",
        ])
        # Row order should match severity order in the rendered document.
        self.assertLess(rows.index("Critical issue"), rows.index("Moderate issue"))
        self.assertLess(rows.index("Moderate issue"), rows.index("Low issue"))

    def test_code_scanning_summary_fields_appear_in_html(self) -> None:
        raw = {
            "number": 7,
            "state": "open",
            "html_url": "https://github.com/acme/demo/security/code-scanning/7",
            "created_at": "2026-01-02T00:00:00Z",
            "rule": {
                "id": "js/sql-injection",
                "severity": "error",
                "security_severity": "high",
                "description": "SQL injection",
                "name": "sql-injection",
            },
            "tool": {"name": "CodeQL"},
            "most_recent_instance": {
                "location": {"path": "src/db.js"},
            },
        }
        alert = main.summarize_code_scanning(raw)
        rows = main.render_code_scanning_rows([alert])

        self.assertIn("SQL injection", rows)
        self.assertIn("js/sql-injection", rows)
        self.assertIn("CodeQL", rows)
        self.assertIn("src/db.js", rows)
        self.assertIn('class="sev high"', rows)
        self.assertEqual(
            link_map(f"<table>{rows}</table>")["SQL injection"],
            "https://github.com/acme/demo/security/code-scanning/7",
        )

    def test_secret_scanning_summary_fields_appear_in_html(self) -> None:
        raw = {
            "number": 3,
            "state": "open",
            "html_url": "https://github.com/acme/demo/security/secret-scanning/3",
            "created_at": "2026-01-03T00:00:00Z",
            "secret_type": "github_personal_access_token",
            "secret_type_display_name": "GitHub Personal Access Token",
            "validity": "active",
        }
        alert = main.summarize_secret_scanning(raw)
        rows = main.render_secret_rows([alert])

        self.assertIn("GitHub Personal Access Token", rows)
        self.assertIn("github_personal_access_token", rows)
        self.assertIn("active", rows)
        self.assertEqual(
            link_map(f"<table>{rows}</table>")["GitHub Personal Access Token"],
            "https://github.com/acme/demo/security/secret-scanning/3",
        )

    def test_render_html_portrays_repo_totals_links_and_ordering(self) -> None:
        report = {
            "generated_at": "2026-08-04T15:00:00+00:00",
            "authenticated_user": "glucero0",
            "owner": "glucero0",
            "totals": {
                "repos_scanned": 2,
                "repos_with_alerts": 1,
                "dependabot": 1,
                "code_scanning": 1,
                "secret_scanning": 0,
                "open_alerts": 2,
            },
            "repositories": [
                {
                    "repo": "glucero0/clean-repo",
                    "html_url": "https://github.com/glucero0/clean-repo",
                    "security_url": "https://github.com/glucero0/clean-repo/security",
                    "counts": {
                        "dependabot": 0,
                        "code_scanning": 0,
                        "secret_scanning": 0,
                    },
                    "alerts": {
                        "dependabot": [],
                        "code_scanning": [],
                        "secret_scanning": [],
                    },
                },
                {
                    "repo": "glucero0/vuln-repo",
                    "html_url": "https://github.com/glucero0/vuln-repo",
                    "security_url": "https://github.com/glucero0/vuln-repo/security",
                    "counts": {
                        "dependabot": 1,
                        "code_scanning": 1,
                        "secret_scanning": 0,
                    },
                    "alerts": {
                        "dependabot": [
                            {
                                "number": 1,
                                "severity": "critical",
                                "package": "requests",
                                "ecosystem": "pip",
                                "vulnerable_range": "< 2.32.0",
                                "ghsa_id": "GHSA-demo-0001",
                                "summary": "Critical requests bug",
                                "html_url": (
                                    "https://github.com/glucero0/vuln-repo"
                                    "/security/dependabot/1"
                                ),
                            }
                        ],
                        "code_scanning": [
                            {
                                "number": 9,
                                "severity": "medium",
                                "rule_id": "py/path-injection",
                                "rule_description": "Uncontrolled data used in path",
                                "tool": "CodeQL",
                                "path": "app/files.py",
                                "html_url": (
                                    "https://github.com/glucero0/vuln-repo"
                                    "/security/code-scanning/9"
                                ),
                            }
                        ],
                        "secret_scanning": [],
                    },
                },
            ],
        }

        document = main.render_html(report)
        links = link_map(document)

        # Summary stats from the report payload.
        self.assertIn(">2</span>", document)  # repos scanned / open alerts appear
        self.assertIn(
            '<div class="stat"><span class="label">Open alerts</span>'
            '<span class="value">2</span></div>',
            document,
        )
        self.assertIn(
            '<div class="stat"><span class="label">Dependabot</span>'
            '<span class="value">1</span></div>',
            document,
        )
        self.assertIn(
            '<div class="stat"><span class="label">Code scanning</span>'
            '<span class="value">1</span></div>',
            document,
        )

        # Repos with alerts come before clean repos.
        self.assertLess(
            document.index('id="glucero0/vuln-repo"'),
            document.index('id="glucero0/clean-repo"'),
        )
        self.assertIn("No open security alerts.", document)

        # Alert details and GitHub deep links are preserved.
        self.assertEqual(
            links["Critical requests bug"],
            "https://github.com/glucero0/vuln-repo/security/dependabot/1",
        )
        self.assertEqual(
            links["Uncontrolled data used in path"],
            "https://github.com/glucero0/vuln-repo/security/code-scanning/9",
        )
        self.assertEqual(
            links["glucero0/vuln-repo"],
            "https://github.com/glucero0/vuln-repo",
        )
        self.assertIn("GHSA-demo-0001", document)
        self.assertIn("requests (pip)", document)
        self.assertIn("py/path-injection", document)
        self.assertIn("app/files.py", document)
        self.assertIn("CodeQL", document)

        # User-controlled text is escaped.
        sneaky = {
            **report,
            "repositories": [
                {
                    "repo": "glucero0/<script>alert(1)</script>",
                    "html_url": "https://github.com/glucero0/x",
                    "security_url": "https://github.com/glucero0/x/security",
                    "counts": {
                        "dependabot": 1,
                        "code_scanning": 0,
                        "secret_scanning": 0,
                    },
                    "alerts": {
                        "dependabot": [
                            {
                                "number": 1,
                                "severity": "high",
                                "package": "pkg",
                                "ecosystem": "npm",
                                "vulnerable_range": "<=1",
                                "ghsa_id": "GHSA-1",
                                "summary": "<img src=x onerror=alert(1)>",
                                "html_url": "https://github.com/glucero0/x/security/dependabot/1",
                            }
                        ],
                        "code_scanning": [],
                        "secret_scanning": [],
                    },
                }
            ],
        }
        escaped = main.render_html(sneaky)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", escaped)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", escaped)
        self.assertNotIn("<script>alert(1)</script>", escaped)


if __name__ == "__main__":
    unittest.main()
