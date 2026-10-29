"""Findings as a CSV that Jira or ServiceNow imports: one ticket per finding that needs work, worst first."""
from .evidence import csv_text
from .rank import TIERS

PRIORITY = {"critical": ("Highest", "1"), "high": ("High", "2"), "medium": ("Medium", "3"), "low": ("Low", "4")}
HEADERS = {"jira": ["Summary", "Description", "Priority", "Labels", "Component", "Assignee", "Due date"],
           "servicenow": ["short_description", "description", "priority", "category", "cmdb_ci", "assignment_group", "due_date"]}
SYSTEMS = tuple(HEADERS)


def csv_for(findings, system, project):
    """`findings`: dicts with name, algorithm, tier, action or why, locations, and optionally owner, service, due, status, test_only.
    Findings with nothing to change, only in tests, fixed or accepted are left out."""
    if system not in HEADERS:
        raise ValueError(f"Choose a ticket system: {', '.join(SYSTEMS)}")
    todo = sorted((f for f in findings if f["tier"] in PRIORITY and not f.get("test_only") and f.get("status", "open") not in ("fixed", "exception")),
                  key=lambda f: TIERS.index(f["tier"]))
    rows = []
    for f in todo:
        places = [f"{p}:{n}" if n else p for p, n in f["locations"][:10]] + ([f"and {len(f['locations']) - 10} more"] if len(f["locations"]) > 10 else [])
        what = f.get("action") or f.get("why") or ""
        text = f"{what}\n\nAlgorithm: {f['algorithm']}\nSeen at:\n" + "\n".join(places) + "\n\nFound by Acxelin Readiness."
        name, owner, service, due = f"{f['name']} in {project}", f.get("owner", ""), f.get("service", ""), f.get("due", "")
        rows.append([name, text, PRIORITY[f["tier"]][0], "post-quantum", service, owner, due] if system == "jira" else
                    [name, text, PRIORITY[f["tier"]][1], "Security", service, owner, due])
    return csv_text(HEADERS[system], rows)
