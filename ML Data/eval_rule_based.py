# eval_rule_checker.py
import os
import re
import json
from pathlib import Path
import requests
from bs4 import BeautifulSoup

BASE = "http://127.0.0.1:5050"

ANALYSIS_LINK_RE = re.compile(r"/analysis/([0-9a-fA-F-]{36})")
TOTAL_RISK_RE    = re.compile(r"Total Risk:\s*<strong>(\d+)</strong>", re.I)
VERDICT_RE       = re.compile(r"Rule-?Based Verdict:\s*<strong>([^<]+)</strong>", re.I)

# ---------------------------------------------------------
# Locate the email_id (UUID) returned by /upload_eml
# ---------------------------------------------------------
def find_email_id_from_index_html(html: str) -> str | None:
    # 1) Look for explicit /analysis/<uuid> link
    m = ANALYSIS_LINK_RE.search(html)
    if m:
        return m.group(1)

    # 2) Try scanning anchor tags for analysis links
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a", href=True):
        m = ANALYSIS_LINK_RE.search(a["href"])
        if m:
            return m.group(1)

    # 3) Fallback: directly search for UUID pattern
    m = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}", html)
    return m.group(0) if m else None


# ---------------------------------------------------------
# Parse analysis.html to extract verdict and total risk
# ---------------------------------------------------------
def parse_analysis_for_metrics(html: str) -> tuple[str | None, int | None]:
    """Extract the Rule-Based Verdict and Total Risk from analysis.html page."""
    soup = BeautifulSoup(html, "html.parser")

    verdict = None
    total = None

    # Find the "Rule-Based Verdict" section
    for elem in soup.find_all(string=lambda t: "Rule-Based Verdict" in t):
        parent = elem.parent
        strong = parent.find("strong") if parent else None
        if strong:
            verdict = strong.get_text(strip=True)
            break

    # Find the "Total Risk" number
    for elem in soup.find_all(string=lambda t: "Total Risk" in t):
        parent = elem.parent
        strong = parent.find("strong") if parent else None
        if strong and strong.get_text(strip=True).isdigit():
            total = int(strong.get_text(strip=True))
            break

    return verdict, total


# ---------------------------------------------------------
# Process all .eml files in a folder
# ---------------------------------------------------------
def process_folder(folder: Path):
    s = requests.Session()

    verdict_counts: dict[str, int] = {}
    total_scores = 0
    n_with_scores = 0
    processed = 0
    failures = []  # store failed file info for later summary

    for p in folder.rglob("*.eml"):
        if not p.is_file():
            continue

        files = {"eml_file": (p.name, p.read_bytes(), "message/rfc822")}
        try:
            # Upload .eml to /upload_eml endpoint
            r = s.post(f"{BASE}/upload_eml", files=files, timeout=20)
            r.raise_for_status()
        except Exception as e:
            failures.append((str(p), f"upload:{e}"))
            continue

        # Extract email_id from index.html response
        email_id = find_email_id_from_index_html(r.text)
        if not email_id:
            failures.append((str(p), "no_email_id"))
            continue

        # Retrieve analysis page
        try:
            a = s.get(f"{BASE}/analysis/{email_id}", timeout=20)
            a.raise_for_status()
        except Exception as e:
            failures.append((str(p), f"analysis:{e}"))
            continue

        # Parse metrics from analysis page
        verdict, total = parse_analysis_for_metrics(a.text)

        if verdict:
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        if isinstance(total, int):
            total_scores += total
            n_with_scores += 1

        processed += 1
        print(f"[OK] {p.name}: verdict={verdict!r}, total_risk={total}")

    # ------------------------------------------
    # Summary section (all failures grouped)
    # ------------------------------------------
    avg = (total_scores / n_with_scores) if n_with_scores else 0.0
    summary = {
        "processed_files": processed,
        "verdict_counts": verdict_counts,
        "average_total_risk": round(avg, 2),
        "files_with_scores": n_with_scores,
        "failures_count": len(failures),
        "failed_files": [f[0] for f in failures],  # list of failed filenames only
    }

    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


# ---------------------------------------------------------
# Entry point
# ---------------------------------------------------------
def main():
    folder_str = input("Folder containing .eml files: ").strip()
    folder = Path(folder_str)
    if not folder.exists() or not folder.is_dir():
        print(f"Not a folder: {folder}")
        return
    process_folder(folder)


if __name__ == "__main__":
    main()
