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

def find_email_id_from_index_html(html: str) -> str | None:
    # 1) Look for explicit /analysis/<uuid> link
    m = ANALYSIS_LINK_RE.search(html)
    if m:
        return m.group(1)

    # 2) If index embeds the id somewhere else, try data-email-id attr
    soup = BeautifulSoup(html, "html.parser")
    # Search any anchor/button that links to analysis
    for a in soup.find_all("a", href=True):
        m = ANALYSIS_LINK_RE.search(a["href"])
        if m:
            return m.group(1)

    # 3) Last resort: look for a UUID-looking string in the page
    m = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}", html)
    return m.group(0) if m else None

def parse_analysis_for_metrics(html: str) -> tuple[str | None, int | None]:
    """Extract the Rule-Based Verdict and Total Risk from analysis.html page."""
    soup = BeautifulSoup(html, "html.parser")

    verdict = None
    total = None

    # --- Extract the "Rule-Based Verdict" ---
    # look for any text node containing "Rule-Based Verdict"
    for elem in soup.find_all(string=lambda t: "Rule-Based Verdict" in t):
        parent = elem.parent
        strong = parent.find("strong") if parent else None
        if strong:
            verdict = strong.get_text(strip=True)
            break

    # --- Extract the "Total Risk" number ---
    for elem in soup.find_all(string=lambda t: "Total Risk" in t):
        parent = elem.parent
        strong = parent.find("strong") if parent else None
        if strong and strong.get_text(strip=True).isdigit():
            total = int(strong.get_text(strip=True))
            break

    return verdict, total

def process_folder(folder: Path):
    s = requests.Session()

    verdict_counts: dict[str, int] = {}
    total_scores = 0
    n_with_scores = 0
    processed = 0
    failures = []

    for p in folder.rglob("*.eml"):
        if not p.is_file():
            continue

        files = {"eml_file": (p.name, p.read_bytes(), "message/rfc822")}
        try:
            # POST upload to /upload_eml
            r = s.post(f"{BASE}/upload_eml", files=files, timeout=20)
            r.raise_for_status()
        except Exception as e:
            print(f"[FAIL UPLOAD] {p}: {e}")
            failures.append((str(p), f"upload:{e}"))
            continue

        # Extract email_id from returned HTML (index page is rendered after upload)
        email_id = find_email_id_from_index_html(r.text)
        if not email_id:
            print(f"[NO ID] Could not find email_id for {p}")
            failures.append((str(p), "no_email_id"))
            continue

        # Open analysis page
        try:
            a = s.get(f"{BASE}/analysis/{email_id}", timeout=20)
            a.raise_for_status()
        except Exception as e:
            print(f"[FAIL ANALYSIS] {p}: {e}")
            failures.append((str(p), f"analysis:{e}"))
            continue

        verdict, total = parse_analysis_for_metrics(a.text)

        # Tally
        if verdict:
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        if isinstance(total, int):
            total_scores += total
            n_with_scores += 1

        processed += 1
        print(f"[OK] {p.name}: verdict={verdict!r}, total_risk={total}")

    # Summary
    avg = (total_scores / n_with_scores) if n_with_scores else 0.0
    summary = {
        "processed_files": processed,
        "verdict_counts": verdict_counts,
        "average_total_risk": round(avg, 2),
        "files_with_scores": n_with_scores,
        "failures": failures,
    }
    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2, ensure_ascii=False))

def main():
    folder_str = input("Folder containing .eml files: ").strip()
    folder = Path(folder_str)
    if not folder.exists() or not folder.is_dir():
        print(f"Not a folder: {folder}")
        return
    process_folder(folder)

if __name__ == "__main__":
    main()
