from .whitelist_checker import check_whitelist
from .keyword_detector import detect_keywords
from .position_scorer import score_positions
from .edit_distance import check_edit_distance
from .url_analyzer import analyze_urls

def _merge(into: dict, part: dict):
    into.setdefault("body_highlights", [])
    into["body_highlights"].extend(part.get("body_highlights", []))
    into["total_risk_points"] = into.get("total_risk_points", 0) + part.get("risk_points", 0)

def analyse_email_content(email_data: dict) -> dict:
    results = {"body_highlights": [], "total_risk_points": 0}
    modules = [
        check_whitelist,
        detect_keywords,
        score_positions,
        check_edit_distance,
        analyze_urls,
    ]
    for fn in modules:
        try:
            _merge(results, fn(email_data))
        except Exception as e:
            print(f"[!] Module {fn.__name__} failed: {e}")
    return results
