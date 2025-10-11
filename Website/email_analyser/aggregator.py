from .whitelist_checker import check_whitelist
from .keyword_detector import detect_keywords
from .edit_distance import check_edit_distance
from .url_analyser import analyse_urls
from .attachment_rules import check_attachment_extensions


def _merge(into, part):
    """
    Merges analysis results from one module into the main result dictionary.

    Appends highlight and warning entries and updates the total risk score 
    with points from each analysis module.
    """
    into.setdefault("body_highlights", [])
    into.setdefault("attachment_warnings", [])
    into["body_highlights"].extend(part.get("body_highlights", []))
    into["attachment_warnings"].extend(part.get("attachment_warnings", []))
    into["total_risk_points"] = into.get("total_risk_points", 0) + part.get(
        "risk_points", 0
    )


def analyse_email_content(email_data):
    """
    Runs all detection modules on the given email data.

    If sender is whitelisted, then skip all other modules and return an 
    empty result. Otherwise, run through the other analysis modules (keywords,
    domain similarity, URLs, and attachments). Combines their results into 
    a dictionary containing highlights, warnings, section, and total risk points.
    """
    results = {"body_highlights": [], "total_risk_points": 0}

    # Check if email is whitelisted
    try:
        wl = check_whitelist(email_data)
        if wl is True:  # means whitelisted
            print("[INFO] Sender is whitelisted, skipping further analysis.")
            return {
                "body_highlights": [],
                "attachment_warnings": [],
                "total_risk_points": 0,
            }
        elif isinstance(wl, dict):  # if whitelist returns scoring info, merge it
            _merge(results, wl)
    except Exception as e:
        print(f"[!] Whitelist check failed: {e}")

    # Run other modules
    modules = [
        detect_keywords, #keyword_detector + position scorer
        check_edit_distance,
        analyse_urls,
        check_attachment_extensions,
    ]

    for fn in modules:
        try:
            _merge(results, fn(email_data))
        except Exception as e:
            # Returns the name of the current function and prints out the exception
            print(f"[INFO] Module {fn.__name__} failed: {e}")

    print("results:", results)
    return results
