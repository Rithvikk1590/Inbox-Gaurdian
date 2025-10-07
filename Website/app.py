from flask import Flask, render_template, request, redirect, url_for, session
import uuid
import re
import pandas as pd

# NEW imports from the package
from email_analyser.parser import parse_eml_to_dict
from email_analyser.aggregator import analyse_email_content

app = Flask(__name__, static_folder='static')
app.secret_key = 'your-secret-key-here'  # replace in production

def analyse_csv(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    print(dict)
    """
    Clean + annotate the CSV with rule-based flags.
    Returns (annotated DataFrame, summary dict).
    """
    results = {
        "suspicious_subject_count": 0,
        "suspicious_attachments": 0,
        "bad_sender_emails": 0,
        "spam_marked_rows": 0
    }

    flagged_rows = []

    for i, row in df.iterrows():
        reasons = []

        # Suspicious subjects
        suspicious_keywords = ["urgent", "verify", "account", "password",
                               "bank", "lottery", "win", "free", "click"]
        if "Subject" in df.columns and pd.notna(row["Subject"]):
            if any(word in row["Subject"].lower() for word in suspicious_keywords):
                results["suspicious_subject_count"] += 1
                reasons.append("Suspicious Subject")

        # Suspicious attachments
        bad_extensions = [".exe", ".scr", ".js", ".bat", ".vbs"]
        if "Attachments" in df.columns and pd.notna(row["Attachments"]):
            if any(row["Attachments"].lower().endswith(ext) for ext in bad_extensions):
                results["suspicious_attachments"] += 1
                reasons.append("Bad Attachment")

        # Bad sender emails
        if "From" in df.columns and pd.notna(row["From"]):
            sender = row["From"].strip()
            if not sender or "@" not in sender or sender.endswith("."):
                results["bad_sender_emails"] += 1
                reasons.append("Bad Sender")

        # Spam-marked rows
        if "is_spam" in df.columns and row["is_spam"] == 1:
            results["spam_marked_rows"] += 1
            reasons.append("Spam Row")

        if reasons:
            flagged_rows.append((i, reasons))

    # Add a new column "Flags" with reasons
    df["Flags"] = ""
    for idx, reasons in flagged_rows:
        df.at[idx, "Flags"] = ", ".join(reasons)

    return df, results

def clean_csv_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    # 1) Standardize column names
    df.columns = [re.sub(r'\s+', ' ', c).strip() for c in df.columns]

    # 2) Normalize string cells: strip + collapse internal whitespace
    def _clean_str(x):
        x = re.sub(r'\s+', ' ', x)  # collapse runs of spaces/tabs/newlines
        return x.strip()

    for col in df.columns:
        if df[col].dtype == object:
            df[col] = df[col].astype(str).apply(_clean_str).replace({'': pd.NA, 'nan': pd.NA})

    # 3) Treat whitespace-only as missing, then drop all-empty rows/cols
    df.replace(r'^\s*$', pd.NA, regex=True, inplace=True)
    df.dropna(how='all', inplace=True)
    df.dropna(how='all', axis=1, inplace=True)

    # 4) Type fixes (optional but nice)
    if 'Age' in df.columns:
        df['Age'] = pd.to_numeric(df['Age'], errors='coerce').astype('Int64')

    if 'Email' in df.columns:
        df['Email'] = df['Email'].str.lower()
        # mark invalid emails as missing (optional)
        valid = df['Email'].str.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', na=False)
        df.loc[~valid, 'Email'] = pd.NA

    # 5) Business-rule filtering (tune as you like)
    key_cols = [c for c in ['Name', 'Email'] if c in df.columns]
    if key_cols:
        # drop rows that are missing BOTH Name and Email
        df.dropna(subset=key_cols, how='all', inplace=True)

    # 6) Remove duplicates (prefer keys if present)
    if key_cols:
        df.drop_duplicates(subset=key_cols, inplace=True)
    else:
        df.drop_duplicates(inplace=True)

    return df


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/guide")
def guide():
    return render_template("guide.html")

@app.route("/upload_eml", methods=["POST"])
def upload_eml():
    try:
        f = request.files.get('eml_file')
        if not f or not f.filename.endswith('.eml'):
            return render_template("index.html")

        email_id = str(uuid.uuid4())
        email_bytes = f.read()
        email_data = parse_eml_to_dict(email_bytes)
        email_data['filename'] = f.filename

        session[email_id] = email_data
        return render_template("index.html", email=email_data, email_id=email_id)
    except Exception as e:
        print("Error parsing email:", e)
        return render_template("index.html")

@app.route("/analysis/<email_id>")
def analysis(email_id):
    try:
        email_data = session.get(email_id)
        if not email_data:
            return redirect(url_for("home"))

        analysis = analyse_email_content(email_data)
        return render_template("analysis.html", email=email_data, analysis=analysis, email_id=email_id, show_analysis=True)
    except Exception as e:
        print("Error in analysis:", e)
        return redirect(url_for("home"))
    
@app.route("/manual_analysis", methods=["POST"])
def manual_analysis():
    sender = request.form.get("manual_sender", "")
    subject = request.form.get("manual_subject", "")
    body = request.form.get("manual_body", "")

    email_data = {
        "sender": sender,
        "subject": subject,
        "body": body,
        "attachments": []
    }

    analysis = analyse_email_content(email_data)

    return render_template("analysis.html", email=email_data, analysis=analysis, email_id="manual")

@app.route("/upload_csv", methods=["POST"])
def upload_csv():
    try:
        f = request.files.get("csv_file")
        if not f or not f.filename.lower().endswith(".csv"):
            return render_template("index.html", error="Please upload a valid CSV file.")

        # Read + clean
        df = pd.read_csv(f, skipinitialspace=True)
        df = clean_csv_dataframe(df)

        # Analyse with simple rules (adds Flags column + summary)
        df, detection_results = analyse_csv(df)

        # --- Styling: force white everywhere, then override Flags column ---
        def style_flags(val):
            if isinstance(val, str) and "Suspicious Subject" in val:
                return "background-color: #ffeeba; color: #000 !important;"
            if isinstance(val, str) and "Bad Attachment" in val:
                return "background-color: #f5c6cb; color: #000 !important;"
            if isinstance(val, str) and "Bad Sender" in val:
                return "background-color: #bee5eb; color: #000 !important;"
            if isinstance(val, str) and "Spam Row" in val:
                return "background-color: #d4edda; color: #000 !important;"
            return "color: #000 !important;"

        styled = (
            df.style
              .set_properties(**{"color": "#fff"})   # everything white
              .set_table_styles([                    # headers also white
                  {"selector": "th", "props": [("color", "#fff")]},
                  {"selector": "td", "props": [("color", "#fff")]},
              ])
        )

        # Override just the Flags column (after global white)
        styled = styled.applymap(style_flags, subset=["Flags"])

        # Hide Pandas index column if not needed
        try:
            styled = styled.hide(axis="index")   # pandas >= 1.4
        except Exception:
            styled = styled.hide_index()         # older pandas

        # Convert to HTML
        table_html = styled.to_html()

        # Render with both cleaned table + analysis results
        return render_template(
            "index.html",
            csv_table=table_html,
            csv_analysis=detection_results
        )

    except Exception as e:
        print("Error in CSV upload:", e)
        return render_template("index.html", error="Error processing CSV file.")
    
@app.route("/csv_analysis/<csv_id>")
def csv_analysis(csv_id):
    data = session.get(csv_id)
    if not data:
        return redirect(url_for("home"))

    df = pd.DataFrame(data["rows"], columns=data["columns"])

    # Render as a nice Bootstrap table
    table_html = df.to_html(classes="table table-striped table-bordered align-middle", index=False)
    return render_template("csv_analysis.html", table=table_html)

if __name__ == "__main__":
    app.run(debug=True, port=5050, host="0.0.0.0")
