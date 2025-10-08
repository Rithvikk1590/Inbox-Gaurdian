from flask import Flask, render_template, request, redirect, url_for, session
import uuid
import re
import pandas as pd
import pickle

# NEW imports from the package
from email_analyser.parser import parse_eml_to_dict
from email_analyser.aggregator import analyse_email_content

with open("vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)
with open(r"C:\Users\asus\OneDrive\Documents\SIT Notes 2025\PRG Fundamentals\Python Project\Inbox-Gaurdian\Website\m1_model.pkl", "rb") as f:
    ml_model = pickle.load(f)

app = Flask(__name__, static_folder='static')
app.secret_key = 'your-secret-key-here'  # replace in production

def analyse_csv(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """
    Clean + annotate the CSV with rule-based flags.
    Returns (annotated DataFrame, summary dict).
    """
    results = {
        "suspicious_subject_count": 0,
        "suspicious_body_count": 0,
        "suspicious_attachments": 0,
        "bad_sender_emails": 0,
        "spam_marked_rows": 0,
        "total_rows": len(df)
    }

    flagged_rows = []
    df["Risk Points"] = 0

    # Suspicious keywords for matching
    suspicious_keywords = ["urgent", "verify", "account", "password",
                           "bank", "lottery", "win", "free", "click"]

    # Suspicious file extensions
    exec_extensions = [".exe", ".scr", ".js", ".bat", ".vbs"]
    doc_extensions = [".docm", ".xlsm", ".pptm"]  # scripts can hide here

    for i, row in df.iterrows():
        reasons = []
        points = 0

        # --- Whitelist Checker ---
        if "From" in df.columns and pd.notna(row["From"]):
            sender = row["From"].strip()
            if "@" not in sender:
                results["bad_sender_emails"] += 1
                reasons.append("Unknown Sender")
                points += 20
            else:
                if not sender.endswith("@sit.singaporetech.edu.sg"):
                    reasons.append("Unknown Sender")
                    points += 20

        # --- Keyword Detector: Subject ---
        subject_hits = []
        if "Subject" in df.columns and pd.notna(row["Subject"]):
            subject = row["Subject"].lower()
            for word in suspicious_keywords:
                if word in subject:
                    subject_hits.append(word)
                    points += 15
            if subject_hits:
                results["suspicious_subject_count"] += 1
                reasons.append(f"Suspicious keywords in subject: {', '.join(subject_hits)}")
                points = min(points, 45)

        # --- Keyword Detector: Body ---
        body_hits = []
        if "Body" in df.columns and pd.notna(row["Body"]):
            body = row["Body"].lower()
            for word in suspicious_keywords:
                if word in body:
                    body_hits.append(word)
                    points += 5
            if body_hits:
                results["suspicious_body_count"] += 1
                reasons.append(f"Suspicious keywords in body: {', '.join(body_hits)}")
                points = min(points, 20)

        # --- File Extension Detection ---
        if "Attachments" in df.columns and pd.notna(row["Attachments"]):
            attach = str(row["Attachments"]).lower()
            if any(attach.endswith(ext) for ext in exec_extensions):
                results["suspicious_attachments"] += 1
                reasons.append("Executable file")
                points += 50
            elif any(attach.endswith(ext) for ext in doc_extensions):
                results["suspicious_attachments"] += 1
                reasons.append("Suspicious document file")
                points += 30

        # --- Spam flag ---
        if "is_spam" in df.columns and row["is_spam"] == 1:
            results["spam_marked_rows"] += 1
            reasons.append("Spam Row")
            points += 20

        # Save flags + points
        if reasons:
            flagged_rows.append((i, reasons))
        df.at[i, "Risk Points"] = points

    # Add Flags column with reasons
    df["Flags"] = ""
    for idx, reasons in flagged_rows:
        df.at[idx, "Flags"] = ", ".join(reasons)
    total_risk = int(df["Risk Points"].sum())
    results["total_risk"] = total_risk

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

        # ML prediction on email body
        body_text = email_data.get("body", "")
        if body_text:
            body_tfidf = vectorizer.transform([body_text])
            ml_output = ml_model.predict(body_tfidf)[0]
        else:
            ml_output = "N/A"

        return render_template("analysis.html", email=email_data, analysis=analysis, email_id=email_id, ml_output=ml_output)
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

        # ML prediction on manual input
    if body:
        body_tfidf = vectorizer.transform([body])
        ml_output = ml_model.predict(body_tfidf)[0]
    else:
        ml_output = "N/A"

    return render_template("analysis.html", email=email_data, analysis=analysis, email_id="manual", ml_output=ml_output)

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
            if isinstance(val, str):
                if "Suspicious Subject" in val or "Suspicious keywords in subject" in val:
                    return "background-color: #ffeeba; color: #000 !important;"  # yellow
                if "Bad Attachment" in val or "Executable file" in val or "Suspicious document file" in val:
                    return "background-color: #f5c6cb; color: #000 !important;"  # red
                if "Bad Sender" in val or "Unknown Sender" in val:
                    return "background-color: #bee5eb; color: #000 !important;"  # blue
                if "Spam Row" in val:
                    return "background-color: #d4edda; color: #000 !important;"  # green
            return "color: #fff !important;"

        def style_risk_points(val):
            try:
                val = int(val)
                if val == 0:
                    return "background-color: #28a745; color: #fff;"  # green safe
                elif val < 30:
                    return "background-color: #ffc107; color: #000;"  # yellow medium
                elif val < 70:
                    return "background-color: #fd7e14; color: #fff;"  # orange high
                else:
                    return "background-color: #dc3545; color: #fff;"  # red critical
            except:
                return ""
            
        styled = (
            df.style
              .set_properties(**{"color": "#fff"})
              .set_table_styles([
                  {"selector": "th", "props": [("color", "#fff")]},
                  {"selector": "td", "props": [("color", "#fff")]},
              ])
        )

        styled = styled.applymap(style_flags, subset=["Flags"])
        styled = styled.applymap(style_risk_points, subset=["Risk Points"])

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
            csv_analysis=detection_results,
            total_risk=detection_results.get("total_risk", 0)
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
