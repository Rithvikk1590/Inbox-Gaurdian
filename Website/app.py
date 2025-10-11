from flask import Flask, render_template, request, redirect, url_for, flash
import uuid
import re
import pandas as pd
import pickle
import secrets
from email_analyser import parse_eml_to_dict
from email_analyser import analyse_email_content

with open(r"../ML Model/vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)
with open(r"../ML Model/m1_model.pkl", "rb") as f:
    ml_model = pickle.load(f)

email_store = {}  # global in-memory store
app = Flask(__name__, static_folder='static')
app.secret_key = secrets.token_hex(16)

def _risk_verdict(points: int) -> str:
    """Return risk verdict based on total risk score."""
    if points is None:
        return "Unknown"
    if points >= 90:
        return "Likely Phishing"
    if points >= 75:
        return "High Risk"
    if points >= 60:
        return "Suspicious"
    if points >= 40:
        return "Caution"
    if points >= 20:
        return "Low Risk"
    return "Safe"


def _row_to_email_data(row: dict) -> dict:
    """
    Converts a CSV row into a standardized email data dictionary.

    Cleans and normalizes fields such as sender, subject, body, 
    and attachments, handling null values and inconsistent key names. 
    Returns a consistent structure for use in email analysis modules.
    """
    def clean_str(val):
        if pd.isna(val):
            return ""
        val = str(val).strip()
        if val.lower() in ["nan", "none", "null"]:
            return ""
        import re
        val = re.sub(r"\s+", " ", val)
        return val

    # Lowercase keys once
    lower_row = {k.lower(): v for k, v in row.items()}

    sender = clean_str(
        lower_row.get("from") or
        lower_row.get("sender") or
        lower_row.get("email from") or
        lower_row.get("email") or
        ""
    )
    subject = clean_str(
        lower_row.get("subject") or
        lower_row.get("title") or
        ""
    )
    body = clean_str(
        lower_row.get("body") or
        lower_row.get("message") or
        lower_row.get("content") or
        ""
    )
    attachments = clean_str(lower_row.get("attachments") or "")

    # Validate sender
    if "@" not in sender and sender != "":
        sender = ""

    # Split attachments
    att_list = []
    if attachments:
        parts = re.split(r"[,\|;]+", attachments)
        att_list = [p.strip() for p in parts if p.strip()]

    return {
        "sender": sender.lower(),  # force lowercase for whitelist checks
        "subject": subject,
        "body": body,
        "attachments": att_list,
    }


@app.route("/")
def home():
    """
    Renders the main homepage of the application.
    """
    return render_template("index.html")


@app.route("/upload_eml", methods=["POST"])
def upload_eml():
    """
    Uploads and parses a .eml.

    Reads the uploaded .eml file, converts it into a dictionary,
    assigns a unique ID, stores it in memory, and renders the
    index page with the parsed email details.
    """
    try:
        # Retrieve content of .eml file and 
        f = request.files.get('eml_file')
        email_bytes = f.read()
        email_data = parse_eml_to_dict(email_bytes)
        email_data['filename'] = f.filename

        # Create a unique identifier for the email
        email_id = str(uuid.uuid4())
        # Store the email data in memory so that it can be retrieved later
        email_store[email_id] = email_data
    
        return render_template("index.html", email=email_data, email_id=email_id)
    except Exception as e:
        print("Error parsing email:", e)
        return render_template("index.html")


@app.route("/analysis/<email_id>")
def analysis(email_id):
    """
    Performs phishing analysis on a previously uploaded email.

    Retrieves the email by its ID, runs rule-based and ML analysis to 
    calculate total risk points, determine a verdict, and display results 
    on the analysis page.
    """
    try:
        # Retrieve email data from in-memory store
        email_data = email_store.get(email_id)
        if not email_data:
            return redirect(url_for("home"))
        
        # Run rule-based analysis
        analysis = analyse_email_content(email_data)

        # Get total risk points
        total = analysis.get("total_risk_points")

        # Cap total at 100
        if total > 100:
            analysis["total_risk_points"] = 100
        # Calculate verdict
        analysis["verdict"] = _risk_verdict(total)

        # ML prediction on email body
        body_text = email_data.get("body", "")
        if body_text:
            body_tfidf = vectorizer.transform([body_text])
            ml_output = ml_model.predict(body_tfidf)[0]
        else:
            ml_output = "N/A"

        return render_template(
            "analysis.html",
            email=email_data,
            analysis=analysis,
            email_id=email_id,
            ml_output=ml_output
        )
    except Exception as e:
        print("Error in analysis:", e)
        return redirect(url_for("home"))


@app.route("/manual_analysis", methods=["POST"])
def manual_analysis():
    """
    Analyses manually entered email content.

    Collects sender, subject, and body text from form input,
    runs rule-based and ML analysis to generate risk scores
    and verdict, then displays the results on the analysis page.
    """
    # Retrieve form inputs
    sender = request.form.get("manual_sender", "")
    subject = request.form.get("manual_subject", "")
    body = request.form.get("manual_body", "")

    # Build email_data dict
    email_data = {
        "sender": sender,
        "subject": subject,
        "body": body,
        "attachments": []
    }
    
    #
    analysis = analyse_email_content(email_data)
    
    # Cap the max score at 100
    total = analysis.get("total_risk_points")
    if total > 100:
        analysis["total_risk_points"] = 100
    
    # Calculate verdict if not already set
    analysis["verdict"] = _risk_verdict(total)

    # ML prediction on manual input
    if body:
        body_tfidf = vectorizer.transform([body])
        ml_output = ml_model.predict(body_tfidf)[0]
    else:
        ml_output = "N/A"

    return render_template("analysis.html", email=email_data, analysis=analysis, email_id="manual", ml_output=ml_output)


@app.route("/upload_csv", methods=["POST"])
def upload_csv():
    """
    Handles bulk email analysis from an uploaded CSV file.

    Reads and cleans the CSV, converts each row into structured email data,
    runs rule-based and ML phishing analysis, caps risk scores at 100, 
    and displays the results in a table on the CSV analysis page.
    """
    try:
        f = request.files.get("csv_file")
        if not f or not f.filename.lower().endswith(".csv"):
            return render_template("index.html", error="Please upload a valid CSV file.")

        # Read + clean dataframe
        df = pd.read_csv(f, skipinitialspace=True)

        # Drop auto index column if present
        if "Unnamed: 0" in df.columns:
            df = df.drop(columns=["Unnamed: 0"])

        # Replace NaN with "" for consistency
        df = df.fillna("")

        # Drop rows where ALL values are empty/whitespace
        df = df.loc[~(df.astype(str).apply(lambda x: x.str.strip()).eq("")).all(axis=1)]

        # Build rows for table
        table_rows = []
        for _, row in df.iterrows():
            email_data = _row_to_email_data(row.to_dict())

            # Skip rows that are totally blank after cleaning
            if not (email_data["sender"] or email_data["subject"] or email_data["body"] or email_data["attachments"]):
                continue

            analysis = analyse_email_content(email_data)  # <- uses email_analyser
            total_points = int(analysis.get("total_risk_points", 0))
            # Cap score at 100
            if total_points > 100:
                total_points = 100

            verdict = _risk_verdict(total_points)

            # ML Prediction
            email_body = email_data.get("body", "")
            if email_body:
                body_tfidf = vectorizer.transform([email_body])
                mlmodel_verdict = ml_model.predict(body_tfidf)[0]
            else:
                mlmodel_verdict = "N/A"

            table_rows.append({
                "sender": email_data.get("sender", ""),
                "subject": email_data.get("subject", ""),
                "body": email_data.get("body", ""),
                "risk_score": total_points,
                "verdict": verdict,
                "ml_verdict": mlmodel_verdict
            })

        return render_template("csv_analysis.html", rows=table_rows)

    except Exception as e:
        print("Error in upload_csv:", e)
        return render_template("index.html", error="Error processing CSV file.")


if __name__ == "__main__":
    app.run(debug=True, port=5050, host="0.0.0.0")
