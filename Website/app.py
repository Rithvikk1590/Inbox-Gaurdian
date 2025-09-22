from flask import Flask, render_template, request, redirect, url_for, session
import uuid

# NEW imports from the package
from email_analyser.parser import parse_eml_to_dict
from email_analyser.aggregator import analyse_email_content

app = Flask(__name__, static_folder='static')
app.secret_key = 'your-secret-key-here'  # replace in production

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
        return render_template("analysis.html", email=email_data, analysis=analysis, email_id=email_id)
    except Exception as e:
        print("Error in analysis:", e)
        return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True, port=5050, host="0.0.0.0")
