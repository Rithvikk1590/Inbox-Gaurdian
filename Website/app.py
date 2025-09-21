from flask import Flask, render_template, request, redirect, url_for
import email
from email.header import decode_header
import os
from datetime import datetime

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/guide")
def guide():
    return render_template("guide.html")

# **NEW ROUTES ADDED**
@app.route("/upload_eml", methods=["POST"])
def upload_eml():
    try:
        if 'eml_file' not in request.files:
            return render_template("index.html")
        
        file = request.files['eml_file']
        if file.filename == '' or not file.filename.endswith('.eml'):
            return render_template("index.html")
        
        # Parse the email
        email_content = file.read()
        msg = email.message_from_bytes(email_content)
        
        # Extract email data with fallbacks
        email_data = {
            'subject': decode_email_header(msg.get('Subject', 'No Subject')),
            'from': decode_email_header(msg.get('From', 'Unknown Sender')),
            'to': decode_email_header(msg.get('To', 'Unknown Recipient')),
            'date': msg.get('Date', 'Unknown Date'),
            'body': get_email_body(msg)
        }
        
        # Render the home page with email data
        return render_template("index.html", email=email_data)
    
    except Exception as e:
        # If parsing fails, render home without email data
        print(f"Error parsing email: {e}")
        return render_template("index.html")

def decode_email_header(header):
    try:
        if header:
            decoded_parts = decode_header(header)
            decoded_header = ""
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    decoded_header += part.decode(encoding or 'utf-8')
                else:
                    decoded_header += part
            return decoded_header
        return ""
    except:
        return str(header) if header else ""

def get_email_body(msg):
    try:
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    charset = part.get_content_charset() or 'utf-8'
                    body = part.get_payload(decode=True).decode(charset, errors='ignore')
                    break
        else:
            charset = msg.get_content_charset() or 'utf-8'
            body = msg.get_payload(decode=True).decode(charset, errors='ignore')
        return body if body else "No text content found"
    except Exception as e:
        return f"Error reading email body: {str(e)}"

if __name__ == "__main__":
    app.run(debug=True, port=5050, host="0.0.0.0")  # remove debug=True in production