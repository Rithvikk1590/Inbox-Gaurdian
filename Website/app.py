from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/guide")
def guide():
    return render_template("guide.html")

if __name__ == "__main__":
    app.run(debug=True, port=8080)  # remove debug=True in production
