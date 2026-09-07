from flask import Flask, render_template, request, jsonify
from analyzer import analyze_input

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    input_type = data.get("input_type", "url")
    text = (data.get("text") or "").strip()

    if not text:
        return jsonify({"error": "Please enter a URL or email text."}), 400

    if input_type not in {"url", "email"}:
        return jsonify({"error": "Input type must be URL or email."}), 400

    result = analyze_input(text, input_type)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
