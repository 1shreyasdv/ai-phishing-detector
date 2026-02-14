from flask import Flask, render_template_string, request
import pickle
import numpy as np
import re
from urllib.parse import urlparse
import pandas as pd

app = Flask(__name__)

model = pickle.load(open("phishing_model.pkl", "rb"))


history = []

def extract_features(url):
    features = {}
    features["url_length"] = len(url)
    features["dot_count"] = url.count(".")
    features["hyphen_count"] = url.count("-")
    features["at_count"] = url.count("@")
    features["has_https"] = 1 if url.startswith("https") else 0
    features["has_ip"] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    
    suspicious_words = ["login", "verify", "bank", "secure", "update"]
    features["suspicious_word_count"] = sum(word in url.lower() for word in suspicious_words)
    
    parsed = urlparse(url)
    features["subdomain_count"] = parsed.netloc.count(".")
    
    shorteners = ["bit.ly", "tinyurl", "goo.gl"]
    features["is_shortened"] = 1 if any(short in url for short in shorteners) else 0
    
    special_chars = re.findall(r'[!@#$%^&*(),?":{}|<>]', url)
    features["special_char_count"] = len(special_chars)
    
    return list(features.values())

html_template = """
<!DOCTYPE html>
<html>
<head>
<title>AI Phishing Detector</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
body.dark-mode {
    background-color: #121212;
    color: white;
}
.spinner-border {
    display: none;
}
</style>
</head>

<body class="bg-light" id="body">

<div class="container mt-5">
    <div class="card shadow p-4">
        <div class="d-flex justify-content-between">
            <h2>🔐 AI Phishing Detector</h2>
            <button onclick="toggleMode()" class="btn btn-secondary">Toggle Dark Mode</button>
        </div>

        <form method="post" onsubmit="showSpinner()">
            <input type="text" name="url" class="form-control mt-3" placeholder="Enter URL (e.g. https://example.com)" required>
            <button type="submit" class="btn btn-primary mt-3">Analyze</button>
            <div class="spinner-border text-primary mt-3" id="spinner"></div>
        </form>

        {% if prediction %}
            <div class="mt-4">
                <h4>{{ prediction }}</h4>
                <div class="progress">
                    <div class="progress-bar" role="progressbar" style="width: {{ probability }}%;">
                        {{ probability }}%
                    </div>
                </div>
            </div>

            <canvas id="probChart" class="mt-4"></canvas>

            <script>
            new Chart(document.getElementById("probChart"), {
                type: 'bar',
                data: {
                    labels: ['Legitimate', 'Phishing'],
                    datasets: [{
                        label: 'Probability',
                        data: [{{ legit_prob }}, {{ phish_prob }}],
                        backgroundColor: ['green', 'red']
                    }]
                }
            });
            </script>
        {% endif %}

        {% if history %}
        <h5 class="mt-4">Prediction History</h5>
        <table class="table table-striped">
            <tr><th>URL</th><th>Result</th></tr>
            {% for item in history %}
            <tr>
                <td>{{ item[0] }}</td>
                <td>{{ item[1] }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}

    </div>
</div>

<script>
function toggleMode() {
    document.getElementById("body").classList.toggle("dark-mode");
}
function showSpinner() {
    document.getElementById("spinner").style.display = "block";
}
</script>

</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def home():
    prediction = None
    probability = None
    legit_prob = None
    phish_prob = None

    if request.method == "POST":
        url = request.form["url"]
        features = extract_features(url)
        prediction_result = model.predict([features])[0]
        probs = model.predict_proba([features])[0]

        legit_prob = round(probs[0] * 100, 2)
        phish_prob = round(probs[1] * 100, 2)

        probability = max(legit_prob, phish_prob)

        if prediction_result == 1:
            prediction = "❌ Phishing Website Detected"
        else:
            prediction = "✅ Legitimate Website"

        history.append((url, prediction))

    return render_template_string(html_template,
                                  prediction=prediction,
                                  probability=probability,
                                  legit_prob=legit_prob,
                                  phish_prob=phish_prob,
                                  history=history)

if __name__ == "__main__":
    app.run(debug=True)
