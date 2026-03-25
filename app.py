from flask import Flask, request, jsonify, send_from_directory
from modules.log_analyzer import analyze_log
from modules.risk_engine import calculate_risk
from modules.ai_insights import generate_insights
from modules.masker import mask_data
from modules.ai_model import detect_anomaly
from modules.threat_detector import detect_attacks
from modules.correlation import correlate_logs
import os
from time import time

app = Flask(__name__, static_folder='frontend')

# ✅ RATE LIMITING
last_request_time = 0

@app.before_request
def rate_limit():
    global last_request_time
    now = time()

    if now - last_request_time < 1:   # 1 request per second
        return jsonify({"error": "Too many requests"}), 429

    last_request_time = now


# ✅ Serve frontend
@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')


# ✅ CHUNK PROCESSING
def process_in_chunks(content, chunk_size=500):
    return [content[i:i+chunk_size] for i in range(0, len(content), chunk_size)]


# ✅ API route
@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        # Handle file upload OR JSON input
        if 'file' in request.files:
            file = request.files['file']
            content = file.read().decode('utf-8')
        else:
            data = request.get_json()
            content = data.get("content", "")

        # ✅ Mask sensitive data
        content = mask_data(content)

        # ✅ Chunk processing for large logs
        chunks = process_in_chunks(content)

        all_findings = []
        for chunk in chunks:
            all_findings.extend(analyze_log(chunk))

        findings = all_findings

        # ✅ Calculate risk
        risk = calculate_risk(findings)

        # ✅ Generate insights
        insights = generate_insights(findings, content)

        # ✅ AI anomaly detection
        log_lines = content.split("\n")
        anomaly_results = detect_anomaly(log_lines)

        # ✅ Attack detection
        threats = detect_attacks(content)

        # ✅ Correlation analysis
        correlations = correlate_logs(content)

        # ✅ FINAL RESPONSE
        return jsonify({
            "summary": "Advanced log analysis completed with AI + correlation",
            "findings": findings,
            "risk_score": risk.get("score", 0),
            "risk_level": risk.get("level", "low"),
            "insights": insights,
            "ai_detection": anomaly_results,
            "threats": threats,
            "correlations": correlations
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ✅ Run app (DEPLOYMENT READY)
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)