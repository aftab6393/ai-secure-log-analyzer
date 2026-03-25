from flask import Flask, request, jsonify, send_from_directory
from modules.log_analyzer import analyze_log
from modules.risk_engine import calculate_risk
from modules.ai_insights import generate_insights
from modules.masker import mask_data

app = Flask(__name__, static_folder='frontend')

#  Serve frontend
@app.route('/')
def serve_frontend():
    return send_from_directory('frontend', 'index.html')

#  API route
@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        # Handle file upload OR JSON
        if 'file' in request.files:
            file = request.files['file']
            content = file.read().decode('utf-8')
        else:
            data = request.json
            content = data.get("content", "")

        # Mask sensitive data
        content = mask_data(content)

        findings = analyze_log(content)
        risk = calculate_risk(findings)
       # insights = generate_insights(findings)

        insights = generate_insights(findings, content)

        return jsonify({
    "summary": "Log contains sensitive credentials and system errors",
    "findings": findings,
    "risk_score": risk["score"],
    "risk_level": risk["level"],
    "insights": insights
})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
