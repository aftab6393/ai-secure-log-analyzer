#  AI Secure Data Intelligence Platform

##  Overview
An intelligent log analysis system that detects sensitive data, classifies risks, and generates AI-based security insights.  
This project combines **AI anomaly detection, rule-based attack detection, and correlation analysis** to simulate a real-world security monitoring system.

---

## Live Application
 https://ai-secure-log-analyzer-8h8w.onrender.com

---

## Features
- Sensitive Data Detection (Email, Password, API Keys)
- Risk Classification Engine (Score + Severity)
- AI Anomaly Detection (Isolation Forest)
- Attack Detection (SQL Injection, XSS, Brute Force)
- Correlation Analysis for repeated suspicious activity
- File Upload Support (.log, .txt)
- Modern Interactive Dashboard
- Data Masking for security
- Rate Limiting for API protection
- Chunk Processing for large log files

---

## Architecture
- Input → Log Upload / Text
- Processing → Masking → Parsing → AI Detection → Attack Detection → Correlation
- Output → Risk Score + Insights + Visualization Dashboard

---

## Tech Stack
- **Backend:** Flask (Python)
- **Frontend:** HTML, CSS, JavaScript
- **Machine Learning:** scikit-learn (Isolation Forest)
- **Data Processing:** Regex + Custom Logic

---

## Input Types
- Raw logs (text input)
- Log files (.log, .txt)

---

## Example Output
```json
{
  "summary": "Log contains sensitive credentials and system errors",
  "risk_level": "high",
  "risk_score": 12,
  "insights": [
    "Sensitive credentials exposed",
    "Stack trace reveals internal system details"
  ]
}



Advanced Features
 Hybrid Detection System (AI + Rule-based)
 Detection of real-world cyber attack Cross-log correlation engine
 Rate limiting for secure API usage
Efficient handling of large logs using chunking

Security Features
Sensitive data masking
Credential exposure detection
Attack pattern detection
Secure API handling
⚙️ Installation
git clone https://github.com/YOUR_USERNAME/ai-secure-log-analyzer.git
cd ai-secure-log-analyzer
pip install -r requirements.txt
python app.py
 Future Enhancements
Real-time log streaming (WebSockets)
NLP-based log understanding
Integration with SIEM tools (Splunk-like systems)
Cloud-based monitoring dashboards
 Key Highlights
Built a mini SIEM-like system
Combines AI + Cybersecurity concepts
Designed with scalable modular architecture
Deployed live for real-world usage
 Author

Aftab Ansari
B.Tech Final Year | Aspiring Software Developer