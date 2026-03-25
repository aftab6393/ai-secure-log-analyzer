from sklearn.ensemble import IsolationForest
import numpy as np

# Simple feature extraction
def extract_features(log):
    return [
        len(log),                     # length
        log.count("error"),           # error count
        log.count("failed"),          # failed attempts
        log.count("login"),           # login attempts
    ]

# Train + Predict
def detect_anomaly(logs):
    features = np.array([extract_features(l) for l in logs])

    model = IsolationForest(contamination=0.3)
    model.fit(features)

    predictions = model.predict(features)

    # -1 = anomaly, 1 = normal
    return ["Anomaly" if p == -1 else "Normal" for p in predictions]