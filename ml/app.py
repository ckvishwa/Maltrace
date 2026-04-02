import json
import pickle
from flask import Flask, request, jsonify
from feature_extractor import extract_features
import tempfile
import os

app = Flask(__name__)
MODEL_PATH = "/opt/CAPEv2/ml/model.pkl"

def load_model():
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)

@app.route("/predict", methods=["POST"])
def predict():
    if "report" not in request.files:
        return jsonify({"error": "No report file"}), 400
    
    f = request.files["report"]
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        f.save(tmp.name)
        tmp_path = tmp.name

    try:
        features = extract_features(tmp_path)
        data = load_model()
        clf = data["model"]
        X = [list(features.values())]
        pred = clf.predict(X)[0]
        prob = clf.predict_proba(X)[0]
        
        return jsonify({
            "prediction": "MALWARE" if pred == 1 else "BENIGN",
            "confidence": round(float(max(prob)) * 100, 2),
            "malware_probability": round(float(prob[1]) * 100, 2),
            "features": features
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        os.unlink(tmp_path)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
