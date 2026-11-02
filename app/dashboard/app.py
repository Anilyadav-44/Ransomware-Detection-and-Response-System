
from flask import Flask, jsonify, render_template, request
from threading import Lock
from collections import deque
from datetime import datetime

app = Flask(__name__)

# Store the latest 500 monitoring events.
events = deque(maxlen=500)
events_lock = Lock()

statistics = {
    "total_events": 0,
    "suspicious_files": 0,
    "high_entropy_files": 0,
    "ransomware_alerts": 0
}


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/events", methods=["GET", "POST"])
def manage_events():

    if request.method == "POST":
        event_data = request.get_json(silent=True)

        if not isinstance(event_data, dict):
            return jsonify({"error": "Invalid event data"}), 400

        required_fields = ["file", "event_type", "entropy", "severity"]

        if not all(field in event_data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        try:
            event_data["entropy"] = float(event_data["entropy"])
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid entropy value"}), 400

        event_data["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with events_lock:
            events.appendleft(event_data)

            statistics["total_events"] += 1

            if event_data["severity"] in ("HIGH", "CRITICAL"):
                statistics["suspicious_files"] += 1

            if event_data.get("high_entropy"):
                statistics["high_entropy_files"] += 1

            if event_data.get("ransomware_burst"):
                statistics["ransomware_alerts"] += 1

        return jsonify({
            "status": "received",
            "message": "Monitoring event stored successfully"
        }), 201

    with events_lock:
        return jsonify(list(events))


@app.route("/api/statistics")
def get_statistics():
    with events_lock:
        return jsonify(statistics.copy())


@app.route("/api/health")
def health():
    return jsonify({
        "status": "online",
        "service": "RDRS Dashboard",
        "time": datetime.now().isoformat(timespec="seconds")
    })


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
