import json
import logging
import os
from flask import Flask, render_template, jsonify, request
from blockchain import blockchain
from quantum_classifier import quantum_clf
from rl_agent import rl_agent
from time_series_predictor import predictor
from edge_capture import capture_traffic_real_time
from threading import Thread
import time

# Configure logging with file output
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("ids_debug.log"),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)
running = False
attack_types = ["DDoS", "SQL Injection", "Port Scanning", "None"]
recent_predictions = []
live_traffic_buffer = []  # Buffer for recent live traffic data

def analyze_traffic(traffic):
    try:
        features = [traffic["packet_size"], traffic["protocol"], 
                    traffic["flags"], traffic["ttl"], traffic["anomaly"]]
        prediction = quantum_clf.predict(features)
        attack_type = attack_types[prediction] if prediction == 1 else "None"
        true_label = 1 if traffic["packet_size"] > 1000 or traffic["ttl"] < 50 else 0
        rl_agent.update(prediction, true_label)
        recent_predictions.append(prediction)
        if len(recent_predictions) > 10:
            quantum_clf.adjust_threshold(recent_predictions[-10:])
        threat_score = (prediction * 0.5) + (traffic["packet_size"] / 2000) + (1 - traffic["ttl"] / 255)
        logging.info(f"Traffic analyzed: Prediction={prediction}, Attack={attack_type}, Score={threat_score:.2f}")
        return prediction, attack_type, min(max(threat_score, 0), 1)
    except Exception as e:
        logging.error(f"Error analyzing traffic: {e}")
        return 0, "None", 0.0

def log_traffic(traffic, prediction, attack_type, threat_score):
    log_entry = (f"Timestamp: {traffic['timestamp']}\n"
                 f"Source IP: {traffic['source_ip']}, Dest IP: {traffic['dest_ip']}\n"
                 f"Source MAC: {traffic['source_mac']}, Dest MAC: {traffic['dest_mac']}\n"
                 f"Source Port: {traffic['source_port']}, Dest Port: {traffic['dest_port']}\n"
                 f"Packet Size: {traffic['packet_size']}, Protocol: {traffic['protocol']}\n"
                 f"Flags: {traffic['flags']}, TTL: {traffic['ttl']}\n"
                 f"Direction: {traffic['direction']}, Encrypted: {traffic['encrypted']}\n"
                 f"Hash: {traffic['hash']}, Active: {traffic['active']}\n"
                 f"Attack Type: {attack_type}, Threat Score: {threat_score:.2f}\n"
                 f"----------------------------------------\n")
    log_file = "safe_traffic.log" if prediction == 0 else "unsafe_traffic.log"
    try:
        logging.info(f"Attempting to write to {log_file}")
        # Ensure file exists and is writable
        if not os.path.exists(log_file):
            open(log_file, "w").close()
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)
        logging.info(f"Successfully wrote to {log_file}: {log_entry[:50]}...")
        # Verify file content
        with open(log_file, "r", encoding="utf-8") as f:
            content = f.read()
        if log_entry not in content:
            logging.warning(f"Log entry not found in {log_file} after write")
    except PermissionError as e:
        logging.error(f"Permission denied writing to {log_file}: {e}")
    except Exception as e:
        logging.error(f"Error writing to {log_file}: {e}")

def save_to_json(traffic):
    json_file = "traffic_data.json"
    try:
        if os.path.exists(json_file):
            with open(json_file, "r") as f:
                data = json.load(f)
        else:
            data = []
        data.append(traffic)
        with open(json_file, "w") as f:
            json.dump(data, f, indent=4)
        logging.info(f"Traffic saved to {json_file}")
    except Exception as e:
        logging.error(f"Error saving to {json_file}: {e}")

def run_ids():
    global running, live_traffic_buffer
    while running:
        try:
            traffic = capture_traffic_real_time()
            if traffic:
                prediction, attack_type, threat_score = analyze_traffic(traffic)
                status = "Safe" if prediction == 0 else "Unsafe"
                traffic_data = {**traffic, "status": status, "attack_type": attack_type, "threat_score": threat_score}
                live_traffic_buffer.append(traffic_data)
                if len(live_traffic_buffer) > 10:  # Keep only last 10 entries
                    live_traffic_buffer.pop(0)
                blockchain.add_block(traffic_data)
                log_traffic(traffic, prediction, attack_type, threat_score)
                save_to_json(traffic_data)
                logging.info(f"Processed real-time traffic: {traffic['timestamp']}")
            else:
                logging.warning("No traffic captured in this cycle")
            time.sleep(0.5)
        except Exception as e:
            logging.error(f"Error in run_ids loop: {e}")
            time.sleep(1)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start():
    global running
    if not running:
        running = True
        Thread(target=run_ids, daemon=True).start()
        logging.info("IDS started")
        return jsonify({"message": "IDS started - Analyzing real-time traffic"})
    return jsonify({"message": "IDS already running"})

@app.route('/stop', methods=['POST'])
def stop():
    global running
    if running:
        running = False
        blockchain.save_chain()
        logging.info("IDS stopped")
        return jsonify({"message": "IDS stopped"})
    return jsonify({"message": "IDS not running"})

@app.route('/reset', methods=['POST'])
def reset():
    global running, recent_predictions, live_traffic_buffer
    running = False
    recent_predictions = []
    live_traffic_buffer = []
    try:
        for file in ["safe_traffic.log", "unsafe_traffic.log", "traffic_data.json", "traffic_chain.json"]:
            if os.path.exists(file):
                open(file, "w").close()
                logging.info(f"Cleared {file}")
        blockchain.reset_chain()  # Adjust if needed
        logging.info("System reset successfully")
        return jsonify({"message": "System reset successfully"})
    except Exception as e:
        logging.error(f"Error during reset: {e}")
        return jsonify({"message": "Error resetting system"}), 500

@app.route('/logs')
def get_logs():
    try:
        with open("safe_traffic.log", "r", encoding="utf-8") as f:
            safe = f.read() or "No safe traffic logged yet."
        logging.info("Safe traffic log read successfully")
    except Exception as e:
        logging.error(f"Error reading safe_traffic.log: {e}")
        safe = "No safe traffic logged yet."
    try:
        with open("unsafe_traffic.log", "r", encoding="utf-8") as f:
            unsafe = f.read() or "No unsafe traffic logged yet."
        logging.info("Unsafe traffic log read successfully")
    except Exception as e:
        logging.error(f"Error reading unsafe_traffic.log: {e}")
        unsafe = "No unsafe traffic logged yet."
    try:
        # Use live_traffic_buffer for real-time graph data
        graph_data = [
            {
                "time": t["timestamp"],
                "unsafe": 1 if t["status"] == "Unsafe" else 0,
                "threat_score": t["threat_score"]
            } 
            for t in live_traffic_buffer[-10:]
        ]
        logging.info(f"Graph data prepared: {len(graph_data)} entries")
    except Exception as e:
        logging.error(f"Error preparing graph data: {e}")
        graph_data = []
    try:
        with open("traffic_chain.json", "r") as f:
            blockchain_data = json.load(f)
    except Exception as e:
        logging.error(f"Error reading traffic_chain.json: {e}")
        blockchain_data = []
    prediction = "WARNING: Potential attack predicted!" if predictor.predict_next() else "No threats predicted."
    return jsonify({
        "safe": safe,
        "unsafe": unsafe,
        "blockchain": blockchain_data,
        "prediction": prediction,
        "graph": graph_data
    })

if __name__ == "__main__":
    # Initialize logs
    for file in ["safe_traffic.log", "unsafe_traffic.log"]:
        try:
            open(file, "w").close()
            logging.info(f"Initialized {file}")
        except Exception as e:
            logging.error(f"Error initializing {file}: {e}")
    logging.info("Starting Flask app")
    app.run(debug=True, host="0.0.0.0", port=5000)