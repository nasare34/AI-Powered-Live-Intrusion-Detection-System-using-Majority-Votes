from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
import re
import pickle
import pandas as pd
import numpy as np
from PyPDF2 import PdfReader
from docx import Document
from scapy.all import sniff, hexdump, IP, TCP, UDP, ICMP
from sklearn.preprocessing import StandardScaler, LabelEncoder
import threading
import time
from collections import deque

# Define the Flask application
app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure the uploads folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- Global variables and model loading ---
all_packets_data = []

try:
    with open('KNN_Classifier.pkl', 'rb') as f:
        KNN_Classifier = pickle.load(f)

    with open('BNB_Classifier.pkl', 'rb') as f:
        BNB_Classifier = pickle.load(f)

    with open('DTC_Classifier.pkl', 'rb') as f:
        DTC_Classifier = pickle.load(f)

    with open('StandardScaler.pkl', 'rb') as f:
        scaler = pickle.load(f)

    with open('LabelEncoder_class.pkl', 'rb') as f:
        le = pickle.load(f)

    with open('Features.pkl', 'rb') as f:
        selected_features = pickle.load(f)

    all_categorical_features = ['protocol_type', 'service', 'flag']
    categorical_features_in_model = [f for f in selected_features if f in all_categorical_features]
    numerical_features_in_model = [f for f in selected_features if f not in all_categorical_features]

    label_encoders = {
        'protocol_type': {'tcp': 1, 'udp': 2, 'icmp': 0},
        'service': {'ftp_data': 1, 'other': 2, 'private': 3, 'http': 4, 'vmnet': 5, 'eco_i': 6},
        'flag': {'SF': 2, 'REJ': 1, 'S0': 0}
    }

    print("All models and preprocessing objects loaded successfully!")
    print(f"Model expects {len(selected_features)} features: {selected_features}")

except FileNotFoundError as e:
    print(f"Error loading model files: {e}. Please ensure all .pkl files are in the same directory.")
    exit()

# --- New Global variables for live capture ---
is_capturing = False
capture_thread = None
capture_stop_event = threading.Event()
# Use a deque to store a limited number of packets for display
captured_packets_log = deque(maxlen=100)
# A lock to safely access the captured_packets_log from multiple threads
log_lock = threading.Lock()


# --- Helper Functions ---
def get_packet_features(pkt):
    """
    Extracts features from a Scapy packet object to match the model's expected input.
    """
    if IP in pkt:
        ip_layer = pkt[IP]

        # Determine protocol and service
        protocol = "other"
        service = "other"
        flag = "S0"  # Default flag for simplicity

        if TCP in pkt:
            protocol = "tcp"
            tcp_layer = pkt[TCP]
            # Use flags string to determine the flag for our model
            flag_str = tcp_layer.sprintf("%TCP.flags%")
            if "S" in flag_str and "A" in flag_str:
                flag = "SF"  # SYN-ACK
            elif "R" in flag_str and "A" in flag_str:
                flag = "REJ"  # RST-ACK
            elif "S" in flag_str:
                flag = "S0"  # SYN

            if tcp_layer.dport == 80:
                service = "http"
            elif tcp_layer.dport == 21:
                service = "ftp_data"
            elif tcp_layer.dport == 23:
                service = "telnet"
            else:
                service = "other"

        elif UDP in pkt:
            protocol = "udp"
            udp_layer = pkt[UDP]
            if udp_layer.dport == 53:
                service = "domain_udp"
            else:
                service = "other"

        elif ICMP in pkt:
            protocol = "icmp"
            service = "eco_i"  # For echo-request

        # Simplified feature values. In a real scenario, these would be calculated over a time window.
        features = {
            'duration': 0, 'src_bytes': len(ip_layer.payload), 'dst_bytes': 0,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0,
            'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0,
            'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1,
            'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0, 'dst_host_count': 1, 'dst_host_srv_count': 1,
            'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 1.0, 'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0,
            'protocol_type': protocol, 'service': service, 'flag': flag
        }

        # Add src_ip, dst_ip, and timestamp for the alert system and display
        features['src_ip'] = ip_layer.src
        features['dst_ip'] = ip_layer.dst
        features['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pkt.time))

        # Filter features to match the model's `selected_features`
        return {k: features.get(k, 0) for k in selected_features + ['src_ip', 'dst_ip', 'time']}

    return None


def preprocess_and_predict_raw(input_data_dict):
    """
    Preprocesses a single data point and makes a prediction using the loaded models.
    Assumes input_data_dict is a dictionary with keys matching the selected_features list.
    """
    try:
        # Create a DataFrame from the dictionary, ensuring column order matches selected_features
        df = pd.DataFrame([input_data_dict])[selected_features]

        # Separate numerical and categorical features
        numerical_data = df[numerical_features_in_model]
        categorical_data = df[categorical_features_in_model]

        # Standard scale the numerical data
        sc_numerical = scaler.transform(numerical_data)
        sc_numerical_df = pd.DataFrame(sc_numerical, columns=numerical_features_in_model)

        # Label encode the categorical data
        en_categorical = categorical_data.copy()
        for col in categorical_features_in_model:
            en_categorical[col] = en_categorical[col].map(label_encoders[col])

        # Concatenate the processed features
        df_processed = pd.concat([sc_numerical_df, en_categorical], axis=1)

        # Get predictions from each model
        pred_knn = le.inverse_transform(KNN_Classifier.predict(df_processed))[0]
        pred_NB = le.inverse_transform(BNB_Classifier.predict(df_processed))[0]
        pred_dt = le.inverse_transform(DTC_Classifier.predict(df_processed))[0]

        predictions = [pred_knn, pred_NB, pred_dt]

        # Implement majority voting
        anomaly_count = predictions.count('anomaly')
        normal_count = predictions.count('normal')

        if anomaly_count >= normal_count:
            final_prediction = 'anomaly'
        else:
            final_prediction = 'normal'

        # The 'is_unanimous_anomaly' flag is no longer the sole trigger for a red alert.
        # We can keep it for more granular logging if needed.
        is_unanimous_anomaly = (anomaly_count == 3)

        return {
            'predictions': {'KNN': pred_knn, 'Naive Bayes': pred_NB, 'Decision Tree': pred_dt},
            'final_prediction': final_prediction,
            'is_unanimous_anomaly': is_unanimous_anomaly
        }

    except Exception as e:
        print(f"Prediction Error (Raw Input): {e}")
        return None


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['pdf', 'docx', 'csv']


# --- Live Capture Functions ---
def packet_callback(pkt):
    """Callback function for Scapy sniff(). Processes and predicts on a single packet."""
    if IP in pkt:
        # Extract features and meta-data from the packet
        features_dict = get_packet_features(pkt)

        if features_dict:
            # Create a dictionary to hold data for the dashboard
            dashboard_data = {
                'timestamp': features_dict.get('time'),
                'src_ip': features_dict.get('src_ip', 'Unknown'),
                'dst_ip': features_dict.get('dst_ip', 'Unknown'),
                'protocol': features_dict.get('protocol_type', 'unknown'),
                'service': features_dict.get('service', 'unknown')
            }

            # Remove metadata before passing to the model for prediction
            model_input = {k: v for k, v in features_dict.items() if k in selected_features}

            prediction_result = preprocess_and_predict_raw(model_input)

            if prediction_result:
                # Add prediction results to the dashboard data
                dashboard_data.update(prediction_result)

                # Use a lock to ensure thread-safe access to the global deque
                with log_lock:
                    captured_packets_log.appendleft(dashboard_data)


def live_capture_thread(interface):
    """
    Sniffs packets from the specified interface until the stop event is set.
    """
    global is_capturing
    is_capturing = True
    print(f"Starting live capture on interface: {interface}")

    try:
        sniff(iface=interface, prn=packet_callback, store=0, stop_filter=lambda x: capture_stop_event.is_set(),
              timeout=600)
    except Exception as e:
        print(f"Error during live capture: {e}")
        # In a real app, you might push this error to a queue for the main thread to display
    finally:
        is_capturing = False
        capture_stop_event.clear()
        print("Live capture stopped.")


# --- Flask Routes ---
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/predict_input', methods=['POST'])
def predict_input():
    if request.method == 'POST':
        packet_str = request.form.get('packet_input')

        if not packet_str:
            flash("Please enter packet data.", 'error')
            return redirect(url_for('index'))

        try:
            input_data_list = re.split(r'[,\s]+', packet_str.strip())
            input_data_dict = dict(zip(selected_features, input_data_list))

            if len(input_data_dict) != len(selected_features):
                flash(
                    "The number of features provided does not match the model's requirements. Please provide all 40 features.",
                    'error')
                return redirect(url_for('index'))

            result = preprocess_and_predict_raw(input_data_dict)

            if result:
                pred_str = ", ".join([f"{k}: {v}" for k, v in result['predictions'].items()])

                if result['final_prediction'] == 'anomaly':
                    flash(
                        f"🚨 ANOMALY DETECTED! A potential network security event, such as a **malicious payload** or **exfiltration attempt**, has been identified. Individual predictions: [{pred_str}] -> Final: {result['final_prediction']}. Take immediate action: review your network logs and consider activating your firewall. ⚠️",
                        'alert')
                else:
                    flash(f"✅ Individual predictions: [{pred_str}] -> Final: {result['final_prediction']}", 'success')
            else:
                flash("An error occurred during prediction. Please check the server logs for details.", 'error')

        except Exception as e:
            flash(f"An unexpected error occurred: {e}", 'error')

        return redirect(url_for('index'))


@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash("No file part", 'error')
        return redirect(url_for('index'))

    file = request.files['file']

    if file.filename == '':
        flash("No selected file", 'error')
        return redirect(url_for('index'))

    if file and allowed_file(file.filename):
        filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filename)

        if file.filename.endswith('.csv'):
            df = pd.read_csv(filename)
            df_processed = df[selected_features]

            first_packet_dict = df_processed.iloc[0].to_dict()

            result = preprocess_and_predict_raw(first_packet_dict)

            if result:
                pred_str = ", ".join([f"{k}: {v}" for k, v in result['predictions'].items()])

                if result['final_prediction'] == 'anomaly':
                    flash(
                        f"🚨 ANOMALY DETECTED IN FILE! The first packet in your document indicates a potential **network intrusion** or **reconnaissance attempt**. Individual predictions: [{pred_str}] -> Final: {result['final_prediction']}. Proceed with caution: analyze the packet metadata and review host activity. ⚠️",
                        'alert')
                else:
                    flash(f"✅ Individual predictions: [{pred_str}] -> Final: {result['final_prediction']}", 'success')

            else:
                flash("An error occurred during file prediction. Please check the server logs.", 'error')

            return redirect(url_for('index'))
        else:
            text_content = ""
            if file.filename.endswith('.pdf'):
                reader = PdfReader(filename)
                for page in reader.pages:
                    text_content += page.extract_text() or ''
            elif file.filename.endswith('.docx'):
                doc = Document(filename)
                for paragraph in doc.paragraphs:
                    text_content += paragraph.text + '\n'

            values_from_file = [v.strip() for v in re.split(r'[,\s]+', text_content) if v.strip()]

            if len(values_from_file) == len(selected_features):
                input_data_dict = dict(zip(selected_features, values_from_file))

                result = preprocess_and_predict_raw(input_data_dict)

                if result:
                    pred_str = ", ".join([f"{k}: {v}" for k, v in result['predictions'].items()])

                    if result['final_prediction'] == 'anomaly':
                        flash(
                            f"🚨 ANOMALY DETECTED IN DOCUMENT! The extracted data points suggest a **suspicious network flow** with a high probability of malicious activity. Individual predictions: [{pred_str}] -> Final: {result['final_prediction']}. Be vigilant: check for unauthorized data access and review the source of this data. ⚠️",
                            'alert')
                    else:
                        flash(f"✅ Individual predictions: [{pred_str}] -> Final: {result['final_prediction']}",
                              'success')
                else:
                    flash("An error occurred during file processing.", 'error')
            else:
                flash("The number of features found in the document does not match the model's requirements.", 'error')

        return redirect(url_for('index'))
    else:
        flash("Invalid file type. Please upload a PDF, DOCX, or CSV file.", 'error')
        return redirect(url_for('index'))


@app.route('/capture_packet', methods=['POST'])
def capture_packet():
    """
    This old route is now a placeholder. The user's form has been updated
    to redirect to the live capture dashboard directly.
    """
    flash("This feature has been upgraded. Please use the Live Capture Dashboard.", 'info')
    return redirect(url_for('index'))


# --- New Routes for Live Capture Dashboard ---
@app.route('/live_capture')
def live_capture_dashboard():
    """Renders the live packet capture dashboard."""
    global is_capturing
    interface = request.args.get('interface', 'eth0')
    return render_template('live_capture.html', is_capturing=is_capturing, interface=interface)


@app.route('/start_capture/<interface>')
def start_capture(interface):
    """Starts the live packet capture in a background thread."""
    global capture_thread, is_capturing, capture_stop_event

    if not is_capturing:
        capture_stop_event.clear()
        capture_thread = threading.Thread(target=live_capture_thread, args=(interface,))
        capture_thread.daemon = True
        capture_thread.start()
        flash(f"Started live capture on interface '{interface}'.", 'success')
    else:
        flash("A capture is already running. Please stop it first.", 'error')

    return redirect(url_for('live_capture_dashboard', interface=interface))


@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    """Stops the live packet capture."""
    global is_capturing, capture_stop_event, captured_packets_log

    if is_capturing:
        capture_stop_event.set()
        flash("Live capture is being stopped. It may take a moment...", 'success')
    else:
        flash("No capture is currently running.", 'error')

    # Wait for the thread to finish
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=5)  # give it 5 seconds to finish gracefully
        if capture_thread and capture_thread.is_alive():
            print("Warning: Capture thread did not stop gracefully.")

    # After stopping, clear the logs for a fresh start on the next capture.
    with log_lock:
        captured_packets_log.clear()

    return redirect(url_for('live_capture_dashboard'))


@app.route('/api/packets')
def get_packets():
    """API endpoint to get the latest captured packets."""
    global captured_packets_log
    with log_lock:
        # Convert deque to a list and return as JSON
        # Reverse the list to show the newest packets at the top
        return jsonify(list(captured_packets_log))


@app.route('/api/status')
def get_status():
    """API endpoint to get the current capture status."""
    global is_capturing
    return jsonify({'is_capturing': is_capturing})


# New route for the "How to use the app" page
@app.route('/howto')
def howto():
    return render_template('howto.html')


if __name__ == '__main__':
    app.run(debug=True, threaded=True)

