
"""
AEGIS Agent - Blue Team Defensive AI
Anomaly detection agent that learns normal behavior and detects threats
"""

import numpy as np
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.exceptions import NotFittedError
import json, os, threading

class AegisAgent:
    def __init__(self, llm_wrapper=None, log_path='logs/aegis_log.json', opponent_log_path='logs/lynx_log.json', input_dim=8):
        self.llm = llm_wrapper
        self.log_path = log_path
        self.opponent_log_path = opponent_log_path
        self.input_dim = input_dim
        self.anomaly_threshold = 0.5
        self.epochs = 10
        self.batch_size = 16
        self.hidden_layers = [16, 8]
        self.autoencoder = None
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.normal_traffic = []
        self.anomalous_traffic = []
        self.detection_history = []
        self.detections = 0
        self.false_positives = 0
        self.true_positives = 0
        self.false_negatives = 0
        self._model_lock = threading.RLock()
        self._build_autoencoder()

    def _build_autoencoder(self):
        try:
            from tensorflow import keras
        except ImportError:
            self.autoencoder = None
            return
        input_layer = keras.layers.Input(shape=(self.input_dim,))
        encoded = input_layer
        for units in self.hidden_layers:
            encoded = keras.layers.Dense(units, activation='relu')(encoded)
            encoded = keras.layers.Dropout(0.2)(encoded)
        decoded = encoded
        for units in reversed(self.hidden_layers):
            decoded = keras.layers.Dense(units, activation='relu')(decoded)
            decoded = keras.layers.Dropout(0.2)(decoded)
        decoded = keras.layers.Dense(self.input_dim, activation='sigmoid')(decoded)
        self.autoencoder = keras.Model(input_layer, decoded)
        self.autoencoder.compile(optimizer=keras.optimizers.Adam(learning_rate=0.001), loss='mse')

    def _extract_features(self, attack_entry):
        # Build a fixed-length numeric feature vector from the attack entry
        features = np.zeros(self.input_dim)
        # Type indicators
        try:
            atype = attack_entry.get('type', '')
        except Exception:
            atype = ''
        features[0] = 1.0 if atype == 'XSS' else 0.0
        features[1] = 1.0 if atype == 'API Abuse' else 0.0
        features[2] = 1.0 if atype == 'Bypass Authentication' else 0.0
        features[3] = 1.0 if atype == 'Exploit Server Error' else 0.0
        features[4] = 1.0 if atype == 'Reconnaissance' else 0.0
        # Use presence of 'success' flag if provided (may come from Lynx/Aegis logs)
        try:
            features[5] = 1.0 if attack_entry.get('success') else 0.0
        except Exception:
            features[5] = 0.0
        # Support both 'payload' (Aegis logs) and 'description' (Lynx logs)
        payload_text = ''
        try:
            payload_text = attack_entry.get('payload') or attack_entry.get('description') or ''
        except Exception:
            payload_text = ''
        features[6] = len(payload_text) / 100.0 if payload_text else 0.0
        # Look for obvious indicators (malicious keyword or script tags)
        pt = payload_text.lower()
        features[7] = 1.0 if ('malicious' in pt or '<script' in pt or 'alert(' in pt or 'cookie' in pt) else 0.0
        return features

    def inspect_request(self, url, attack_entry):
        # Use LLM to classify if incoming request is an attack
        is_attack = None
        if self.llm and getattr(self.llm, 'query', None):
            prompt = f"Is the following request an attack? Details: {attack_entry}. Respond with 'attack' or 'benign'."
            try:
                llm_result = self.llm.query(prompt)
                if isinstance(llm_result, str) and 'attack' in llm_result.lower():
                    is_attack = True
                elif isinstance(llm_result, str) and 'benign' in llm_result.lower():
                    is_attack = False
            except Exception as e:
                print(f"AEGIS: LLM classification failed: {e}")
                is_attack = None
        # Fallback to dynamic defense if LLM is unavailable or uncertain
        if is_attack is None:
            # Load previous defense logs and block similar attacks
            try:
                with open(self.log_path, 'r') as f:
                    logs = json.load(f)
            except Exception:
                logs = []
            # Block if a similar attack type/sub_type/payload was previously blocked
            for entry in logs:
                if not isinstance(entry, dict):
                    continue
                same_type = (entry.get('type') == attack_entry.get('type') and entry.get('sub_type') == attack_entry.get('sub_type'))
                same_payload = (entry.get('payload') == attack_entry.get('description'))
                # If previous defense marked that a similar request was blocked (success=True), treat as attack
                if same_type or same_payload:
                    if entry.get('success', False):
                        is_attack = True
                        break
            # If not found in logs, fallback to anomaly detection
        if is_attack is None:
            features = self._extract_features(attack_entry)
            try:
                features_scaled = self.scaler.transform(features.reshape(1, -1))
            except NotFittedError:
                baseline = np.vstack([
                    np.clip(features + np.random.normal(0, 0.01, size=self.input_dim), 0, 1)
                    for _ in range(16)
                ])
                self.scaler.fit(baseline)
                features_scaled = self.scaler.transform(features.reshape(1, -1))
            try:
                isolation_score = self.isolation_forest.decision_function(features_scaled)[0]
                isolation_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
            except NotFittedError:
                baseline = np.vstack([
                    np.clip(features + np.random.normal(0, 0.02, size=self.input_dim), 0, 1)
                    for _ in range(64)
                ])
                self.isolation_forest.fit(baseline)
                isolation_score = self.isolation_forest.decision_function(features_scaled)[0]
                isolation_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
            anomaly_score = 1 - isolation_score
            is_attack = anomaly_score > self.anomaly_threshold or isolation_anomaly
        # Log in required format
        # success=True indicates the defense detected/blocked an attack
        log_entry = {
            "time": attack_entry.get("time", datetime.utcnow().isoformat()),
            "type": attack_entry.get("type", "Unknown"),
            "sub_type": attack_entry.get("sub_type", "Unknown"),
            "payload": attack_entry.get("description", attack_entry.get("payload", "Unknown")),
            "success": bool(is_attack)
        }
        self._log_defense(log_entry)
        return 'block' if is_attack else 'allow'

    def _log_defense(self, entry):
        log_dir = os.path.dirname(self.log_path)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        if not os.path.exists(self.log_path):
            with open(self.log_path, 'w') as f:
                json.dump([], f)
        try:
            with open(self.log_path, 'r') as f:
                logs = json.load(f)
        except Exception:
            logs = []
        logs.append(entry)
        with open(self.log_path, 'w') as f:
            json.dump(logs, f, indent=2)

    def learn(self):
        pass
