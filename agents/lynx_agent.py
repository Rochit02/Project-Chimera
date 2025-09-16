"""
LYNX Agent - Red Team Offensive AI
Reinforcement Learning agent that continuously searches for vulnerabilities
"""

import os
import json
import random
import threading
from collections import deque
from datetime import datetime
from typing import Dict, List
import socket
import asyncio

try:
    import numpy as np
    import tensorflow as tf
    from tensorflow import keras
except Exception:
    np = None
    tf = None
    keras = None
    print("LYNX: TensorFlow/NumPy not available; running in lightweight fallback mode (no neural networks)")

# Optional config import
try:
    from py_agents.config import LYNX_CONFIG
except Exception:
    # Fallback config
    LYNX_CONFIG = {
        "learning_rate": 0.001,
        "exploration_rate": 0.2,
        "memory_size": 1000,
        "batch_size": 16,
        "target_update_freq": 10,
        "attack_types": ["XSS", "API Abuse", "Generic Attack", "Bypass Authentication", "Exploit Server Error", "Reconnaissance"]
    }

# Placeholder LLM helper fallback
class _LLMStub:
    enabled = False
    def query(self, prompt: str) -> str:
        return "LLM not configured"

try:
    from py_agents.llm_helper import llm_helper
except Exception:
    llm_helper = _LLMStub()

class LynxAgent:
    def __init__(self, state_size: int = 10, action_size: int = None, llm_wrapper=None, log_path='logs/lynx_log.json', opponent_log_path='logs/aegis_log.json'):
        self.state_size = state_size
        self.action_size = action_size or len(LYNX_CONFIG["attack_types"]) if LYNX_CONFIG and "attack_types" in LYNX_CONFIG else 6
        self.learning_rate = LYNX_CONFIG.get("learning_rate", 0.001)
        self.epsilon = LYNX_CONFIG.get("exploration_rate", 0.2)
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.995
        self.memory = deque(maxlen=LYNX_CONFIG.get("memory_size", 1000))
        self.batch_size = LYNX_CONFIG.get("batch_size", 16)
        self.target_update_freq = LYNX_CONFIG.get("target_update_freq", 10)
        self.update_count = 0

        self.attack_types = set(LYNX_CONFIG.get("attack_types", [
            # ...existing code...
            "UDP Flood", "ICMP Flood", "SYN Flood", "Ping of Death", "Smurf Attack",
            "HTTP Flood", "Slowloris", "RUDY",
            "SQL Injection", "NoSQL Injection", "OS Command Injection", "LDAP Injection", "XXE Injection", "Code Injection", "SSTI",
            "Brute Force", "Dictionary Attack", "Credential Stuffing", "Password Spraying", "Session Hijacking", "MitM Attack", "SSRF",
            "Path Traversal", "File Inclusion", "LFI", "RFI",
            "Ransomware", "Web Shell", "Rootkit", "Trojan", "Cryptojacking",
            "Known Vulnerability Exploit", "Insecure Deserialization", "Security Misconfiguration", "Default Credentials", "Directory Listing", "Improper Error Handling",
            "DNS Spoofing", "DNS Tunneling",
            "ReDoS", "TOCTOU", "Prototype Pollution", "HTTP Request Smuggling", "XML Bomb", "Padding Oracle", "Web Cache Poisoning", "CORS Misconfiguration",
            "XSS", "API Abuse", "Generic Attack", "Bypass Authentication", "Exploit Server Error", "Reconnaissance"
        ]))

        self.llm = llm_wrapper or llm_helper
        self.log_path = os.path.abspath(log_path)
        self.opponent_log_path = os.path.abspath(opponent_log_path)

        # Store successful LLM payloads for future learning
        self.llm_payload_memory = deque(maxlen=100)

        # Model placeholders
        self.q_network = None
        self.target_network = None
        if keras is not None and np is not None:
            try:
                self.q_network = self._build_network()
                self.target_network = self._build_network()
                self._update_target_network()
            except Exception as e:
                print(f"LYNX: Failed to build neural networks: {e}")
                self.q_network = None
                self.target_network = None

        # Stats
        self.attack_history = []
        self.successful_attacks = 0
        self.total_attempts = 0

        # Ensure log file exists
        self._ensure_log_file()

        # Model lock
        self._model_lock = threading.RLock()
        # Port scan configuration: enable/disable and default ports
        self.port_scan_enabled = LYNX_CONFIG.get('port_scan_enabled', True)
        # default common ports (tcp)
        self.port_scan_ports = LYNX_CONFIG.get('port_scan_ports', [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080])

    def _ensure_log_file(self):
        log_dir = os.path.dirname(self.log_path)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        if not os.path.exists(self.log_path):
            with open(self.log_path, 'w') as f:
                json.dump([], f)

    def _build_network(self):
        if keras is None or np is None:
            return None
        model = keras.Sequential([
            keras.layers.Dense(128, activation='relu', input_shape=(self.state_size,)),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(64, activation='relu'),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(32, activation='relu'),
            keras.layers.Dense(self.action_size, activation='linear')
        ])
        model.compile(optimizer=keras.optimizers.Adam(learning_rate=self.learning_rate), loss='mse')
        return model

    def _update_target_network(self):
        if self.q_network is not None and self.target_network is not None:
            self.target_network.set_weights(self.q_network.get_weights())

    async def _tcp_scan_host(self, host: str, ports: List[int], timeout: float = 0.5) -> List[int]:
        """Asynchronously scan TCP ports on host and return list of open ports."""
        open_ports = []
        # Resolve host to avoid repeated DNS lookups
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None)
        except Exception:
            infos = None

        async def _scan(port: int):
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout)
                try:
                    open_ports.append(port)
                finally:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
            except Exception:
                return

        # Limit concurrency
        semaphore = asyncio.Semaphore(200)
        async def _bounded_scan(p):
            async with semaphore:
                await _scan(p)

        tasks = [asyncio.create_task(_bounded_scan(p)) for p in ports]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return sorted(open_ports)

    def _tcp_port_scan_sync(self, host: str, ports: List[int], timeout: float = 0.5):
        """Synchronous wrapper around async TCP port scanner. Returns dict with results."""
        try:
            # Create and run a new event loop to avoid interfering with any running loop
            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                open_ports = loop.run_until_complete(self._tcp_scan_host(host, ports, timeout))
            finally:
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except Exception:
                    pass
                loop.close()
            return {"open_ports": open_ports}
        except Exception as e:
            return {"error": str(e)}

    def choose_action(self, state: List[float]) -> int:
        # Epsilon-greedy
        if random.random() <= self.epsilon or self.q_network is None:
            return random.randint(0, self.action_size - 1)
        try:
            arr = np.array(state).reshape(1, -1)
            qv = self.q_network.predict(arr, verbose=0)
            return int(np.argmax(qv[0]))
        except Exception:
            return random.randint(0, self.action_size - 1)

    def generate_payload(self, attack_type: str, sub_type: str, url: str) -> str:
        # Use LLM to generate payload if available
        payload = None
        if self.llm and getattr(self.llm, 'query', None):
            prompt = f"Generate an attack payload for type: {attack_type}, sub_type: {sub_type}, target URL: {url}."
            try:
                payload = self.llm.query(prompt)
                if payload and isinstance(payload, str):
                    # Learn from LLM payloads: store for future use
                    self.llm_payload_memory.append(payload)
                    return payload
            except Exception as e:
                print(f"LYNX: LLM payload generation failed: {e}")
        # If LLM payloads exist and are successful, reuse/adapt them
        if self.llm_payload_memory:
            # Select a random successful LLM payload
            return random.choice(list(self.llm_payload_memory))
        # If attack history exists, dynamically craft payloads from previous successful attacks
        successful_payloads = [entry['description'] for entry in getattr(self, 'attack_history', []) if entry.get('success')]
        if successful_payloads:
            candidates = [p for p in successful_payloads if attack_type in p or sub_type in p]
            if candidates:
                base = random.choice(candidates)
                return f"{base}--{url[-5:]}"
            else:
                return random.choice(successful_payloads)
        # Fallback to static payloads for all supported attack types
        static_payloads = {
            # DoS/DDoS
            "UDP Flood": f"UDP flood packets to {url}",
            "ICMP Flood": f"ICMP ping flood to {url}",
            "SYN Flood": f"SYN flood packets to {url}",
            "Ping of Death": f"Oversized ping packets to {url}",
            "Smurf Attack": f"ICMP echo requests with spoofed source to {url}",
            "HTTP Flood": f"Massive HTTP GET requests to {url}",
            "Slowloris": f"Slow HTTP headers to {url}",
            "RUDY": f"Slow POST requests to {url}",
            # Injection
            "SQL Injection": f"' OR '1'='1'; -- on {url}",
            "NoSQL Injection": f'{{"$ne":null}} on {url}',
            "OS Command Injection": f"; cat /etc/passwd on {url}",
            "LDAP Injection": f"*)(uid=*))(|(uid=*)) on {url}",
            "XXE Injection": f"<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo> on {url}",
            "Code Injection": f"{{7*7}} on {url}",
            "SSTI": f"{{7*7}} on {url}",
            # Auth & Access Control
            "Brute Force": f"Automated password attempts on {url}",
            "Dictionary Attack": f"Dictionary-based password attempts on {url}",
            "Credential Stuffing": f"Known credentials on {url}",
            "Password Spraying": f"Common passwords on {url}",
            "Session Hijacking": f"Steal session cookie from {url}",
            "MitM Attack": f"Intercept traffic to {url}",
            "SSRF": f"Request internal resource via {url}",
            # File & Directory
            "Path Traversal": f"../../etc/passwd on {url}",
            "File Inclusion": f"/etc/passwd included via {url}",
            "LFI": f"Local file inclusion on {url}",
            "RFI": f"Remote file inclusion from evil.com via {url}",
            # Malware
            "Ransomware": f"Encrypt files on {url}",
            "Web Shell": f"Upload web shell to {url}",
            "Rootkit": f"Install rootkit on {url}",
            "Trojan": f"Upload trojan to {url}",
            "Cryptojacking": f"Inject cryptominer into {url}",
            # Config & Vuln Exploits
            "Known Vulnerability Exploit": f"Exploit CVE on {url}",
            "Insecure Deserialization": f"Malicious serialized object to {url}",
            "Security Misconfiguration": f"Exploit misconfiguration on {url}",
            "Default Credentials": f"Login with admin:admin on {url}",
            "Directory Listing": f"Access / on {url} for directory listing",
            "Improper Error Handling": f"Trigger error for info leak on {url}",
            # DNS-Based
            "DNS Spoofing": f"Poison DNS cache for {url}",
            "DNS Tunneling": f"Tunnel data via DNS for {url}",
            # Other
            "ReDoS": f"Evil regex to {url}",
            "TOCTOU": f"Exploit race condition on {url}",
            "Prototype Pollution": f"Pollute prototype via {url}",
            "HTTP Request Smuggling": f"Smuggle HTTP requests to {url}",
            "XML Bomb": f"Billion Laughs XML to {url}",
            "Padding Oracle": f"Padding oracle attack on {url}",
            "Web Cache Poisoning": f"Poison cache via {url}",
            "CORS Misconfiguration": f"Exploit CORS on {url}",
            # Web
            "XSS": f'<script>alert("XSS on {url}")</script>',
            "API Abuse": '{"param":"malicious_value"}',
            "Generic Attack": f'Generic payload for {attack_type} on {url}',
            "Bypass Authentication": f'GET {url}/admin HTTP/1.1\nCookie: auth=malicious',
            "Exploit Server Error": f'POST {url} with payload causing 500 error',
            "Reconnaissance": f'GET {url}/robots.txt'
        }
        return static_payloads.get(attack_type, f'Generic payload for {attack_type} on {url}')

    def _log_attack(self, entry: Dict):
        try:
            with open(self.log_path, 'r') as f:
                logs = json.load(f)
        except Exception:
            logs = []
        logs.append(entry)
        try:
            with open(self.log_path, 'w') as f:
                json.dump(logs, f, indent=2)
            print(f"[LYNX] Logged attack to {self.log_path}")
        except Exception as e:
            print(f"[LYNX] Failed to write log: {e}")

    def attack(self, url: str) -> Dict:
        import requests
        now = datetime.utcnow().isoformat()
        scan_result = None
        # Optionally run a quick TCP port scan on the target host
        if self.port_scan_enabled:
            try:
                # Extract hostname from URL (simple)
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.hostname or url
                # run synchronous wrapper around asyncio scanner
                scan_result = self._tcp_port_scan_sync(host, ports=self.port_scan_ports, timeout=0.75)
            except Exception as e:
                scan_result = {'error': str(e)}
        try:
            resp = requests.get(url, timeout=5)
            status = resp.status_code
            ctype = resp.headers.get('Content-Type', '')
            response_text = resp.text if hasattr(resp, 'text') else ''
        except Exception as e:
            status = None
            ctype = ''
            response_text = ''

        # Use LLM for attack type/subtype decision if available
        if self.llm and getattr(self.llm, 'query', None):
            prompt = f"Given the following response status: {status}, content-type: {ctype}, and response: {response_text[:200]}, suggest the most effective attack type and sub_type."
            try:
                llm_decision = self.llm.query(prompt)
                if llm_decision and isinstance(llm_decision, str) and ':' in llm_decision:
                    parts = llm_decision.split(':')
                    attack_type = parts[0].strip()
                    sub_type = parts[1].strip() if len(parts) > 1 else 'Unknown'
                    if attack_type not in self.attack_types:
                        self.attack_types.add(attack_type)
                else:
                    attack_type = 'Reconnaissance'
                    sub_type = 'Info Gathering'
            except Exception as e:
                print(f"LYNX: LLM decision failed: {e}")
                attack_type = 'Reconnaissance'
                sub_type = 'Info Gathering'
        else:
            # Fallback to static decision logic
            if status == 200 and 'text/html' in ctype:
                attack_type = 'XSS'
                sub_type = 'Reflected XSS'
            elif status == 200 and 'application/json' in ctype:
                attack_type = 'API Abuse'
                sub_type = 'Parameter Tampering'
            elif status == 403:
                attack_type = 'Bypass Authentication'
                sub_type = '403 Bypass'
            elif status == 500:
                attack_type = 'Exploit Server Error'
                sub_type = '500 Exploit'
            elif status is None:
                attack_type = 'Reconnaissance'
                sub_type = 'Network Error'
            else:
                attack_type = 'Reconnaissance'
                sub_type = 'Info Gathering'
            # Use LLM to analyze response for forms, fields, directories, and vulnerabilities
            vuln_info = None
            if self.llm and getattr(self.llm, 'query', None):
                # Prompt LLM for analysis, encourage diversity
                analysis_prompt = (
                    f"Analyze the following HTTP response and suggest:\n"
                    f"1. Any forms, input fields, or directories you see.\n"
                    f"2. What type of attack (from this list: {list(self.attack_types)}) is most likely to succeed, and why.\n"
                    f"3. Suggest a specific payload for the attack.\n"
                    f"4. IMPORTANT: Do NOT always suggest XSS. Consider a variety of attack types (e.g., SQLi, SSRF, Auth Bypass, etc.) based on the context.\n"
                    f"Response status: {status}\nContent-Type: {ctype}\nBody (truncated):\n{response_text[:1000]}"
                )
                try:
                    llm_analysis = self.llm.query(analysis_prompt)
                    vuln_info = llm_analysis
                    # Try to extract attack type and payload from LLM response
                    attack_type = None
                    sub_type = None
                    payload = None
                    for line in llm_analysis.splitlines():
                        if 'attack type' in line.lower():
                            attack_type = line.split(':',1)[-1].strip()
                        elif 'sub-type' in line.lower():
                            sub_type = line.split(':',1)[-1].strip()
                        elif 'payload' in line.lower():
                            payload = line.split(':',1)[-1].strip()
                    # Avoid repeated XSS attacks
                    recent_attacks = [a['type'] for a in self.attack_history[-5:]] if hasattr(self, 'attack_history') else []
                    if attack_type == 'XSS' and recent_attacks.count('XSS') >= 2:
                        # Pick a different attack type from the list
                        alt_types = [t for t in self.attack_types if t != 'XSS']
                        if alt_types:
                            import random
                            attack_type = random.choice(list(alt_types))
                            sub_type = 'AutoDiversify'
                            payload = self.generate_payload(attack_type, sub_type, url)
                    if not attack_type:
                        attack_type = 'Reconnaissance'
                    if not sub_type:
                        sub_type = 'Info Gathering'
                    if not payload:
                        payload = self.generate_payload(attack_type, sub_type, url)
                    if attack_type not in self.attack_types:
                        self.attack_types.add(attack_type)
                except Exception as e:
                    print(f"LYNX: LLM analysis failed: {e}")
                    attack_type = 'Reconnaissance'
                    sub_type = 'Info Gathering'
                    payload = self.generate_payload(attack_type, sub_type, url)
            else:
                # Fallback to static decision logic
                if status == 200 and 'text/html' in ctype:
                    attack_type = 'XSS'
                    sub_type = 'Reflected XSS'
                elif status == 200 and 'application/json' in ctype:
                    attack_type = 'API Abuse'
                    sub_type = 'Parameter Tampering'
                elif status == 403:
                    attack_type = 'Bypass Authentication'
                    sub_type = '403 Bypass'
                elif status == 500:
                    attack_type = 'Exploit Server Error'
                    sub_type = '500 Exploit'
                elif status is None:
                    attack_type = 'Reconnaissance'
                    sub_type = 'Network Error'
                else:
                    attack_type = 'Reconnaissance'
                    sub_type = 'Info Gathering'
                payload = self.generate_payload(attack_type, sub_type, url)

        # Track consecutive failures for mutation and switching
        if not hasattr(self, '_fail_count'):
            self._fail_count = 0
            self._last_attack_type = None
        # Mutate payload if repeated failures
        payload = self.generate_payload(attack_type, sub_type, url)
        mutated = False
        if self._last_attack_type == attack_type and self._fail_count > 0:
            # Mutate payload by appending random string
            payload += f"--mut{random.randint(1000,9999)}"
            mutated = True

        # Actual sandbox evaluation: check if payload pattern appears in response
        success = False
        if attack_type == 'XSS' and payload in response_text:
            success = True
        elif attack_type == 'API Abuse' and 'malicious_value' in response_text:
            success = True
        elif attack_type == 'Bypass Authentication' and 'admin' in response_text:
            success = True
        elif attack_type == 'Exploit Server Error' and status == 500:
            success = True
        # Mark as successful if server response indicates vulnerability
        elif status in [500, 502, 503, 504]:
            success = True
        elif status == 403 and attack_type in ['Bypass Authentication', 'SSRF']:
            # If trying to bypass and get forbidden, may indicate partial success
            success = True
        elif status == 200 and any(err in response_text.lower() for err in ['syntax error', 'exception', 'traceback', 'sql error', 'fatal', 'segmentation fault', 'stacktrace']):
            success = True

        # If failed, increment fail count and switch attack type after 3 failures
        if not success:
            if self._last_attack_type == attack_type:
                self._fail_count += 1
            else:
                self._fail_count = 1
                self._last_attack_type = attack_type
            if self._fail_count >= 3:
                # Switch to a different attack type
                alt_types = [t for t in self.attack_types if t != attack_type]
                if alt_types:
                    attack_type = random.choice(list(alt_types))
                    sub_type = 'AutoSwitch'
                    payload = self.generate_payload(attack_type, sub_type, url)
                    self._fail_count = 0
                    self._last_attack_type = attack_type
                    # Re-evaluate success for switched attack
                    if attack_type == 'XSS' and payload in response_text:
                        success = True
                    elif attack_type == 'API Abuse' and 'malicious_value' in response_text:
                        success = True
                    elif attack_type == 'Bypass Authentication' and 'admin' in response_text:
                        success = True
                    elif attack_type == 'Exploit Server Error' and status == 500:
                        success = True
                    else:
                        success = False
        else:
            self._fail_count = 0
            self._last_attack_type = attack_type

        entry = {
            "time": now,
            "type": attack_type,
            "sub_type": sub_type,
            "description": payload,
            "port_scan": scan_result,
            "success": success,
            "mutated": mutated
        }

        self._log_attack(entry)
        return entry

    def attack_sequence(self, url: str, count: int = 3, delay: int = 2) -> List[Dict]:
        """Perform `count` attacks against `url`, spaced by `delay` seconds."""
        import time
        results = []
        for i in range(count):
            entry = self.attack(url)
            results.append(entry)
            if i < count - 1:
                time.sleep(delay)
        return results

    def learn_from_defense(self, defense_entry: Dict):
        # Lightweight learning: store defense feedback and adapt epsilon
        # If defense marked "Blocked by ML" or similar, increase exploration
        action = defense_entry.get('action', '').lower()
        if 'blocked' in action:
            self.epsilon = min(1.0, self.epsilon + 0.05)
        elif 'allowed' in action:
            self.epsilon = max(self.epsilon_min, self.epsilon * 0.99)

    # Backwards-compatible simple API
    def defend_feedback(self, feedback: Dict):
        self.learn_from_defense(feedback)

    # Keep previous lightweight learn method
    def learn(self):
        pass
