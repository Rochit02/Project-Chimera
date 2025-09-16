
import threading
from flask import Flask, render_template, request, redirect
from flask_socketio import SocketIO, emit
import json
import sys
sys.path.append('..')
from agents.lynx_agent import LynxAgent
from agents.aegis_agent import AegisAgent
from llm.gemini_wrapper import GeminiWrapper
from sandbox import Sandbox

app = Flask(__name__)
socketio = SocketIO(app)

import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
LYNX_LOG = os.path.join(BASE_DIR, '..', 'logs', 'lynx_log.json')
AEGIS_LOG = os.path.join(BASE_DIR, '..', 'logs', 'aegis_log.json')
gemini = GeminiWrapper(api_key='YOUR_GEMINI_API_KEY')
SETTINGS_PATH = os.path.join(BASE_DIR, 'settings.json')


def load_settings():
    default = {"enable_llm_training": True}
    try:
        with open(SETTINGS_PATH, 'r') as f:
            cfg = json.load(f)
            default.update(cfg)
    except Exception:
        # write default
        with open(SETTINGS_PATH, 'w') as f:
            json.dump(default, f, indent=2)
    return default


def save_settings(settings: dict):
    with open(SETTINGS_PATH, 'w') as f:
        json.dump(settings, f, indent=2)


settings = load_settings()


def create_agents():
    global gemini, lynx, aegis, sbox
    # If LLM training disabled, pass None to agents' llm wrapper
    llm_wrapper = gemini if settings.get('enable_llm_training', True) else None
    lynx = LynxAgent(llm_wrapper, LYNX_LOG, AEGIS_LOG)
    aegis = AegisAgent(llm_wrapper, AEGIS_LOG, LYNX_LOG)
    sbox = Sandbox(lynx, aegis)


create_agents()


# Redirect old socket client requests to a CDN-hosted client to avoid 400 errors
@app.route('/socket.io/socket.io.js')
def socketio_client_redirect():
    return redirect('https://cdn.socket.io/4.5.4/socket.io.min.js', code=302)

def read_log(log_path):
    try:
        with open(log_path, 'r') as f:
            return json.load(f)
    except Exception:
        return []




# Global state for attack thread (move outside POST handler)
if not hasattr(app, 'attack_thread'):
    app.attack_thread = None
    app.attack_stop_event = threading.Event()

# Home page (welcome)
@app.route('/')
def home():
    return render_template('home.html')


# Main dashboard page
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    lynx_log = read_log(LYNX_LOG)
    aegis_log = read_log(AEGIS_LOG)
    result = None
    url = None
    lynx_report = None
    aegis_report = None
    if request.method == 'POST':
        # Support button named 'action' with values 'start' or 'stop'
        action = request.form.get('action')
        # Stop should work even if no URL is provided
        if action == 'stop':
            app.attack_stop_event.set()
            results = None
        elif action == 'start':
            url = request.form.get('url')
            try:
                delay = int(request.form.get('delay', 2))
            except Exception:
                delay = 2
            if url:
                # Start continuous attack in background thread
                if app.attack_thread is None or not app.attack_thread.is_alive():
                    app.attack_stop_event.clear()
                    import time
                    def attack_loop():
                        while not app.attack_stop_event.is_set():
                            try:
                                sbox.process_sequence(url, count=1, delay=delay)
                            except Exception:
                                pass
                            time.sleep(delay)
                    app.attack_thread = threading.Thread(target=attack_loop, daemon=True)
                    app.attack_thread.start()
                results = None
        elif request.form.get('lynx_report'):
            lynx_report = read_log(LYNX_LOG)
        elif request.form.get('aegis_report'):
            report_path = os.path.join(os.path.dirname(AEGIS_LOG), 'defense_report.json')
            aegis_report = read_log(report_path)
    return render_template('dashboard.html', lynx_log=lynx_log, aegis_log=aegis_log, result=result, url=url, lynx_report=lynx_report, aegis_report=aegis_report)

# Page to view Lynx agent logs
@app.route('/lynx_logs')
def lynx_logs():
    lynx_log = read_log(LYNX_LOG)
    return render_template('lynx_logs.html', lynx_log=lynx_log)

# Page to view Aegis agent logs
@app.route('/aegis_logs')
def aegis_logs():
    aegis_log = read_log(AEGIS_LOG)
    return render_template('aegis_logs.html', aegis_log=aegis_log)


@app.route('/sandbox')
def sandbox_page():
    # Show last N sandbox requests by reading lynx log as the source of requests
    lynx_log = read_log(LYNX_LOG)
    recent = list(reversed(lynx_log))[:50]
    return render_template('sandbox.html', sandbox_requests=recent)


@app.route('/settings', methods=['GET', 'POST'])
def settings_page():
    global settings
    if request.method == 'POST':
        enable = request.form.get('enable_llm_training') == 'on'
        settings['enable_llm_training'] = enable
        save_settings(settings)
        # Recreate agents with new LLM setting
        create_agents()
    return render_template('settings.html', settings=settings)

def emit_logs():
    lynx_log = read_log(LYNX_LOG)
    aegis_log = read_log(AEGIS_LOG)
    stats = compute_stats(lynx_log, aegis_log)
    socketio.emit('log_update', {
        'lynx_log': lynx_log,
        'aegis_log': aegis_log,
        'stats': stats
    })


def compute_stats(lynx_log, aegis_log):
    # Basic numeric summaries and distributions
    stats = {
        'lynx': {
            'total': len(lynx_log),
            'success': sum(1 for e in lynx_log if isinstance(e, dict) and e.get('success')),
            'mutated': sum(1 for e in lynx_log if isinstance(e, dict) and e.get('mutated')),
            'by_type': {}
        },
        'aegis': {
            'total': len(aegis_log),
            'blocked': sum(1 for e in aegis_log if isinstance(e, dict) and e.get('success')),
            'by_type': {}
        }
    }
    for e in lynx_log:
        if isinstance(e, dict):
            t = e.get('type', 'Unknown')
            stats['lynx']['by_type'][t] = stats['lynx']['by_type'].get(t, 0) + 1
    for e in aegis_log:
        if isinstance(e, dict):
            t = e.get('type', 'Unknown')
            stats['aegis']['by_type'][t] = stats['aegis']['by_type'].get(t, 0) + 1
    # recent examples (keep small summaries)
    try:
        recent_lynx_success = [e for e in lynx_log if isinstance(e, dict) and e.get('success')][-3:]
    except Exception:
        recent_lynx_success = []
    try:
        recent_lynx_mutated_fail = [e for e in lynx_log if isinstance(e, dict) and not e.get('success') and e.get('mutated')][-3:]
    except Exception:
        recent_lynx_mutated_fail = []
    try:
        recent_aegis_block = [e for e in aegis_log if isinstance(e, dict) and e.get('success')][-3:]
    except Exception:
        recent_aegis_block = []

    stats['recent'] = {
        'lynx_success': recent_lynx_success,
        'lynx_mutated_fail': recent_lynx_mutated_fail,
        'aegis_block': recent_aegis_block
    }
    return stats

@socketio.on('request_logs')
def handle_request_logs():
    emit_logs()


import time
import threading
def log_watcher():
    lynx_last = None
    aegis_last = None
    while True:
        try:
            with open(LYNX_LOG, 'r') as f:
                lynx_data = f.read()
            with open(AEGIS_LOG, 'r') as f:
                aegis_data = f.read()
            if lynx_data != lynx_last or aegis_data != aegis_last:
                lynx_last = lynx_data
                aegis_last = aegis_data
                emit_logs()
        except Exception:
            pass
        time.sleep(2)

threading.Thread(target=log_watcher, daemon=True).start()

if __name__ == '__main__':
    socketio.run(app, debug=True)
