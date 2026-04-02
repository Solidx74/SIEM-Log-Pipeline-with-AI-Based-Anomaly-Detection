#!/usr/bin/env python3
"""
SIEM Pipeline Web Application
Real-time dashboard for log monitoring and anomaly detection
"""

import os
import json
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_file, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import pandas as pd
import plotly.graph_objs as go
import plotly.utils
import json as plotly_json
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# NEW: Import Flask-Limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'SOLID_SIEM_SECRET_KEY'
app.config['JSON_AS_ASCII'] = False
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# ---------------------------------------------
# NEW: Rate Limiter Configuration
# ---------------------------------------------
limiter = Limiter(
    get_remote_address,          # Track by client IP address
    app=app,
    default_limits=["200 per day", "50 per hour"],   # Global fallback limits
    storage_uri="memory://",     # In-memory storage (change to Redis in production)
)

# Custom handler for rate limit exceeded (HTTP 429)
@app.errorhandler(429)
def rate_limit_exceeded(e):
    flash(f"Too many login attempts. Please wait before trying again.", "error")
    logger.warning(f"Rate limit exceeded for IP: {request.remote_addr}")
    return redirect(url_for('login'))

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access the SIEM dashboard'
login_manager.login_message_category = 'warning'

# Mock Database for Users
users = {
    "Solid": {
        "password": generate_password_hash("solid123"),
        "role": "admin",
        "email": "solid@sentinel.local"
    },
    "Analyst": {
        "password": generate_password_hash("analyst456"),
        "role": "analyst",
        "email": "analyst@sentinel.local"
    }
}

class User(UserMixin):
    def __init__(self, id, role='user', email=''):
        self.id = id
        self.role = role
        self.email = email
    
    def is_admin(self):
        return self.role == 'admin'

@login_manager.user_loader
def load_user(user_id):
    if user_id not in users:
        return None
    user_data = users[user_id]
    return User(user_id, user_data.get('role', 'user'), user_data.get('email', ''))


# File paths
BASE_DIR = Path(__file__).parent
FEATURES_FILE = BASE_DIR / "logs" / "logs_features.jsonl"
ANOMALIES_FILE = BASE_DIR / "anomalies.jsonl"
ALERTS_FILE = BASE_DIR / "alerts.jsonl"
RAW_LOGS_FILE = BASE_DIR / "logs" / "raw_logs.log"
PARSED_LOGS_FILE = BASE_DIR / "logs" / "logs_parsed.json"

(BASE_DIR / "logs").mkdir(exist_ok=True)

# Global variables
last_alert_count = 0
last_position = 0
file_observer = None

def get_stats_data():
    """Return statistics data without Flask context"""
    try:
        alert_count = 0
        if ALERTS_FILE.exists():
            with open(ALERTS_FILE, 'r') as f:
                alert_count = sum(1 for _ in f)
        
        anomaly_count = 0
        if ANOMALIES_FILE.exists():
            with open(ANOMALIES_FILE, 'r') as f:
                anomaly_count = sum(1 for _ in f)
        
        log_count = 0
        if PARSED_LOGS_FILE.exists():
            with open(PARSED_LOGS_FILE, 'r') as f:
                log_count = sum(1 for _ in f)
        
        last_anomaly = None
        if ANOMALIES_FILE.exists():
            with open(ANOMALIES_FILE, 'r') as f:
                lines = f.readlines()
                if lines:
                    last = json.loads(lines[-1])
                    last_anomaly = last.get('timestamp')
        
        return {
            'alert_count': alert_count,
            'anomaly_count': anomaly_count,
            'log_count': log_count,
            'last_anomaly': last_anomaly
        }
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return {'error': str(e)}

class AlertFileHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path == str(ALERTS_FILE):
            logger.debug("Alerts file changed")
            socketio.emit('new_alert', {'message': 'New alert detected'})

def start_file_watcher():
    global file_observer
    if not ALERTS_FILE.exists():
        ALERTS_FILE.touch()
    event_handler = AlertFileHandler()
    observer = Observer()
    observer.schedule(event_handler, path=str(ALERTS_FILE.parent), recursive=False)
    observer.start()
    file_observer = observer
    logger.info("File watcher started for alerts file")

# ---------------------------------------------
# Authentication Routes (with Rate Limiting)
# ---------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")   # 🔒 Max 5 login attempts per IP per minute
def login():
    """Login page with brute-force protection"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        user_data = users.get(username)
        if user_data and check_password_hash(user_data['password'], password):
            user_obj = User(username, user_data.get('role', 'user'), user_data.get('email', ''))
            login_user(user_obj)
            logger.info(f"User {username} logged in successfully")
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('index'))
        else:
            logger.warning(f"Failed login attempt for username: {username} from IP {request.remote_addr}")
            flash('Invalid Security Credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.id
    logout_user()
    logger.info(f"User {username} logged out")
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))

# ---------------------------------------------
# Protected Routes
# ---------------------------------------------
@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user)

@app.route('/api/stats')
@login_required
def get_stats():
    return jsonify(get_stats_data())

@app.route('/api/anomalies')
@login_required
def get_anomalies():
    limit = int(request.args.get('limit', 100))
    anomalies = []
    if ANOMALIES_FILE.exists():
        try:
            with open(ANOMALIES_FILE, 'r') as f:
                for line in f:
                    anomalies.append(json.loads(line))
            anomalies = anomalies[-limit:][::-1]
        except Exception as e:
            logger.error(f"Error reading anomalies: {e}")
    return jsonify(anomalies)

@app.route('/api/logs')
@login_required
def get_logs():
    limit = int(request.args.get('limit', 100))
    logs = []
    if PARSED_LOGS_FILE.exists():
        try:
            with open(PARSED_LOGS_FILE, 'r') as f:
                for line in f:
                    logs.append(json.loads(line))
            logs = logs[-limit:][::-1]
        except Exception as e:
            logger.error(f"Error reading logs: {e}")
    return jsonify(logs)

@app.route('/api/alerts')
@login_required
def get_alerts():
    limit = int(request.args.get('limit', 100))
    alerts = []
    if ALERTS_FILE.exists():
        try:
            with open(ALERTS_FILE, 'r') as f:
                for line in f:
                    alerts.append(json.loads(line))
            alerts = alerts[-limit:][::-1]
        except Exception as e:
            logger.error(f"Error reading alerts: {e}")
    return jsonify(alerts)

@app.route('/api/config')
@login_required
def get_config():
    return jsonify({
        'algorithm': 'Isolation Forest',
        'contamination': 0.1,
        'batch_size': 100,
        'raw_logs_path': str(RAW_LOGS_FILE),
        'parsed_logs_path': str(PARSED_LOGS_FILE),
        'features_path': str(FEATURES_FILE),
        'alerts_path': str(ALERTS_FILE),
        'engine_status': 'Online',
        'update_interval': '5s',
        'active_algorithms': ['Isolation Forest', 'LOF', 'One-Class SVM'],
        'user': current_user.id,
        'user_role': current_user.role
    })

@app.route('/api/charts/anomaly_trend')
@login_required
def anomaly_trend():
    hours = 24
    now = datetime.now()
    timestamps = []
    counts = []
    
    for i in range(hours):
        timestamps.append((now - timedelta(hours=i)).strftime('%H:%M'))
    timestamps.reverse()
    counts = [0] * hours
    
    if ANOMALIES_FILE.exists():
        try:
            with open(ANOMALIES_FILE, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    try:
                        anomaly_time = datetime.fromisoformat(data.get('timestamp', ''))
                        hour_diff = (now - anomaly_time).total_seconds() / 3600
                        if 0 <= hour_diff < hours:
                            idx = int(hour_diff)
                            counts[hours - 1 - idx] += 1
                    except:
                        pass
        except Exception as e:
            logger.error(f"Error building anomaly trend: {e}")
    
    fig = go.Figure(data=[go.Bar(x=timestamps, y=counts, name='Anomalies')])
    fig.update_layout(
        title='Anomalies per Hour (Last 24h)',
        xaxis_title='Time',
        yaxis_title='Count',
        template='plotly_dark'
    )
    return jsonify(plotly_json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder))

@app.route('/api/charts/log_volume')
@login_required
def log_volume():
    hours = 24
    now = datetime.now()
    timestamps = []
    counts = [0] * hours
    
    for i in range(hours):
        timestamps.append((now - timedelta(hours=i)).strftime('%H:%M'))
    timestamps.reverse()
    
    if PARSED_LOGS_FILE.exists():
        try:
            with open(PARSED_LOGS_FILE, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    try:
                        log_time = datetime.fromisoformat(data.get('timestamp', ''))
                        hour_diff = (now - log_time).total_seconds() / 3600
                        if 0 <= hour_diff < hours:
                            idx = int(hour_diff)
                            counts[hours - 1 - idx] += 1
                    except:
                        pass
        except Exception as e:
            logger.error(f"Error building log volume: {e}")
    
    fig = go.Figure(data=[go.Scatter(x=timestamps, y=counts, mode='lines+markers', name='Logs')])
    fig.update_layout(
        title='Log Volume per Hour (Last 24h)',
        xaxis_title='Time',
        yaxis_title='Count',
        template='plotly_dark'
    )
    return jsonify(plotly_json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder))

@app.route('/api/charts/alert_types')
@login_required
def alert_types():
    alert_types = {}
    if ALERTS_FILE.exists():
        try:
            with open(ALERTS_FILE, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    algo = data.get('algorithm', 'unknown')
                    alert_types[algo] = alert_types.get(algo, 0) + 1
        except Exception as e:
            logger.error(f"Error building alert types: {e}")
    
    fig = go.Figure(data=[go.Pie(labels=list(alert_types.keys()), values=list(alert_types.values()))])
    fig.update_layout(
        title='Alert Distribution by Algorithm',
        template='plotly_dark'
    )
    return jsonify(plotly_json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder))

# ---------------------------------------------
# WebSocket Events
# ---------------------------------------------
@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

# ---------------------------------------------
# Background Thread
# ---------------------------------------------
def background_updater():
    while True:
        socketio.sleep(5)
        stats_data = get_stats_data()
        socketio.emit('stats_update', stats_data)

# ---------------------------------------------
# Main
# ---------------------------------------------
if __name__ == '__main__':
    watcher_thread = threading.Thread(target=start_file_watcher, daemon=True)
    watcher_thread.start()
    
    socketio.start_background_task(background_updater)
    
    logger.info("Starting SENTINEL SIEM Dashboard on http://localhost:5000")
    logger.info("Login credentials:")
    logger.info("  Username: Solid")
    logger.info("  Password: solid123")
    logger.info("  Username: Analyst")
    logger.info("  Password: analyst456")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access the SIEM dashboard'
login_manager.login_message_category = 'warning'

# Mock Database for Users
users = {
    "Solid": {
        "password": generate_password_hash("solid123"),
        "role": "admin",
        "email": "solid@sentinel.local"
    },
    "Analyst": {
        "password": generate_password_hash("analyst456"),
        "role": "analyst",
        "email": "analyst@sentinel.local"
    }
}

class User(UserMixin):
    def __init__(self, id, role='user', email=''):
        self.id = id
        self.role = role
        self.email = email
    
    def is_admin(self):
        return self.role == 'admin'

@login_manager.user_loader
def load_user(user_id):
    if user_id not in users:
        return None
    user_data = users[user_id]
    return User(user_id, user_data.get('role', 'user'), user_data.get('email', ''))

# File paths
BASE_DIR = Path(__file__).parent
FEATURES_FILE = BASE_DIR / "logs" / "logs_features.jsonl"
ANOMALIES_FILE = BASE_DIR / "anomalies.jsonl"
ALERTS_FILE = BASE_DIR / "alerts.jsonl"
RAW_LOGS_FILE = BASE_DIR / "logs" / "raw_logs.log"
PARSED_LOGS_FILE = BASE_DIR / "logs" / "logs_parsed.json"

(BASE_DIR / "logs").mkdir(exist_ok=True)

# Global variables
last_alert_count = 0
last_position = 0
file_observer = None

def get_stats_data():
    """Return statistics data without Flask context"""
    try:
        alert_count = 0
        if ALERTS_FILE.exists():
            with open(ALERTS_FILE, 'r') as f:
                alert_count = sum(1 for _ in f)
        
        anomaly_count = 0
        if ANOMALIES_FILE.exists():
            with open(ANOMALIES_FILE, 'r') as f:
                anomaly_count = sum(1 for _ in f)
        
        log_count = 0
        if PARSED_LOGS_FILE.exists():
            with open(PARSED_LOGS_FILE, 'r') as f:
                log_count = sum(1 for _ in f)
        
        last_anomaly = None
        if ANOMALIES_FILE.exists():
            with open(ANOMALIES_FILE, 'r') as f:
                lines = f.readlines()
                if lines:
                    last = json.loads(lines[-1])
                    last_anomaly = last.get('timestamp')
        
        return {
            'alert_count': alert_count,
            'anomaly_count': anomaly_count,
            'log_count': log_count,
            'last_anomaly': last_anomaly
        }
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return {'error': str(e)}

class AlertFileHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path == str(ALERTS_FILE):
            logger.debug("Alerts file changed")
            socketio.emit('new_alert', {'message': 'New alert detected'})

def start_file_watcher():
    global file_observer
    if not ALERTS_FILE.exists():
        ALERTS_FILE.touch()
    event_handler = AlertFileHandler()
    observer = Observer()
    observer.schedule(event_handler, path=str(ALERTS_FILE.parent), recursive=False)
    observer.start()
    file_observer = observer
    logger.info("File watcher started for alerts file")

# ---------------------------------------------
# Authentication Routes (with Rate Limiting)
# ---------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")   # 🔒 Max 5 login attempts per IP per minute
def login():
    """Login page with brute-force protection"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        user_data = users.get(username)
        if user_data and check_password_hash(user_data['password'], password):
            user_obj = User(username, user_data.get('role', 'user'), user_data.get('email', ''))
            login_user(user_obj)
            logger.info(f"User {username} logged in successfully")
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('index'))
        else:
            logger.warning(f"Failed login attempt for username: {username} from IP {request.remote_addr}")
            flash('Invalid Security Credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.id
    logout_user()
    logger.info(f"User {username} logged out")
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))

# ---------------------------------------------
# Protected Routes
# ---------------------------------------------
@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user)

@app.route('/api/stats')
@login_required
def get_stats():
    return jsonify(get_stats_data())

@app.route('/api/anomalies')
@login_required
def get_anomalies():
    limit = int(request.args.get('limit', 100))
    anomalies = []
    if ANOMALIES_FILE.exists():
        try:
            with open(ANOMALIES_FILE, 'r') as f:
                for line in f:
                    anomalies.append(json.loads(line))
            anomalies = anomalies[-limit:][::-1]
        except Exception as e:
            logger.error(f"Error reading anomalies: {e}")
    return jsonify(anomalies)

@app.route('/api/logs')
@login_required
def get_logs():
    limit = int(request.args.get('limit', 100))
    logs = []
    if PARSED_LOGS_FILE.exists():
        try:
            with open(PARSED_LOGS_FILE, 'r') as f:
                for line in f:
                    logs.append(json.loads(line))
            logs = logs[-limit:][::-1]
        except Exception as e:
            logger.error(f"Error reading logs: {e}")
    return jsonify(logs)

@app.route('/api/alerts')
@login_required
def get_alerts():
    limit = int(request.args.get('limit', 100))
    alerts = []
    if ALERTS_FILE.exists():
        try:
            with open(ALERTS_FILE, 'r') as f:
                for line in f:
                    alerts.append(json.loads(line))
            alerts = alerts[-limit:][::-1]
        except Exception as e:
            logger.error(f"Error reading alerts: {e}")
    return jsonify(alerts)

@app.route('/api/config')
@login_required
def get_config():
    return jsonify({
        'algorithm': 'Isolation Forest',
        'contamination': 0.1,
        'batch_size': 100,
        'raw_logs_path': str(RAW_LOGS_FILE),
        'parsed_logs_path': str(PARSED_LOGS_FILE),
        'features_path': str(FEATURES_FILE),
        'alerts_path': str(ALERTS_FILE),
        'engine_status': 'Online',
        'update_interval': '5s',
        'active_algorithms': ['Isolation Forest', 'LOF', 'One-Class SVM'],
        'user': current_user.id,
        'user_role': current_user.role
    })

@app.route('/api/charts/anomaly_trend')
@login_required
def anomaly_trend():
    hours = 24
    now = datetime.now()
    timestamps = []
    counts = []
    
    for i in range(hours):
        timestamps.append((now - timedelta(hours=i)).strftime('%H:%M'))
    timestamps.reverse()
    counts = [0] * hours
    
    if ANOMALIES_FILE.exists():
        try:
            with open(ANOMALIES_FILE, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    try:
                        anomaly_time = datetime.fromisoformat(data.get('timestamp', ''))
                        hour_diff = (now - anomaly_time).total_seconds() / 3600
                        if 0 <= hour_diff < hours:
                            idx = int(hour_diff)
                            counts[hours - 1 - idx] += 1
                    except:
                        pass
        except Exception as e:
            logger.error(f"Error building anomaly trend: {e}")
    
    fig = go.Figure(data=[go.Bar(x=timestamps, y=counts, name='Anomalies')])
    fig.update_layout(
        title='Anomalies per Hour (Last 24h)',
        xaxis_title='Time',
        yaxis_title='Count',
        template='plotly_dark'
    )
    return jsonify(plotly_json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder))

@app.route('/api/charts/log_volume')
@login_required
def log_volume():
    hours = 24
    now = datetime.now()
    timestamps = []
    counts = [0] * hours
    
    for i in range(hours):
        timestamps.append((now - timedelta(hours=i)).strftime('%H:%M'))
    timestamps.reverse()
    
    if PARSED_LOGS_FILE.exists():
        try:
            with open(PARSED_LOGS_FILE, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    try:
                        log_time = datetime.fromisoformat(data.get('timestamp', ''))
                        hour_diff = (now - log_time).total_seconds() / 3600
                        if 0 <= hour_diff < hours:
                            idx = int(hour_diff)
                            counts[hours - 1 - idx] += 1
                    except:
                        pass
        except Exception as e:
            logger.error(f"Error building log volume: {e}")
    
    fig = go.Figure(data=[go.Scatter(x=timestamps, y=counts, mode='lines+markers', name='Logs')])
    fig.update_layout(
        title='Log Volume per Hour (Last 24h)',
        xaxis_title='Time',
        yaxis_title='Count',
        template='plotly_dark'
    )
    return jsonify(plotly_json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder))

@app.route('/api/charts/alert_types')
@login_required
def alert_types():
    alert_types = {}
    if ALERTS_FILE.exists():
        try:
            with open(ALERTS_FILE, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    algo = data.get('algorithm', 'unknown')
                    alert_types[algo] = alert_types.get(algo, 0) + 1
        except Exception as e:
            logger.error(f"Error building alert types: {e}")
    
    fig = go.Figure(data=[go.Pie(labels=list(alert_types.keys()), values=list(alert_types.values()))])
    fig.update_layout(
        title='Alert Distribution by Algorithm',
        template='plotly_dark'
    )
    return jsonify(plotly_json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder))

# ---------------------------------------------
# WebSocket Events
# ---------------------------------------------
@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

# ---------------------------------------------
# Background Thread
# ---------------------------------------------
def background_updater():
    while True:
        socketio.sleep(5)
        stats_data = get_stats_data()
        socketio.emit('stats_update', stats_data)

# ---------------------------------------------
# Main
# ---------------------------------------------
if __name__ == '__main__':
    watcher_thread = threading.Thread(target=start_file_watcher, daemon=True)
    watcher_thread.start()
    
    socketio.start_background_task(background_updater)
    
    logger.info("Starting SENTINEL SIEM Dashboard on http://localhost:5000")
    logger.info("Login credentials:")
    logger.info("  Username: Solid")
    logger.info("  Password: solid123")
    logger.info("  Username: Analyst")
    logger.info("  Password: analyst456")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)