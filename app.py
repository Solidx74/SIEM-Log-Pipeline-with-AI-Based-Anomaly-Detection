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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-cyber-secret-key-change-this-to-random-string-2024'
app.config['JSON_AS_ASCII'] = False
CORS(app)  # Allow cross-origin requests if needed
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access the SIEM dashboard'
login_manager.login_message_category = 'warning'

# Mock Database for Users
# In production, use a real database like SQLite or PostgreSQL
# Passwords are hashed for security
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
    """User class for Flask-Login"""
    def __init__(self, id, role='user', email=''):
        self.id = id
        self.role = role
        self.email = email
    
    def is_admin(self):
        return self.role == 'admin'

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID"""
    if user_id not in users:
        return None
    user_data = users[user_id]
    return User(user_id, user_data.get('role', 'user'), user_data.get('email', ''))

# File paths (relative to project root)
BASE_DIR = Path(__file__).parent
FEATURES_FILE = BASE_DIR / "logs" / "logs_features.jsonl"
ANOMALIES_FILE = BASE_DIR / "anomalies.jsonl"
ALERTS_FILE = BASE_DIR / "alerts.jsonl"
RAW_LOGS_FILE = BASE_DIR / "logs" / "raw_logs.log"
PARSED_LOGS_FILE = BASE_DIR / "logs" / "logs_parsed.json"

# Ensure required directories exist
(BASE_DIR / "logs").mkdir(exist_ok=True)

# Global variables for real-time updates
last_alert_count = 0
last_position = 0
file_observer = None

# ---------------------------------------------
# Helper Functions (No Flask Context Needed)
# ---------------------------------------------
def get_stats_data():
    """Return statistics data without Flask context"""
    try:
        # Count total alerts
        alert_count = 0
        if ALERTS_FILE.exists():
            with open(ALERTS_FILE, 'r') as f:
                alert_count = sum(1 for _ in f)
        
        # Count anomalies
        anomaly_count = 0
        if ANOMALIES_FILE.exists():
            with open(ANOMALIES_FILE, 'r') as f:
                anomaly_count = sum(1 for _ in f)
        
        # Count logs (from parsed file)
        log_count = 0
        if PARSED_LOGS_FILE.exists():
            with open(PARSED_LOGS_FILE, 'r') as f:
                log_count = sum(1 for _ in f)
        
        # Get last anomaly timestamp
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

# ---------------------------------------------
# File Watcher for Real-Time Anomaly Updates
# ---------------------------------------------
class AlertFileHandler(FileSystemEventHandler):
    """Watch for new alerts appended to alerts.jsonl"""
    def on_modified(self, event):
        if event.src_path == str(ALERTS_FILE):
            logger.debug("Alerts file changed")
            # Emit event to all connected clients
            socketio.emit('new_alert', {'message': 'New alert detected'})

def start_file_watcher():
    """Start watching the alerts file for changes"""
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
# Authentication Routes
# ---------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
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
            logger.warning(f"Failed login attempt for username: {username}")
            flash('Invalid Security Credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    username = current_user.id
    logout_user()
    logger.info(f"User {username} logged out")
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))

# ---------------------------------------------
# Protected Routes (require authentication)
# ---------------------------------------------
@app.route('/')
@login_required
def index():
    """Dashboard main page"""
    return render_template('index.html', user=current_user)

@app.route('/api/stats')
@login_required
def get_stats():
    """Return overall statistics"""
    return jsonify(get_stats_data())

@app.route('/api/anomalies')
@login_required
def get_anomalies():
    """Return recent anomalies (last 100)"""
    limit = int(request.args.get('limit', 100))
    anomalies = []
    if ANOMALIES_FILE.exists():
        try:
            with open(ANOMALIES_FILE, 'r') as f:
                for line in f:
                    anomalies.append(json.loads(line))
            # Return most recent first
            anomalies = anomalies[-limit:][::-1]
        except Exception as e:
            logger.error(f"Error reading anomalies: {e}")
    return jsonify(anomalies)

@app.route('/api/logs')
@login_required
def get_logs():
    """Return recent logs (last 100)"""
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
    """Return recent alerts (last 100)"""
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
    """Return system configuration"""
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
    """Return data for anomaly trend chart (last 24 hours)"""
    # Aggregate anomalies per hour
    hours = 24
    now = datetime.now()
    timestamps = []
    counts = []
    
    # Initialize with zeros
    for i in range(hours):
        timestamps.append((now - timedelta(hours=i)).strftime('%H:%M'))
    timestamps.reverse()
    counts = [0] * hours
    
    # Read anomalies and count per hour
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
    
    # Create Plotly figure
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
    """Return data for log volume chart (last 24 hours)"""
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
    """Return distribution of alert types (algorithms used)"""
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
    """Handle WebSocket connection"""
    # Note: WebSocket authentication is handled separately
    # For production, implement token-based auth
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

# ---------------------------------------------
# Background Thread for Periodic Updates
# ---------------------------------------------
def background_updater():
    """Periodically emit stats to connected clients"""
    while True:
        socketio.sleep(5)
        # Get stats data without Flask context
        stats_data = get_stats_data()
        # Emit using socketio (no Flask context needed)
        socketio.emit('stats_update', stats_data)

# ---------------------------------------------
# Main
# ---------------------------------------------
if __name__ == '__main__':
    # Start file watcher in a separate thread
    watcher_thread = threading.Thread(target=start_file_watcher, daemon=True)
    watcher_thread.start()
    
    # Start background updater
    socketio.start_background_task(background_updater)
    
    # Run the app
    logger.info("Starting SENTINEL SIEM Dashboard on http://localhost:5000")
    logger.info("Login credentials:")
    logger.info("  Username: Solid")
    logger.info("  Password: solid123")
    logger.info("  Username: Analyst")
    logger.info("  Password: analyst456")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)