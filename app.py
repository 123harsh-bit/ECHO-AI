# MUST BE AT THE VERY TOP - Fixes gevent monkey patching warning
from gevent import monkey
monkey.patch_all()

import os
import re
import time
import asyncio
from threading import Thread
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, render_template, request, jsonify, redirect, url_for, session as flask_session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import openai
from dotenv import load_dotenv
from flask_cors import CORS
from flask_migrate import Migrate
from flask_socketio import SocketIO, emit, join_room, disconnect
from flask_session import Session
import requests
from bleak import BleakClient, BleakScanner

# ------------------ INITIAL SETUP ------------------
load_dotenv()

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')

# Configure session
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-fallback-secret-key')
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Enable CORS
CORS(app, resources={
    r"/chat": {"origins": "*"},
    r"/api/*": {"origins": "*"},
    r"/socket.io/*": {"origins": "*"}
})

# Database configuration
db_url = os.getenv('DATABASE_URL')
if db_url and db_url.startswith('postgres://'):
    db_url = db_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_timeout': 30,
    'pool_size': 20,
    'max_overflow': 10
}

# Initialize database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize SocketIO
socketio = SocketIO(
    app,
    manage_session=True,
    cors_allowed_origins="*",
    async_mode='gevent',
    logger=os.getenv('FLASK_ENV') == 'development',
    engineio_logger=os.getenv('FLASK_ENV') == 'development',
    ping_timeout=30,
    ping_interval=25,
    max_http_buffer_size=1e8,
    auth={
        'auth_headers': ['Authorization'],
        'auth_cookie': 'session'
    }
)

# OpenAI configuration
openai.api_key = os.getenv('OPENAI_API_KEY')

# Global variables
executor = ThreadPoolExecutor(max_workers=4)
latest_bpm = None

# ------------------ DATABASE MODELS ------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    heart_rates = db.relationship('HeartRate', backref='user', lazy=True)
    devices = db.relationship('Device', backref='user', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

class Device(db.Model):
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    device_type = db.Column(db.String(50))
    device_id = db.Column(db.String(100))
    auth_token = db.Column(db.String(500))
    is_connected = db.Column(db.Boolean, default=False)
    last_sync = db.Column(db.DateTime)

class HeartRate(db.Model):
    __tablename__ = "heart_rates"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    bpm = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20))
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'))
    confidence = db.Column(db.Float)

# ------------------ UTILITY FUNCTIONS ------------------
def is_heart_related(user_input):
    required_keywords = {
        'heart', 'cardiac', 'blood pressure', 'cholesterol',
        'cardiovascular', 'pulse', 'artery', 'vein', 'ecg', 'ekg'
    }
    input_words = set(user_input.lower().split())
    return not required_keywords.isdisjoint(input_words)

def classify_heart_rate(bpm):
    if bpm < 60: return 'low'
    elif 60 <= bpm <= 100: return 'normal'
    else: return 'elevated'

def contains_recursive_pattern(text):
    patterns = ["repeat after me", "say this exactly", "recursion"]
    return any(pattern in text.lower() for pattern in patterns)

def sanitize_input(text):
    text = text.strip()
    if len(text) > 500:
        raise ValueError("Input too long")
    if any(cmd in text.lower() for cmd in ["repeat", "loop", "recurs"]):
        raise ValueError("Recursive pattern detected")
    return text

def start_heart_rate_monitor(user_id, device_id):
    """Background thread to monitor heart rate"""
    def monitor():
        while True:
            try:
                device = Device.query.get(device_id)
                if not device or not device.is_connected:
                    break
                
                # Simulate heart rate data (replace with actual device API call)
                mock_bpm = 60 + int(time.time()) % 40
                
                new_reading = HeartRate(
                    user_id=user_id,
                    bpm=mock_bpm,
                    status=classify_heart_rate(mock_bpm),
                    device_id=device_id,
                    confidence=0.95
                )
                db.session.add(new_reading)
                db.session.commit()
                
                emit('heart_rate_update', {
                    'bpm': mock_bpm,
                    'status': new_reading.status,
                    'timestamp': datetime.utcnow().isoformat(),
                    'device_connected': True
                }, room=f'user_{user_id}')
                
                time.sleep(5)
                
            except Exception as e:
                app.logger.error(f"Heart rate monitor error: {str(e)}")
                time.sleep(10)
    
    Thread(target=monitor, daemon=True).start()

# ------------------ BLUETOOTH FUNCTIONS ------------------
def get_ai_advice(bpm):
    """Get health advice based on current heart rate"""
    prompt = f"""
    The user's current heart rate is {bpm} BPM ({classify_heart_rate(bpm)}).
    Provide 1-2 sentences of medical advice.
    Be factual and concise.
    """
    
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=100,
        temperature=0.3
    )
    return response.choices[0].message.content.strip()

async def read_heart_rate(mac_address):
    """BLE connection handler"""
    global latest_bpm
    try:
        async with BleakClient(mac_address) as client:
            def callback(_, data):
                global latest_bpm
                latest_bpm = data[1]  # BPM is usually the 2nd byte
                
                # Store in database
                with app.app_context():
                    device = Device.query.filter_by(device_id=mac_address).first()
                    if device:
                        new_reading = HeartRate(
                            user_id=device.user_id,
                            bpm=latest_bpm,
                            status=classify_heart_rate(latest_bpm),
                            device_id=device.id,
                            confidence=0.95
                        )
                        db.session.add(new_reading)
                        db.session.commit()
                
                # Send real-time update
                socketio.emit('heart_rate_update', {
                    'bpm': latest_bpm,
                    'status': classify_heart_rate(latest_bpm),
                    'timestamp': datetime.utcnow().isoformat(),
                    'device_connected': True
                }, room=f'user_{device.user_id}')
            
            await client.start_notify("00002a37-0000-1000-8000-00805f9b34fb", callback)
            while True:
                await asyncio.sleep(1)
    except Exception as e:
        app.logger.error(f"Bluetooth error: {str(e)}")

def start_bluetooth_monitor(mac_address):
    """Start BLE in background thread"""
    asyncio.run(read_heart_rate(mac_address))

# ------------------ MIDDLEWARE ------------------
@app.before_request
def before_request():
    if request.url.startswith('http://') and os.getenv('FLASK_ENV') == 'production':
        return redirect(request.url.replace('http://', 'https://'), 301)

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

# ------------------ ROUTES ------------------
# [ALL YOUR EXISTING ROUTES REMAIN UNCHANGED UNTIL...]

@app.route('/api/device/connect', methods=['POST'])
def connect_device():
    if 'user_id' not in flask_session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    device_type = data.get('device_type')
    device_id = data.get('device_id')
    
    if not device_type or not device_id:
        return jsonify({'error': 'Missing device info'}), 400
    
    try:
        device = Device.query.filter_by(
            user_id=flask_session['user_id'],
            device_id=device_id
        ).first()
        
        if not device:
            device = Device(
                user_id=flask_session['user_id'],
                device_type=device_type,
                device_id=device_id,
                is_connected=True,
                last_sync=datetime.utcnow()
            )
            db.session.add(device)
        else:
            device.is_connected = True
            device.last_sync = datetime.utcnow()
        
        db.session.commit()
        
        # Start appropriate monitor based on device type
        if "watch" in device_type.lower():
            executor.submit(start_bluetooth_monitor, device_id)
        else:
            start_heart_rate_monitor(flask_session['user_id'], device.id)
        
        return jsonify({
            'status': 'connected',
            'device_id': device.id,
            'device_type': device.device_type
        })
    except Exception as e:
        app.logger.error(f"Device connection error: {str(e)}")
        return jsonify({'error': 'Connection failed'}), 500

@app.route('/chat', methods=['POST'])
def chat():
    try:
        if 'user_id' not in flask_session:
            return jsonify({'error': 'Unauthorized'}), 401

        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
            
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({'error': 'Missing message field'}), 400
            
        try:
            user_input = sanitize_input(data['message'])
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        # NEW: Handle heart rate queries
        if "my heart rate" in user_input.lower() and latest_bpm:
            advice = get_ai_advice(latest_bpm)
            return jsonify({
                'response': f"Your current heart rate is {latest_bpm} BPM. {advice}",
                'bpm': latest_bpm
            })

        # [REST OF YOUR EXISTING CHAT FUNCTION REMAINS UNCHANGED]
        response_map = {
            'who are you': "I'm Echo, your heart health assistant.",
            'who created you': "Developed by medical AI specialists.",
            'what can you do': "I provide heart health information.",
            'how does this work': "Ask me heart-related questions."
        }
        
        lower_input = user_input.lower()
        for question, response in response_map.items():
            if question in lower_input:
                return jsonify({'response': response})

        if not is_heart_related(user_input):
            return jsonify({'error': 'I only answer heart-health questions'}), 400

        with requests.Session() as http_session:
            response = http_session.post(
                'https://api.openai.com/v1/chat/completions',
                headers={
                    'Authorization': f'Bearer {openai.api_key}',
                    'Content-Type': 'application/json'
                },
                json={
                    'model': 'gpt-3.5-turbo',
                    'messages': [
                        {
                            "role": "system",
                            "content": """You are a cardiac specialist AI. Rules:
                            1. Never repeat the user's exact words
                            2. Maximum 3 sentence response
                            3. Never suggest repeating anything
                            4. Only discuss verified medical information"""
                        },
                        {"role": "user", "content": user_input}
                    ],
                    'temperature': 0.3,
                    'max_tokens': 100,
                    'frequency_penalty': 1.0,
                    'presence_penalty': 1.0
                },
                timeout=10
            )
            
            response.raise_for_status()
            data = response.json()
            bot_response = data['choices'][0]['message']['content'][:400]
            
            if contains_recursive_pattern(bot_response):
                raise ValueError("Invalid response pattern")
                
            return jsonify({'response': bot_response})

    except requests.exceptions.Timeout:
        return jsonify({'error': 'Request timeout'}), 504
    except requests.exceptions.RequestException as e:
        app.logger.error(f"API request failed: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503
    except Exception as e:
        app.logger.error(f"Chat error: {type(e).__name__}: {str(e)}")
        return jsonify({'error': 'Processing error'}), 500

# [ALL OTHER EXISTING ROUTES AND SOCKET.IO HANDLERS REMAIN UNCHANGED]

# ------------------ MAIN APPLICATION ------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    socketio.run(app,
                host='0.0.0.0',
                port=int(os.environ.get('PORT', 5000)),
                debug=os.getenv('FLASK_ENV') == 'development',
                allow_unsafe_werkzeug=True)
