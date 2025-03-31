# MUST BE AT THE VERY TOP - Fixes gevent monkey patching warning
from gevent import monkey
monkey.patch_all()

import os
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session as flask_session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import openai
from dotenv import load_dotenv
from flask_cors import CORS
from flask_migrate import Migrate
from flask_socketio import SocketIO, disconnect
from flask_session import Session
import requests

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

# Initialize SocketIO with proper async mode
socketio = SocketIO(
    app,
    manage_session=False,
    cors_allowed_origins="*",
    async_mode='gevent',
    logger=os.getenv('FLASK_ENV') == 'development',
    engineio_logger=os.getenv('FLASK_ENV') == 'development',
    ping_timeout=30,
    ping_interval=25,
    reconnection=True,
    max_http_buffer_size=1e8  # 100MB
)

# OpenAI configuration
openai.api_key = os.getenv('OPENAI_API_KEY')

# ------------------ DATABASE MODELS ------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    heart_rates = db.relationship('HeartRate', backref='user', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

class HeartRate(db.Model):
    __tablename__ = "heart_rates"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    bpm = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20))
    device_type = db.Column(db.String(50))
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

# ------------------ MIDDLEWARE ------------------
@app.before_request
def before_request():
    if request.url.startswith('http://') and os.getenv('FLASK_ENV') == 'production':
        return redirect(request.url.replace('http://', 'https://'), 301)

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

# ------------------ ROUTES ------------------
@app.route('/')
def home():
    if 'user_id' not in flask_session:
        return redirect(url_for('login'))
    
    user = User.query.get(flask_session['user_id'])
    if not user:
        flask_session.clear()
        return redirect(url_for('login'))
    
    return render_template('index.html', current_user=user.username)

@app.route('/check-auth')
def check_auth():
    if 'user_id' in flask_session:
        user = User.query.get(flask_session['user_id'])
        if not user:
            flask_session.clear()
            return jsonify({'authenticated': False}), 401
        return jsonify({
            'authenticated': True,
            'username': user.username,
            'email': user.email
        })
    return jsonify({'authenticated': False}), 401

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in flask_session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        errors = []
        if not username or not password or not email:
            errors.append("All fields are required.")
        if len(username) < 4:
            errors.append("Username must be 4+ characters.")
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            errors.append("Invalid email format.")
        if len(password) < 8:
            errors.append("Password must be 8+ characters.")
            
        if errors:
            return render_template('signup.html', error_message=" ".join(errors))

        if User.query.filter_by(username=username).first():
            return render_template('signup.html', error_message="Username taken.")
        if User.query.filter_by(email=email).first():
            return render_template('signup.html', error_message="Email registered.")

        try:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(
                username=username,
                email=email,
                password=hashed_password,
                created_at=datetime.utcnow(),
                last_login=datetime.utcnow()
            )
            db.session.add(new_user)
            db.session.commit()

            flask_session.permanent = True
            flask_session['user_id'] = new_user.id
            flask_session['username'] = new_user.username
            flask_session['_fresh'] = True

            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Signup error: {str(e)}")
            return render_template('signup.html', error_message="Registration failed")

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in flask_session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        identifier = request.form.get('username_or_email', '').strip()
        password = request.form.get('password', '').strip()

        if not identifier or not password:
            return render_template('login.html', error_message="Credentials required")

        user = User.query.filter((User.email == identifier) | (User.username == identifier)).first()

        if not user or not check_password_hash(user.password, password):
            return render_template('login.html', error_message="Invalid credentials")
        if not user.is_active:
            return render_template('login.html', error_message="Account disabled")

        user.last_login = datetime.utcnow()
        db.session.commit()

        flask_session.permanent = True
        flask_session['user_id'] = user.id
        flask_session['username'] = user.username
        flask_session['_fresh'] = True
        flask_session['_ip'] = request.remote_addr

        return redirect(url_for('home'), code=303)

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    flask_session.clear()
    response = jsonify({'success': True})
    response.delete_cookie('session')
    return response, 200

@app.route('/api/heart-rate/history')
def get_heart_rate_history():
    if 'user_id' not in flask_session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        records = HeartRate.query.filter_by(
            user_id=flask_session['user_id']
        ).order_by(HeartRate.timestamp.desc()).limit(20).all()
        
        return jsonify([{
            'bpm': r.bpm,
            'status': r.status,
            'timestamp': r.timestamp.isoformat(),
            'device_type': r.device_type
        } for r in records])
    except Exception as e:
        app.logger.error(f"Heart rate history error: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/chat', methods=['POST'])
def chat():
    try:
        # 1. Authentication Check
        if 'user_id' not in flask_session:
            return jsonify({'error': 'Unauthorized'}), 401

        # 2. Input Validation
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
            
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({'error': 'Missing message field'}), 400
            
        try:
            user_input = sanitize_input(data['message'])
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        # 3. Predefined Responses
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

        # 4. Content Filtering
        if not is_heart_related(user_input):
            return jsonify({'error': 'I only answer heart-health questions'}), 400

        # 5. API Call with requests Session
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
            
            # 6. Response Validation
            response.raise_for_status()
            data = response.json()
            bot_response = data['choices'][0]['message']['content'][:400]  # Hard limit
            
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

# ------------------ SOCKET.IO HANDLERS ------------------
@socketio.on('connect')
def handle_connect():
    try:
        if 'user_id' not in flask_session:
            app.logger.warning("Unauthorized socket connection attempt")
            return False
        
        user_id = str(flask_session['user_id'])
        socketio.server.enter_room(request.sid, user_id)
        app.logger.info(f"Client connected: {user_id}")
        return True
    except Exception as e:
        app.logger.error(f"Connection error: {str(e)}")
        disconnect()
        return False

@socketio.on('disconnect')
def handle_disconnect():
    try:
        if 'user_id' in flask_session:
            user_id = str(flask_session['user_id'])
            socketio.server.leave_room(request.sid, user_id)
            app.logger.info(f"Client disconnected: {user_id}")
    except Exception as e:
        app.logger.error(f"Disconnection error: {str(e)}")

@socketio.on_error_default
def default_error_handler(e):
    app.logger.error(f"Socket.IO error: {str(e)}")
    disconnect()

# ------------------ MAIN APPLICATION ------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    socketio.run(app,
                host='0.0.0.0',
                port=int(os.environ.get('PORT', 5000)),
                debug=os.getenv('FLASK_ENV') == 'development',
                allow_unsafe_werkzeug=True)
