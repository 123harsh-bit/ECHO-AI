import os
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import openai
from dotenv import load_dotenv
from flask_cors import CORS
from flask_migrate import Migrate
from flask_socketio import SocketIO
from flask_session import Session
import requests

class RecursionGuard:
    def __init__(self):
        self._call_stack = set()
    
    def __call__(self, func):
        def wrapped(*args, **kwargs):
            key = f"{func.__name__}:{str(args)}:{str(kwargs)}"
            if key in self._call_stack:
                raise RecursionError("Recursion detected")
            self._call_stack.add(key)
            try:
                result = func(*args, **kwargs)
            finally:
                self._call_stack.remove(key)
            return result
        return wrapped

recursion_guard = RecursionGuard()

# ------------------ INITIAL SETUP ------------------
load_dotenv()

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')

# Configure session
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-fallback-secret-key')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
app.config['SESSION_TYPE'] = 'filesystem'  # or 'redis' in production
Session(app)

# Enable CORS
CORS(app, resources={
    r"/chat": {"origins": "*"},
    r"/api/*": {"origins": "*"}
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
    manage_session=False,
    cors_allowed_origins="*",
    async_mode='gevent',
    logger=os.getenv('FLASK_ENV') == 'development',
    engineio_logger=os.getenv('FLASK_ENV') == 'development'
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
    user_input = user_input.lower()
    heart_keywords = [
        "heart", "cardiac", "blood pressure", "cholesterol", 
        "heart attack", "stroke", "arrhythmia", "hypertension"
    ]
    return any(keyword in user_input for keyword in heart_keywords)

def classify_heart_rate(bpm):
    if bpm < 60: return 'low'
    elif 60 <= bpm <= 100: return 'normal'
    else: return 'elevated'

def contains_recursive_pattern(text):
    patterns = ["repeat after me", "say this exactly", "recursion"]
    return any(pattern in text.lower() for pattern in patterns)
    
def is_recursive_response(prompt, response):
    """Check if response might cause recursion"""
    prompt_words = set(prompt.lower().split())
    response_words = set(response.lower().split())
    common_words = prompt_words & response_words
    return len(common_words) > 5  # If more than 5 words match

def sanitize_input(text):
    """Clean and validate input"""
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

# ------------------ AUTHENTICATION ROUTES ------------------
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    return render_template('index.html', current_user=user.username)

@app.route('/check-auth')
def check_auth():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            return jsonify({'authenticated': False}), 401
            
        return jsonify({
            'authenticated': True,
            'username': user.username,
            'email': user.email
        })
    return jsonify({'authenticated': False}), 401

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        errors = []
        if not username or not password or not email:
            errors.append("All fields are required.")
        if len(username) < 4:
            errors.append("Username too short.")
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

            session.permanent = True
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            session['_fresh'] = True

            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Signup error: {str(e)}")
            return render_template('signup.html', error_message="Registration failed")

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
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

        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        session['_fresh'] = True
        session['_ip'] = request.remote_addr

        return redirect(url_for('home'), code=303)

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    response = jsonify({'success': True})
    response.delete_cookie('session')
    return response, 200

# ------------------ CHAT ROUTE ------------------
@app.route('/chat', methods=['POST'])
@recursion_guard
def chat():
    try:
        # 1. Authentication Check
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        # 2. Input Validation
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({'error': 'Invalid request format'}), 400
            
        user_input = data['message'].strip()[:500]  # Hard length limit

        # 3. Predefined Responses (avoid API calls for common questions)
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

        # 5. API Call with Atomic Operation
        with requests.Session() as session:
            response = session.post(
                'https://api.openai.com/v1/chat/completions',
                headers={
                    'Authorization': f'Bearer {openai.api_key}',
                    'Content-Type': 'application/json',
                    'X-Request-ID': str(hash(user_input))  # Unique identifier
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
                    'temperature': 0.3,  # More deterministic
                    'max_tokens': 75,
                    'frequency_penalty': 1.5,
                    'presence_penalty': 1.5
                },
                timeout=8
            )
            
            # 6. Response Validation
            response.raise_for_status()
            data = response.json()
            bot_response = data['choices'][0]['message']['content'][:400]  # Hard limit
            
            # Final recursion check
            if any(word in bot_response.lower() for word in ["repeat", "recurse", "loop"]):
                raise ValueError("Invalid response pattern")
                
            return jsonify({'response': bot_response})

    except RecursionError:
        return jsonify({'error': 'System busy'}), 429
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Service unavailable'}), 503
    except Exception as e:
        app.logger.error(f"Chat error: {type(e).__name__}: {str(e)}")
        return jsonify({'error': 'Processing error'}), 500
# ------------------ MAIN APPLICATION ------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    socketio.run(app,
                host='0.0.0.0',
                port=int(os.environ.get('PORT', 5000)),
                debug=os.getenv('FLASK_ENV') == 'development')
