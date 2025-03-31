import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import openai
from dotenv import load_dotenv
from flask_cors import CORS
from flask_migrate import Migrate
from flask_socketio import SocketIO
import random

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

# Initialize database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

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
    device_token = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)

class HeartRate(db.Model):
    __tablename__ = "heart_rates"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    bpm = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20))  # normal/elevated/critical
    device_type = db.Column(db.String(50))
    confidence = db.Column(db.Float)

# ------------------ HEALTH KEYWORDS ------------------
HEART_KEYWORDS = [
    "heart", "cardiac", "blood pressure", "cholesterol", "heart attack",
    "stroke", "arrhythmia", "hypertension", "pulse", "artery", "circulation",
    "ECG", "EKG", "cardiovascular", "angioplasty", "bypass surgery"
]

def is_heart_related(user_input):
    user_input = user_input.lower()
    return any(keyword in user_input for keyword in HEART_KEYWORDS)

def classify_heart_rate(bpm):
    """Classify heart rate into categories"""
    if bpm < 60: return 'low'
    elif 60 <= bpm <= 100: return 'normal'
    else: return 'elevated'

# ------------------ MIDDLEWARE ------------------
@app.before_request
def before_request():
    """Force HTTPS in production"""
    if request.url.startswith('http://') and os.getenv('FLASK_ENV') == 'production':
        return redirect(request.url.replace('http://', 'https://'), 301)

# ------------------ HEART RATE API ROUTES ------------------
@app.route('/api/heart-rate', methods=['POST'])
def save_heart_rate():
    """Save new heart rate reading from connected device"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    if not data or 'bpm' not in data:
        return jsonify({'error': 'Missing BPM data'}), 400
    
    try:
        new_record = HeartRate(
            user_id=session['user_id'],
            bpm=data['bpm'],
            status=classify_heart_rate(data['bpm']),
            device_type=data.get('device_type', 'simulated'),
            confidence=data.get('confidence', 1.0)
        )
        db.session.add(new_record)
        db.session.commit()
        
        # Broadcast to WebSocket clients
        socketio.emit('heart_rate_update', {
            'bpm': new_record.bpm,
            'status': new_record.status,
            'timestamp': new_record.timestamp.isoformat()
        }, room=str(session['user_id']))
        
        return jsonify({
            'status': 'success',
            'data': {
                'id': new_record.id,
                'bpm': new_record.bpm,
                'status': new_record.status,
                'timestamp': new_record.timestamp.isoformat()
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/heart-rate/history')
def get_heart_rate_history():
    """Get user's heart rate history (last 20 readings)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        records = HeartRate.query.filter_by(
            user_id=session['user_id']
        ).order_by(HeartRate.timestamp.desc()).limit(20).all()
        
        return jsonify([{
            'bpm': r.bpm,
            'status': r.status,
            'timestamp': r.timestamp.isoformat(),
            'device_type': r.device_type
        } for r in records])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/heart-rate/analysis')
def get_heart_rate_analysis():
    """Get analysis of user's recent heart rate data"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get records from last 24 hours
        records = HeartRate.query.filter(
            HeartRate.user_id == session['user_id'],
            HeartRate.timestamp >= datetime.utcnow() - timedelta(hours=24)
        ).order_by(HeartRate.timestamp.asc()).all()
        
        if not records:
            return jsonify({'message': 'No heart rate data available'})
        
        # Basic analysis
        bpms = [r.bpm for r in records]
        avg_bpm = round(sum(bpms) / len(bpms))
        min_bpm = min(bpms)
        max_bpm = max(bpms)
        
        return jsonify({
            'average_bpm': avg_bpm,
            'min_bpm': min_bpm,
            'max_bpm': max_bpm,
            'record_count': len(records),
            'status_distribution': {
                'low': sum(1 for r in records if r.status == 'low'),
                'normal': sum(1 for r in records if r.status == 'normal'),
                'elevated': sum(1 for r in records if r.status == 'elevated')
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ------------------ SOCKET.IO HANDLERS ------------------
@socketio.on('connect')
def handle_connect():
    """Handle new WebSocket connection"""
    if 'user_id' in session:
        user_id = str(session['user_id'])
        socketio.server.enter_room(request.sid, user_id)
        print(f"Client connected to room {user_id}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    if 'user_id' in session:
        print(f"Client disconnected from room {session['user_id']}")

# ------------------ EXISTING ROUTES ------------------
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('index.html', current_user=user.username)

@app.route('/check-auth')
def check_auth():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
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

        if not username or not password or not email:
            return render_template('signup.html', error_message="All fields are required.")

        if '@' not in email or '.' not in email.split('@')[-1]:
            return render_template('signup.html', error_message="Please enter a valid email address.")

        if User.query.filter_by(username=username).first():
            return render_template('signup.html', error_message="Username already exists.")
            
        if User.query.filter_by(email=email).first():
            return render_template('signup.html', error_message="Email already registered.")

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()

            session.permanent = True
            session['user_id'] = new_user.id
            session['username'] = new_user.username

            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration error: {str(e)}")
            error_msg = "Registration failed. Please try again."
            if "unique constraint" in str(e).lower():
                error_msg = "Username or email already exists."
            return render_template('signup.html', error_message=error_msg)

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        identifier = request.form.get('username_or_email', '').strip()
        password = request.form.get('password', '').strip()

        user = None
        if '@' in identifier:
            user = User.query.filter_by(email=identifier).first()
        else:
            user = User.query.filter_by(username=identifier).first()

        if not user or not check_password_hash(user.password, password):
            return render_template('login.html', error_message="Invalid credentials.")

        # Update last login
        user.last_login = datetime.utcnow()
        db.session.commit()

        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username

        return redirect(url_for('home'), code=303)

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True}), 200

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    heart_rates = HeartRate.query.filter_by(
        user_id=session['user_id']
    ).order_by(HeartRate.timestamp.desc()).limit(10).all()
    
    return render_template('profile.html', 
                         user=user,
                         heart_rates=heart_rates)

@app.route('/chat', methods=['POST'])
def chat():
    if 'user_id' not in session:
        return jsonify({
            'status': 'error',
            'message': 'Please log in first.',
            'type': 'text'
        }), 401

    if not request.is_json:
        return jsonify({
            'status': 'error',
            'message': 'Invalid request format. JSON expected.',
            'type': 'text'
        }), 400

    data = request.get_json()
    user_input = data.get('message', '').strip().lower()

    if not user_input:
        return jsonify({
            'status': 'error',
            'message': 'Empty message received.',
            'type': 'text'
        }), 400

    # Custom responses
    if user_input in ["who are you?", "what is your name?", "who is this?","who are you","what is echo ai"]:
        return jsonify({
            'status': 'success',
            'response': "I am Echo, your heart health assistant. I provide guidance and insights related to heart health to help you stay informed and make better health decisions.",
            'type': 'text'
        })

    if user_input in ["who created you?", "who invented you?", "who made you?"]:
        return jsonify({
            'status': 'success',
            'response': "I was created by a dedicated team of developers. Our team includes Guru Prasad, Harshavardhan Reddy, Ranjith, Giri. We are working to provide reliable heart health assistance through AI.",
            'type': 'text'
        })

    if not is_heart_related(user_input):
        return jsonify({
            'status': 'error',
            'message': 'I can only answer heart health-related questions.',
            'type': 'text'
        }), 400

    try:
        if not openai.api_key:
            return jsonify({
                'status': 'error',
                'message': 'OpenAI API key is missing.',
                'type': 'text'
            }), 500

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful heart health expert."},
                {"role": "user", "content": user_input}
            ],
            temperature=0.7
        )

        chatbot_response = response['choices'][0]['message']['content']

        return jsonify({
            'status': 'success',
            'response': chatbot_response,
            'type': 'text'
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}',
            'type': 'text'
        }), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    # For development, use SocketIO's run method
    socketio.run(app, 
                host='0.0.0.0', 
                port=int(os.environ.get('PORT', 5000)), 
                debug=os.getenv('FLASK_ENV') == 'development')
