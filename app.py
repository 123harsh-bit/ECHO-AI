import os
from datetime import timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import openai
from dotenv import load_dotenv
from flask_cors import CORS
from flask_migrate import Migrate
import json
from datetime import datetime

# ------------------ INITIAL SETUP ------------------
load_dotenv()  # Load environment variables from .env

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
migrate = Migrate(app, db)  # For database migrations

# OpenAI configuration
openai.api_key = os.getenv('OPENAI_API_KEY')

# ------------------ DATABASE MODELS ------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    chat_sessions = db.relationship('ChatSession', backref='user', lazy=True)

class ChatSession(db.Model):
    __tablename__ = "chat_sessions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    messages = db.relationship('ChatMessage', backref='session', lazy=True, cascade="all, delete-orphan")

class ChatMessage(db.Model):
    __tablename__ = "chat_messages"
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('chat_sessions.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_user = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ------------------ HEALTH KEYWORDS ------------------
HEART_KEYWORDS = [
   # General Terms
    "heart", "cardiac", "cardiovascular", "pulse", "BPM", "heartbeat", 
    "circulation", "blood flow", "ventricle", "atrium", "aorta", "artery",
    "vein", "capillary", "myocardium", "pericardium", "valve", "ventricular",
    
    # Conditions & Diseases
    "heart attack", "myocardial infarction", "angina", "arrhythmia", 
    "tachycardia", "bradycardia", "AFib", "atrial fibrillation", 
    "ventricular fibrillation", "heart failure", "CHF", "cardiomyopathy",
    "endocarditis", "pericarditis", "atherosclerosis", "ischemia", 
    "heart murmur", "mitral regurgitation", "aortic stenosis", 
    "congenital heart", "CHD", "cardiac arrest", "sudden cardiac death",
    
    # Measurements & Tests
    "blood pressure", "BP", "systolic", "diastolic", "hypertension", 
    "hypotension", "cholesterol", "LDL", "HDL", "triglycerides", 
    "lipid profile", "ECG", "EKG", "electrocardiogram", "echo", 
    "echocardiogram", "stress test", "angiogram", "Holter monitor",
    "cardiac CT", "calcium score", "CABG", "angioplasty", "stent",
    
    # Symptoms
    "chest pain", "palpitations", "dizziness", "shortness of breath",
    "SOB", "fatigue", "edema", "swelling", "syncope", "fainting",
    "fluttering", "racing heart", "skipped beats", "indigestion",
    "arm pain", "jaw pain", "cold sweat", "cyanosis", "clubbing",
    
    # Lifestyle & Prevention
    "heart-healthy diet", "Mediterranean diet", "DASH diet", "exercise", 
    "cardio", "aerobic", "walking", "swimming", "cycling", "smoking", 
    "alcohol", "stress", "BMI", "obesity", "salt intake", "sodium",
    "potassium", "omega-3", "coenzyme Q10", "antioxidants", "fiber",
    
    # Medications & Treatments
    "statin", "beta blocker", "ACE inhibitor", "ARB", "diuretic",
    "blood thinner", "warfarin", "aspirin", "nitroglycerin", "pacemaker",
    "ICD", "defibrillator", "CABG", "bypass surgery", "valve replacement",
    "TAVR", "cardiac rehab", "CPR", "AED",
    
    # Demographic Terms
    "women heart health", "men's cardiovascular", "senior heart care",
    "pediatric cardiology", "athlete heart", "genetic risk",
    
    # Numbers & Ranges
    "72", "120/80", "140/90", "60-100", "40-60", "100+", "200+",
    
    # Emergency Terms
    "911", "emergency", "chest tightness", "crushing pain", "call doctor"
]

def is_heart_related(user_input):
    user_input = user_input.lower()
    return any(keyword in user_input for keyword in HEART_KEYWORDS)

def generate_chat_title(user_input):
    """Generate a title for the chat session based on the first user message"""
    try:
        if not openai.api_key:
            return user_input[:30] + ("..." if len(user_input) > 30 else "")
            
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Generate a very short title (3-5 words max) for this chat about heart health. Just return the title, nothing else."},
                {"role": "user", "content": user_input}
            ],
            temperature=0.3,
            max_tokens=15
        )
        return response['choices'][0]['message']['content'].strip('"\'')
    except Exception:
        return user_input[:30] + ("..." if len(user_input) > 30 else "")

# ------------------ MIDDLEWARE ------------------
@app.before_request
def before_request():
    """Force HTTPS in production"""
    if request.url.startswith('http://') and os.getenv('FLASK_ENV') == 'production':
        return redirect(request.url.replace('http://', 'https://'), 301)

# ------------------ ROUTES ------------------
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get current user's username
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

@app.route('/api/chat-sessions', methods=['GET'])
def get_chat_sessions():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    sessions = ChatSession.query.filter_by(user_id=session['user_id']).order_by(ChatSession.updated_at.desc()).all()
    
    sessions_data = [{
        'id': session.id,
        'title': session.title,
        'created_at': session.created_at.strftime('%Y-%m-%d %H:%M'),
        'updated_at': session.updated_at.strftime('%Y-%m-%d %H:%M'),
        'is_current': 'current_chat_id' in session and session.id == session['current_chat_id']
    } for session in sessions]
    
    return jsonify(sessions_data)

@app.route('/api/chat-sessions', methods=['POST'])
def create_chat_session():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    new_session = ChatSession(
        user_id=session['user_id'],
        title="New Chat"
    )
    
    try:
        db.session.add(new_session)
        db.session.commit()
        session['current_chat_id'] = new_session.id
        return jsonify({
            'id': new_session.id,
            'title': new_session.title,
            'created_at': new_session.created_at.strftime('%Y-%m-%d %H:%M')
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat-sessions/<int:session_id>', methods=['GET'])
def get_chat_session(session_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    chat_session = ChatSession.query.filter_by(id=session_id, user_id=session['user_id']).first()
    if not chat_session:
        return jsonify({'error': 'Chat session not found'}), 404
    
    messages = [{
        'content': msg.content,
        'is_user': msg.is_user,
        'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M')
    } for msg in chat_session.messages]
    
    return jsonify({
        'id': chat_session.id,
        'title': chat_session.title,
        'messages': messages
    })

@app.route('/api/chat-sessions/<int:session_id>', methods=['DELETE'])
def delete_chat_session(session_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    chat_session = ChatSession.query.filter_by(id=session_id, user_id=session['user_id']).first()
    if not chat_session:
        return jsonify({'error': 'Chat session not found'}), 404
    
    try:
        db.session.delete(chat_session)
        db.session.commit()
        
        # If we deleted the current chat, create a new one
        if 'current_chat_id' in session and session['current_chat_id'] == session_id:
            new_session = ChatSession(user_id=session['user_id'], title="New Chat")
            db.session.add(new_session)
            db.session.commit()
            session['current_chat_id'] = new_session.id
            
        return jsonify({'success': True}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # (Keep your existing signup route code)
    # ... your existing signup code ...

@app.route('/login', methods=['GET', 'POST'])
def login():
    # (Keep your existing login route code)
    # ... your existing login code ...

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True}), 200

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/api/heart-rate', methods=['POST'])
def handle_heart_rate():
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
        
    data = request.get_json()
    
    # Here you can:
    # 1. Store in database
    # 2. Perform analysis
    # 3. Trigger alerts if needed
    
    print(f"Heart rate received from user {session['user_id']}: {data['bpm']} bpm at {data['timestamp']}")
    
    return jsonify({'status': 'success'})

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

    # Check if we have a current chat session
    if 'current_chat_id' not in session:
        # Create a new chat session
        chat_title = generate_chat_title(user_input)
        new_session = ChatSession(
            user_id=session['user_id'],
            title=chat_title
        )
        db.session.add(new_session)
        db.session.commit()
        session['current_chat_id'] = new_session.id
    else:
        # Get current chat session
        chat_session = ChatSession.query.get(session['current_chat_id'])
        if not chat_session:
            # Session was deleted or doesn't exist
            chat_title = generate_chat_title(user_input)
            new_session = ChatSession(
                user_id=session['user_id'],
                title=chat_title
            )
            db.session.add(new_session)
            db.session.commit()
            session['current_chat_id'] = new_session.id

    # Save user message to database
    user_message = ChatMessage(
        session_id=session['current_chat_id'],
        content=user_input,
        is_user=True
    )
    db.session.add(user_message)

    # Custom responses
    if user_input in ["who are you?","Who are you", "what is your name?", "who is this?","who are you","what is echo ai"]:
        bot_response = "I am Echo Ai, your heart health assistant. I provide guidance and insights related to heart health to help you stay informed and make better health decisions."
    elif user_input in ["what is echo ai","what is echo ai"]:
        bot_response = "Echo Ai is a heart health assistant. It provide guidance and insights related to heart health to help you stay informed and make better health decisions."
    elif user_input in ["hello","hi",]:
        bot_response = "I am Echo Ai, your heart health assistant. How can i Help you?"
    elif user_input in ["who created you?", "who invented you?", "who made you?","who created you", "who invented you", "who made you","who created you echo ai","who created you echoai","who created you echo ai?"]:
        bot_response = "I was created by a dedicated team of developers. Our team includes Guru Prasad, Harshavardhan Reddy, Ranjith, Giri. We are working to provide reliable heart health assistance through AI."
    elif not is_heart_related(user_input):
        bot_response = 'I can only answer heart health-related questions.'
    else:
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

            bot_response = response['choices'][0]['message']['content']
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': f'Error: {str(e)}',
                'type': 'text'
            }), 500

    # Save bot response to database
    bot_message = ChatMessage(
        session_id=session['current_chat_id'],
        content=bot_response,
        is_user=False
    )
    db.session.add(bot_message)
    
    # Update chat session title if it's the first message
    chat_session = ChatSession.query.get(session['current_chat_id'])
    if len(chat_session.messages) <= 2:  # User message + bot response
        chat_session.title = generate_chat_title(user_input)
    
    db.session.commit()

    return jsonify({
        'status': 'success',
        'response': bot_response,
        'type': 'text',
        'chat_session_id': session['current_chat_id']
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_ENV') == 'development')
