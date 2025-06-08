import os
from datetime import timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import openai
from dotenv import load_dotenv
from flask_cors import CORS
from flask_migrate import Migrate
import json
from datetime import datetime
from authlib.integrations.flask_client import OAuth
from urllib.parse import urlencode
import secrets
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
app_logger = logging.getLogger(__name__)

# ------------------ INITIAL SETUP ------------------
load_dotenv()  # Load environment variables from .env

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')

# Configure session
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(16))
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7) # Increased lifetime for user convenience

# Enable CORS (for API routes, as defined in original code)
CORS(app, resources={
    r"/chat": {"origins": "*"},
    r"/api/*": {"origins": "*"}
})

# Database configuration
db_url = os.getenv('DATABASE_URL')
if db_url and db_url.startswith('postgres://'):
    db_url = db_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///echoai.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # For database migrations

# OpenAI configuration
openai.api_key = os.getenv('OPENAI_API_KEY')
if not openai.api_key:
    app_logger.warning("OPENAI_API_KEY is not set. Chatbot functionality may be limited.")


# OAuth configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v3/',
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_post'
    },
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

# ------------------ DATABASE MODELS ------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=True)  # Made nullable for Google users
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)  # Made nullable for Google users
    google_id = db.Column(db.String(150), unique=True, nullable=True)
    profile_picture = db.Column(db.String(500), nullable=True)
    chat_sessions = db.relationship('ChatSession', backref='user', lazy=True, cascade="all, delete-orphan") # Added cascade

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
    # English Terms - General
    "heart", "cardiac", "cardiovascular", "pulse", "bpm", "heartbeat",
    "circulation", "blood flow", "ventricle", "atrium", "aorta", "artery",
    "vein", "capillary", "myocardium", "pericardium", "valve", "ventricular",
    
    # Conditions & Diseases
    "heart attack", "myocardial infarction", "angina", "arrhythmia",
    "tachycardia", "bradycardia", "afib", "atrial fibrillation",
    "ventricular fibrillation", "heart failure", "chf", "cardiomyopathy",
    "endocarditis", "pericarditis", "atherosclerosis", "ischemia",
    "heart murmur", "mitral regurgitation", "aortic stenosis",
    "congenital heart", "chd", "cardiac arrest", "sudden cardiac death",
    
    # Measurements & Tests
    "blood pressure", "bp", "systolic", "diastolic", "hypertension",
    "hypotension", "cholesterol", "ldl", "hdl", "triglycerides",
    "lipid profile", "ecg", "ekg", "electrocardiogram", "echo",
    "echocardiogram", "stress test", "angiogram", "holter monitor",
    "cardiac ct", "calcium score", "cabg", "angioplasty", "stent",
    
    # Symptoms
    "chest pain", "palpitations", "dizziness", "shortness of breath",
    "sob", "fatigue", "edema", "swelling", "syncope", "fainting",
    "fluttering", "racing heart", "skipped beats", "indigestion",
    "arm pain", "jaw pain", "cold sweat", "cyanosis", "clubbing",
    
    # Lifestyle & Prevention
    "heart-healthy diet", "mediterranean diet", "dash diet", "exercise",
    "cardio", "aerobic", "walking", "swimming", "cycling", "smoking",
    "alcohol", "stress", "bmi", "obesity", "salt intake", "sodium",
    "potassium", "omega-3", "coenzyme q10", "antioxidants", "fiber",
    
    # Medications & Treatments
    "statin", "beta blocker", "ace inhibitor", "arb", "diuretic",
    "blood thinner", "warfarin", "aspirin", "nitroglycerin", "pacemaker",
    "icd", "defibrillator", "cabg", "bypass surgery", "valve replacement",
    "tavr", "cardiac rehab", "cpr", "aed",
    
    # Telugu Terms
    "గుండె", "హృదయం", "హృదయ వైఫల్యం", "రక్తపోటు", "బీపీ", "గుండె ఆరోగ్యం",
    "గుండె నొప్పి", "హృదయ స్పందన", "పల్స్", "గుండె జబ్బు", "హృదయ వ్యాయామం",
    "కొలెస్ట్రాల్", "గుండెపోటు", "హృదయ నాళాలు", "రక్తం", "ధమనులు", "సిరలు",
    "గుండె మందులు", "హృదయ శస్త్రచికిత్స", "గుండె వైద్యుడు", "కార్డియాలజిస్ట్",
    
    # Hindi Terms
    "हृदय", "दिल", "हार्ट", "हृदय रोग", "रक्तचाप", "बीपी", "हृदय स्वास्थ्य",
    "सीने में दर्द", "हृदय गति", "नब्ज", "हृदय रोग", "हृदय व्यायाम",
    "कोलेस्ट्रॉल", "हार्ट अटैक", "हृदय धमनियाँ", "रक्त", "धमनियाँ", "नसें",
    "हृदय की दवाएं", "हृदय शल्य चिकित्सा", "हृदय रोग विशेषज्ञ", "कार्डियोलॉजिस्ट",
    
    # Kannada Terms
    "ಹೃದಯ", "ಗುಂಡಿಗೆ", "ಹೃದಯ ಸಮಸ್ಯೆ", "ರಕ್ತದೊತ್ತಡ", "ಬಿಪಿ", "ಹೃದಯ ಆರೋಗ್ಯ",
    "ಎದೆ ನೋವು", "ಹೃದಯ ಬಡಿತ", "ನಾಡಿ", "ಹೃದಯ ರೋಗ", "ಹೃದಯ ವ್ಯಾಯಾಮ",
    "ಕೊಲೆಸ್ಟರಾಲ್", "ಹೃದಯಾಘಾತ", "ಹೃದಯ ಧಮನಿಗಳು", "ರಕ್ತ", "ಧಮನಿಗಳು", "ಸಿರೆಗಳು",
    "ಹೃದಯ medicine", "ಹೃದಯ ಶಸ್ತ್ರಚಿಕಿತ್ಸೆ", "ಹೃದಯ ವೈದ್ಯ", "ಕಾರ್ಡಿಯೋಲಜಿಸ್ಟ್",
    
    # Tamil Terms
    "இதயம்", "கார்டியாக்", "இதய நோய்", "இரத்த அழுத்தம்", "பிபி", "இதய ஆரோக்கியம்",
    "மார்பு வலி", "இதய துடிப்பு", "நாடி", "இதய பிரச்சினை", "இதய உடற்பயிற்சி",
    "கொலஸ்ட்ரால்", "இதயத்துடிப்பு", "இதய நாளங்கள்", "இரத்தம்", "தமனிகள்", "சிரைகள்",
    "இதய மருந்துகள்", "இதய அறுவை சிகிச்சை", "இதய மருத்துவர்", "கார்டியாலஜிஸ்ட்",
    
    # Common health terms across languages
    "health", "ఆరోగ్యం", "स्वास्थ्य", "ಆರೋಗ್ಯ", "ஆரோக்யம்",
    "doctor", "డాక్టర్", "डॉक्टर", "ಡಾಕ್ಟರ್", "மருத்துவர்",
    "medicine", "మందు", "दवा", "ಮದ್ದು", "மருந்து",
    "treatment", "చికిత్స", "इलाज", "ಚಿಕಿತ್ಸೆ", "சிகிச்சை",
    "symptoms", "లక్షణాలు", "लक्षण", "ಲಕ್ಷಣಗಳು", "அறிகுறிகள்"
]

def is_heart_related(user_input):
    """Improved function to detect heart-related questions in multiple languages"""
    user_input = user_input.lower()
    
    # Direct keyword match in any language
    for keyword in HEART_KEYWORDS:
        if keyword.lower() in user_input:
            return True
    
    # Common health phrases that might be heart-related (multilingual)
    health_phrases = [
        # English
        "check my heart", "my heart", "heart health", "chest", "breathing problem",
        "blood pressure", "exercise advice", "diet for heart", "medical history",
        "heart rate", "heart monitor", "cardiac", "heart specialist", "cardiologist",
        "risk factor", "family history", "check up", "monitor", "ecg", "ekg",
        
        # Telugu
        "గుండె తనిఖీ", "నా గుండె", "గుండె ఆరోగ్యం", "ఛాతీ", "శ్వాస సమస్య",
        "రక్తపోటు", "వ్యాయామ సలహా", "గుండెకు ఆహారం", "వైద్య చరిత్ర",
        
        # Hindi
        "दिल की जांच", "मेरा दिल", "दिल की सेहत", "छाती", "सांस की समस्या",
        "ब्लड प्रेशर", "व्यायाम सलाह", "दिल के लिए आहार", "चिकित्सा इतिहास",
        
        # Kannada
        "ಹೃದಯ ಪರಿಶೀಲನೆ", "ನನ್ನ ಹೃದಯ", "ಹೃದಯ ಆರೋಗ್ಯ", "ಎದೆ", "ಉಸಿರಾಟದ ತೊಂದರೆ",
        "ರಕ್ತದೊತ್ತಡ", "ವ್ಯಾಯಾಮ ಸಲಹೆ", "ಹೃದಯಕ್ಕೆ ಆಹಾರ", "ವೈದ್ಯಕೀಯ ಇತಿಹಾಸ",
        
        # Tamil
        "இதய சோதனை", "என் இதயம்", "இதய ஆரோக்கியம்", "மார்பு", "மூச்சுத் திணறல்",
        "இரத்த அழுத்தம்", "உடற்பயிற்சி ஆலோசனை", "இதயத்திற்கான உணவு", "மருத்துவ வரலாறு"
    ]
    
    for phrase in health_phrases:
        if phrase.lower() in user_input:
            return True
    
    # If the question seems to be asking about health in general
    general_health_terms = [
        # English
        "health", "healthy", "doctor", "medical", "condition", "symptoms", "treatment",
        # Telugu
        "ఆరోగ్యం", "వైద్యుడు", "వైద్య", "స్థితి", "లక్షణాలు", "చికిత్స",
        # Hindi
        "स्वास्थ्य", "स्वस्थ", "डॉक्टर", "चिकित्सा", "स्थिति", "लक्षण", "इलाज",
        # Kannada
        "ಆರೋಗ್ಯ", "ಆರೋಗ್ಯಕರ", "ವೈದ್ಯ", "ವೈದ್ಯಕೀಯ", "ಸ್ಥಿತಿ", "ಲಕ್ಷಣಗಳು", "ಚಿಕಿತ್ಸೆ",
        # Tamil
        "ஆரோக்கியம்", "ஆரோக்கியமான", "மருத்துவர்", "மருத்துவ", "நிலை", "அறிகுறிகள்", "சிகிச்சை"
    ]
    
    if any(term in user_input for term in general_health_terms):
        # For general health questions, be more permissive
        return True
        
    return False

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
        return response['choices'][0]['message']['content'].strip('"\'').strip('.')
    except Exception as e:
        app_logger.error(f"Error generating chat title with OpenAI: {e}")
        return user_input[:30] + ("..." if len(user_input) > 30 else "")

def create_or_get_user(email, username=None, google_id=None, profile_picture=None):
    """Helper function to create or get user"""
    user = User.query.filter_by(email=email).first()
    if not user:
        # Create new user
        user = User(
            email=email,
            username=username or email.split('@')[0],
            google_id=google_id,
            profile_picture=profile_picture
        )
        db.session.add(user)
        db.session.commit()
    else:
        # Update existing user with Google ID and profile picture if they are missing
        if google_id and not user.google_id:
            user.google_id = google_id
        if profile_picture and (not user.profile_picture or user.profile_picture != profile_picture):
            user.profile_picture = profile_picture
        # Update username if it's default (email part) and a better one is provided
        if user.username == user.email.split('@')[0] and username and username != user.username:
            user.username = username
        db.session.commit()
    return user

# ------------------ MIDDLEWARE ------------------
@app.before_request
def before_request():
    """Force HTTPS in production"""
    if request.url.startswith('http://') and os.getenv('FLASK_ENV') == 'production':
        return redirect(request.url.replace('http://', 'https://'), 301)

# ------------------ AUTH ROUTES ------------------
@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'username': user.username,
        'email': user.email,
        'profile_picture': user.profile_picture,
        'google_id': user.google_id
    })

@app.route('/google-login')
def google_login():
    """Initialize Google OAuth flow"""
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    # Generate a secure nonce
    nonce = secrets.token_urlsafe(16)
    session['google_nonce'] = nonce
    
    # Force HTTPS in production
    redirect_uri = url_for('google_authorize', _external=True)
    if os.getenv('FLASK_ENV') == 'production':
        redirect_uri = redirect_uri.replace('http://', 'https://')
    
    return google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/google-authorize')
def google_authorize():
    try:
        # Check if nonce exists in session
        if 'google_nonce' not in session:
            flash('Google authentication failed: Missing nonce. Please try again.', 'error')
            return redirect(url_for('login'))
            
        # Force HTTPS in production
        if os.getenv('FLASK_ENV') == 'production':
            request.url = request.url.replace('http://', 'https://')
            
        # Get token with proper nonce verification
        token = google.authorize_access_token()
        if not token or 'id_token' not in token:
            flash('Google authentication failed: No token received. Please try again.', 'error')
            return redirect(url_for('login'))
            
        # Verify token with the stored nonce
        user_info = google.parse_id_token(token, nonce=session.pop('google_nonce', None))
        if not user_info.get('email'):
            flash('Google authentication failed: No email provided by Google. Please ensure your email is public.', 'error')
            return redirect(url_for('login'))
            
        # Get additional user info including profile picture
        google_user_info = google.get('userinfo').json()
        profile_picture = google_user_info.get('picture')
        
        # Create or get user with profile picture
        user = create_or_get_user(
            email=user_info['email'],
            username=user_info.get('name', user_info['email'].split('@')[0]),
            google_id=user_info['sub'],
            profile_picture=profile_picture
        )
        
        # Set session
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        session['email'] = user.email
        
        flash(f'Welcome, {user.username}!', 'success')
        return redirect(url_for('home'))
        
    except Exception as e:
        app_logger.error(f"Google OAuth error: {str(e)}")
        flash(f'Google login failed: {str(e)}. Please try again.', 'error')
        return redirect(url_for('login'))

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
        if not user:
            # User ID in session but not in DB (e.g., deleted account)
            session.clear()
            return jsonify({'authenticated': False}), 401
            
        return jsonify({
            'authenticated': True,
            'username': user.username,
            'email': user.email,
            'profile_picture': user.profile_picture,
            'google_id': user.google_id
        })
    return jsonify({'authenticated': False}), 401
    
@app.route('/api/chat-sessions', methods=['GET'])
def get_chat_sessions():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    sessions = ChatSession.query.filter_by(user_id=session['user_id']).order_by(ChatSession.updated_at.desc()).all()
    
    sessions_data = []
    for s in sessions:
        # Fetch only the first message to use for the icon heuristic if needed
        first_message = ChatMessage.query.filter_by(session_id=s.id, is_user=True).order_by(ChatMessage.created_at.asc()).first()
        sessions_data.append({
            'id': s.id,
            'title': s.title,
            'created_at': s.created_at.isoformat(), # ISO format for easy JS parsing
            'updated_at': s.updated_at.isoformat(),
            'first_message_content': first_message.content if first_message else "",
            'message_count': len(s.messages) # Helps determine if it's an empty "New Chat"
        })
        
    return jsonify(sessions_data)

@app.route('/api/chat-sessions', methods=['POST'])
def create_chat_session():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Check if there's an existing empty "New Chat" session and activate it
    existing_empty_session = ChatSession.query.filter_by(user_id=session['user_id'], title="New Chat").first()
    if existing_empty_session and len(existing_empty_session.messages) == 0:
        session['current_chat_id'] = existing_empty_session.id
        # Re-fetch sessions to update the active state correctly on the client
        updated_sessions = ChatSession.query.filter_by(user_id=session['user_id']).order_by(ChatSession.updated_at.desc()).all()
        sessions_data = []
        for s in updated_sessions:
             first_message = ChatMessage.query.filter_by(session_id=s.id, is_user=True).order_by(ChatMessage.created_at.asc()).first()
             sessions_data.append({
                'id': s.id,
                'title': s.title,
                'created_at': s.created_at.isoformat(),
                'updated_at': s.updated_at.isoformat(),
                'first_message_content': first_message.content if first_message else "",
                'message_count': len(s.messages)
            })
        return jsonify({
            'id': existing_empty_session.id,
            'title': existing_empty_session.title,
            'created_at': existing_empty_session.created_at.isoformat(),
            'message': 'Activated existing empty chat session',
            'sessions': sessions_data # Return updated sessions list for client to refresh
        }), 200

    new_session = ChatSession(
        user_id=session['user_id'],
        title="New Chat" # Default title
    )
    
    try:
        db.session.add(new_session)
        db.session.commit()
        session['current_chat_id'] = new_session.id
        return jsonify({
            'id': new_session.id,
            'title': new_session.title,
            'created_at': new_session.created_at.isoformat(),
            'message': 'New chat session created'
        }), 201
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"Error creating chat session: {e}")
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
        'created_at': msg.created_at.isoformat() # ISO format for easy JS parsing
    } for msg in chat_session.messages]
    
    session['current_chat_id'] = chat_session.id # Set current session in Flask session
    
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
        
        # If we deleted the current chat, redirect to home to create a new session
        if 'current_chat_id' in session and session['current_chat_id'] == session_id:
            session.pop('current_chat_id', None) # Clear the current chat ID
            # Frontend will handle creating a new chat when it detects no current_chat_id
            return jsonify({'success': True, 'message': 'Chat deleted and session reset'}), 200
        
        return jsonify({'success': True, 'message': 'Chat deleted'}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"Error deleting chat session: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        # Validate all fields
        if not username or not password or not email:
            flash("All fields are required.", 'error')
            return render_template('signup.html', username=username, email=email)

        # Basic email validation
        if '@' not in email or '.' not in email.split('@')[-1]:
            flash("Please enter a valid email address.", 'error')
            return render_template('signup.html', username=username, email=email)

        # Check for existing username or email
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", 'error')
            return render_template('signup.html', username=username, email=email)
            
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", 'error')
            return render_template('signup.html', username=username, email=email)

        # Create new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()

            # Set session variables
            session.permanent = True
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            session['email'] = new_user.email
            flash("Registration successful! Welcome to Echo AI.", 'success')
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            app_logger.error(f"Registration error: {str(e)}")
            error_msg = "Registration failed. Please try again."
            if "unique constraint" in str(e).lower():
                error_msg = "Username or email already exists."
            flash(error_msg, 'error')
            return render_template('signup.html', username=username, email=email)

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        identifier = request.form.get('username_or_email', '').strip()
        password = request.form.get('password', '').strip()

        # Find user by username or email
        user = None
        if '@' in identifier:
            user = User.query.filter_by(email=identifier).first()
        else:
            user = User.query.filter_by(username=identifier).first()

        # Validate credentials
        if not user or not user.password or not check_password_hash(user.password, password):
            flash("Invalid credentials. Please check your username/email and password.", 'error')
            return render_template('login.html', identifier=identifier)

        # Set session variables
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        session['email'] = user.email
        
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(url_for('home'), code=303)

    return render_template('login.html')
    
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return jsonify({'success': True}), 200

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user = User.query.get(session['user_id'])
    if not user:
        flash("User not found.", 'error')
        session.clear()
        return redirect(url_for('login'))

    return render_template('profile.html',
                           user=user,
                           profile_picture=user.profile_picture)

@app.route('/api/heart-rate', methods=['POST'])
def handle_heart_rate():
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
        
    data = request.get_json()
    bpm = data.get('bpm')
    timestamp = data.get('timestamp')

    if not bpm or not timestamp:
        return jsonify({'status': 'error', 'message': 'Missing bpm or timestamp'}), 400

    try:
        # In a real application, you'd store this in a dedicated HR table
        # For now, we'll just log it.
        app_logger.info(f"Heart rate received from user {session['user_id']}: {bpm} bpm at {timestamp}")
        
        # You could add logic here to trigger further analysis or alerts based on stored data
        
        return jsonify({'status': 'success', 'message': 'Heart rate received successfully'})
    except Exception as e:
        app_logger.error(f"Error handling heart rate: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/test-openai', methods=['GET'])
def test_openai():
    """Test OpenAI API connection"""
    try:
        if not openai.api_key:
            return jsonify({
                'status': 'error',
                'message': 'OpenAI API key is missing.'
            }), 500

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hello, are you working?"}
            ],
            temperature=0.7
        )

        return jsonify({
            'status': 'success',
            'message': 'OpenAI API is working.',
            'response': response['choices'][0]['message']['content']
        })
    except Exception as e:
        app_logger.error(f"OpenAI API test error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}. Please check your OpenAI API key and network connection.'
        }), 500

@app.route('/chat', methods=['POST'])
def chat():
    if 'user_id' not in session:
        return jsonify({
            'status': 'error',
            'message': 'Please log in first.',
            'type': 'auth_required'
        }), 401

    if not request.is_json:
        return jsonify({
            'status': 'error',
            'message': 'Invalid request format. JSON expected.',
            'type': 'text'
        }), 400

    data = request.get_json()
    user_input = data.get('message', '').strip()
    session_id = data.get('session_id') # Get session_id from client

    app_logger.info(f"User {session['user_id']} message: '{user_input}' (Session ID: {session_id})")

    if not user_input:
        return jsonify({
            'status': 'error',
            'message': 'Empty message received.',
            'type': 'text'
        }), 400

    chat_session = None
    if session_id:
        chat_session = ChatSession.query.filter_by(id=session_id, user_id=session['user_id']).first()

    if not chat_session:
        # If no session_id or invalid session_id, create a new one
        chat_title = generate_chat_title(user_input)
        new_session = ChatSession(
            user_id=session['user_id'],
            title=chat_title
        )
        db.session.add(new_session)
        db.session.commit()
        chat_session = new_session
        session['current_chat_id'] = chat_session.id # Update Flask session to new chat_id
        app_logger.info(f"Created new chat session: {chat_session.id} with title '{chat_session.title}'")
    else:
        # Update updated_at timestamp for existing session
        chat_session.updated_at = datetime.utcnow()
        db.session.add(chat_session) # Mark as modified
        db.session.commit()
        session['current_chat_id'] = chat_session.id # Ensure Flask session is aligned

    # Save user message to database
    user_message = ChatMessage(
        session_id=chat_session.id,
        content=user_input,
        is_user=True
    )
    db.session.add(user_message)
    db.session.commit() # Commit user message immediately

    # Update session title if it's the first message and still "New Chat"
    # This might happen if a new chat was created but the title not yet set
    if chat_session.title == "New Chat" and len(chat_session.messages) <= 1: # Only user message is there
        chat_session.title = generate_chat_title(user_input)
        db.session.commit() # Commit title update


    # Get previous messages for context
    previous_messages = ChatMessage.query.filter_by(session_id=chat_session.id).order_by(ChatMessage.created_at.asc()).all()
    
    # Prepare messages for OpenAI API
    # Start with a system prompt including medical disclaimer
    system_prompt = """You are Echo AI, a helpful and empathetic heart health assistant.
    You provide accurate, evidence-based, and concise information about heart health topics in the user's preferred language (English, Telugu, Hindi, Kannada, Tamil).
    You can discuss symptoms, preventive measures, lifestyle changes, common conditions, and general medical facts related to the heart.
    
    ***IMPORTANT MEDICAL DISCLAIMER:***
    I am an AI assistant and *not* a medical professional. The information I provide is for educational and informational purposes only, and should not be considered medical advice, diagnosis, or treatment. Always consult with a qualified healthcare professional for any health concerns or before making any decisions related to your health or medical care. In case of a medical emergency, call your local emergency services immediately.
    """
    
    messages_for_openai = [{"role": "system", "content": system_prompt}]
    
    # Add historical messages to provide context
    for msg in previous_messages:
        messages_for_openai.append({"role": "user" if msg.is_user else "assistant", "content": msg.content})

    # Add the current user input as the last message
    # We already saved it, but for context we need to send it to OpenAI
    messages_for_openai.append({"role": "user", "content": user_input})

    bot_response = ""
    # Handle predefined queries or non-heart-related questions first
    lower_input = user_input.lower().strip()
    
    if lower_input in ["who are you?", "who are you", "what is your name?", "who is this?", "what is echo ai?", "what is echoai?"]:
        bot_response = "I am cardiX, your heart health assistant. I provide guidance and insights related to heart health to help you stay informed and make better health decisions."
    elif lower_input in ["hello", "hi", "hey", "greetings"]:
        bot_response = "Hello! I am cardiX, your heart health assistant. How can I help you today?"
    elif lower_input in ["who created you?", "who invented you?", "who made you?", "who created you", "who invented you", "who made you", "who created you echo ai", "who created you echoai", "who created you echo ai?"]:
        bot_response = "I was created by  Harsha . We are working to provide reliable heart health assistance through AI."
    elif not is_heart_related(user_input):
        bot_response = "I'm specially designed to answer heart health-related questions. Could you please ask me something related to heart health, cardiac care, or general health concerns?"
    else:
        try:
            if not openai.api_key:
                bot_response = "I'm sorry, my AI brain is not connected. Please check the API key configuration."
            else:
                app_logger.info(f"Sending to OpenAI: {messages_for_openai}")
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=messages_for_openai,
                    temperature=0.7 # A bit higher for more creative but still factual responses
                )
                bot_response = response['choices'][0]['message']['content']
        except openai.error.OpenAIError as e:
            app_logger.error(f"OpenAI API error: {e}")
            bot_response = f"I'm experiencing issues connecting to my AI knowledge base. Please try again in a moment. Error: {e}"
            if "AuthenticationError" in str(e):
                 bot_response = "I'm having trouble with my AI brain due to an authentication issue. Please contact support."
        except Exception as e:
            app_logger.error(f"Unexpected chat error: {e}")
            bot_response = "I encountered an unexpected error. Please try again or rephrase your question."

    # Save bot response to database
    bot_message = ChatMessage(
        session_id=chat_session.id,
        content=bot_response,
        is_user=False
    )
    db.session.add(bot_message)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'response': bot_response,
        'type': 'text',
        'chat_session_id': chat_session.id, # Ensure client knows the session ID
        'chat_title': chat_session.title # Send back the (potentially updated) title
    })

@app.route('/forgot-password')
def forgot_password():
    # This is a placeholder for a real forgot password flow
    return render_template('forgot_password.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # You might want to run migrations here in production:
        # from flask_migrate import upgrade
        # upgrade()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_ENV') == 'development')
