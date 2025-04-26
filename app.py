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
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        # Validate all fields
        if not username or not password or not email:
            return render_template('signup.html', error_message="All fields are required.")

        # Basic email validation
        if '@' not in email or '.' not in email.split('@')[-1]:
            return render_template('signup.html', error_message="Please enter a valid email address.")

        # Check for existing username or email
        if User.query.filter_by(username=username).first():
            return render_template('signup.html', error_message="Username already exists.")
            
        if User.query.filter_by(email=email).first():
            return render_template('signup.html', error_message="Email already registered.")

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

        # Find user by username or email
        user = None
        if '@' in identifier:
            user = User.query.filter_by(email=identifier).first()
        else:
            user = User.query.filter_by(username=identifier).first()

        # Validate credentials
        if not user or not check_password_hash(user.password, password):
            return render_template('login.html', error_message="Invalid credentials.")

        # Set session variables
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
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }), 500

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
    user_input = data.get('message', '').strip()

    # Debug info
    print(f"Received message: '{user_input}'")
    print(f"Is heart related: {is_heart_related(user_input.lower())}")

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

    # Handle predefined queries with specific responses
    lower_input = user_input.lower().strip()
    
    # Custom responses
    if lower_input in ["who are you?", "who are you", "what is your name?", "who is this?", "what is echo ai?"]:
        bot_response = "I am Echo AI, your heart health assistant. I provide guidance and insights related to heart health to help you stay informed and make better health decisions."
    elif lower_input in ["what is echo ai", "what is echo ai?"]:
        bot_response = "Echo AI is a heart health assistant. It provides guidance and insights related to heart health to help you stay informed and make better health decisions."
    elif lower_input in ["hello", "hi", "hey", "greetings"]:
        bot_response = "Hello! I am Echo AI, your heart health assistant. How can I help you today?"
    elif lower_input in ["who created you?", "who invented you?", "who made you?", "who created you", "who invented you", "who made you", "who created you echo ai", "who created you echoai", "who created you echo ai?"]:
        bot_response = "I was created by a dedicated team of developers. Our team includes Guru Prasad, Harshavardhan Reddy, Ranjith, and Giri. We are working to provide reliable heart health assistance through AI."
    elif not is_heart_related(user_input):
        bot_response = "I'm specially designed to answer heart health-related questions. Could you please ask me something related to heart health, cardiac care, or general health concerns?"
    else:
        try:
            if not openai.api_key:
                return jsonify({
                    'status': 'error',
                    'message': 'OpenAI API key is missing.',
                    'type': 'text'
                }), 500

            # Detect language and respond appropriately
            system_prompt = """You are a helpful heart health expert who can communicate in English, Telugu, Hindi, Kannada, and Tamil. 
            Provide accurate, empathetic, and concise information about heart health topics in the user's preferred language. 
            Include relevant medical facts when appropriate, but always encourage users to consult healthcare professionals for personalized advice."""
            
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_input}
                ],
                temperature=0.7
            )

            bot_response = response['choices'][0]['message']['content']
        except Exception as e:
            app.logger.error(f"OpenAI API error: {str(e)}")
            bot_response = "I'm having trouble connecting to my knowledge base right now. Please try again in a moment or rephrase your question."

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
