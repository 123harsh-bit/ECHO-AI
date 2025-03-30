import os
from datetime import timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import openai
from dotenv import load_dotenv
from flask_cors import CORS

# ------------------ INITIAL SETUP ------------------
load_dotenv()  # Load environment variables from .env

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')

# Configure session
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-fallback-secret-key')  # Always set a secret key
app.config['SESSION_COOKIE_SECURE'] = True  # Requires HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)  # Session expires after 1 day

# Enable CORS for API routes
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

# OpenAI configuration
openai.api_key = os.getenv('OPENAI_API_KEY')

# ------------------ DATABASE MODELS ------------------
class Users(db.Model):
    """User model with authentication"""
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    chats = db.relationship('ChatHistory', backref='user', lazy=True)

class ChatHistory(db.Model):
    """Chat history model for storing chatbot interactions"""
    __tablename__ = "chat_history"
    id = db.Column(db.Integer, primary_key=True)
    user_input = db.Column(db.Text, nullable=False)
    bot_response = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

# ------------------ HEALTH KEYWORDS ------------------
HEART_KEYWORDS = [
    "heart", "cardiac", "blood pressure", "cholesterol", "heart attack", 
    "stroke", "arrhythmia", "hypertension", "pulse", "artery", "circulation",
    "ECG", "EKG", "cardiovascular", "angioplasty", "bypass surgery"
]

def is_heart_related(user_input):
    """Check if the user input contains heart-related keywords."""
    user_input = user_input.lower()
    return any(keyword in user_input for keyword in HEART_KEYWORDS)

# ------------------ MIDDLEWARE ------------------
@app.before_request
def before_request():
    """Ensure all requests use HTTPS and check session."""
    # Force HTTPS in production
    if request.url.startswith('http://') and os.getenv('FLASK_ENV') == 'production':
        return redirect(request.url.replace('http://', 'https://'), 301

# ------------------ ROUTES ------------------
@app.route('/')
def home():
    """Home route - requires authentication"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/check-auth')
def check_auth():
    """Endpoint for frontend to check authentication status"""
    if 'user_id' in session:
        return jsonify({
            'authenticated': True,
            'username': session.get('username')
        })
    return jsonify({'authenticated': False}), 401

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User signup route"""
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            return render_template('signup.html', error_message="Username and password are required.")

        if Users.query.filter_by(username=username).first():
            return render_template('signup.html', error_message="Username already exists.")

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = Users(username=username, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Automatically log in the new user
            session.permanent = True
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            return render_template('signup.html', error_message="Registration failed. Please try again.")

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        user = Users.query.filter_by(username=username).first()

        if not user:
            return render_template('login.html', error_message="Invalid username or password.")

        if not check_password_hash(user.password, password):
            return render_template('login.html', error_message="Invalid username or password.")

        # Set session variables
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        
        # Use 303 redirect to prevent form resubmission
        return redirect(url_for('home'), code=303)

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    """Logout route"""
    session.clear()
    return jsonify({'success': True}), 200

@app.route('/chat', methods=['POST'])
def chat():
    """Chat API endpoint"""
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

    if not user_input:
        return jsonify({
            'status': 'error',
            'message': 'Empty message received.',
            'type': 'text'
        }), 400

    if not is_heart_related(user_input):
        return jsonify({
            'status': 'error',
            'message': 'I can only answer heart health-related questions.',
            'type': 'text'
        }), 400

    # Get previous chats for context
    previous_chats = ChatHistory.query.filter_by(user_id=session['user_id']).order_by(ChatHistory.id.desc()).limit(5).all()
    conversation_history = [{"role": "system", "content": "You are a helpful heart health expert."}]

    for chat in reversed(previous_chats):  # Oldest first
        conversation_history.append({"role": "user", "content": chat.user_input})
        conversation_history.append({"role": "assistant", "content": chat.bot_response})

    conversation_history.append({"role": "user", "content": user_input})

    try:
        if not openai.api_key:
            return jsonify({
                'status': 'error',
                'message': 'OpenAI API key is missing.',
                'type': 'text'
            }), 500

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=conversation_history,
            temperature=0.7
        )

        chatbot_response = response['choices'][0]['message']['content']

        # Save to chat history
        new_chat = ChatHistory(
            user_input=user_input,
            bot_response=chatbot_response,
            user_id=session['user_id']
        )
        db.session.add(new_chat)
        db.session.commit()

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

@app.route('/history')
def history():
    """Chat history route"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    chats = ChatHistory.query.filter_by(user_id=session['user_id']).order_by(ChatHistory.id.desc()).all()
    return render_template('history.html', chats=chats)

# ------------------ MAIN ------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_ENV') == 'development')
