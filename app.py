import os
from datetime import timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import openai
from dotenv import load_dotenv
from flask_cors import CORS
from flask_migrate import Migrate

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

# ------------------ HEALTH KEYWORDS ------------------
HEART_KEYWORDS = [
    "heart", "cardiac", "blood pressure", "cholesterol", "heart attack",
    "stroke", "arrhythmia", "hypertension", "pulse", "artery", "circulation",
    "ECG", "EKG", "cardiovascular", "angioplasty", "bypass surgery"
]

def is_heart_related(user_input):
    user_input = user_input.lower()
    return any(keyword in user_input for keyword in HEART_KEYWORDS)

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
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_ENV') == 'development')
    
