from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import openai
import os
from dotenv import load_dotenv

# ------------------ INITIAL SETUP ------------------

# Initialize Flask app
app = Flask(__name__)

# Load environment variables from .env
load_dotenv()

# Secret Key & OpenAI Key
app.secret_key = os.getenv("FLASK_SECRET_KEY")
openai.api_key = os.getenv("OPENAI_API_KEY")

# Fix DATABASE_URL for SQLAlchemy (Render uses "postgres://", but SQLAlchemy needs "postgresql://")
db_url = os.getenv("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# PostgreSQL Config
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Enable Flask-Migrate for migrations

# ------------------ DATABASE MODELS ------------------

class Users(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    chats = db.relationship('ChatHistory', backref='user', lazy=True)

class ChatHistory(db.Model):
    __tablename__ = "chat_history"
    id = db.Column(db.Integer, primary_key=True)
    user_input = db.Column(db.Text, nullable=False)
    bot_response = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

# ------------------ HEART KEYWORDS ------------------

HEART_KEYWORDS = [
    "heart", "cardiac", "blood pressure", "cholesterol", "heart attack",
    "stroke", "arrhythmia", "hypertension", "pulse", "artery", "ECG", "EKG",
    "coronary", "circulation", "aorta", "cardiovascular", "angioplasty"
]

def is_heart_related(user_input):
    """Check if the user input contains heart-related keywords."""
    user_input = user_input.lower()
    return any(keyword in user_input for keyword in HEART_KEYWORDS)

# ------------------ ROUTES ------------------

# ---------- Home ----------
@app.route('/')
def home():
    if 'user_id' in session:
        return render_template('index.html', username=session.get('username'))
    return redirect(url_for('login'))

# ---------- Sign Up ----------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if username exists
        if Users.query.filter_by(username=username).first():
            return render_template('signup.html', error_message="⚠️ Username already exists. Please try another.")

        # Hash password and add user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = Users(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('signup.html')

# ---------- Login ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = Users.query.filter_by(username=username).first()

        if not user:
            return render_template('login.html', error_message="⚠️ Username does not exist.")

        if not check_password_hash(user.password, password):
            return render_template('login.html', error_message="⚠️ Invalid password. Please try again.")

        session['user_id'] = user.id
        session['username'] = user.username  # Store username in session

        return redirect(url_for('home'))

    return render_template('login.html')

# ---------- Logout ----------
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)  # Clear username from session
    return redirect(url_for('login'))

# ---------- Chat ----------
@app.route('/chat', methods=['POST'])
def chat():
    if 'user_id' not in session:
        return jsonify({"response": "Please log in first.", "type": "text"}), 401

    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({"response": "Invalid input. Please enter a message.", "type": "text"}), 400

    user_input = data['message'].strip()

    if not is_heart_related(user_input):
        return jsonify({"response": "I can only answer heart health-related questions.", "type": "text"}), 400

    try:
        previous_chats = ChatHistory.query.filter_by(user_id=session['user_id']).order_by(ChatHistory.id.desc()).limit(5).all()
        conversation_history = [{"role": "system", "content": "You are a heart health expert."}]

        for chat in reversed(previous_chats):  
            conversation_history.append({"role": "user", "content": chat.user_input})
            conversation_history.append({"role": "assistant", "content": chat.bot_response})

        conversation_history.append({"role": "user", "content": user_input})

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=conversation_history
        )

        chatbot_response = response['choices'][0]['message']['content']

        # Save chat history
        new_chat = ChatHistory(user_input=user_input, bot_response=chatbot_response, user_id=session['user_id'])
        db.session.add(new_chat)
        db.session.commit()

        return jsonify({"response": chatbot_response, "type": "text"}), 200

    except openai.error.OpenAIError as e:
        return jsonify({"response": f"⚠️ OpenAI API error: {str(e)}", "type": "text"}), 500

    except Exception as e:
        return jsonify({"response": f"⚠️ Unexpected error: {str(e)}", "type": "text"}), 500

# ---------- Chat History ----------
@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    chats = ChatHistory.query.filter_by(user_id=session['user_id']).order_by(ChatHistory.id.desc()).all()
    return render_template('history.html', chats=chats)

# ------------------ MAIN ------------------

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
