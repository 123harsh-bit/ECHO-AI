from flask import Flask, render_template, request, jsonify
import openai
import os
from dotenv import load_dotenv

app = Flask(__name__)

# Load environment variables
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
def chat():
    user_input = request.json['message']

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",  
            messages=[{"role": "user", "content": user_input}]
        )
        chatbot_response = response['choices'][0]['message']['content']
        return jsonify({"response": chatbot_response})
    except Exception as e:
        return jsonify({"response": f"Error: {str(e)}"})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
