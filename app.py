# app.py
import os
import jwt
import random
import smtplib
import torch
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'qwertyuiopasdfghjklzxcvbnm'  # Replace with a strong secret key
app.config['MONGO_URI'] = 'mongodb+srv://22it113:smit@cluster0.4qp35.mongodb.net/auth_app?retryWrites=true&w=majority&appName=Cluster0'
app.config['JWT_SECRET_KEY'] = 'qwertyuiopasdfghjklzxcvbnm'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'smitpatel53751@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'fpaw decw yspa sifo'  
app.config['MODEL_PATH'] = 'best_model'  # Replace with your model path

# Initialize MongoDB
mongo = PyMongo(app)

# Model loading function
def load_model():
    model = torch.load(app.config['MODEL_PATH'])
    model.eval()
    return model

# JWT token verification decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            current_user = mongo.db.users.find_one({'email': data['email']})
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Email OTP function
def send_otp_email(email, otp):
    msg = MIMEMultipart()
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = email
    msg['Subject'] = 'Your OTP for Login'
    
    body = f'Your OTP for login is: {otp}'
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        text = msg.as_string()
        server.sendmail(app.config['MAIL_USERNAME'], email, text)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Validate password
        if len(password) < 8:
            return render_template('register.html', error='Password must be at least 8 characters long')
        
        if not any(char.isupper() for char in password):
            return render_template('register.html', error='Password must contain at least one uppercase letter')
            
        if not any(char.isdigit() for char in password):
            return render_template('register.html', error='Password must contain at least one number')
            
        if not any(char in '!@#$%^&*()-_=+[]{}|;:,.<>?/~`' for char in password):
            return render_template('register.html', error='Password must contain at least one special character')
        
        # Check if user already exists
        existing_user = mongo.db.users.find_one({'email': email})
        if existing_user:
            return render_template('register.html', error='Email already registered')
        
        # Create new user
        hashed_password = generate_password_hash(password)
        user_data = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'created_at': datetime.now()
        }
        
        mongo.db.users.insert_one(user_data)
        return redirect(url_for('login'))
    
    return render_template('register.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = mongo.db.users.find_one({'email': email})
        
        if user and check_password_hash(user['password'], password):
            # Generate OTP
            otp = str(random.randint(100000, 999999))
            
            # Store OTP and expiry in session
            session['otp'] = otp
            session['otp_expiry'] = (datetime.now() + timedelta(minutes=10)).timestamp()
            session['email'] = email
            
            # Send OTP via email
            if send_otp_email(email, otp):
                return redirect(url_for('verify_otp'))
            else:
                return render_template('login.html', error='Failed to send OTP')
        
        return render_template('login.html', error='Invalid email or password')
    
    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session or 'email' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        
        if datetime.now().timestamp() > session.get('otp_expiry', 0):
            return render_template('verify_otp.html', error='OTP expired')
        
        if user_otp == session['otp']:
            # Get user details
            user = mongo.db.users.find_one({'email': session['email']})
            
            # Generate JWT token
            token = jwt.encode({
                'email': user['email'],
                'exp': datetime.now() + timedelta(hours=24)
            }, app.config['JWT_SECRET_KEY'])
            
            # Clear OTP session variables
            session.pop('otp', None)
            session.pop('otp_expiry', None)
            
            # Store token in session
            session['token'] = token
            
            return redirect(url_for('model_page'))
        
        return render_template('verify_otp.html', error='Invalid OTP')
    
    return render_template('verify_otp.html')

@app.route('/model-page')
def model_page():
    if 'token' not in session:
        return redirect(url_for('login'))
    
    try:
        # Verify token
        data = jwt.decode(session['token'], app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        user = mongo.db.users.find_one({'email': data['email']})
        
        if not user:
            return redirect(url_for('login'))
        
        # Here you would load your model and render the model page
        return render_template('model_page.html', username=user['username'])
    
    except:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/predict', methods=['POST'])
@token_required
def predict(current_user):
    # Load model
    try:
        model = load_model()
        
        # Process input data (adjust according to your model's requirements)
        data = request.json.get('data')
        
        # Convert data to tensor and make prediction
        input_tensor = torch.tensor(data, dtype=torch.float32)
        with torch.no_grad():
            prediction = model(input_tensor)
        
        result = prediction.tolist()
        
        return jsonify({'prediction': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)