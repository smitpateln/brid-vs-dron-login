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
def send_otp_email(email, otp, is_registration=False):
    msg = MIMEMultipart()
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = email
    
    if is_registration:
        msg['Subject'] = 'Verify Your Email Registration'
        body = f'Your OTP for email verification is: {otp}\n\nPlease enter this code to complete your registration.'
    else:
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
        
        # Generate OTP
        otp = str(random.randint(100000, 999999))
        
        # Store registration data and OTP in session
        session['reg_username'] = username
        session['reg_email'] = email
        session['reg_password'] = password
        session['reg_otp'] = otp
        session['reg_otp_expiry'] = (datetime.now() + timedelta(minutes=10)).timestamp()
        
        # Send OTP via email
        if send_otp_email(email, otp, is_registration=True):
            return redirect(url_for('verify_registration_otp'))
        else:
            return render_template('register.html', error='Failed to send verification OTP')
    
    return render_template('register.html')

@app.route('/verify-registration-otp', methods=['GET', 'POST'])
def verify_registration_otp():
    if 'reg_otp' not in session or 'reg_email' not in session:
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        
        if datetime.now().timestamp() > session.get('reg_otp_expiry', 0):
            # Clear session data
            for key in ['reg_username', 'reg_email', 'reg_password', 'reg_otp', 'reg_otp_expiry']:
                session.pop(key, None)
            return render_template('register.html', error='OTP expired. Please register again.')
        
        if user_otp == session['reg_otp']:
            # Create new user
            username = session['reg_username']
            email = session['reg_email']
            password = session['reg_password']
            
            hashed_password = generate_password_hash(password)
            user_data = {
                'username': username,
                'email': email,
                'password': hashed_password,
                'email_verified': True,
                'created_at': datetime.now()
            }
            
            mongo.db.users.insert_one(user_data)
            
            # Clear registration session data
            for key in ['reg_username', 'reg_email', 'reg_password', 'reg_otp', 'reg_otp_expiry']:
                session.pop(key, None)
            
            return redirect(url_for('login', message='Registration successful! Please login.'))
        
        return render_template('verify_registration_otp.html', error='Invalid OTP')
    
    return render_template('verify_registration_otp.html', email=session.get('reg_email'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = request.args.get('message', '')
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = mongo.db.users.find_one({'email': email})
        
        if not user:
            return render_template('login.html', error='Invalid email or password')
            
        if not user.get('email_verified', False):
            return render_template('login.html', error='Email not verified. Please register again.')
        
        if check_password_hash(user['password'], password):
            # Generate JWT token
            token = jwt.encode({
                'email': user['email'],
                'exp': datetime.now() + timedelta(hours=24)
            }, app.config['JWT_SECRET_KEY'])
            
            # Store token in session
            session['token'] = token
            session['email'] = email
            
            return redirect(url_for('model_page'))
        
        return render_template('login.html', error='Invalid email or password')
    
    return render_template('login.html', message=message)

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

@app.route('/resend-registration-otp')
def resend_registration_otp():
    if 'reg_email' not in session:
        return redirect(url_for('register'))
    
    # Generate new OTP
    otp = str(random.randint(100000, 999999))
    
    # Update session with new OTP
    session['reg_otp'] = otp
    session['reg_otp_expiry'] = (datetime.now() + timedelta(minutes=10)).timestamp()
    
    # Send OTP via email
    if send_otp_email(session['reg_email'], otp, is_registration=True):
        return redirect(url_for('verify_registration_otp', message='New OTP sent!'))
    else:
        return render_template('verify_registration_otp.html', 
                              error='Failed to send new OTP', 
                              email=session.get('reg_email'))

if __name__ == '__main__':
    app.run(debug=True)