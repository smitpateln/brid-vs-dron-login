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
from flask_wtf.csrf import CSRFProtect

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MONGO_URI'] = os.getenv('MONGO_URI')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MODEL_PATH'] = 'best_model'

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Add HTTPS enforcement
@app.before_request
def force_https():
    # Check if we're already using HTTPS
    if request.headers.get('X-Forwarded-Proto') == 'http':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)
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
def send_otp_email(email, otp, is_registration=False, is_reset=False):
    msg = MIMEMultipart()
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = email
    
    if is_registration:
        msg['Subject'] = 'Verify Your Email Registration'
        body = f'Your OTP for email verification is: {otp}\n\nPlease enter this code to complete your registration.'
    elif is_reset:
        msg['Subject'] = 'Reset Your Password'
        body = f'Your OTP for password reset is: {otp}\n\nPlease enter this code to reset your password.'
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
        
        # Check if the stored hash begins with 'scrypt:' which indicates an unsupported hash type
        if user['password'].startswith('scrypt:'):
            # Option 1: Reset the password (safer but requires user action)
            # Redirect to password reset flow
            session['reset_email'] = email
            return redirect(url_for('forgot_password', 
                                   message="Your account needs a password update. Please reset your password."))

            # Option 2: Bypass password check for migration (less secure, temporary fix)
            # Instead of the code above, you could use this code to migrate the user:
            # new_hash = generate_password_hash(password)
            # mongo.db.users.update_one({'email': email}, {'$set': {'password': new_hash}})
            # However, this assumes the user entered the correct password
        else:
            # Normal password check
            try:
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
            except ValueError as e:
                print(f"Password verification error: {e}")
                # If we hit an error with the password hash, guide the user to reset
                session['reset_email'] = email
                return redirect(url_for('forgot_password', 
                               message="Your password needs to be updated for security reasons. Please reset it."))
        
        # If we get here, password was wrong
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
# Add these routes after the existing routes

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Check if user exists
        user = mongo.db.users.find_one({'email': email})
        
        if not user:
            return render_template('verify_email.html', error='Email not found in our records')
            
        if user.get('email_verified', False):
            return redirect(url_for('login', message='Your email is already verified. Please login.'))
        
        # Generate OTP
        otp = str(random.randint(100000, 999999))
        
        # Store email verification data in session
        session['verify_email'] = email
        session['verify_otp'] = otp
        session['verify_otp_expiry'] = (datetime.now() + timedelta(minutes=10)).timestamp()
        
        # Send OTP via email
        if send_otp_email(email, otp, is_registration=True):
            return redirect(url_for('confirm_email'))
        else:
            return render_template('verify_email.html', error='Failed to send verification email')
    
    return render_template('verify_email.html')

@app.route('/confirm-email', methods=['GET', 'POST'])
def confirm_email():
    if 'verify_email' not in session or 'verify_otp' not in session:
        return redirect(url_for('verify_email'))
    
    email = session.get('verify_email')
    
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        
        if datetime.now().timestamp() > session.get('verify_otp_expiry', 0):
            # Clear session data
            for key in ['verify_email', 'verify_otp', 'verify_otp_expiry']:
                session.pop(key, None)
            return render_template('verify_email.html', error='OTP expired. Please try again.')
        
        if user_otp == session['verify_otp']:
            # Update user's email verification status
            mongo.db.users.update_one({'email': email}, {'$set': {'email_verified': True}})
            
            # Clear verification session data
            for key in ['verify_email', 'verify_otp', 'verify_otp_expiry']:
                session.pop(key, None)
            
            return redirect(url_for('login', message='Email verified successfully! You can now login.'))
        
        return render_template('confirm_email.html', error='Invalid OTP', email=email)
    
    return render_template('confirm_email.html', email=email)

@app.route('/resend-verification-otp')
def resend_verification_otp():
    if 'verify_email' not in session:
        return redirect(url_for('verify_email'))
    
    email = session.get('verify_email')
    
    # Generate new OTP
    otp = str(random.randint(100000, 999999))
    
    # Update session with new OTP
    session['verify_otp'] = otp
    session['verify_otp_expiry'] = (datetime.now() + timedelta(minutes=10)).timestamp()
    
    # Send OTP via email
    if send_otp_email(email, otp, is_registration=True):
        return redirect(url_for('confirm_email', message='New verification code sent!'))
    else:
        return render_template('confirm_email.html', 
                              error='Failed to send new verification code', 
                              email=email)
# Add these routes to the end of your file, before if __name__ == '__main__':

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Check if user exists
        user = mongo.db.users.find_one({'email': email})
        
        if not user:
            return render_template('forgot_password.html', error='No account found with this email address')
        
        # Generate OTP
        otp = str(random.randint(100000, 999999))
        
        # Store password reset data in session
        session['reset_email'] = email
        session['reset_otp'] = otp
        session['reset_otp_expiry'] = (datetime.now() + timedelta(minutes=10)).timestamp()
        
        # Send OTP via email
        if send_otp_email(email, otp, is_reset=True):
            return redirect(url_for('reset_password'))
        else:
            return render_template('forgot_password.html', error='Failed to send reset code. Please try again.')
    
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session or 'reset_otp' not in session:
        return redirect(url_for('forgot_password'))
    
    email = session.get('reset_email')
    message = request.args.get('message', '')
    
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if datetime.now().timestamp() > session.get('reset_otp_expiry', 0):
            # Clear session data
            for key in ['reset_email', 'reset_otp', 'reset_otp_expiry']:
                session.pop(key, None)
            return render_template('forgot_password.html', error='Reset code expired. Please request a new one.')
        
        if user_otp != session['reset_otp']:
            return render_template('reset_password.html', email=email, error='Invalid reset code')
        
        if new_password != confirm_password:
            return render_template('reset_password.html', email=email, error='Passwords do not match')
        
        # Validate password
        if len(new_password) < 8:
            return render_template('reset_password.html', email=email, error='Password must be at least 8 characters long')
        
        if not any(char.isupper() for char in new_password):
            return render_template('reset_password.html', email=email, error='Password must contain at least one uppercase letter')
            
        if not any(char.isdigit() for char in new_password):
            return render_template('reset_password.html', email=email, error='Password must contain at least one number')
            
        if not any(char in '!@#$%^&*()-_=+[]{}|;:,.<>?/~`' for char in new_password):
            return render_template('reset_password.html', email=email, error='Password must contain at least one special character')
        
        # Update user's password
        hashed_password = generate_password_hash(new_password)
        mongo.db.users.update_one(
            {'email': email}, 
            {'$set': {'password': hashed_password}}
        )
        
        # Clear reset session data
        for key in ['reset_email', 'reset_otp', 'reset_otp_expiry']:
            session.pop(key, None)
        
        return redirect(url_for('login', message='Password reset successful! Please login with your new password.'))
    
    return render_template('reset_password.html', email=email, message=message)

@app.route('/resend-reset-otp')
def resend_reset_otp():
    if 'reset_email' not in session:
        return redirect(url_for('forgot_password'))
    
    # Generate new OTP
    otp = str(random.randint(100000, 999999))
    
    # Update session with new OTP
    session['reset_otp'] = otp
    session['reset_otp_expiry'] = (datetime.now() + timedelta(minutes=10)).timestamp()
    
    # Send OTP via email
    if send_otp_email(session['reset_email'], otp, is_reset=True):
        return redirect(url_for('reset_password', message='New reset code sent!'))
    else:
        return render_template('reset_password.html', 
                             error='Failed to send new reset code', 
                             email=session.get('reset_email'))
if __name__ == '__main__':
    app.run(debug=True)
