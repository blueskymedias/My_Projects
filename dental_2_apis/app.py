from flask import Flask, request, jsonify, render_template
from flask_bcrypt import Bcrypt
import psycopg2
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_cors import CORS
import logging
import random
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Enable CORS for the Flask app
CORS(app, resources={r"/*": {"origins": "http://localhost:5000"}})

# Load configurations from environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key_here")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "postgres")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "1616")
SMTP_SERVER = os.getenv("SMTP_SERVER", "email-smtp.ap-south-1.amazonaws.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "AKIAZAI4GTWCOJATHHPW")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "your-ses-smtp-password")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "loginsa80@gmail.com")

# In-memory OTP storage with expiration
otp_storage = {}

# Database connection
def get_db_connection():
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        logger.debug("Database connection established successfully.")
        return conn
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise

# Create tables
def create_tables():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id SERIAL PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS appointments (
                appointment_id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(user_id),
                name TEXT NOT NULL,
                phone_number TEXT NOT NULL,
                department TEXT NOT NULL,
                time TEXT NOT NULL,
                date TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'pending'
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                admin_id SERIAL PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            );
        """)
        hashed_user_password = bcrypt.generate_password_hash("securepassword123").decode('utf-8')
        cur.execute("""
            INSERT INTO users (email, password)
            VALUES (%s, %s)
            ON CONFLICT (email) DO NOTHING;
        """, ("patipraveen68@gmail.com", hashed_user_password))
        hashed_admin_password = bcrypt.generate_password_hash("admin123").decode('utf-8')
        cur.execute("""
            INSERT INTO admins (admin_id, email, password)
            VALUES (1, %s, %s)
            ON CONFLICT (admin_id) DO UPDATE SET
                email = EXCLUDED.email,
                password = EXCLUDED.password;
        """, ("admin@example.com", hashed_admin_password))
        conn.commit()
        logger.info("Database tables created, test user and admin inserted.")
    except Exception as e:
        logger.error(f"Failed to create tables: {e}")
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()

create_tables()

# Token handling
def encode_token(user_id, email, is_admin=False):
    try:
        token = jwt.encode({
            'user_id': user_id,
            'email': email,
            'is_admin': is_admin,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, SECRET_KEY, algorithm='HS256')
        logger.debug(f"Token generated for user_id={user_id}, is_admin={is_admin}")
        return token
    except Exception as e:
        logger.error(f"Error encoding token: {str(e)}")
        raise

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        logger.debug(f"Token verified: {payload}")
        return payload
    except jwt.ExpiredSignatureError:
        logger.error("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {str(e)}")
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            logger.warning("No token provided in Authorization header")
            return jsonify({'message': 'Token is missing'}), 401
        if token.startswith('Bearer '):
            token = token.split(' ')[1]
        else:
            logger.warning(f"Invalid Authorization header format: {token}")
            return jsonify({'message': 'Invalid token format. Use Bearer <token>'}), 401
        payload = verify_token(token)
        if not payload:
            logger.warning(f"Token validation failed: {token}")
            return jsonify({'message': 'Invalid or expired token'}), 401
        request.user = payload
        logger.info(f"Token validated for user: {payload['email']}")
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if not request.user.get('is_admin'):
            logger.warning(f"Non-admin access attempt: {request.user}")
            return jsonify({'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

# OTP handling
def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp, purpose="registration"):
    try:
        logger.info(f"Attempting to send OTP email from {SENDER_EMAIL} to {email} for {purpose}")
        msg = MIMEText(f"Your OTP for {purpose} is: {otp}. It is valid for 10 minutes.")
        msg['Subject'] = f'Email Verification OTP - {purpose.capitalize()}'
        msg['From'] = SENDER_EMAIL
        msg['To'] = email
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        logger.info(f"OTP email sent to {email} for {purpose}: {otp}")
    except Exception as e:
        logger.error(f"Failed to send OTP email to {email} for {purpose}: {str(e)}")
        raise

def verify_otp(email, otp, purpose="registration"):
    key = f"{email}:{purpose}"
    if key not in otp_storage:
        logger.warning(f"No OTP found for email: {email}, purpose: {purpose}")
        return False
    stored_otp_data = otp_storage[key]
    if datetime.now() > stored_otp_data["expiry"]:
        logger.warning(f"OTP expired for email: {email}, purpose: {purpose}")
        del otp_storage[key]
        return False
    if stored_otp_data["otp"] != otp:
        logger.warning(f"Invalid OTP for email: {email}, purpose: {purpose}, provided: {otp}")
        return False
    return True

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/history')
def history_page():
    return render_template('history.html')
# Route for About Us page
@app.route('/about')
def about():
    return render_template('abouts.html')

@app.route('/services')
def services():
    return render_template('services.html')
@app.route('/team')
def team():
    return render_template('teams.html')

@app.route('/request-otp', methods=['POST'])
def request_otp():
    data = request.json
    if not data:
        logger.warning("Invalid JSON or no data provided in /request-otp")
        return jsonify({"message": "Invalid JSON or no data provided."}), 400

    required_fields = ['email', 'password']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        logger.warning(f"Missing required fields in /request-otp: {missing_fields}")
        return jsonify({"message": f"Missing required fields: {', '.join(missing_fields)}."}), 400

    email = data['email'].lower()
    password = data['password']

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM users WHERE email = %s;", (email,))
        if cur.fetchone():
            logger.warning(f"Email already exists in /request-otp: {email}")
            return jsonify({"message": "Email already exists."}), 400
    except Exception as e:
        logger.error(f"Error checking email existence for {email}: {e}")
        return jsonify({"message": "Failed to process request. Please try again."}), 500
    finally:
        cur.close()
        conn.close()

    otp = generate_otp()
    expiry = datetime.now() + timedelta(minutes=10)
    otp_storage[f"{email}:registration"] = {
        "otp": otp,
        "password": bcrypt.generate_password_hash(password).decode('utf-8'),
        "expiry": expiry
    }
    logger.debug(f"OTP generated for {email} (registration): {otp}, expires at {expiry}")

    try:
        send_otp_email(email, otp, purpose="registration")
        logger.info(f"OTP request successful for {email}")
        return jsonify({"message": "OTP sent to your email. Please verify to complete registration."}), 200
    except Exception as e:
        logger.error(f"Failed to send OTP for {email}: {e}")
        return jsonify({"message": "Failed to send OTP. Please try again."}), 500

@app.route('/verify-otp', methods=['POST'])
def verify_otp_route():
    data = request.json
    if not data:
        logger.warning("Invalid JSON or no data provided in /verify-otp")
        return jsonify({"message": "Invalid JSON or no data provided."}), 400

    required_fields = ['email', 'otp']
    missing_fields = [field for field in required_fields if field not in data or not data[field]]
    if missing_fields:
        logger.warning(f"Missing or empty required fields in /verify-otp: {missing_fields}")
        return jsonify({"message": f"Missing required fields: {', '.join(missing_fields)}."}), 400

    email = data['email'].lower()
    otp = data['otp']

    if not verify_otp(email, otp, purpose="registration"):
        return jsonify({"message": "Invalid or expired OTP."}), 400

    hashed_password = otp_storage[f"{email}:registration"]["password"]
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (email, password) VALUES (%s, %s) RETURNING user_id;", (email, hashed_password))
        user_id = cur.fetchone()[0]
        conn.commit()
        del otp_storage[f"{email}:registration"]
        logger.info(f"User registered: {email}, user_id: {user_id}")
        return jsonify({"message": "Registration successful. Please log in."}), 201
    except Exception as e:
        conn.rollback()
        logger.error(f"Registration error for {email}: {e}")
        return jsonify({"message": "Failed to register. Please try again."}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    if not data:
        logger.warning("Invalid JSON or no data provided in /forgot-password")
        return jsonify({"message": "Invalid JSON or no data provided."}), 400

    required_fields = ['email']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        logger.warning(f"Missing required fields in /forgot-password: {missing_fields}")
        return jsonify({"message": f"Missing required fields: {', '.join(missing_fields)}."}), 400

    email = data['email'].lower()

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM users WHERE email = %s;", (email,))
        user = cur.fetchone()
        if not user:
            logger.warning(f"Email not found in /forgot-password: {email}")
            return jsonify({"message": "Email not found."}), 404
    except Exception as e:
        logger.error(f"Error checking email existence for {email}: {e}")
        return jsonify({"message": "Failed to process request. Please try again."}), 500
    finally:
        cur.close()
        conn.close()

    otp = generate_otp()
    expiry = datetime.now() + timedelta(minutes=10)
    otp_storage[f"{email}:password_reset"] = {
        "otp": otp,
        "expiry": expiry
    }
    logger.debug(f"OTP generated for {email} (password reset): {otp}, expires at {expiry}")

    try:
        send_otp_email(email, otp, purpose="password reset")
        logger.info(f"Password reset OTP request successful for {email}")
        return jsonify({"message": "OTP sent to your email. Please verify to reset your password."}), 200
    except Exception as e:
        logger.error(f"Failed to send password reset OTP for {email}: {e}")
        return jsonify({"message": "Failed to send OTP. Please try again."}), 500

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    if not data:
        logger.warning("Invalid JSON or no data provided in /reset-password")
        return jsonify({"message": "Invalid JSON or no data provided."}), 400

    required_fields = ['email', 'otp', 'new_password']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        logger.warning(f"Missing required fields in /reset-password: {missing_fields}")
        return jsonify({"message": f"Missing required fields: {', '.join(missing_fields)}."}), 400

    email = data['email'].lower()
    otp = data['otp']
    new_password = data['new_password']

    if not verify_otp(email, otp, purpose="password_reset"):
        return jsonify({"message": "Invalid or expired OTP."}), 400

    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET password = %s WHERE email = %s;", (hashed_password, email))
        conn.commit()
        del otp_storage[f"{email}:password_reset"]
        logger.info(f"Password reset successful for {email}")
        return jsonify({"message": "Password reset successful. Please log in with your new password."}), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Password reset error for {email}: {e}")
        return jsonify({"message": "Failed to reset password. Please try again."}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data:
        logger.warning("Invalid JSON or no data provided in /login")
        return jsonify({"message": "Invalid JSON or no data provided."}), 400

    required_fields = ['email', 'password']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        logger.warning(f"Missing required fields in /login: {missing_fields}")
        return jsonify({"message": f"Missing required fields: {', '.join(missing_fields)}."}), 400

    email = data['email'].lower()
    password = data['password']

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT admin_id FROM admins WHERE email = %s;", (email,))
        admin = cur.fetchone()
        if admin:
            logger.warning(f"Admin login attempt in /login for email: {email}")
            return jsonify({"message": "This email belongs to an admin. Please use the 'Admin Login' section."}), 401

        cur.execute("SELECT user_id, password FROM users WHERE email = %s;", (email,))
        user = cur.fetchone()
        if user and bcrypt.check_password_hash(user[1], password):
            token = encode_token(user_id=user[0], email=email, is_admin=False)
            logger.info(f"User logged in: {email}, user_id: {user[0]}")
            return jsonify({"message": "Login successful.", "token": token}), 200
        logger.warning(f"Login failed for {email}: Invalid credentials")
        return jsonify({"message": "Invalid credentials."}), 401
    except Exception as e:
        logger.error(f"Login error for {email}: {e}")
        return jsonify({"message": "Failed to log in. Please try again."}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    if not data:
        logger.warning("Invalid JSON or no data provided in /admin/login")
        return jsonify({"message": "Invalid JSON or no data provided."}), 400

    required_fields = ['email', 'password']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        logger.warning(f"Missing required fields in /admin/login: {missing_fields}")
        return jsonify({"message": f"Missing required fields: {', '.join(missing_fields)}."}), 400

    email = data['email'].lower()
    password = data['password']

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT admin_id, password FROM admins WHERE email = %s;", (email,))
        admin = cur.fetchone()
        if admin and bcrypt.check_password_hash(admin[1], password):
            token = encode_token(user_id=admin[0], email=email, is_admin=True)
            logger.info(f"Admin logged in: {email}, admin_id: {admin[0]}")
            return jsonify({"message": "Admin login successful.", "token": token}), 200
        logger.warning(f"Admin login failed for {email}: Invalid credentials")
        return jsonify({"message": "Invalid credentials."}), 401
    except Exception as e:
        logger.error(f"Admin login error for {email}: {e}")
        return jsonify({"message": "Failed to log in. Please try again."}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/create-appointment', methods=['POST'])
@token_required
def create_appointment():
    user_id = request.user['user_id']
    data = request.json
    if not data:
        logger.warning("Invalid JSON or no data provided in /create-appointment")
        return jsonify({"message": "Invalid JSON or no data provided."}), 400

    required_fields = ['name', 'phone_number', 'department', 'time', 'date', 'description']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        logger.warning(f"Missing required fields in /create-appointment: {missing_fields}")
        return jsonify({"message": f"Missing required fields: {', '.join(missing_fields)}."}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO appointments (user_id, name, phone_number, department, time, date, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING appointment_id;
        """, (user_id, data['name'], data['phone_number'], data['department'], data['time'], data['date'], data['description']))
        appointment_id = cur.fetchone()[0]
        conn.commit()
        logger.info(f"Appointment created: appointment_id={appointment_id}, user_id={user_id}")
        return jsonify({"message": "Appointment created successfully.", "appointment_id": appointment_id}), 201
    except Exception as e:
        conn.rollback()
        logger.error(f"Create appointment error for user_id {user_id}: {e}")
        return jsonify({"message": "Failed to create appointment. Please try again."}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/appointment-history', methods=['GET'])
@token_required
def get_appointment_history():
    user_id = request.user['user_id']
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT appointment_id, name, department, time, date, description, status FROM appointments WHERE user_id = %s;", (user_id,))
        appointments = cur.fetchall()
        result = [{
            "appointment_id": a[0],
            "name": a[1],
            "department": a[2],
            "time": a[3],
            "date": a[4],
            "description": a[5],
            "status": a[6]
        } for a in appointments]
        logger.info(f"Appointment history retrieved for user_id {user_id}")
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Get appointment history error for user_id {user_id}: {e}")
        return jsonify({"message": "Failed to retrieve appointment history. Please try again."}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/admin/appointments', methods=['GET'])
@admin_required
def get_all_appointments():
    admin_id = request.user['user_id']
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT appointment_id, user_id, name, phone_number, department, time, date, description, status FROM appointments;")
        appointments = cur.fetchall()
        result = [{
            "appointment_id": a[0],
            "user_id": a[1],
            "name": a[2],
            "phone_number": a[3],
            "department": a[4],
            "time": a[5],
            "date": a[6],
            "description": a[7],
            "status": a[8]
        } for a in appointments]
        logger.info(f"All appointments retrieved by admin_id {admin_id}")
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Get all appointments error for admin_id {admin_id}: {e}")
        return jsonify({"message": "Failed to retrieve appointments. Please try again."}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/admin/appointment/<int:appointment_id>', methods=['PUT'])
@admin_required
def update_appointment(appointment_id):
    admin_id = request.user['user_id']
    data = request.json
    if not data or 'status' not in data:
        logger.warning("Missing required field 'status' in /admin/appointment")
        return jsonify({"message": "Missing required field: status."}), 400

    status = data['status']
    if status not in ['accepted', 'rejected']:
        logger.warning(f"Invalid status in /admin/appointment: {status}")
        return jsonify({"message": "Invalid status. Must be 'accepted' or 'rejected'."}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE appointments SET status = %s WHERE appointment_id = %s RETURNING user_id;", (status, appointment_id))
        appointment = cur.fetchone()
        if not appointment:
            logger.warning(f"Appointment not found: {appointment_id}")
            return jsonify({"message": "Appointment not found."}), 404
        conn.commit()
        logger.info(f"Appointment {appointment_id} updated to {status} by admin_id {admin_id}")
        return jsonify({"message": "Appointment status updated."}), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Update appointment error for appointment_id {appointment_id}: {e}")
        return jsonify({"message": "Failed to update appointment status. Please try again."}), 500
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)