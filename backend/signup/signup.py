from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import re
import sys
import os

# Add backend directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(current_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Import Supabase client
try:
    from database.supabase_client import supabase
    print("Supabase client imported successfully!")
except ImportError as e:
    print(f"Error importing supabase_client: {e}")
    print(f"Backend directory: {backend_dir}")
    print(f"Python path: {sys.path}")
    raise

app = Flask(__name__)
CORS(app)


# Helper Validation Functions

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"


def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


# Signup Endpoint

@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.json or {}

        # Extract data safely
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()

        # Basic validation
        if not username or not email or not password:
            return jsonify({'error': 'Username, email, and password are required'}), 400

        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters long'}), 400

        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400

        is_valid, message = validate_password(password)
        if not is_valid:
            return jsonify({'error': message}), 400

        # Check if username exists in profiles
        existing_user = supabase.table('profiles').select('username').eq('username', username).execute()
        if existing_user.data:
            return jsonify({'error': 'Username already exists'}), 409


        # Create Auth User in Supabase

        try:
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password
            })

            # Fix for Supabase v2: access data safely
            user = getattr(auth_response, "user", None) or getattr(auth_response, "data", {}).get("user")
            if not user:
                return jsonify({'error': 'Failed to create authentication account'}), 500

            user_id = user.id

        except Exception as auth_error:
            error_msg = str(auth_error)
            if "already registered" in error_msg.lower():
                return jsonify({'error': 'Email already registered'}), 409
            return jsonify({'error': f'Authentication error: {error_msg}'}), 500


        # Create Profile Record

        profile_data = {
            'user_id': user_id,
            'username': username,
            'first_name': first_name or None,
            'last_name': last_name or None,
            'is_locked': False
        }

        print("Inserting into customer_accounts:", profile_data)

        profile_result = supabase.table('customer_accounts').insert(profile_data).execute()

        if not profile_result.data:
            return jsonify({'error': 'Failed to create user profile'}), 500

        # Return success response

        return jsonify({
            'message': 'User account created successfully',
            'user_id': user_id,
            'username': username,
            'email': email
        }), 201

    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


# Check Username Endpoint

@app.route('/api/check-username', methods=['POST'])
def check_username():
    try:
        username = request.json.get('username', '').strip()

        if not username:
            return jsonify({'available': False, 'message': 'Username is required'}), 400
        if len(username) < 3:
            return jsonify({'available': False, 'message': 'Username must be at least 3 characters'}), 400

        existing_user = supabase.table('profiles').select('username').eq('username', username).execute()
        if existing_user.data:
            return jsonify({'available': False, 'message': 'Username is already taken'}), 200

        return jsonify({'available': True, 'message': 'Username is available'}), 200

    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500



# Check Email Endpoint

@app.route('/api/check-email', methods=['POST'])
def check_email():
    try:
        email = request.json.get('email', '').strip()

        if not email:
            return jsonify({'available': False, 'message': 'Email is required'}), 400
        if not validate_email(email):
            return jsonify({'available': False, 'message': 'Invalid email format'}), 400

        # Just confirm format; cannot check auth.users directly
        return jsonify({'available': True, 'message': 'Email format is valid'}), 200

    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500



if __name__ == '__main__':
    app.run(debug=True, port=5000)
