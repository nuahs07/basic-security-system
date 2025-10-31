from flask import Blueprint, request, jsonify
from database.supabase_client import (
    supabase,
    supabase_admin,
    SUPABASE_URL,
    SUPABASE_SERVICE_KEY
)
from security_logic.lockout_manager import (
    check_lock_status,
    log_login_attempt,
    trigger_lock_if_needed,
    LOCKOUT_DURATION_SECONDS
)
from datetime import datetime
import traceback

auth_api = Blueprint('auth_api', __name__)

# ----------------------------------------------------------
# 🟢 SIGN UP
# ----------------------------------------------------------
@auth_api.route('/api/signup', methods=['POST'])
def signup():
    """Handle user sign-up"""
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        first_name = data.get('first_name', '')
        last_name = data.get('last_name', '')

        if not all([username, email, password]):
            return jsonify({'error': 'Username, email, and password are required'}), 400
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400

        print(f"Attempting signup for: {email}")

        # Create the user in Supabase Auth
        auth_response = supabase.auth.sign_up({"email": email, "password": password})

        if auth_response.user:
            user_id = auth_response.user.id
            print(f"✅ User created in Auth: {user_id}")

            # Insert or update user profile in 'profiles' table
            profile_data = {
                "user_id": user_id,
                "username": username,
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "is_locked": False
            }

            # Use ADMIN client to bypass RLS and modify profile
            supabase_admin.table("profiles").upsert(profile_data).execute()

            return jsonify({
                'success': True,
                'user_id': user_id,
                'message': 'User created successfully. Please check your email for confirmation.'
            }), 201
        else:
            error_message = "Failed to create user in Auth."
            if hasattr(auth_response, 'error') and auth_response.error:
                error_message += f" Reason: {auth_response.error.message}"
            elif hasattr(auth_response, 'message'):
                error_message += f" Reason: {auth_response.message}"
            print(error_message)
            return jsonify({'error': error_message}), 400

    except Exception as e:
        print(f"❌ Sign-up endpoint error: {e}")
        traceback.print_exc()
        return jsonify({'error': f"An internal server error occurred: {str(e)}"}), 500


# ----------------------------------------------------------
# 🟡 LOGIN
# ----------------------------------------------------------
@auth_api.route('/api/login', methods=['POST'])
def login():
    """Handle user login with custom security checks"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        user_id = None

        if not all([email, password]):
            return jsonify({'error': 'Email and password are required'}), 400

        # --- 1. Lookup user_id from the profiles table ---
        try:
            user_res = supabase_admin.table("profiles").select("user_id").eq("email", email).execute()
            if user_res.data and len(user_res.data) > 0:
                user_id = user_res.data[0]['user_id']
                print(f"Found user_id ({user_id}) for email {email}.")
            else:
                print(f"No user found for email {email}.")
        except Exception as lookup_err:
            print(f"Admin client error looking up user by email: {lookup_err}")

        # --- 2. Check lockout status ---
        if user_id:
            is_locked, message, remaining_sec = check_lock_status(user_id)
            if is_locked:
                return jsonify({
                    'error': 'account_locked',
                    'message': message,
                    'lockout_duration_seconds': remaining_sec
                }), 429

        # --- 3. Attempt login ---
        try:
            session_response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            # --- 4. Success ---
            if session_response.session and session_response.user:
                user_id = session_response.user.id
                print(f"✅ Login successful for user {user_id} ({email}).")

                log_login_attempt(user_id, email, request.remote_addr, True, None)
                supabase_admin.table("profiles").update({"is_locked": False}).eq("user_id", user_id).execute()

                return jsonify({
                    'success': True,
                    'message': 'Login successful!',
                    'access_token': session_response.session.access_token,
                    'refresh_token': session_response.session.refresh_token
                }), 200
            else:
                raise Exception("Login response from Supabase unexpected.")

        except Exception as auth_error:
            print(f"❌ Authentication failed for {email}: {auth_error}")
            log_login_attempt(user_id, email, request.remote_addr, False, "Invalid credentials")

            if user_id:
                is_now_locked, message = trigger_lock_if_needed(user_id, email)
                if is_now_locked:
                    return jsonify({
                        'error': 'account_locked',
                        'message': message,
                        'lockout_duration_seconds': LOCKOUT_DURATION_SECONDS
                    }), 429

            return jsonify({'error': 'Invalid email or password'}), 401

    except Exception as e:
        print(f"🔥 FATAL login endpoint error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'An internal server error occurred.'}), 500


# ----------------------------------------------------------
# 🔵 EMAIL CONFIRMATION PLACEHOLDER
# ----------------------------------------------------------
@auth_api.route('/api/confirm-email', methods=['GET'])
def confirm_email():
    """Handle confirmation redirect (placeholder)."""
    return jsonify({'message': 'Email confirmation simulated (this route is for demonstration).'}), 200
