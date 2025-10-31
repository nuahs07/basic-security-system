from flask import Blueprint, request, jsonify
# --- FIX: Import the missing variables and create_client function ---
from database.supabase_client import (
    supabase, 
    supabase_admin, 
    SUPABASE_URL, 
    SUPABASE_SERVICE_KEY
)
from supabase import create_client
# --- END FIX ---
from security_logic.lockout_manager import (
    check_lock_status, 
    log_login_attempt, 
    trigger_lock_if_needed,
    LOCKOUT_DURATION_MINUTES # Import the constant
)
import traceback
from datetime import datetime, timedelta # Make sure datetime is imported

auth_api = Blueprint('auth_api', __name__)

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
        
        # Use the ANON client for signup
        auth_response = supabase.auth.sign_up({ "email": email, "password": password })

        if auth_response.user:
            user_id = auth_response.user.id
            print(f"User created in Auth: {user_id}")
            
            profile_data = {
                "username": username,
                "first_name": first_name,
                "last_name": last_name,
                "is_locked": False
            }
            
            # Use the ADMIN client to UPDATE the profile (bypasses RLS)
            profile_result = supabase_admin.table("profiles") \
                                     .update(profile_data) \
                                     .eq("user_id", user_id) \
                                     .execute()
            print(f"Profile update attempted: {profile_result.data}")

            return jsonify({
                'success': True,
                'user_id': user_id,
                'message': 'User created successfully. Please check your email for confirmation.'
            }), 201
        else:
             # Handle errors from Supabase
             error_message = "Failed to create user in Auth."
             if hasattr(auth_response, 'error') and auth_response.error:
                  error_message += f" Reason: {auth_response.error.message}"
             elif hasattr(auth_response, 'message'):
                 error_message += f" Reason: {auth_response.message}"
             print(error_message)
             return jsonify({'error': error_message}), 400

    except Exception as e:
        print(f"Sign-up endpoint error: {e}")
        traceback.print_exc()
        return jsonify({'error': f"An internal server error occurred: {str(e)}"}), 500

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

        # --- 1. Get User ID from email (THE CORRECT FIX) ---
        try:
            # Create a new, temporary admin client pointed *only* at the auth schema
            supabase_auth_admin = create_client(
                SUPABASE_URL, 
                SUPABASE_SERVICE_KEY,
                options={"schema": "auth"} # Tell the client to use the 'auth' schema
            )
            
            # Query the 'users' table (which this client knows is in the 'auth' schema)
            user_res = supabase_auth_admin.table("users").select("id").eq("email", email).execute()

            if user_res.data and len(user_res.data) > 0:
                user_id = user_res.data[0]['id']
                print(f"Found user_id ({user_id}) for email {email}.")
            else:
                print(f"No user found for email {email}.")
        except Exception as lookup_err:
             print(f"Admin client error looking up user by email: {lookup_err}")
        
        # --- 2. Check if user is ALREADY locked ---
        if user_id:
            is_locked, message, remaining_sec = check_lock_status(user_id)
            if is_locked:
                return jsonify({
                    'error': 'account_locked',
                    'message': message,
                    'lockout_duration_seconds': remaining_sec
                }), 429

        # --- 3. ATTEMPT LOGIN ---
        try:
            # Use the ANON client for the actual login attempt
            session_response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            # --- 4. SUCCESS ---
            if session_response.session and session_response.user:
                user_id = session_response.user.id # Confirm user_id
                print(f"Login successful for user {user_id} ({email}).")
                
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
            # --- 5. FAILURE ---
            print(f"Authentication failed for {email}.")
            
            log_login_attempt(user_id, email, request.remote_addr, False, "Invalid password or email")

            # --- 6. Check if this failure triggers a lock ---
            if user_id: # Only lock if we know who the user is
                is_now_locked, message = trigger_lock_if_needed(user_id, email)
                if is_now_locked:
                    return jsonify({
                        'error': 'account_locked',
                        'message': message,
                        'lockout_duration_seconds': LOCKOUT_DURATION_MINUTES * 60
                    }), 429
            
            return jsonify({'error': 'Invalid email or password'}), 401 # Unauthorized

    except Exception as e:
        print(f"FATAL login endpoint error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'An internal server error occurred.'}), 500