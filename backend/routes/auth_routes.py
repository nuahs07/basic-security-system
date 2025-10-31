from flask import Blueprint, request, jsonify
from database.supabase_client import supabase, supabase_admin
from security_logic.lockout_manager import check_lock_status, log_login_attempt, trigger_lock_if_needed

auth_api = Blueprint('auth_api', __name__)

@auth_api.route('/api/signup', methods=['POST'])
def signup():
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
             error_message = "Failed to create user in Auth."
             if auth_response.error:
                  error_message += f" Reason: {auth_response.error.message}"
             print(error_message)
             return jsonify({'error': error_message}), 400

    except Exception as e:
        print(f"Sign-up endpoint error: {e}")
        return jsonify({'error': f"An internal server error occurred: {str(e)}"}), 500

@auth_api.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        user_id = None

        if not all([email, password]):
            return jsonify({'error': 'Email and password are required'}), 400

        # --- 1. Get User ID from email ---
        try:
            list_users_response = supabase_admin.auth.admin.list_users(filter=f"email='{email}'")
            if list_users_response and list_users_response.users and len(list_users_response.users) > 0:
                user_id = list_users_response.users[0].id
        except Exception as lookup_err:
             print(f"Admin client error looking up user by email: {lookup_err}")

        # --- 2. Check if user is ALREADY locked ---
        if user_id:
            is_locked, message, remaining_sec = check_lock_status(user_id)
            if is_now_locked:
                # Get the duration from your lockout_manager constant
                from security_logic.lockout_manager import LOCKOUT_DURATION_MINUTES
                return jsonify({
                    'error': 'account_locked',
                    'message': message,
                    'lockout_duration_seconds': LOCKOUT_DURATION_MINUTES * 60
                }), 429

        # --- 3. ATTEMPT LOGIN ---
        try:
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
            if user_id:
                is_now_locked, message = trigger_lock_if_needed(user_id, email)
                if is_now_locked:
                    return jsonify({
                        'error': 'account_locked',
                        'message': message
                    }), 429
            
            return jsonify({'error': 'Invalid email or password'}), 401 # Unauthorized

    except Exception as e:
        print(f"FATAL login endpoint error: {e}")
        return jsonify({'error': 'An internal server error occurred.'}), 500