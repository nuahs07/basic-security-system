from flask import Blueprint, request, jsonify
from database.supabase_client import (
    supabase,
    supabase_admin,
    SUPABASE_URL,
    SUPABASE_SERVICE_KEY,
    SUPABASE_ANON_KEY
)
from security_logic.lockout_manager import (
    check_lock_status,
    log_login_attempt,
    trigger_lock_if_needed,
    LOCKOUT_DURATION_SECONDS
)
from security_logic.data_encryptor import encrypt_data
import base64
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

            # 1. Insert or update user profile in 'profiles' table
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
            print("✅ Profile upserted.")

            try:
                initial_data = f"User {username}'s secure file, created on {datetime.now().isoformat()}"
                
                # 3. Encrypt it using the new user's password
                encrypted_content_bytes, salt_bytes = encrypt_data(initial_data, password)
                
                # 4. Encode to base64 text for database storage
                encrypted_content_text = base64.b64encode(encrypted_content_bytes).decode('utf-8')
                salt_text = base64.b64encode(salt_bytes).decode('utf-8')

                # 5. Insert the encrypted data and the salt into user_data
                user_data_payload = {
                    "user_id": user_id,
                    "data_type": "profile_info",
                    "data_content": encrypted_content_text, # Store encrypted text
                    "salt": salt_text,                   # Store the salt
                    "encrypted": True
                }
                data_result = supabase_admin.table("user_data").insert(user_data_payload).execute()
                print(f"✅ Initial user data (encrypted) created.")

            except Exception as data_err:
                    print(f"❌ Warning: Could not create initial user_data. {data_err}")
                    # Don't fail the whole signup, just log the warning

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
            user_res = supabase_admin.from_("profiles").select("user_id").eq("email", email).execute()
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
                
                # --- RESET FAILED ATTEMPTS ON SUCCESSFUL LOGIN ---
                print(f"Resetting failed login attempts for user {user_id}.")
                supabase_admin.table("login_attempts") \
                              .delete() \
                              .eq("user_id", user_id) \
                              .eq("success", False) \
                              .execute()

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
            print(f"❌ Authentication failed for {email}: {auth_error}")
            log_login_attempt(user_id, email, request.remote_addr, False, "Invalid credentials")

            if user_id: # Only lock if we know who the user is
                is_now_locked, message, duration_sec = trigger_lock_if_needed(user_id, email)
                if is_now_locked:
                    return jsonify({
                        'error': 'account_locked',
                        'message': message,
                        'lockout_duration_seconds': duration_sec 
                    }), 429

            return jsonify({'error': 'Invalid email or password'}), 401

    except Exception as e:
        print(f"🔥 FATAL login endpoint error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'An internal server error occurred.'}), 500


#forgot pass
@auth_api.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    """Send password reset email to user"""
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({'error': 'Email is required'}), 400

        print(f"Attempting password reset for: {email}")

        # Use Supabase Auth to send password reset email
        # This will send an email with a reset link to the user
        response = supabase.auth.reset_password_for_email(
            email,
            {
                "redirect_to": "http://localhost:5000/reset-password"
            }
        )

        # Supabase doesn't raise an error if email doesn't exist (security feature)
        # So we always return success to prevent email enumeration
        return jsonify({
            'success': True,
            'message': 'If an account with that email exists, a password reset link has been sent.'
        }), 200

    except Exception as e:
        print(f"Forgot password endpoint error: {e}")
        traceback.print_exc()
        # Still return success to prevent email enumeration
        return jsonify({
            'success': True,
            'message': 'If an account with that email exists, a password reset link has been sent.'
        }), 200


#reset pass
@auth_api.route('/api/reset-password', methods=['POST'])
def reset_password():
    """Reset user password using token from email"""
    try:
        data = request.get_json()
        password = data.get('password')
        token = data.get('token')

        if not password:
            return jsonify({'error': 'Password is required'}), 400
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400
        if not token:
            return jsonify({'error': 'Reset token is required'}), 400

        print(f"Attempting password reset with token")

        # Exchange the token for a session and update password
        session_response = supabase.auth.set_session(token)
        
        if session_response.user:
            user_id = session_response.user.id
            
            # Update the password
            update_response = supabase.auth.update_user({
                "password": password
            })

            if update_response.user:
                print(f"Password reset successful for user {user_id}")
                
                # Also unlock the account if it was locked
                supabase_admin.table("profiles").update({"is_locked": False}).eq("user_id", user_id).execute()
                
                # Clear failed login attempts
                supabase_admin.table("login_attempts") \
                              .delete() \
                              .eq("user_id", user_id) \
                              .eq("success", False) \
                              .execute()

                return jsonify({
                    'success': True,
                    'message': 'Password reset successful. You can now login with your new password.'
                }), 200
            else:
                return jsonify({'error': 'Failed to update password'}), 400
        else:
            return jsonify({'error': 'Invalid or expired reset token'}), 400

    except Exception as e:
        print(f"Reset password endpoint error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Invalid or expired reset token'}), 400



# reset pass (unlock account after reset)
@auth_api.route('/api/reset-password-cleanup', methods=['POST'])
def reset_password_cleanup():
    """Unlock account and clear failed attempts after password reset"""
    try:
        # Get access token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization token'}), 401
        
        access_token = auth_header.split('Bearer ')[1]
        
        # Create a Supabase client with the access token to get user info
        from supabase import create_client
        supabase_with_token = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        
        # Get the user from the token
        user_res = supabase_with_token.auth.get_user(access_token)
        
        if not user_res.user:
            return jsonify({'error': 'Invalid or expired token'}), 401

        user_id = user_res.user.id
        print(f"Cleaning up after password reset for user {user_id}")

        # Unlock the account if it was locked
        supabase_admin.table("profiles").update({"is_locked": False}).eq("user_id", user_id).execute()
        
        # Clear failed login attempts
        supabase_admin.table("login_attempts") \
                      .delete() \
                      .eq("user_id", user_id) \
                      .eq("success", False) \
                      .execute()

        return jsonify({
            'success': True,
            'message': 'Account unlocked and login attempts cleared.'
        }), 200

    except Exception as e:
        print(f"Reset password cleanup error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'An error occurred during cleanup'}), 500