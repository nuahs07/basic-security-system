"""
Simple Flask server for sign-up, login, and static files.
Run this to serve the API endpoints and frontend.
"""

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
import os
from supabase import create_client, Client
from datetime import datetime, timedelta
from dotenv import load_dotenv # Import dotenv

# Load environment variables from .env file
load_dotenv(os.path.join(os.path.dirname(__file__), '.env')) # Specify path to .env

# Initialize Flask app
app = Flask(
    __name__,
    static_folder='../frontend/static', # Path to the 'static' folder
    static_url_path='/static',         # URL path to access static files
    template_folder="../frontend/static/templates" # Path to templates
)
CORS(app)  # Enable CORS for frontend

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY") # Load service key

# Validate credentials
if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    raise ValueError("Missing SUPABASE_URL or SUPABASE_ANON_KEY in .env file")
if not SUPABASE_SERVICE_KEY:
     print("Warning: SUPABASE_SERVICE_KEY not found in .env. Some admin operations might fail.")

# Initialize Supabase client (using ANON key for general use)
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# Constants for Security Core logic
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 10

# --- Static File Serving ---
@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serves static files from the frontend/static directory."""
    # This serves files like CSS, JS, or images if needed
    # HTML files in 'templates' are served by render_template or redirect
    return send_from_directory(app.static_folder, filename)

@app.route('/')
def serve_root():
    """Serves the login page as the root."""
    return render_template('login.html') # Serve login.html from templates

@app.route('/signup')
def serve_signup():
    """Serves the signup page."""
    return render_template('signup-direct.html')

@app.route('/index.html')
def serve_index():
    """Serves the dashboard/homepage."""
    return render_template('index.html')

@app.route('/homepage')
def serve_homepage():
    """Serves the homepage with account and file access."""
    return render_template('homepage.html')

# --- API Endpoints ---

@app.route('/api/signup', methods=['POST'])
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

        # Step 1: Create user in Supabase Auth
        auth_response = supabase.auth.sign_up({
            "email": email,
            "password": password
            # "options": { "data": { ... } } # Note: options.data doesn't reliably pass to profile trigger
        })

        if auth_response.user:
            user_id = auth_response.user.id
            print(f"User created in Auth: {user_id}")

            # Step 2: Update the profile created by the trigger
            profile_data = {
                "username": username,
                "first_name": first_name,
                "last_name": last_name,
                "is_locked": False # Ensure unlocked on creation
            }
            # Use the *service role key* client to ensure update works
            if SUPABASE_SERVICE_KEY:
                supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
                profile_result = supabase_admin.table("profiles") \
                                         .update(profile_data) \
                                         .eq("user_id", user_id) \
                                         .execute()
                print(f"Profile update attempted using service key: {profile_result.data}")
            else:
                 print("Warning: SERVICE_KEY missing. Profile update might fail due to RLS.")
                 # Try with anon key - likely fails if RLS is enabled correctly
                 profile_result = supabase.table("profiles") \
                                          .update(profile_data) \
                                          .eq("user_id", user_id) \
                                          .execute()
                 print(f"Profile update attempted using anon key: {profile_result.data}")


            # Step 3: Create initial user data (Optional)
            try:
                user_data_payload = {
                    "user_id": user_id,
                    "data_type": "profile_info",
                    "data_content": f"User {username} signed up.",
                    "encrypted": False
                }
                data_result = supabase.table("user_data").insert(user_data_payload).execute()
                print(f"Initial user data created: {data_result.data}")
            except Exception as data_err:
                 print(f"Warning: Could not create initial user_data. {data_err}")

            return jsonify({
                'success': True,
                'user_id': user_id,
                'username': username,
                'email': email,
                'message': 'User created successfully. Please check your email for confirmation.'
            }), 201

        else:
             # Handle Supabase Auth errors more specifically if possible
             error_message = "Failed to create user in Auth."
             if auth_response.error:
                  error_message += f" Reason: {auth_response.error.message}"
             print(error_message)
             return jsonify({'error': error_message}), 400

    except Exception as e:
        print(f"Sign-up endpoint error: {e}")
        # Consider more specific error logging
        return jsonify({'error': f"An internal server error occurred: {str(e)}"}), 500


@app.route('/api/login', methods=['POST'])
def login():
    """Handle user login with custom security checks"""
    supabase_admin = None # Initialize admin client variable
    if SUPABASE_SERVICE_KEY:
        try:
            supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        except Exception as admin_init_err:
            print(f"Error initializing Supabase Admin client: {admin_init_err}")
            # Consider if you want to proceed without admin functions or return an error
            return jsonify({'error': 'Server configuration error.'}), 500
    else:
        print("FATAL: SUPABASE_SERVICE_KEY is missing. Cannot perform required operations.")
        return jsonify({'error': 'Server configuration error.'}), 500

    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        user_id = None # Initialize user_id

        if not all([email, password]):
            return jsonify({'error': 'Email and password are required'}), 400

        # --- Try to get User ID First using Admin client ---
        try:
            list_users_response = supabase_admin.auth.admin.list_users(filter=f"email='{email}'")
            if list_users_response and list_users_response.users and len(list_users_response.users) > 0:
                user_id = list_users_response.users[0].id
                print(f"Found user_id ({user_id}) for email {email} using admin client.")
            else:
                print(f"No user found for email {email} using admin client.")
                # Don't return error yet, let login fail naturally for invalid email
        except Exception as lookup_err:
             print(f"Admin client error looking up user by email: {lookup_err}")

        # --- Check if user is ALREADY locked (only possible if user_id was found) ---
        if user_id:
            try:
                # Use ADMIN client to bypass RLS on account_locks
                lock_res = supabase_admin.table("account_locks") \
                                 .select("unlock_at") \
                                 .eq("user_id", user_id) \
                                 .order("locked_at", desc=True) \
                                 .limit(1) \
                                 .execute()
                # ... (rest of lockout check logic remains the same)
                if lock_res.data:
                    unlock_at_str = lock_res.data[0]['unlock_at']
                    unlock_at = datetime.fromisoformat(unlock_at_str.replace('Z', '+00:00'))
                    now_utc = datetime.now(timedelta(0)) # UTC time
                    if now_utc < unlock_at:
                        remaining = unlock_at - now_utc
                        print(f"User {user_id} is locked. Unlock at: {unlock_at}, Now: {now_utc}")
                        return jsonify({
                            'error': 'account_locked',
                            'message': f'Account locked. Try again in {remaining.seconds // 60} minutes {remaining.seconds % 60} seconds.'
                        }), 429
                    else:
                         print(f"User {user_id} was locked, but lock expired.")
            except Exception as lock_check_err:
                print(f"Error checking existing lock for user {user_id}: {lock_check_err}")

        # --- ATTEMPT LOGIN (using ANON client is okay here) ---
        try:
            # Use the normal 'supabase' client for auth actions
            session_response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            # --- SUCCESS ---
            if session_response.session and session_response.user:
                user_id = session_response.user.id # Confirm user_id
                print(f"Login successful for user {user_id} ({email}).")

                # Log successful attempt using ADMIN client
                supabase_admin.table("login_attempts").insert({
                    "user_id": user_id,
                    "username_attempted": email,
                    "success": True,
                    "failure_reason": None,
                    "ip_address": request.remote_addr
                }).execute()

                # Ensure account is marked as unlocked using ADMIN client
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
            # --- FAILURE ---
            print(f"Authentication failed for {email}. Error: {auth_error}")
            failure_reason = "Invalid password or email"

            # Log failed attempt using ADMIN client
            supabase_admin.table("login_attempts").insert({
                "user_id": user_id, # May be None if email was invalid
                "username_attempted": email,
                "success": False,
                "failure_reason": failure_reason,
                 "ip_address": request.remote_addr
            }).execute()

            # --- Check if this failure triggers a lock (Requires user_id) ---
            if user_id:
                try:
                    # Use ADMIN client to count failures
                    time_window_start = datetime.now() - timedelta(minutes=LOCKOUT_DURATION_MINUTES * 2)
                    failures = supabase_admin.table("login_attempts") \
                                     .select("attempt_id", count='exact') \
                                     .eq("user_id", user_id) \
                                     .eq("success", False) \
                                     .gte("timestamp", time_window_start.isoformat()) \
                                     .execute()

                    print(f"User {user_id} has {failures.count} recent failed attempts (including this one).")

                    if failures.count >= MAX_FAILED_ATTEMPTS:
                        # Use ADMIN client to check for recent lock
                        recent_lock = supabase_admin.table("account_locks") \
                                          .select("lock_id") \
                                          .eq("user_id", user_id) \
                                          .gte("locked_at", (datetime.now() - timedelta(minutes=1)).isoformat()) \
                                          .limit(1) \
                                          .execute()

                        if not recent_lock.data:
                            # --- TRIGGER LOCK using ADMIN client ---
                            print(f"Threshold reached. Locking account for user {user_id}")
                            unlock_time = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                            supabase_admin.table("account_locks").insert({
                                "user_id": user_id,
                                "unlock_at": unlock_time.isoformat(),
                                "failed_attempts_count": failures.count
                            }).execute()
                            # Mark profile as locked using ADMIN client
                            supabase_admin.table("profiles").update({"is_locked": True}).eq("user_id", user_id).execute()

                            return jsonify({
                                'error': 'account_locked',
                                'message': f'Account locked for {LOCKOUT_DURATION_MINUTES} minutes due to too many failed attempts.'
                            }), 429
                        else:
                            # Return existing lock message
                            print(f"User {user_id} already locked recently.")
                            return jsonify({
                                'error': 'account_locked',
                                'message': f'Account locked for {LOCKOUT_DURATION_MINUTES} minutes due to too many failed attempts.'
                            }), 429
                except Exception as lock_trigger_err:
                     print(f"Error during lock check/trigger for user {user_id}: {lock_trigger_err}")

            # If not locked return standard failure
            return jsonify({'error': 'Invalid email or password'}), 401 # Unauthorized

    except Exception as e:
        # Catch-all for unexpected errors
        print(f"FATAL login endpoint error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'An internal server error occurred.'}), 500


@app.route('/confirm-email') # Route Supabase redirects to
def handle_email_confirm():
    """Serves the confirmation success page."""
    # This route just serves the HTML page. Supabase handles the actual token verification.
    print("Serving confirm-email.html")
    return render_template('confirm-email.html')

@app.route('/api/confirm-email') 
def handle_api_email_confirm():
    """Serves the confirmation success page for API redirects."""
    print("Serving confirm-email.html via API route")
    return render_template('confirm-email.html')

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'message': 'Server is running'}), 200

# --- Main execution ---
if __name__ == '__main__':
    print("🚀 Starting Basic Security System server...")
    print(f"🔧 Supabase URL: {SUPABASE_URL}")
    print(f"🔑 Supabase Anon Key: {'Loaded' if SUPABASE_ANON_KEY else 'MISSING!'}")
    print(f"🔑 Supabase Service Key: {'Loaded' if SUPABASE_SERVICE_KEY else 'MISSING! (Needed for admin tasks)'}")
    print("📡 Server will run on http://localhost:5000 (or http://0.0.0.0:5000)")
    print("🔗 API endpoints:")
    print("  POST /api/signup")
    print("  POST /api/login")
    print("  GET  /api/health")
    print("🔗 Static Files served from /static/")
    print("🔗 Root '/' redirects to /static/templates/login.html")
    print("💡 Make sure your Supabase DB schema & RLS are set up correctly!")
    # Use host='0.0.0.0' to make it accessible from other devices on the network if needed
    app.run(debug=True, host='0.0.0.0', port=5000)