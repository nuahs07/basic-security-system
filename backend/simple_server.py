"""
Simple Flask server for sign-up testing.
Run this to serve the API endpoints your frontend needs.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from supabase import create_client, Client
from datetime import datetime, timedelta

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

# Supabase configuration
SUPABASE_URL = 'https://porcvcjxmjwpmhpvqckj.supabase.co'
SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBvcmN2Y2p4bWp3cG1ocHZxY2tqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjEyNzc4MzYsImV4cCI6MjA3Njg1MzgzNn0.r0CHtaPGHNfCe4SAm4MwBq8vAyyadYEbJhgI1g1LpEU'

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 10

@app.route('/api/signup', methods=['POST'])
def signup():
    """Handle user sign-up"""
    try:
        data = request.get_json()
        
        # Extract form data
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        first_name = data.get('first_name', '')
        last_name = data.get('last_name', '')
        
        # Validate required fields
        if not all([username, email, password]):
            return jsonify({'error': 'Username, email, and password are required'}), 400
        
        # Validate password length
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400
        
        print(f"Creating user: {email}")
        
        # Step 1: Create user in Supabase Auth
        auth_response = supabase.auth.sign_up({
            "email": email,
            "password": password
        })
        
        if auth_response.user:
            user_id = auth_response.user.id
            print(f"User created in Auth: {user_id}")
            
            # Step 2: Create profile
            profile_data = {
                #"user_id": user_id,
                "username": username,
                "first_name": first_name,
                "last_name": last_name,
                "is_locked": False
            }
            
            profile_result = supabase.table("profiles") \
                                     .update(profile_data) \
                                     .eq("user_id", user_id) \
                                     .execute()
            
            print(f"Profile updated: {profile_result.data}")
            
            # Step 3: Create initial user data
            user_data = {
                "user_id": user_id,
                "data_type": "profile_info",
                "data_content": f"User {first_name} {last_name} signed up on {__import__('datetime').datetime.now().isoformat()}",
                "encrypted": False
            }
            
            data_result = supabase.table("user_data").insert(user_data).execute()
            print(f"User data created: {data_result.data}")
            
            return jsonify({
                'success': True,
                'user_id': user_id,
                'username': username,
                'email': email,
                'message': 'User created successfully'
            }), 201
            
        else:
            return jsonify({'error': 'Failed to create user in Auth'}), 400
            
    except Exception as e:
        print(f"Sign-up error: {e}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/login', methods=['POST'])
def login():
    """Handle user login with custom security checks"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not all([email, password]):
            return jsonify({'error': 'Email and password are required'}), 400

        # --- 1. SECURITY CORE: Check for existing lock ---
        # Get the user's profile to see if they are locked
        profile_res = supabase.table("profiles").select("user_id", "is_locked").eq("email", email).execute() # Note: You'd first get the user_id from auth.users, but this is a shortcut.
        
        if profile_res.data:
            user_id = profile_res.data[0]['user_id']
            
            # Check if user is locked
            lock_res = supabase.table("account_locks") \
                             .select("unlock_at") \
                             .eq("user_id", user_id) \
                             .order("locked_at", desc=True) \
                             .limit(1) \
                             .execute()
                             
            if lock_res.data:
                unlock_at = datetime.fromisoformat(lock_res.data[0]['unlock_at'])
                if datetime.now(unlock_at.tzinfo) < unlock_at:
                    # User is still locked out
                    remaining = unlock_at - datetime.now(unlock_at.tzinfo)
                    return jsonify({
                        'error': 'account_locked',
                        'message': f'Account locked. Try again in {remaining.seconds // 60} minutes.'
                    }), 429 # Too Many Requests

        # --- 2. ATTEMPT LOGIN ---
        try:
            # If not locked, try to sign in
            session_response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            # --- 3. LOG SUCCESSFUL ATTEMPT ---
            if session_response.session:
                user_id = session_response.user.id
                supabase.table("login_attempts").insert({
                    "user_id": user_id,
                    "username": email,
                    "success": True,
                    "failure_reason": None
                }).execute()
                
                # Unlock the account on success
                supabase.table("profiles").update({"is_locked": False}).eq("user_id", user_id).execute()

                return jsonify({
                    'success': True,
                    'message': 'Login successful!',
                    'access_token': session_response.session.access_token
                }), 200

        except Exception as auth_error:
            # --- 4. LOG FAILED ATTEMPT & CHECK FOR LOCK ---
            # This is where the 5-attempt logic happens
            user_id = profile_res.data[0]['user_id'] if profile_res.data else None
            
            supabase.table("login_attempts").insert({
                "user_id": user_id,
                "username": email,
                "success": False,
                "failure_reason": "Invalid password"
            }).execute()

            if user_id:
                # Count recent failures
                failures = supabase.table("login_attempts") \
                                 .select("attempt_id", count='exact') \
                                 .eq("user_id", user_id) \
                                 .eq("success", False) \
                                 .order("timestamp", desc=True) \
                                 .limit(MAX_FAILED_ATTEMPTS) \
                                 .execute()
                
                if failures.count >= MAX_FAILED_ATTEMPTS:
                    # --- TRIGGER LOCK ---
                    unlock_time = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                    supabase.table("account_locks").insert({
                        "user_id": user_id,
                        "username": email,
                        "unlock_at": unlock_time.isoformat(),
                        "failed_attempts_count": failures.count
                    }).execute()
                    # Mark profile as locked
                    supabase.table("profiles").update({"is_locked": True}).eq("user_id", user_id).execute()
                    
                    return jsonify({
                        'error': 'account_locked',
                        'message': f'Account locked for {LOCKOUT_DURATION_MINUTES} minutes.'
                    }), 429

            return jsonify({'error': 'Invalid email or password'}), 401 # Unauthorized

    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'An internal server error occurred'}), 500

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'message': 'Server is running'}), 200

if __name__ == '__main__':
    print("🚀 Starting simple sign-up server...")
    print("📡 Server will run on http://localhost:5000")
    print("🔗 API endpoint: http://localhost:5000/api/signup")
    print("💡 Make sure your Supabase database schema is set up correctly!")
    app.run(debug=True, host='0.0.0.0', port=5000)
