"""
Simple Flask server for sign-up testing.
Run this to serve the API endpoints your frontend needs.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from supabase import create_client, Client

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

# Supabase configuration
SUPABASE_URL = 'https://porcvcjxmjwpmhpvqckj.supabase.co'
SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBvcmN2Y2p4bWp3cG1ocHZxY2tqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjEyNzc4MzYsImV4cCI6MjA3Njg1MzgzNn0.r0CHtaPGHNfCe4SAm4MwBq8vAyyadYEbJhgI1g1LpEU'

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

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
