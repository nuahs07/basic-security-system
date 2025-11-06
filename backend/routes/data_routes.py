from flask import Blueprint, request, jsonify
from database.supabase_client import supabase, supabase_admin
from security_logic.data_encryptor import encrypt_data, decrypt_data
from datetime import datetime
import base64

data_api = Blueprint('data_api', __name__)

@data_api.route('/api/access-file', methods=['POST'])
def access_file():
    """
    Securely fetches and decrypts a user's data.
    Expects a valid JWT for auth and the user's password in the body.
    """
    try:
        # 1. Get access token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Missing or invalid authorization token"}), 401
        
        access_token = auth_header.split('Bearer ')[1]
        
        # 2. Get user from their session token
        user_res = supabase.auth.get_user(access_token)
        if not user_res.user:
            return jsonify({"error": "Not authenticated"}), 401
        
        user_id = user_res.user.id
        print(f"🔍 Accessing file for user_id: {user_id}")
        
        # 3. Get password from request body
        data = request.get_json()
        password = data.get('password')
        if not password:
            return jsonify({"error": "Password is required"}), 400

        # 4. Fetch the user's encrypted data from the 'user_data' table
        # This assumes you have one row of data per user.
        db_res = supabase_admin.table("user_data").select("data_content", "salt").eq("user_id", user_id).limit(1).execute()

        if not db_res.data:
            print(f"⚠️ No user_data found for user_id: {user_id}. Creating initial data...")
            # Check if user exists in profiles table
            profile_check = supabase_admin.table("profiles").select("username, email").eq("user_id", user_id).limit(1).execute()
            if not profile_check.data:
                print(f"❌ User profile also not found for user_id: {user_id}")
                return jsonify({"error": "User profile not found"}), 404
            
            # User exists but no data file - create initial data
            username = profile_check.data[0].get('username', 'User')
            try:
                initial_data = f"User {username}'s secure file, created on {datetime.now().isoformat()}"
                
                # Encrypt it using the user's password
                encrypted_content_bytes, salt_bytes = encrypt_data(initial_data, password)
                
                # Encode to base64 text for database storage
                encrypted_content_text = base64.b64encode(encrypted_content_bytes).decode('utf-8')
                salt_text = base64.b64encode(salt_bytes).decode('utf-8')

                # Insert the encrypted data and the salt into user_data
                user_data_payload = {
                    "user_id": user_id,
                    "data_type": "profile_info",
                    "data_content": encrypted_content_text,
                    "salt": salt_text,
                    "encrypted": True
                }
                supabase_admin.table("user_data").insert(user_data_payload).execute()
                print(f"✅ Initial user data (encrypted) created for user_id: {user_id}")
                
                # Now fetch the newly created data
                db_res = supabase_admin.table("user_data").select("data_content", "salt").eq("user_id", user_id).limit(1).execute()
                if not db_res.data:
                    return jsonify({"error": "Failed to create initial data file"}), 500
            except Exception as create_err:
                print(f"❌ Error creating initial user_data: {create_err}")
                return jsonify({"error": "Failed to create initial data file. Please try again."}), 500

        # 5. Decode the data from the database
        encrypted_data = base64.b64decode(db_res.data[0]['data_content'])
        salt = base64.b64decode(db_res.data[0]['salt'])

        # 6. Decrypt the data using the provided password
        decrypted_content = decrypt_data(encrypted_data, password, salt)

        if decrypted_content is None:
            return jsonify({"error": "Decryption failed. Invalid password."}), 403

        # 7. Success! Send the decrypted data back
        return jsonify({
            "success": True,
            "decrypted_data": decrypted_content
        }), 200

    except Exception as e:
        print(f"🔥 FATAL data access error: {e}")
        return jsonify({"error": "An internal server error occurred"}), 500