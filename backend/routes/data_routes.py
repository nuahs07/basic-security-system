from flask import Blueprint, request, jsonify
from database.supabase_client import supabase, supabase_admin
from security_logic.data_encryptor import decrypt_data
import base64

data_api = Blueprint('data_api', __name__)

@data_api.route('/api/access-file', methods=['POST'])
def access_file():
    """
    Securely fetches and decrypts a user's data.
    Expects a valid JWT for auth and the user's password in the body.
    """
    try:
        # 1. Get user from their session token
        user_res = supabase.auth.get_user()
        if not user_res.user:
            return jsonify({"error": "Not authenticated"}), 401
        
        user_id = user_res.user.id
        
        # 2. Get password from request body
        data = request.get_json()
        password = data.get('password')
        if not password:
            return jsonify({"error": "Password is required"}), 400

        # 3. Fetch the user's encrypted data from the 'user_data' table
        # This assumes you have one row of data per user.
        db_res = supabase_admin.table("user_data").select("data_content", "salt").eq("user_id", user_id).limit(1).execute()

        if not db_res.data:
            return jsonify({"error": "No data file found for this user"}), 404

        # 4. Decode the data from the database
        encrypted_data = base64.b64decode(db_res.data[0]['data_content'])
        salt = base64.b64decode(db_res.data[0]['salt'])

        # 5. Decrypt the data using the provided password
        decrypted_content = decrypt_data(encrypted_data, password, salt)

        if decrypted_content is None:
            return jsonify({"error": "Decryption failed. Invalid password."}), 403

        # 6. Success! Send the decrypted data back
        return jsonify({
            "success": True,
            "decrypted_data": decrypted_content
        }), 200

    except Exception as e:
        print(f"🔥 FATAL data access error: {e}")
        return jsonify({"error": "An internal server error occurred"}), 500