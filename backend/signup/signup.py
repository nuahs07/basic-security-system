from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import re
import os
import sys

# --- Setup Python Path ---
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(current_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# --- Import Supabase Client ---
from database.supabase_client import SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_KEY
from supabase import create_client

# Create Supabase client
supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)          # For auth/sign-up

# --- Flask App ---
app = Flask(
    __name__,
    static_folder="../../frontend/static",
    static_url_path="/static",
    template_folder="../../frontend/static/templates"
)

CORS(app)

FRONTEND_URL = "http://localhost:5000"

# --- Validation ---
def validate_password(password):
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
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# --- Signup Endpoint ---
@app.route("/api/signup", methods=["POST"])
def signup():
    try:
        data = request.json
        username = data.get("username", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password", "")
        first_name = data.get("first_name", "").strip()
        last_name = data.get("last_name", "").strip()

        if not username or not email or not password:
            return jsonify({"error": "Username, email, and password are required"}), 400

        if not validate_email(email):
            return jsonify({"error": "Invalid email format"}), 400

        is_valid, msg = validate_password(password)
        if not is_valid:
            return jsonify({"error": msg}), 400

        # --- Create Auth User ---
        auth_response = supabase.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "email_redirect_to": f"{FRONTEND_URL}/confirm-email",
                "data": {
                    "username": username,
                    "first_name": first_name,
                    "last_name": last_name
                }
            }
        })

        user = getattr(auth_response, "user", None)
        if not user:
            user = getattr(auth_response, "data", {}).get("user") if hasattr(auth_response, "data") else None
        if not user:
            return jsonify({"error": "Failed to create authentication account"}), 500

        user_id = user.id

        # --- Create profile using service role (bypasses RLS) ---
        profile_data = {
            "user_id": user_id,
            "username": username,
            "first_name": first_name,
            "last_name": last_name,
            "is_locked": False
        }

        try:
            # Use service role key to bypass RLS
            if SUPABASE_SERVICE_KEY:
                supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
                res = supabase_admin.table("profiles").insert(profile_data).execute()
                print("Profile created successfully with service role")
            else:
                # Fallback: try with regular client (might fail due to RLS)
                res = supabase.table("profiles").insert(profile_data).execute()
                print("Profile created successfully")
        except Exception as e:
            print(f"Profile creation warning: {e}")
            # Continue anyway - user is created in Auth

        return jsonify({
            "message": "User account created. Check your email to confirm.",
            "user_id": user_id,
            "username": username,
            "email": email
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Serve Pages ---
@app.route("/signup")
def serve_signup():
    return render_template("signup-direct.html")


@app.route("/confirm-email")
def serve_confirm_email():
    return render_template("confirm-email.html")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
