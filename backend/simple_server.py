from flask import Flask, render_template, send_from_directory, redirect
from flask_cors import CORS
from routes.auth_routes import auth_api
# Import other route blueprints here as you make them
# from backend.routes.data_routes import data_api 

# Initialize Flask app
app = Flask(
    __name__,
    static_folder='../frontend/static', # Path to the 'static' folder
    static_url_path='/static',         # URL path to access static files
    template_folder="../frontend/static/templates" # Path to templates
)
CORS(app)  # Enable CORS for frontend

# --- Register API Blueprints ---
app.register_blueprint(auth_api)
# app.register_blueprint(data_api)

# --- Routes to Serve HTML Pages ---
@app.route('/')
def serve_root():
    """Serves the login page as the root."""
    return render_template('login.html')

@app.route('/signup')
def serve_signup():
    """Serves the signup page."""
    return render_template('signup-direct.html')

@app.route('/homepage')
def serve_homepage():
    """Serves the main homepage."""
    return render_template('homepage.html')

@app.route('/account-info')
def serve_account_info():
    """Serves the account info page."""
    return render_template('index.html')

@app.route('/api/confirm-email') 
def handle_email_confirm():
    """Serves the confirmation success page."""
    return render_template('confirm-email.html')

# --- Main execution ---
if __name__ == '__main__':
    print("🚀 Starting Basic Security System server...")
    print("📡 Server will run on http://localhost:5000")
    print("🔗 Root '/' serves the login page.")
    app.run(debug=True, host='0.0.0.0', port=5000)