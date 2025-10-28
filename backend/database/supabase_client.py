import os
from supabase import create_client, Client
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get Supabase credentials from environment
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

# Validate that credentials exist
if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    raise ValueError(
        "Missing Supabase credentials! "
        "Please set SUPABASE_URL and SUPABASE_ANON_KEY in your .env file"
    )

# Create and export the Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# Optional: Helper function to test connection
def test_connection():
    """Test if Supabase connection is working"""
    try:
        # Try to query the profiles table
        # --- FIX: Changed 'users' to 'profiles' ---
        result = supabase.table('profiles').select('user_id').limit(1).execute()
        print("Supabase connection successful!")
        return True
    except Exception as e:
        print(f"Supabase connection failed: {e}")
        return False

# Optional: Helper functions for common operations
def get_user_by_username(username: str):
    """Get user by username"""
    try:
        # --- FIX: Changed 'users' to 'profiles' ---
        result = supabase.table('profiles').select('*').eq('username', username).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error fetching user: {e}")
        return None

def get_user_by_email(email: str):
    """Get user by email"""
    try:
        # --- FIX: Changed 'users' to 'profiles' ---
        result = supabase.table('profiles').select('*').eq('email', email).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error fetching user: {e}")
        return None

def get_user_by_id(user_id: int):
    """Get user by ID"""
    try:
        # --- FIX: Changed 'users' to 'profiles' ---
        result = supabase.table('profiles').select('*').eq('user_id', user_id).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error fetching user: {e}")
        return None

# If running this file directly, test the connection
if __name__ == "__main__":
    print("Testing Supabase connection...")
    test_connection()