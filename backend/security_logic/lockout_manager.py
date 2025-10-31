from database.supabase_client import supabase_admin
from datetime import datetime, timedelta, timezone

MAX_FAILED_ATTEMPTS = 5
# Renamed to seconds and set to 600 (10 minutes)
LOCKOUT_DURATION_SECONDS = 30

def get_utc_now():
    """Returns the current time in UTC."""
    return datetime.now(timezone.utc)

def check_lock_status(user_id):
    """Checks if a user is currently locked out."""
    try:
        lock_res = supabase_admin.table("account_locks") \
                         .select("unlock_at") \
                         .eq("user_id", user_id) \
                         .order("locked_at", desc=True) \
                         .limit(1) \
                         .execute()
        
        if lock_res.data:
            unlock_at_str = lock_res.data[0]['unlock_at']
            unlock_at = datetime.fromisoformat(unlock_at_str.replace('Z', '+00:00'))
            now_utc = get_utc_now()

            if now_utc < unlock_at:
                remaining = unlock_at - now_utc
                print(f"User {user_id} is locked. Unlock at: {unlock_at}, Now: {now_utc}")
                # Return the remaining seconds for the timer
                return True, f'Account locked. Try again in {remaining.seconds // 60} minutes {remaining.seconds % 60} seconds.', remaining.seconds
            else:
                 print(f"User {user_id} was locked, but lock expired.")
                 return False, "Lock expired.", 0

    except Exception as e:
        print(f"Error checking lock status: {e}")
        
    return False, "Not locked.", 0

def log_login_attempt(user_id, email, ip_address, success, reason=""):
    """Logs a login attempt to the database."""
    try:
        supabase_admin.table("login_attempts").insert({
            "user_id": user_id,
            "username_attempted": email,
            "success": success,
            "failure_reason": reason,
            "ip_address": ip_address
        }).execute()
    except Exception as e:
        print(f"Error logging login attempt: {e}")

def trigger_lock_if_needed(user_id, email):
    """Counts failures and triggers a lock if the threshold is met."""
    try:
        now_utc = get_utc_now()
        # Use seconds for the time window calculation
        time_window_start = now_utc - timedelta(seconds=LOCKOUT_DURATION_SECONDS * 2)
        
        failures = supabase_admin.table("login_attempts") \
                                 .select("attempt_id", count='exact') \
                                 .eq("user_id", user_id) \
                                 .eq("success", False) \
                                 .gte("timestamp", time_window_start.isoformat()) \
                                 .execute()
        
        print(f"User {user_id} has {failures.count} recent failed attempts.")

        if failures.count >= MAX_FAILED_ATTEMPTS:
            # --- ASCENDING LOCKOUT DURATION (in Seconds) ---
            # 1. Count previous locks
            previous_locks_res = supabase_admin.table("account_locks") \
                                               .select("lock_id", count='exact') \
                                               .eq("user_id", user_id) \
                                               .execute()
            previous_lock_count = previous_locks_res.count
            print(f"User has {previous_lock_count} previous lock(s).")

            # 2. Calculate new duration in seconds (1st=600s, 2nd=1200s, 3rd=1800s)
            new_duration_seconds = LOCKOUT_DURATION_SECONDS * (previous_lock_count + 1)
            # --- END NEW LOGIC ---

            # Check if already locked recently (to avoid spamming new entries)
            recent_lock = supabase_admin.table("account_locks") \
                                      .select("lock_id") \
                                      .eq("user_id", user_id) \
                                      .gte("locked_at", (now_utc - timedelta(minutes=1)).isoformat()) \
                                      .limit(1) \
                                      .execute()
            
            if not recent_lock.data:
                print(f"Threshold reached. Locking account for {new_duration_seconds} seconds.")
                # Use seconds for the unlock time calculation
                unlock_time = now_utc + timedelta(seconds=new_duration_seconds)
                
                supabase_admin.table("account_locks").insert({
                    "user_id": user_id,
                    "unlock_at": unlock_time.isoformat(),
                    "failed_attempts_count": failures.count
                }).execute()
                
                supabase_admin.table("profiles").update({"is_locked": True}).eq("user_id", user_id).execute()
            
            # Return the new duration in seconds
            return True, f'Account locked for {new_duration_seconds // 60} minutes.', new_duration_seconds
            
    except Exception as e:
        print(f"Error in trigger_lock_if_needed: {e}")
        
    # Return 0 seconds if no lock was triggered
    return False, "Invalid email or password", 0