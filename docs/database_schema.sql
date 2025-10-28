-- SQL to create all tables and set up the database schema (FOR REFERENCE)

-- Creates the "profiles" table for public user data
CREATE TABLE public.profiles (
  user_id uuid NOT NULL PRIMARY KEY, -- This is the Primary Key
  username text UNIQUE,
  first_name text,
  last_name text,
  is_locked boolean DEFAULT false,

  -- This creates the One-to-One link to the auth.users table
  CONSTRAINT profiles_user_id_fkey FOREIGN KEY (user_id) 
  REFERENCES auth.users (id) ON DELETE CASCADE
);

-- Optional but HIGHLY recommended:
-- This function automatically copies the new user_id from auth.users
-- into your new profiles table, creating a profile row on sign-up.
CREATE FUNCTION public.handle_new_user() 
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.profiles (user_id)
  VALUES (new.id);
  RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- This trigger calls the function every time a new user signs up
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();

  






  -- 1. LOGIN_ATTEMPTS Table
-- This table will log every single login attempt.
-- I've simplified it from your diagram to be more efficient.
CREATE TABLE public.login_attempts (
  attempt_id bigserial PRIMARY KEY, -- Automatically increments
  user_id uuid, -- Can be NULL if the username/email didn't exist
  username_attempted text, -- The username/email they typed
  success boolean NOT NULL,
  failure_reason text, -- e.g., "Invalid password" or "User not found"
  ip_address inet,
  timestamp timestamptz DEFAULT now()
);

-- 2. ACCOUNT_LOCKS Table
-- This table creates a log entry every time an account is locked.
CREATE TABLE public.account_locks (
  lock_id bigserial PRIMARY KEY,
  user_id uuid NOT NULL,
  locked_at timestamptz DEFAULT now(),
  unlock_at timestamptz NOT NULL, -- You calculate this (e.g., NOW() + 10 minutes)
  failed_attempts_count integer, -- The # of attempts that triggered this lock
  
  -- Foreign key link to the user
  CONSTRAINT account_locks_user_id_fkey FOREIGN KEY (user_id) 
  REFERENCES auth.users (id) ON DELETE CASCADE
);

-- 3. USER_DATA Table
-- This is for your "clocked" (encrypted) data.
CREATE TABLE public.user_data (
  data_id bigserial PRIMARY KEY,
  user_id uuid NOT NULL,
  data_type text,
  data_content text, -- Use 'text' for encrypted strings, or 'bytea' for binary
  encrypted boolean DEFAULT true,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  
  -- Foreign key link to the user
  CONSTRAINT user_data_user_id_fkey FOREIGN KEY (user_id) 
  REFERENCES auth.users (id) ON DELETE CASCADE
);