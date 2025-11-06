-- 1. Create Profiles Table
CREATE TABLE public.profiles (
  user_id uuid NOT NULL PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  username text UNIQUE,
  email text,
  first_name text,
  last_name text,
  is_locked boolean DEFAULT false
);

-- 2. Create Login Attempts Table
CREATE TABLE public.login_attempts (
  attempt_id bigserial PRIMARY KEY,
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  username_attempted text,
  success boolean NOT NULL,
  failure_reason text,
  ip_address inet,
  timestamp timestamptz DEFAULT now()
);

-- 3. Create Account Locks Table
CREATE TABLE public.account_locks (
  lock_id bigserial PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  locked_at timestamptz DEFAULT now(),
  unlock_at timestamptz NOT NULL,
  failed_attempts_count int4
);

-- 4. Create User Data (Security File) Table
CREATE TABLE public.user_data (
  data_id bigserial PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  data_type text,
  data_content text, -- Stores the base64-encoded encrypted string
  encrypted boolean DEFAULT true,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  salt text NOT NULL -- Stores the base64-encoded salt
);

-- 5. Create Trigger Function for New User Profiles
CREATE FUNCTION public.handle_new_user() 
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.profiles (user_id)
  VALUES (new.id);
  RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 6. Create Trigger
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();