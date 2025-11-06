# Basic Security System

A secure Flask-based web application with user authentication, account lockout protection, and encrypted data storage. Built with Flask, Supabase, and modern security practices.

## Features

- 🔐 **User Authentication**
  - Secure signup with email verification
  - Login with JWT tokens
  - Password reset functionality
  - Email confirmation flow

- 🛡️ **Security Features**
  - Account lockout after failed login attempts
  - Encrypted user data storage using AES-256-GCM
  - Password-based encryption keys
  - Login attempt tracking and monitoring
  - IP address logging

- 📁 **Data Management**
  - Encrypted file storage per user
  - Secure data access with password verification
  - Automatic data initialization on signup

- 🎨 **Modern UI**
  - Responsive design
  - Clean, intuitive interface
  - Multiple pages: login, signup, homepage, account info

## Tech Stack

- **Backend**: Flask 3.0.0
- **Database**: Supabase (PostgreSQL)
- **Authentication**: Supabase Auth
- **Encryption**: Python Cryptography (AES-256-GCM)
- **Frontend**: HTML, CSS, JavaScript
- **CORS**: Flask-CORS

## Project Structure

```
basic-security-system/
├── backend/
│   ├── database/
│   │   ├── supabase_client.py      # Supabase client initialization
│   │   └── .env                     # Environment variables (not in repo)
│   ├── routes/
│   │   ├── auth_routes.py           # Authentication endpoints
│   │   └── data_routes.py           # Data access endpoints
│   ├── security_logic/
│   │   ├── data_encryptor.py        # Encryption/decryption logic
│   │   └── lockout_manager.py       # Account lockout logic
│   ├── simple_server.py             # Flask app entry point
│   └── requirements.txt             # Python dependencies
├── frontend/
│   ├── static/
│   │   ├── styles/                  # CSS files
│   │   └── templates/               # HTML templates
│   └── scripts/                     # JavaScript files
├── docs/
│   ├── database_schema.sql          # Database schema
│   └── documentation.docx           # Additional documentation
└── README.md
```

## Prerequisites

- Python 3.8 or higher
- Supabase account and project
- pip (Python package manager)

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd basic-security-system/basic-security-system
   ```

2. **Create a virtual environment**
   ```bash
   cd backend
   python -m venv venv
   ```

3. **Activate the virtual environment**
   
   On Windows:
   ```bash
   venv\Scripts\activate
   ```
   
   On macOS/Linux:
   ```bash
   source venv/bin/activate
   ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Set up environment variables**
   
   Create a `.env` file in the `backend/` directory:
   ```env
   SUPABASE_URL=your_supabase_project_url
   SUPABASE_ANON_KEY=your_supabase_anon_key
   SUPABASE_SERVICE_KEY=your_supabase_service_role_key
   ```

   You can find these values in your Supabase project settings under API.

6. **Set up the database**
   
   Run the SQL schema from `docs/database_schema.sql` in your Supabase SQL editor to create the necessary tables:
   - `profiles` - User profile information
   - `login_attempts` - Login attempt tracking
   - `account_locks` - Account lockout records
   - `user_data` - Encrypted user data storage

## Running the Application

1. **Navigate to the backend directory**
   ```bash
   cd backend
   ```

2. **Start the Flask server**
   ```bash
   python simple_server.py
   ```

3. **Access the application**
   
   Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

## API Endpoints

### Authentication

- `POST /api/signup` - Create a new user account
  ```json
  {
    "username": "string",
    "email": "string",
    "password": "string",
    "first_name": "string (optional)",
    "last_name": "string (optional)"
  }
  ```

- `POST /api/login` - Authenticate user and get access token
  ```json
  {
    "email": "string",
    "password": "string"
  }
  ```

- `POST /api/forgot-password` - Request password reset email
  ```json
  {
    "email": "string"
  }
  ```

- `POST /api/reset-password` - Reset password with token
  ```json
  {
    "password": "string",
    "token": "string"
  }
  ```

### Data Access

- `POST /api/access-file` - Access encrypted user data
  ```json
  {
    "password": "string"
  }
  ```
  **Headers**: `Authorization: Bearer <access_token>`

## Security Features

### Account Lockout
- Accounts are locked after multiple failed login attempts
- Lockout duration is configurable (default: 5 minutes)
- Failed attempts are tracked per user
- Successful login resets the failed attempt counter

### Data Encryption
- User data is encrypted using AES-256-GCM
- Encryption keys are derived from user passwords
- Each encrypted record has a unique salt
- Data is stored as base64-encoded strings in the database

### Password Requirements
- Minimum 6 characters
- Enforced on signup and password reset

## Development

### Project Structure Notes

- **Backend**: Flask application with blueprints for route organization
- **Frontend**: Static HTML/CSS/JS files served by Flask
- **Database**: Supabase handles authentication and data storage
- **Security Logic**: Separate modules for encryption and lockout management

### Environment Variables

The application requires the following environment variables in `backend/.env`:

- `SUPABASE_URL` - Your Supabase project URL
- `SUPABASE_ANON_KEY` - Supabase anonymous (public) key
- `SUPABASE_SERVICE_KEY` - Supabase service role key (for admin operations)

⚠️ **Important**: Never commit the `.env` file to version control. It's already included in `.gitignore`.

## Troubleshooting

### Common Issues

1. **Import errors**
   - Ensure the virtual environment is activated
   - Verify all dependencies are installed: `pip install -r requirements.txt`

2. **Supabase connection errors**
   - Check that your `.env` file exists and contains correct credentials
   - Verify the Supabase project is active and accessible

3. **Database errors**
   - Ensure you've run the SQL schema from `docs/database_schema.sql`
   - Check that Row Level Security (RLS) policies are configured correctly in Supabase

4. **Port already in use**
   - Change the port in `simple_server.py` if port 5000 is occupied

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is open source and available under the MIT License.

## Support

For issues, questions, or contributions, please open an issue in the repository.

---

**Note**: This is a basic security system for educational purposes. For production use, consider additional security measures such as:
- Rate limiting
- Two-factor authentication
- Security headers (CSP, HSTS, etc.)
- Regular security audits
- Input validation and sanitization
- SQL injection prevention (already handled by Supabase)
- XSS protection
