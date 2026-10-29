# COCOONInn - Authentication System

This project includes a complete authentication system with a frontend UI and backend server.

## Features

- **Translucent notch bar** with Login and Sign Up buttons at the top
- **Login modal** with email, password, and forgot password option
- **Signup modal** with full name, email, mobile number, and password
- **Backend server** with Express.js
- **SQLite database** for real-time user data storage
- **Password hashing** with bcrypt for security

## Setup Instructions

### 1. Install Dependencies

```bash
npm install
```

### 2. Start the Backend Server

```bash
npm start
```

Or for development with auto-reload:

```bash
npm run dev
```

The server will run on `http://localhost:3000`

### 3. Open the Website

Simply open `index.html` in your browser. The authentication system will connect to the backend server automatically.

## API Endpoints

- `POST /api/signup` - Register a new user
- `POST /api/login` - Login with email and password
- `GET /api/health` - Health check endpoint
- `GET /api/users` - Get all users (for testing)

## Database

The SQLite database (`users.db`) is automatically created when you first run the server. It stores:
- Full name
- Email (unique)
- Mobile number
- Hashed password
- Created timestamp

## Notes

- The database file (`users.db`) is created in the project root
- Passwords are securely hashed using bcrypt
- Email addresses must be unique
- Mobile numbers are validated (10 digits)
- Passwords must be at least 6 characters long
