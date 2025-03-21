from flask import Flask, request, jsonify  #Import Flask for API handling
import bcrypt  #Import bcrypt for password hashing
import sqlite3  #Import SQLite3 for database management

app = Flask(__name__)  #Initialize Flask application

# Database file name
DATABASE = "users.db"

def create_users_table():
    """Creates the users table in SQLite database if it does not exist."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,  -- Ensures unique usernames
            password BLOB NOT NULL  -- Stores hashed passwords as binary
        )
        """)
        conn.commit()  #Save changes

#Run database setup when the application starts
create_users_table()

def get_user(username):
    """Fetches user information from the database by username.
    
    Returns:
        tuple: (id, username, password) if user exists, otherwise None.
    """
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()  # Returns user row if found, otherwise None

@app.route('/register', methods=['POST'])
def register():
    """Registers a new user by hashing their password and storing it in SQLite."""
    data = request.json  # Get JSON request data
    username = data.get("username")
    password = data.get("password")

    if not username or not password:  # Check for missing fields
        return jsonify({"error": "Username and password are required"}), 400

    if get_user(username):  # Check if user already exists
        return jsonify({"error": "Username already exists"}), 400

    #Hash the password using bcrypt with a randomly generated salt
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    #Store the user in the database
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()  # Save changes

    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    """Authenticates a user by verifying the bcrypt password hash."""
    data = request.json  # Get JSON request data
    username = data.get("username")
    password = data.get("password")

    if not username or not password:  # Ensure fields are provided
        return jsonify({"error": "Username and password are required"}), 400

    user = get_user(username)  # Retrieve user from database
    if user and bcrypt.checkpw(password.encode(), user[2]):  #Compare passwords
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"message": "Invalid username or password"}), 401

@app.route('/reset-password', methods=['POST'])
def reset_password():
    """Allows users to reset their password if they remember their old password."""
    data = request.json  #Get JSON request data
    username = data.get("username")
    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not username or not old_password or not new_password:
        return jsonify({"error": "All fields are required"}), 400

    user = get_user(username)  # Retrieve user from database
    if not user or not bcrypt.checkpw(old_password.encode(), user[2]):  #Validate old password
        return jsonify({"message": "Invalid username or old password"}), 401

    #Hash the new password before storing it
    hashed_new_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())

    #Update password in the database
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_new_password, username))
        conn.commit()  # Save changes

    return jsonify({"message": "Password updated successfully"}), 200

#Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)  # Enable debug mode for development
