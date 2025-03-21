from flask import Flask, request, jsonify
import bcrypt
import sqlite3

app = Flask(__name__)

#Database initialization
DATABASE = "users.db"

def create_users_table():
    """Creates the users table in SQLite database if it does not exist."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """)
        conn.commit()

#Run database setup
create_users_table()


def get_user(username):
    """Fetches user information from the database by username."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()


@app.route('/register', methods=['POST'])
def register():
    """Registers a new user by hashing their password and storing it in SQLite."""
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    #Check if the user already exists
    if get_user(username):
        return jsonify({"error": "Username already exists"}), 400

    #Hash the password using bcrypt
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    #Store the user in the database
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()

    return jsonify({"message": "User registered successfully"}), 201


@app.route('/login', methods=['POST'])
def login():
    """Authenticates a user by verifying the bcrypt password hash."""
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = get_user(username)
    if user and bcrypt.checkpw(password.encode(), user[2].encode):
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"message": "Invalid username or password"}), 401


@app.route('/reset-password', methods=['POST'])
def reset_password():
    """Allows users to reset their password if they remember their old password."""
    data = request.json
    username = data.get("username")
    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not username or not old_password or not new_password:
        return jsonify({"error": "All fields are required"}), 400

    user = get_user(username)
    if not user or not bcrypt.checkpw(old_password.encode(), user[2].encode()):
        return jsonify({"message": "Invalid username or old password"}), 401

    #Hash the new password
    hashed_new_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())

    #Update password in the database
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_new_password, username))
        conn.commit()

    return jsonify({"message": "Password updated successfully"}), 200


if __name__ == '__main__':
    app.run(debug=True)
