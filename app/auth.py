import sqlite3
import hashlib
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_FILE = PROJECT_ROOT / "nebula_security.db"

class Authenticator:
    def __init__(self, db_name=DEFAULT_DB_FILE):
        self.db_name = db_name
        self._setup_database()

    @staticmethod
    def _hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def _validate_credentials_input(username, password):
        clean_username = username.strip()
        if not clean_username:
            raise ValueError("Username cannot be empty.")
        if not password:
            raise ValueError("Password cannot be empty.")
        return clean_username

    def _setup_database(self):
        """Creates tables for users (with roles) and audit logs."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            # 1. Users Table with Roles
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL
                )
            ''')
            # 2. Audit Log Table (Requirement from report)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    action TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            ''')
            
            # Initialize Default Users if empty
            cursor.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] == 0:
                # Admin: Full Access
                # Analyst: Detection Only
                users = [
                    ("admin", self._hash_password("admin123"), "Admin"),
                    ("analyst1", self._hash_password("pass123"), "Analyst")
                ]
                cursor.executemany("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", users)
            conn.commit()

    def log_action(self, username, action):
        """Records user activity in the SQL Audit Log."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("INSERT INTO audit_logs (username, action, timestamp) VALUES (?, ?, ?)",
                           (username, action, timestamp))
            conn.commit()

    def verify_credentials(self, username, password):
        """Verifies user and returns their role if successful."""
        input_hash = self._hash_password(password)
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash, role FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            
            if row and row[0] == input_hash:
                role = row[1]
                self.log_action(username, "Successful Login")
                return role # Returns 'Admin' or 'Analyst'
        return None

    def list_users(self, role=None):
        """Returns users for account management without exposing password hashes."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            if role:
                cursor.execute(
                    "SELECT id, username, role FROM users WHERE role = ? ORDER BY username",
                    (role,),
                )
            else:
                cursor.execute("SELECT id, username, role FROM users ORDER BY role, username")
            return cursor.fetchall()

    def create_analyst(self, username, password):
        """Creates an Analyst account."""
        clean_username = self._validate_credentials_input(username, password)
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (clean_username, self._hash_password(password), "Analyst"),
                )
                conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"User '{clean_username}' already exists.") from exc
        return clean_username

    def reset_analyst_password(self, username, new_password):
        """Resets the password for an Analyst account only."""
        clean_username = self._validate_credentials_input(username, new_password)
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT role FROM users WHERE username = ?", (clean_username,))
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"User '{clean_username}' does not exist.")
            if row[0] != "Analyst":
                raise ValueError("Only Analyst accounts can be managed here.")

            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (self._hash_password(new_password), clean_username),
            )
            conn.commit()
        return clean_username

    def delete_analyst(self, username):
        """Deletes an Analyst account only."""
        clean_username = username.strip()
        if not clean_username:
            raise ValueError("Username cannot be empty.")

        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT role FROM users WHERE username = ?", (clean_username,))
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"User '{clean_username}' does not exist.")
            if row[0] != "Analyst":
                raise ValueError("Only Analyst accounts can be managed here.")

            cursor.execute("DELETE FROM users WHERE username = ?", (clean_username,))
            conn.commit()
        return clean_username
