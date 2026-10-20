import sqlite3
import hashlib
import os
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_FILE = PROJECT_ROOT / "behavioral_security.db"

class Authenticator:
    def __init__(self, db_name=DEFAULT_DB_FILE):
        self.db_name = db_name
        self._setup_database()

    @staticmethod
    def _hash_password(password, salt=None):
        """Hashes a password with PBKDF2-HMAC-SHA256 using a 32-byte salt.

        Args:
            password: The plaintext password to hash.
            salt: A bytes salt. If None, a new random salt is generated.

        Returns:
            A tuple of (password_hash_hex, salt_hex).
        """
        if salt is None:
            salt = os.urandom(32)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations=100_000)
        return dk.hex(), salt.hex()

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
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL
                )
            ''')
            # 2. Audit Log Table
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
                admin_hash, admin_salt = self._hash_password("admin123")
                analyst_hash, analyst_salt = self._hash_password("pass123")
                users = [
                    ("admin", admin_hash, admin_salt, "Admin"),
                    ("analyst1", analyst_hash, analyst_salt, "Analyst")
                ]
                cursor.executemany(
                    "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                    users,
                )
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
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash, salt, role FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            
            if row:
                stored_hash, salt_hex, role = row
                input_hash, _ = self._hash_password(password, salt=bytes.fromhex(salt_hex))
                if input_hash == stored_hash:
                    self.log_action(username, "Successful Login")
                    return role  # Returns 'Admin' or 'Analyst'
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
        pw_hash, salt_hex = self._hash_password(password)
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                    (clean_username, pw_hash, salt_hex, "Analyst"),
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

            pw_hash, salt_hex = self._hash_password(new_password)
            cursor.execute(
                "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
                (pw_hash, salt_hex, clean_username),
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
