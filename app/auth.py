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
                    ("admin", hashlib.sha256("admin123".encode()).hexdigest(), "Admin"),
                    ("analyst1", hashlib.sha256("pass123".encode()).hexdigest(), "Analyst")
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
        input_hash = hashlib.sha256(password.encode()).hexdigest()
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash, role FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            
            if row and row[0] == input_hash:
                role = row[1]
                self.log_action(username, "Successful Login")
                return role # Returns 'Admin' or 'Analyst'
        return None
