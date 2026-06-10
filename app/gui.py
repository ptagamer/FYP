import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import os
import sqlite3
from pathlib import Path

# --- THE BRIDGES (Imports) ---
try:
    from .auth import Authenticator       # SQL Security Logic
    from .main import run_detection_pipeline  # Detection Engine Logic
except ImportError:
    from auth import Authenticator
    from main import run_detection_pipeline

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_FILE = PROJECT_ROOT / "nebula_security.db"
CHART_FILE = PROJECT_ROOT / "models" / "behavioral_feature_importance.png"

def center_window(window, width, height):
    window.update_idletasks()
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x_position = (screen_width - width) // 2
    y_position = (screen_height - height) // 2
    window.geometry(f"{width}x{height}+{x_position}+{y_position}")

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Behavioral Security Portal")
        center_window(self.root, 350, 250)
        self.auth = Authenticator(DB_FILE)

        tk.Label(self.root, text="System Login", font=("Arial", 14, "bold")).pack(pady=10)
        
        tk.Label(self.root, text="Username:").pack()
        self.user_entry = tk.Entry(self.root)
        self.user_entry.pack(pady=5)

        tk.Label(self.root, text="Password:").pack()
        self.pass_entry = tk.Entry(self.root, show="*")
        self.pass_entry.pack(pady=5)

        tk.Button(self.root, text="Login", command=self.handle_login, bg="teal", fg="white", width=15).pack(pady=20)

    def handle_login(self):
        user = self.user_entry.get()
        password = self.pass_entry.get()
        
        # Returns 'Admin', 'Analyst', or None
        user_role = self.auth.verify_credentials(user, password)

        if user_role:
            messagebox.showinfo("Success", f"Welcome, {user} ({user_role})")
            self.root.destroy()
            open_dashboard(user, user_role) 
        else:
            messagebox.showerror("Access Denied", "Invalid username or password")

class DetectionGUI:
    def __init__(self, root, username, role):
        self.root = root
        self.username = username
        self.role = role
        self.root.title(f"Behavioral Classifier - {role} Mode")
        center_window(self.root, 500, 500)
        self.auth = Authenticator(DB_FILE)
        self.selected_file = None

        tk.Label(root, text="Behavioral Detection Dashboard", font=("Arial", 16, "bold")).pack(pady=10)
        
        # Display current user info (Requirement U1)
        tk.Label(root, text=f"Logged in as: {username} ({role})", fg="blue").pack()

        self.file_label = tk.Label(root, text="No file selected", fg="gray", font=("Arial", 10))
        self.file_label.pack(pady=20)

        # Standard Features
        tk.Button(root, text="Select Dataset", command=self.select_file, width=25).pack(pady=5)
        tk.Button(root, text="Run Analysis", command=self.execute, width=25, bg="teal", fg="white").pack(pady=5)

        # ADMIN ONLY: Audit Log Feature (Requirement F7)
        if self.role == "Admin":
            tk.Label(root, text="--- Admin Tools ---", font=("Arial", 10, "italic")).pack(pady=10)
            tk.Button(root, text="View System Audit Logs", command=self.view_logs, width=25, bg="orange").pack(pady=5)

        tk.Button(root, text="Logout & Exit", command=root.quit, width=25).pack(pady=20)

    def select_file(self):
        self.selected_file = filedialog.askopenfilename(filetypes=[("Supported Datasets", "*.csv *.json")])
        if self.selected_file:
            self.file_label.config(text=f"Selected: {os.path.basename(self.selected_file)}", fg="black")

    def execute(self):
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a dataset first!")
            return
        try:
            self.auth.log_action(self.username, f"Ran analysis on {os.path.basename(self.selected_file)}")
            
            # Catch the NEW 'reason' variable from main.py
            verdict, confidence, reason = run_detection_pipeline(self.selected_file)
            
            res_color = "red" if verdict == "Malicious" else "green"
            
            # Update UI to include the XAI Reason
            result_text = f"Verdict: {verdict}\nConfidence: {confidence:.2f}%\nKey Indicator: {reason}"
            
            self.file_label.config(text=result_text, fg=res_color, font=("Arial", 12, "bold"))
            messagebox.showinfo("Analysis Complete", result_text)
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {e}")

    def view_logs(self):
        """Displays forensic logs AND the Global XAI Chart (Admin only)."""
        log_win = tk.Toplevel(self.root)
        log_win.title("System Audit Logs & Analytics")
        center_window(log_win, 550, 600) 
        
        tk.Label(log_win, text="Forensic Audit Trail", font=("Arial", 12, "bold")).pack(pady=5)
        
        text_area = tk.Text(log_win, height=10, width=60)
        text_area.pack(padx=10, pady=5)
        
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC")
            logs = cursor.fetchall()
            for log in logs:
                text_area.insert(tk.END, f"[{log[3]}] {log[1]}: {log[2]}\n")
        text_area.config(state=tk.DISABLED) 

        # --- NEW VISUAL XAI LOGIC (Admin Analytics) ---
        tk.Label(log_win, text="Global XAI: Feature Importance", font=("Arial", 12, "bold")).pack(pady=10)
        tk.Label(
            log_win,
            text=(
                "This chart shows which behavioral features the model relies on most overall. "
                "Longer bars mean the model used that feature more when making decisions across the training data. "
                "It is a global explanation, not a per-file reason."
            ),
            wraplength=500,
            justify="left",
            fg="gray30"
        ).pack(padx=10, pady=(0, 10))
        
        if CHART_FILE.exists():
            # Load and resize the chart to fit nicely in the window
            img = Image.open(CHART_FILE)
            img = img.resize((450, 250), Image.Resampling.LANCZOS)
            self.chart_img = ImageTk.PhotoImage(img) 
            
            tk.Label(log_win, image=self.chart_img).pack()
        else:
            tk.Label(log_win, text="[Chart not found. Run main.py to train the model.]", fg="red").pack()

def open_dashboard(username, role):
    main_root = tk.Tk()
    DetectionGUI(main_root, username, role)
    main_root.mainloop()

if __name__ == "__main__":
    login_root = tk.Tk()
    LoginWindow(login_root)
    login_root.mainloop()
