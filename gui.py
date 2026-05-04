import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import sqlite3

# --- THE BRIDGES (Imports) ---
from auth import Authenticator       # SQL Security Logic
from main import run_nebula_pipeline  # Detection Engine Logic

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
        self.root.title("Nebula Security Portal")
        center_window(self.root, 350, 250)
        self.auth = Authenticator() 

        tk.Label(self.root, text="Nebula Login", font=("Arial", 14, "bold")).pack(pady=10)
        
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

class NebulaGUI:
    def __init__(self, root, username, role):
        self.root = root
        self.username = username
        self.role = role
        self.root.title(f"Nebula Engine - {role} Mode")
        center_window(self.root, 500, 500)
        self.auth = Authenticator()
        self.selected_file = None

        tk.Label(root, text="Nebula Engine Dashboard", font=("Arial", 16, "bold")).pack(pady=10)
        
        # Display current user info (Requirement U1)
        tk.Label(root, text=f"Logged in as: {username} ({role})", fg="blue").pack()

        self.file_label = tk.Label(root, text="No file selected", fg="gray", font=("Arial", 10))
        self.file_label.pack(pady=20)

        # Standard Features
        tk.Button(root, text="Select Dataset (CSV)", command=self.select_file, width=25).pack(pady=5)
        tk.Button(root, text="Run Analysis", command=self.execute, width=25, bg="teal", fg="white").pack(pady=5)

        # ADMIN ONLY: Audit Log Feature (Requirement F7)
        if self.role == "Admin":
            tk.Label(root, text="--- Admin Tools ---", font=("Arial", 10, "italic")).pack(pady=10)
            tk.Button(root, text="View System Audit Logs", command=self.view_logs, width=25, bg="orange").pack(pady=5)

        tk.Button(root, text="Logout & Exit", command=root.quit, width=25).pack(pady=20)

    def select_file(self):
        self.selected_file = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if self.selected_file:
            self.file_label.config(text=f"Selected: {self.selected_file.split('/')[-1]}", fg="black")

    def execute(self):
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a dataset first!")
            return
        try:
            # 1. Log the action to the SQL Audit Trail (F7)
            self.auth.log_action(self.username, f"Ran analysis on {self.selected_file.split('/')[-1]}")
            
            # 2. Run the detection pipeline (F5, F6)
            verdict, confidence = run_nebula_pipeline(self.selected_file)
            
            # 3. Update UI with Color-Coding (NF3)
            res_color = "red" if verdict == "Malicious" else "green"
            result_text = f"Verdict: {verdict}\nConfidence: {confidence:.2f}%"
            
            self.file_label.config(text=result_text, fg=res_color, font=("Arial", 12, "bold"))
            
            messagebox.showinfo("Analysis Complete", result_text)
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {e}")

    def view_logs(self):
        """Displays the forensic audit trail (Admin only)."""
        log_win = tk.Toplevel(self.root)
        log_win.title("System Audit Logs")
        center_window(log_win, 450, 350)
        
        tk.Label(log_win, text="Forensic Audit Trail", font=("Arial", 12, "bold")).pack(pady=10)
        
        text_area = tk.Text(log_win, height=15, width=50)
        text_area.pack(padx=10, pady=10)
        
        with sqlite3.connect("nebula_security.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC")
            logs = cursor.fetchall()
            for log in logs:
                text_area.insert(tk.END, f"[{log[3]}] {log[1]}: {log[2]}\n")
        
        text_area.config(state=tk.DISABLED) # Make it read-only

def open_dashboard(username, role):
    main_root = tk.Tk()
    NebulaGUI(main_root, username, role)
    main_root.mainloop()

if __name__ == "__main__":
    login_root = tk.Tk()
    LoginWindow(login_root)
    login_root.mainloop()