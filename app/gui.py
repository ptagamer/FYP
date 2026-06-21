import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from PIL import Image, ImageTk
import contextlib
import queue
import threading
import os
import sqlite3
from pathlib import Path

# --- THE BRIDGES (Imports) ---
try:
    from .auth import Authenticator       # SQL Security Logic
    from .main import DATASET_FILE, train_detection_model, run_detection_pipeline  # Detection Engine Logic
except ImportError:
    from auth import Authenticator
    from main import DATASET_FILE, train_detection_model, run_detection_pipeline

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_FILE = PROJECT_ROOT / "nebula_security.db"
CHART_FILE = PROJECT_ROOT / "models" / "behavioral_feature_importance.png"
TRAINING_REPORT_FILE = PROJECT_ROOT / "models" / "latest_training_report.txt"
FAILED_TRAINING_REPORT_FILE = PROJECT_ROOT / "models" / "latest_failed_training_report.txt"


class QueueWriter:
    """File-like writer that sends training output safely back to the Tkinter thread."""
    def __init__(self, output_queue, report_parts):
        self.output_queue = output_queue
        self.report_parts = report_parts

    def write(self, text):
        if text:
            self.report_parts.append(text)
            self.output_queue.put(("output", text))

    def flush(self):
        pass

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
        self.training_thread = None
        self.training_button = None

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
            tk.Button(root, text="Manage Analysts", command=self.open_user_management_window, width=25, bg="navy", fg="white").pack(pady=5)
            self.training_button = tk.Button(root, text="Train Model", command=self.open_training_window, width=25, bg="purple", fg="white")
            self.training_button.pack(pady=5)

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

    def open_training_window(self):
        if self.role != "Admin":
            messagebox.showerror("Access Denied", "Only admins can train models.")
            return

        if self.training_thread and self.training_thread.is_alive():
            messagebox.showinfo("Training Running", "Model training is already in progress.")
            return

        train_win = tk.Toplevel(self.root)
        train_win.title("Admin Model Training")
        center_window(train_win, 700, 500)
        train_win.minsize(520, 360)
        train_win.columnconfigure(0, weight=1)
        train_win.rowconfigure(2, weight=1)
        train_win.protocol("WM_DELETE_WINDOW", lambda: self.close_training_window(train_win))
        selected_training_file = tk.StringVar(value=str(DATASET_FILE))

        tk.Label(train_win, text="Model Training Output", font=("Arial", 12, "bold")).grid(
            row=0,
            column=0,
            sticky="ew",
            padx=10,
            pady=(8, 5),
        )

        dataset_frame = tk.Frame(train_win)
        dataset_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 6))
        dataset_frame.columnconfigure(0, weight=1)

        tk.Label(dataset_frame, text="Training CSV:").grid(row=0, column=0, columnspan=2, sticky="w")
        dataset_entry = tk.Entry(dataset_frame, textvariable=selected_training_file, state="readonly")
        dataset_entry.grid(row=1, column=0, sticky="ew", pady=(3, 0))
        tk.Button(
            dataset_frame,
            text="Browse",
            command=lambda: self.select_training_csv(selected_training_file),
            width=10,
        ).grid(row=1, column=1, sticky="e", padx=(8, 0), pady=(3, 0))

        output_frame = tk.Frame(train_win)
        output_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 6))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)

        output_text = tk.Text(output_frame, height=22, width=85, wrap=tk.WORD)
        output_text.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(output_frame, orient=tk.VERTICAL, command=output_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        output_text.configure(yscrollcommand=scrollbar.set)

        action_frame = tk.Frame(train_win)
        action_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 10))
        action_frame.columnconfigure(0, weight=1)

        status_label = tk.Label(action_frame, text="Training not started.", fg="gray30", anchor="w")
        status_label.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        start_button = tk.Button(
            action_frame,
            text="Start Training",
            width=20,
            bg="purple",
            fg="white",
            command=lambda: self.start_model_training(selected_training_file.get(), output_text, status_label, start_button),
        )
        start_button.grid(row=0, column=1, sticky="e")

        tk.Button(
            action_frame,
            text="Back",
            width=10,
            command=lambda: self.close_training_window(train_win),
        ).grid(row=0, column=2, sticky="e", padx=(8, 0))

        self.load_latest_training_report(output_text, status_label)

    def select_training_csv(self, selected_training_file):
        file_path = filedialog.askopenfilename(
            initialdir=DATASET_FILE.parent,
            filetypes=[("CSV datasets", "*.csv")],
        )
        if file_path:
            selected_training_file.set(file_path)

    def load_latest_training_report(self, output_text, status_label):
        if not TRAINING_REPORT_FILE.exists():
            return

        output_text.config(state=tk.NORMAL)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, TRAINING_REPORT_FILE.read_text(encoding="utf-8"))
        output_text.see("1.0")
        output_text.config(state=tk.DISABLED)
        status_label.config(text=f"Loaded previous report: {TRAINING_REPORT_FILE.name}", fg="gray30")

    def close_training_window(self, train_win):
        if self.training_thread and self.training_thread.is_alive():
            messagebox.showinfo("Training Running", "Training is still running. Please wait until it finishes.")
            return
        train_win.destroy()

    def start_model_training(self, training_file, output_text, status_label, start_button):
        if self.training_thread and self.training_thread.is_alive():
            messagebox.showinfo("Training Running", "Model training is already in progress.")
            return

        training_path = Path(training_file)
        if not training_path.exists():
            messagebox.showerror("Dataset Missing", f"Training dataset not found:\n{training_path}")
            return
        if training_path.suffix.lower() != ".csv":
            messagebox.showerror("Invalid Dataset", "Please select a CSV training dataset.")
            return

        output_queue = queue.Queue()
        output_text.config(state=tk.NORMAL)
        output_text.delete("1.0", tk.END)
        output_text.config(state=tk.DISABLED)
        status_label.config(text="Training in progress...", fg="blue")
        start_button.config(state=tk.DISABLED)
        if self.training_button:
            self.training_button.config(state=tk.DISABLED)

        self.auth.log_action(self.username, f"Started model training using {training_path.name}")
        self.training_thread = threading.Thread(
            target=self._run_training_worker,
            args=(output_queue, training_path),
            daemon=True,
        )
        self.training_thread.start()
        self.root.after(100, self._poll_training_output, output_queue, output_text, status_label, start_button)

    def _run_training_worker(self, output_queue, training_path):
        report_parts = [f"Starting model training...\nDataset: {training_path}\n\n"]
        writer = QueueWriter(output_queue, report_parts)
        try:
            if not training_path.exists():
                raise FileNotFoundError(f"Training dataset not found: {training_path}")
            output_queue.put(("output", report_parts[0]))
            with contextlib.redirect_stdout(writer), contextlib.redirect_stderr(writer):
                train_detection_model(training_path)
            report_parts.append("\nModel training completed successfully.\n")
            TRAINING_REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
            TRAINING_REPORT_FILE.write_text("".join(report_parts), encoding="utf-8")
            output_queue.put(("complete", "Model training completed successfully."))
        except Exception as exc:
            error_message = f"Model training failed: {exc}"
            report_parts.append(f"\n{error_message}\n")
            FAILED_TRAINING_REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
            FAILED_TRAINING_REPORT_FILE.write_text("".join(report_parts), encoding="utf-8")
            output_queue.put(("error", error_message))

    def _poll_training_output(self, output_queue, output_text, status_label, start_button):
        while True:
            try:
                message_type, message = output_queue.get_nowait()
            except queue.Empty:
                break

            if message_type == "output":
                output_text.config(state=tk.NORMAL)
                output_text.insert(tk.END, message)
                output_text.see(tk.END)
                output_text.config(state=tk.DISABLED)
            elif message_type == "complete":
                output_text.config(state=tk.NORMAL)
                output_text.insert(tk.END, f"\n{message}\n")
                output_text.see(tk.END)
                output_text.config(state=tk.DISABLED)
                status_label.config(text=message, fg="green")
                start_button.config(state=tk.NORMAL)
                if self.training_button:
                    self.training_button.config(state=tk.NORMAL)
                self.auth.log_action(self.username, "Completed model training")
                messagebox.showinfo("Training Complete", message)
                return
            elif message_type == "error":
                output_text.config(state=tk.NORMAL)
                output_text.insert(tk.END, f"\n{message}\n")
                output_text.see(tk.END)
                output_text.config(state=tk.DISABLED)
                status_label.config(text=message, fg="red")
                start_button.config(state=tk.NORMAL)
                if self.training_button:
                    self.training_button.config(state=tk.NORMAL)
                self.auth.log_action(self.username, message)
                messagebox.showerror("Training Failed", message)
                return

        if self.training_thread and self.training_thread.is_alive():
            self.root.after(100, self._poll_training_output, output_queue, output_text, status_label, start_button)

    def open_user_management_window(self):
        if self.role != "Admin":
            messagebox.showerror("Access Denied", "Only admins can manage analyst accounts.")
            return

        user_win = tk.Toplevel(self.root)
        user_win.title("Manage Analyst Accounts")
        center_window(user_win, 620, 420)
        user_win.minsize(500, 320)
        user_win.columnconfigure(0, weight=1)
        user_win.rowconfigure(1, weight=1)

        tk.Label(user_win, text="Analyst Account Management", font=("Arial", 12, "bold")).grid(
            row=0,
            column=0,
            sticky="ew",
            padx=10,
            pady=(10, 6),
        )

        table_frame = tk.Frame(user_win)
        table_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 8))
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        analyst_table = ttk.Treeview(
            table_frame,
            columns=("username", "role"),
            show="headings",
            selectmode="browse",
        )
        analyst_table.heading("username", text="Username")
        analyst_table.heading("role", text="Role")
        analyst_table.column("username", width=340, anchor="w")
        analyst_table.column("role", width=120, anchor="center")
        analyst_table.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=analyst_table.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        analyst_table.configure(yscrollcommand=scrollbar.set)

        status_label = tk.Label(user_win, text="", fg="gray30", anchor="w")
        status_label.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 6))

        action_frame = tk.Frame(user_win)
        action_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 10))
        action_frame.columnconfigure(4, weight=1)

        tk.Button(
            action_frame,
            text="Create Analyst",
            width=16,
            command=lambda: self.create_analyst_account(analyst_table, status_label),
        ).grid(row=0, column=0, padx=(0, 6))
        tk.Button(
            action_frame,
            text="Reset Password",
            width=16,
            command=lambda: self.reset_selected_analyst_password(analyst_table, status_label),
        ).grid(row=0, column=1, padx=(0, 6))
        tk.Button(
            action_frame,
            text="Delete Analyst",
            width=16,
            command=lambda: self.delete_selected_analyst(analyst_table, status_label),
        ).grid(row=0, column=2, padx=(0, 6))
        tk.Button(
            action_frame,
            text="Refresh",
            width=10,
            command=lambda: self.refresh_analyst_table(analyst_table, status_label),
        ).grid(row=0, column=3, padx=(0, 6))
        tk.Button(
            action_frame,
            text="Back",
            width=10,
            command=user_win.destroy,
        ).grid(row=0, column=5, sticky="e")

        self.refresh_analyst_table(analyst_table, status_label)

    def refresh_analyst_table(self, analyst_table, status_label):
        analyst_table.delete(*analyst_table.get_children())
        analysts = self.auth.list_users(role="Analyst")
        for user_id, username, role in analysts:
            analyst_table.insert("", tk.END, iid=str(user_id), values=(username, role))
        status_label.config(text=f"{len(analysts)} analyst account(s) loaded.", fg="gray30")

    def get_selected_analyst_username(self, analyst_table):
        selected = analyst_table.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select an analyst account first.")
            return None
        values = analyst_table.item(selected[0], "values")
        return values[0] if values else None

    def create_analyst_account(self, analyst_table, status_label):
        username = simpledialog.askstring("Create Analyst", "Username:", parent=self.root)
        if username is None:
            return
        password = simpledialog.askstring("Create Analyst", "Password:", show="*", parent=self.root)
        if password is None:
            return

        try:
            created_username = self.auth.create_analyst(username, password)
            self.auth.log_action(self.username, f"Created analyst account '{created_username}'")
            self.refresh_analyst_table(analyst_table, status_label)
            status_label.config(text=f"Created analyst account: {created_username}", fg="green")
        except ValueError as exc:
            messagebox.showerror("Create Analyst Failed", str(exc))

    def reset_selected_analyst_password(self, analyst_table, status_label):
        username = self.get_selected_analyst_username(analyst_table)
        if not username:
            return

        password = simpledialog.askstring(
            "Reset Password",
            f"New password for {username}:",
            show="*",
            parent=self.root,
        )
        if password is None:
            return

        try:
            updated_username = self.auth.reset_analyst_password(username, password)
            self.auth.log_action(self.username, f"Reset password for analyst account '{updated_username}'")
            status_label.config(text=f"Password reset for: {updated_username}", fg="green")
        except ValueError as exc:
            messagebox.showerror("Password Reset Failed", str(exc))

    def delete_selected_analyst(self, analyst_table, status_label):
        username = self.get_selected_analyst_username(analyst_table)
        if not username:
            return

        confirmed = messagebox.askyesno(
            "Delete Analyst",
            f"Delete analyst account '{username}'?",
        )
        if not confirmed:
            return

        try:
            deleted_username = self.auth.delete_analyst(username)
            self.auth.log_action(self.username, f"Deleted analyst account '{deleted_username}'")
            self.refresh_analyst_table(analyst_table, status_label)
            status_label.config(text=f"Deleted analyst account: {deleted_username}", fg="green")
        except ValueError as exc:
            messagebox.showerror("Delete Analyst Failed", str(exc))

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
