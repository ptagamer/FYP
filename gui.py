import tkinter as tk
from tkinter import filedialog, messagebox

# --- THE BRIDGES (Imports) ---
from auth import Authenticator       # Tells GUI to use your SQL logic
from main import run_nebula_pipeline  # Tells GUI to use your Detection logic

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Nebula Security Portal")
        self.root.geometry("350x250")
        self.auth = Authenticator() # Initializes the SQL Database

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
        
        user_role = self.auth.verify_credentials(user, password)

        if user_role:
            messagebox.showinfo("Success", f"Welcome, {user} ({user_role})")
            self.root.destroy()
            # Pass the role to the dashboard so it knows what to show/hide
            open_dashboard(user, user_role) 
        else:
            messagebox.showerror("Access Denied", "Invalid username or password")

class NebulaGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Nebula Malware Detection Engine")
        self.root.geometry("500x400")
        self.selected_file = None

        tk.Label(root, text="Nebula Engine Dashboard", font=("Arial", 16, "bold")).pack(pady=20)
        self.file_label = tk.Label(root, text="No file selected", fg="red")
        self.file_label.pack(pady=5)

        tk.Button(root, text="Select Dataset (CSV)", command=self.select_file, width=25).pack(pady=10)
        tk.Button(root, text="Run Analysis", command=self.execute, width=25, bg="teal", fg="white").pack(pady=10)
        tk.Button(root, text="Logout & Exit", command=root.quit, width=25).pack(pady=10)

    def select_file(self):
        self.selected_file = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if self.selected_file:
            self.file_label.config(text=f"Selected: {self.selected_file.split('/')[-1]}", fg="green")

    def execute(self):
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a dataset first!")
            return
        try:
            # Calls the function in main.py
            run_nebula_pipeline(self.selected_file)
            messagebox.showinfo("Success", "Analysis Complete! Check terminal for details.")
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {e}")

def open_dashboard(username, role):
    """Starts the main Nebula interface for an authenticated user."""
    main_root = tk.Tk()
    NebulaGUI(main_root)
    main_root.mainloop()

if __name__ == "__main__":
    # Start at the Login Screen
    login_root = tk.Tk()
    LoginWindow(login_root)
    login_root.mainloop()
    