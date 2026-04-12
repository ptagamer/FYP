import tkinter as tk
from tkinter import filedialog, messagebox
from main import run_nebula_pipeline

class NebulaGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Nebula Malware Detection Engine")
        self.root.geometry("500x350")
        self.selected_file = None

        # UI Styling
        self.label = tk.Label(root, text="Nebula Engine Dashboard", font=("Arial", 16, "bold"))
        self.label.pack(pady=20)

        self.file_label = tk.Label(root, text="No file selected", fg="red")
        self.file_label.pack(pady=5)

        # Buttons
        tk.Button(root, text="Select Dataset (CSV)", command=self.select_file, width=25).pack(pady=10)
        tk.Button(root, text="Run Analysis", command=self.execute, width=25, bg="teal", fg="white").pack(pady=10)
        tk.Button(root, text="Exit", command=root.quit, width=25).pack(pady=10)

    def select_file(self):
        """Triggers the File Picker window."""
        self.selected_file = filedialog.askopenfilename(
            title="Select Malware Dataset",
            filetypes=[("CSV Files", "*.csv")]
        )
        if self.selected_file:
            self.file_label.config(text=f"Selected: {self.selected_file.split('/')[-1]}", fg="green")

    def execute(self):
        """Calls the backend logic."""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a dataset first!")
            return
        
        try:
            # Passing the chosen file to your existing pipeline
            run_nebula_pipeline(self.selected_file)
            messagebox.showinfo("Success", "Analysis Complete! Check terminal for report.")
        except Exception as e:
            messagebox.showerror("Error", f"Pipeline failed: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NebulaGUI(root)
    root.mainloop()