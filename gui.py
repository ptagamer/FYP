from app.gui import LoginWindow
import tkinter as tk


if __name__ == "__main__":
    login_root = tk.Tk()
    LoginWindow(login_root)
    login_root.mainloop()
