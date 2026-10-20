import customtkinter as ctk
from app.gui import LoginWindow


if __name__ == "__main__":
    login_root = ctk.CTk()
    LoginWindow(login_root)
    login_root.mainloop()
