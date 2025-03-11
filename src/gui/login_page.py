import tkinter as tk
from tkinter import ttk
from customtkinter import *

class LoginPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.pack(fill='both', expand=True)

        self.create_widgets()

    def create_widgets(self):
        self.label_username = ttk.Label(self, text="Username:")
        self.label_username.pack(pady=10)

        self.entry_username = ttk.Entry(self)
        self.entry_username.pack(pady=10)

        self.label_password = ttk.Label(self, text="Password:")
        self.label_password.pack(pady=10)

        self.entry_password = ttk.Entry(self, show="*")
        self.entry_password.pack(pady=10)

        self.button_login = ttk.Button(self, text="Login", command=self.check_login)
        self.button_login.pack(pady=20)

    def check_login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        # Add your login logic here
        if username == "admin" and password == "password":
            self.app.show_main_page()
        else:
            tk.messagebox.showerror("Login Failed", "Invalid username or password")
