import os
import sys
import hashlib
import sqlite3
import time
import tkinter as tk
import requests
from auth_client import AuthClient
from dotenv import load_dotenv
from tkinter import ttk
from tkinter import filedialog
from Crypto.Cipher import AES


load_dotenv()
AUTH_SERVER_URL = os.getenv("AUTH_SERVER_URL")


class Encryption:
    def __init__(self, user_file, user_key):
        self.user_file = user_file

        self.input_file_size = os.path.getsize(self.user_file)
        self.chunk_size = 5242880
        self.total_chunks = (self.input_file_size // self.chunk_size) + 1
        
        self.user_key = bytes(user_key, "utf-8")

        self.file_extension = self.user_file.split(".")[-1]
        
        self.hash_type = "SHA256"

        self.encrypt_output_file = ".".join(self.user_file.split(".")[:-1]) \
            + "." + self.file_extension + ".encryp"

        self.decrypt_output_file = self.user_file[:-5].split(".")
        self.decrypt_output_file = ".".join(self.decrypt_output_file[:-1]) \
            + "__decrypted__." + self.decrypt_output_file[-1]

        self.hashed_key_salt = dict()
        self.hash_key_salt()


    def encrypt(self):
        nonce = os.urandom(8)
        
        cipher_object = AES.new(
            self.hashed_key_salt["key"],
            AES.MODE_CTR,
            nonce=nonce
        )

        self.abort()

        try:
            with open(self.user_file, "rb") as input_file:
                file_data = input_file.read()

            encrypted_content = cipher_object.encrypt(file_data)

            with open(self.encrypt_output_file, "wb") as output_file:
                output_file.write(nonce)
                output_file.write(encrypted_content)
        finally:
            del cipher_object 

    def decrypt(self):
        self.abort()

        try:
            with open(self.user_file, "rb") as input_file:
                nonce = input_file.read(8)
                encrypted_data = input_file.read()
                
                cipher_object = AES.new(
                    self.hashed_key_salt["key"],
                    AES.MODE_CTR,
                    nonce=nonce
                )
                
                decrypted_content = cipher_object.decrypt(encrypted_data)
                
                with open(self.decrypt_output_file, "wb") as output_file:
                    output_file.write(decrypted_content)
        finally:
            del cipher_object

    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)


    def hash_key_salt(self):
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_key)

        self.hashed_key_salt["key"] = bytes(hasher.hexdigest()[:32], "utf-8")

        del hasher


class LoginWindow:
    def __init__(self, root):
        self.auth_client = AuthClient(AUTH_SERVER_URL)

        self.root = root
        self.root.title("Login")
        self.root.geometry("300x250")
        self.root.resizable(False, False)
        
        window_width = 300
        window_height = 250
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        center_x = int(screen_width/2 - window_width/2)
        center_y = int(screen_height/2 - window_height/2)
        self.root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
        
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.login_frame = ttk.Frame(self.main_frame)
        self.login_frame.pack(fill="both", expand=True)
        
        self.register_frame = ttk.Frame(self.main_frame)
        
        self.username_label = ttk.Label(self.login_frame, text="Username:")
        self.username_label.pack(padx=10, pady=(10, 5))
        self.username_entry = ttk.Entry(self.login_frame, width=30)
        self.username_entry.pack(padx=10, pady=5)
        
        self.password_label = ttk.Label(self.login_frame, text="Password:")
        self.password_label.pack(padx=10, pady=5)
        self.password_entry = ttk.Entry(self.login_frame, width=30, show="•")
        self.password_entry.pack(padx=10, pady=5)
        
        self.error_var = tk.StringVar()
        self.error_label = ttk.Label(
            self.login_frame, 
            textvariable=self.error_var, 
            foreground="red",
            wraplength=280
        )
        self.error_label.pack(padx=10, pady=5)

        button_frame = ttk.Frame(self.login_frame)
        button_frame.pack(fill="x", padx=10, pady=10)
        
        self.login_button = ttk.Button(
            button_frame,
            text="Login",
            command=self.authenticate
        )
        self.login_button.pack(side="left", padx=(0, 5), expand=True, fill="x")
        
        self.show_register_button = ttk.Button(
            button_frame,
            text="Register",
            command=self.show_registration_form
        )
        self.show_register_button.pack(side="right", padx=(5, 0), expand=True, fill="x")
        
        self.reg_username_label = ttk.Label(self.register_frame, text="New Username:")
        self.reg_username_label.pack(padx=10, pady=(10, 5))
        self.reg_username_entry = ttk.Entry(self.register_frame, width=30)
        self.reg_username_entry.pack(padx=10, pady=5)
        
        self.reg_password_label = ttk.Label(self.register_frame, text="New Password:")
        self.reg_password_label.pack(padx=10, pady=5)
        self.reg_password_entry = ttk.Entry(self.register_frame, width=30, show="•")
        self.reg_password_entry.pack(padx=10, pady=5)
        
        self.reg_confirm_label = ttk.Label(self.register_frame, text="Confirm Password:")
        self.reg_confirm_label.pack(padx=10, pady=5)
        self.reg_confirm_entry = ttk.Entry(self.register_frame, width=30, show="•")
        self.reg_confirm_entry.pack(padx=10, pady=5)
        
        self.reg_message_var = tk.StringVar()
        self.reg_message_label = ttk.Label(
            self.register_frame, 
            textvariable=self.reg_message_var,
            foreground="red",
            wraplength=280
        )
        self.reg_message_label.pack(padx=10, pady=5)
        
        reg_button_frame = ttk.Frame(self.register_frame)
        reg_button_frame.pack(fill="x", padx=10, pady=10)
        
        self.register_button = ttk.Button(
            reg_button_frame,
            text="Create Account",
            style="Login.TButton", 
            command=self.register_user
        )
        self.register_button.pack(side="left", padx=(0, 5), expand=True, fill="x")
        
        self.back_button = ttk.Button(
            reg_button_frame,
            text="Back to Login",
            command=self.show_login_form
        )
        self.back_button.pack(side="right", padx=(5, 0), expand=True, fill="x")
        
        self.root.bind("<Return>", lambda event: self.authenticate() if self.login_frame.winfo_ismapped() else self.register_user())
        
        self.username_entry.focus()
    
    def show_registration_form(self):
        """Switch to registration form"""
        self.root.geometry("350x350")
        self.login_frame.pack_forget()
        self.register_frame.pack(fill="both", expand=True)
        self.reg_username_entry.focus()
        self.error_var.set("")
        self.reg_message_var.set("")
    
    def show_login_form(self):
        """Switch back to login form"""
        self.root.geometry("300x250")
        self.register_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)
        self.username_entry.focus()
        self.error_var.set("")
        self.reg_message_var.set("")

    def register_user(self):
        """Register a new user with secure remote authentication"""
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()
        confirm = self.reg_confirm_entry.get()
        
        if not username or not password or not confirm:
            self.reg_message_var.set("Please fill all fields")
            return
        
        if password != confirm:
            self.reg_message_var.set("Passwords don't match")
            return
        
        if len(password) < 6:
            self.reg_message_var.set("Password must be at least 6 characters")
            return
        
        self.reg_message_var.set("Registering...")
        self.reg_message_label.config(foreground="blue")
        self.register_button.config(state="disabled")
        self.root.update()
        
        try:
            start = time.perf_counter()
            result = self.auth_client.register(username, password)
            
            end = time.perf_counter()
            print("Registration in", end - start)
            
            if result.get('status') == 'success':
                decrypted_key = result.get('decrypted_key', '')
                print("Decrypted key:", decrypted_key)

                self.reg_message_var.set("")
                self.reg_message_label.config(foreground="green")
                self.reg_message_var.set("Registration successful! You can now login.")
                
                self.reg_username_entry.delete(0, tk.END)
                self.reg_password_entry.delete(0, tk.END)
                self.reg_confirm_entry.delete(0, tk.END)
                
                self.root.destroy()

                
                self.open_main_application(decrypted_key, username)
            else:
                error_message = result.get('message', 'Registration failed')
                print(f"[ERROR] Registration failed. Full response: {result}")
                self.reg_message_label.config(foreground="red")
                self.reg_message_var.set(f"Error: {error_message}")
        except Exception as e:
            self.reg_message_label.config(foreground="red")
            self.reg_message_var.set(f"Connection error: {str(e)}")
        
        self.register_button.config(state="normal")

    def authenticate(self):
        """Authenticate with secure remote authentication"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            self.error_var.set("Please enter both username and password")
            return
        
        self.error_var.set("Logging in...")
        self.error_label.config(foreground="blue")
        self.login_button.config(state="disabled")
        self.root.update()
        
        try:
            start = time.perf_counter()

            result = self.auth_client.login(username, password)

            end = time.perf_counter()
            print("Authentication in", end - start)
            
            if result.get('status') == 'success':
                decrypted_key = result.get('decrypted_key', '')
                print("decrypted key:", decrypted_key)

                self.root.destroy()
                self.open_main_application(decrypted_key, username)
            else:
                error_message = result.get('message', 'Authentication failed')
                self.error_label.config(foreground="red")
                self.error_var.set(f"Error: {error_message}")
                self.password_entry.delete(0, tk.END)
        except requests.exceptions.ConnectionError:
            self.error_label.config(foreground="red")
            self.error_var.set("Server connection error. Please try again later.")
        except Exception as e:
            self.error_label.config(foreground="red")
            self.error_var.set(f"Login error: {str(e)}")
        
        self.login_button.config(state="normal") 
    
    def open_main_application(self, decrypted_key, username):
        app_root = tk.Tk()
        
        style = ttk.Style()
        style.configure("Dark.TButton", background="#333333", foreground="#ffffff", borderwidth=1)
        
        main_app = MainWindow(app_root, decrypted_key, username)
        app_root.mainloop()


class MainWindow:
    THIS_FOLDER_G = ""
    if getattr(sys, "frozen", False):
        THIS_FOLDER_G = os.path.dirname(sys.executable)
    else:
        THIS_FOLDER_G = os.path.dirname(os.path.realpath(__file__))

    def __init__(self, root, decrypted_key, username=None):
        self.db_path = "encrypted_files.db" 
        self._initialize_database()
        self.username = username

        if username:
            root.title(f"File Encryption - Logged in as {username}")
        else:
            root.title("File Encryption")

        self.root = root
        self._cipher = None
        self._file_url = tk.StringVar()
        self._secret_key= decrypted_key or os.urandom(32)
        self._status = tk.StringVar()
        self._status.set("---")
        self.current_directory = os.getcwd()
        self.selected_file = None

        if decrypted_key:
            self._status.set("Secure key received from authentication server")
        
        self.should_cancel = False

        root.title("File Encryption")
        root.geometry("1000x600")
        
        self.main_container = ttk.PanedWindow(root, orient=tk.HORIZONTAL)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.left_panel = ttk.Frame(self.main_container, width=200)
        self.main_container.add(self.left_panel, weight=1)
        
        self.right_panel = ttk.Frame(self.main_container)
        self.main_container.add(self.right_panel, weight=4)
        
        self._create_left_panel()
        
        self._create_right_panel()
        
        self.status_frame = ttk.Frame(root)
        self.status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.status_label = ttk.Label(
            self.status_frame,
            textvariable=self._status,
            anchor=tk.W
        )
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.refresh_files()

    def _initialize_database(self):
        """Initialize the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS encrypted_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL UNIQUE,
                encrypted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                file_size INTEGER,
                encryption_key_hash TEXT
            )
        """)
        conn.commit()
        conn.close()

    def _create_left_panel(self):
        """Create the left panel with control buttons"""
        for i in range(10):
            self.left_panel.grid_rowconfigure(i, pad=5)
        self.left_panel.grid_columnconfigure(0, pad=10, weight=1)
        
        file_label = ttk.Label(self.left_panel, text="Selected File:")
        file_label.grid(row=0, column=0, sticky=tk.W, padx=10, pady=(10, 0))
        
        self.file_entry = ttk.Entry(
            self.left_panel,
            textvariable=self._file_url,
            state="readonly",
        )
        self.file_entry.grid(row=0, column=0, sticky=tk.W+tk.E, padx=10, pady=(35, 15))
        
        btn_width = 20
        btn_style = "Dark.TButton"
        
        self.select_btn = ttk.Button(
            self.left_panel,
            text="SELECT FILE",
            command=self.selectfile_callback,
            style=btn_style,
            width=btn_width
        )
        self.select_btn.grid(row=1, column=0, sticky=tk.W+tk.E, padx=10, pady=(20, 5))
        
        self.encrypt_btn = ttk.Button(
            self.left_panel,
            text="ENCRYPT",
            command=self.encrypt_callback,
            style=btn_style,
            width=btn_width
        )
        self.encrypt_btn.grid(row=2, column=0, sticky=tk.W+tk.E, padx=10, pady=5)
        
        self.decrypt_btn = ttk.Button(
            self.left_panel,
            text="DECRYPT",
            command=self.decrypt_callback,
            style=btn_style,
            width=btn_width
        )
        self.decrypt_btn.grid(row=3, column=0, sticky=tk.W+tk.E, padx=10, pady=5)
        
        self.reset_btn = ttk.Button(
            self.left_panel,
            text="RESET",
            command=self.reset_callback,
            style=btn_style,
            width=btn_width
        )
        self.reset_btn.grid(row=4, column=0, sticky=tk.W+tk.E, padx=10, pady=5)
        
        self.refresh_btn = ttk.Button(
            self.left_panel,
            text="REFRESH FILES",
            command=self.refresh_files,
            style=btn_style,
            width=btn_width
        )
        self.refresh_btn.grid(row=5, column=0, sticky=tk.W+tk.E, padx=10, pady=5)
        
        self.parent_dir_btn = ttk.Button(
            self.left_panel,
            text="GO UP",
            command=self.go_to_parent_directory,
            style=btn_style,
            width=btn_width
        )
        self.parent_dir_btn.grid(row=6, column=0, sticky=tk.W+tk.E, padx=10, pady=5)

    def _create_right_panel(self):
        """Create the right panel with file listing"""
        self.dir_var = tk.StringVar()
        self.dir_var.set(self.current_directory)
        
        self.dir_label = ttk.Label(self.right_panel, textvariable=self.dir_var, 
                                   anchor=tk.W, background="#f0f0f0", 
                                   padding=5)
        self.dir_label.pack(fill=tk.X, expand=False, padx=5, pady=5)
        
        columns = ("name", "type", "size", "modified")
        self.file_tree = ttk.Treeview(self.right_panel, columns=columns, show="headings")
        
        self.file_tree.heading("name", text="Name")
        self.file_tree.heading("type", text="Type")
        self.file_tree.heading("size", text="Size")
        self.file_tree.heading("modified", text="Modified Date")
        
        self.file_tree.column("name", width=300)
        self.file_tree.column("type", width=100)
        self.file_tree.column("size", width=100)
        self.file_tree.column("modified", width=150)
        
        vsb = ttk.Scrollbar(self.right_panel, orient="vertical", command=self.file_tree.yview)
        hsb = ttk.Scrollbar(self.right_panel, orient="horizontal", command=self.file_tree.xview)
        self.file_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.file_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.file_tree.bind("<Double-1>", self.on_file_double_click)
        self.file_tree.bind("<<TreeviewSelect>>", self.on_file_select)

    def refresh_files(self):
        """Refresh the file list to show only encrypted files from the current user."""
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)

        self.dir_var.set(self.current_directory)

        try:
            current_key_hash = hashlib.sha256(self._secret_key.encode()).hexdigest()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT file_path, file_size, encrypted_at 
                FROM encrypted_files 
                WHERE encryption_key_hash = ?
            """, (current_key_hash,))
            encrypted_files = cursor.fetchall()
            conn.close()

            for file_path, file_size, encrypted_at in encrypted_files:
                file_name = os.path.basename(file_path)
                file_size_str = self.format_size(file_size)
                self.file_tree.insert("", "end", values=(file_name, "Encrypted", file_size_str, encrypted_at))

            self._status.set(f"Found {len(encrypted_files)} encrypted files for your account.")
        except Exception as e:
            self._status.set(f"Error loading encrypted files: {str(e)}")

    def format_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes/(1024*1024):.1f} MB"
        else:
            return f"{size_bytes/(1024*1024*1024):.1f} GB"

    def go_to_parent_directory(self):
        """Navigate to parent directory"""
        parent = os.path.dirname(self.current_directory)
        if parent != self.current_directory:  
            self.current_directory = parent
            self.refresh_files()

    def on_file_double_click(self, event):
        """Handle double click on a file or directory"""
        selection = self.file_tree.selection()
        if selection:
            item = selection[0]
            values = self.file_tree.item(item, "values")
            if len(values) > 0:
                file_name = values[0]
                file_type = values[1]
                
                if file_type == "Directory":
                    self.current_directory = os.path.join(self.current_directory, file_name)
                    self.refresh_files()
                else:
                    self._file_url.set(os.path.join(self.current_directory, file_name))
                    self._status.set(f"Selected: {file_name}")

    def on_file_select(self, event):
        """Handle file selection"""
        selection = self.file_tree.selection()
        if selection:
            item = selection[0]
            values = self.file_tree.item(item, "values")
            if len(values) > 0:
                file_name = values[0]
                
                try:
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT file_path FROM encrypted_files WHERE file_path LIKE ?", 
                                  (f"%{file_name}",))
                    result = cursor.fetchone()
                    conn.close()
                    
                    if result:
                        file_path = result[0]
                    else:
                        file_path = os.path.join(self.current_directory, file_name)
                        if not file_path.endswith(".encryp"):
                            file_path = file_path + ".encryp"
                except Exception as e:
                    print(f"Database error: {e}")
                    file_path = os.path.join(self.current_directory, file_name)

                self._file_url.set(file_path)
                self.selected_file = file_path
                self._status.set(f"Selected: {file_name}")

    def selectfile_callback(self):
        """Open file dialog to select a file"""
        try:
            name = filedialog.askopenfile(parent=self.root)
            if name:
                self._file_url.set(name.name)
                self._status.set(f"Selected: {os.path.basename(name.name)}")
                
                self.current_directory = os.path.dirname(name.name)
                self.refresh_files()
        except Exception as e:
            self._status.set(f"Error: {str(e)}")
            self.status_label.update()

    def freeze_controls(self):
        """Disable controls during operations"""
        self.select_btn.configure(state="disabled")
        self.encrypt_btn.configure(state="disabled")
        self.decrypt_btn.configure(state="disabled")
        self.refresh_btn.configure(state="disabled")
        self.parent_dir_btn.configure(state="disabled")
        self.reset_btn.configure(text="CANCEL", command=self.cancel_callback)
        self.file_tree.unbind("<Double-1>")
        self.file_tree.unbind("<<TreeviewSelect>>")
        self.status_label.update()
    
    def unfreeze_controls(self):
        """Re-enable controls after operations"""
        self.select_btn.configure(state="normal")
        self.encrypt_btn.configure(state="normal")
        self.decrypt_btn.configure(state="normal")
        self.refresh_btn.configure(state="normal")
        self.parent_dir_btn.configure(state="normal")
        self.reset_btn.configure(text="RESET", command=self.reset_callback)
        self.file_tree.bind("<Double-1>", self.on_file_double_click)
        self.file_tree.bind("<<TreeviewSelect>>", self.on_file_select)
 
        self.status_label.update()

    def encrypt_callback(self):
        """Encrypt selected file and store metadata in the database."""
        if not self._file_url.get():
            self._status.set("Please select a file first.")
            return

        if not self._secret_key:
            self._status.set("Error.")
            return

        self.freeze_controls()

        try:
            start_time = time.perf_counter()

            self._cipher = Encryption(
                self._file_url.get(),
                self._secret_key,
            )

            self._cipher.encrypt()

            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Operation cancelled.")
            else:
                end_time = time.perf_counter()
                encryption_time = end_time - start_time
                print("Encryption time:", encryption_time)
        
                encrypted_file_path = self._cipher.encrypt_output_file
                file_size = os.path.getsize(encrypted_file_path)
                key_hash = hashlib.sha256(self._secret_key.encode()).hexdigest()

                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR IGNORE INTO encrypted_files (file_path, file_size, encryption_key_hash)
                    VALUES (?, ?, ?)
                """, (encrypted_file_path, file_size, key_hash))
                conn.commit()
                conn.close()

                self._status.set("File successfully encrypted!")
                self.refresh_files()

            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            self._status.set(f"Error: {str(e)}")

        self.unfreeze_controls() 

    def decrypt_callback(self):
        """Decrypt selected file and remove metadata from the database."""
        if not self._file_url.get():
            self._status.set("Please select a file first.")
            return

        if not self._file_url.get().endswith(".encryp"):
            self._status.set("Selected file is not an encrypted file (.encryp).")
            return
        
        try:
            file_path = self._file_url.get()
            current_key_hash = hashlib.sha256(self._secret_key.encode()).hexdigest()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT encryption_key_hash FROM encrypted_files WHERE file_path = ?", (file_path,))
            result = cursor.fetchone()
            conn.close()
            
            if result and result[0] != current_key_hash:
                self._status.set("This file was encrypted with a different key and cannot be decrypted.")
                return
        except Exception as e:
            print(f"Key validation error: {e}")

        self.freeze_controls()

        start_time = time.perf_counter()

        try:
            self._cipher = Encryption(
                self._file_url.get(),
                self._secret_key,
            )
            
            self._cipher.decrypt()
            
            file_path = self._file_url.get()
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM encrypted_files WHERE file_path = ?", (file_path,))
            conn.commit()
            conn.close()

            self._status.set("File successfully decrypted!")
            self.refresh_files()

            end_time = time.perf_counter()
            encryption_time = end_time - start_time
            print("Decryption time:", encryption_time)

            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            self._status.set(f"Error: {str(e)}")

        self.unfreeze_controls()

    def reset_callback(self):
        """Reset the form"""
        self._cipher = None
        self._file_url.set("")
        self._status.set("Form reset.")
    
    def cancel_callback(self):
        """Cancel ongoing operation"""
        self.should_cancel = True
        self._status.set("Cancelling operation...")


if __name__ == "__main__":
    login_root = tk.Tk()
    login_app = LoginWindow(login_root)
    login_root.mainloop()