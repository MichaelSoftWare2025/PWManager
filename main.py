# Password manager (PWManager)
# Maded by Michael

import tkinter as tk
from tkinter import messagebox
import json
import os
from cryptography.fernet import Fernet
import random as rand


# Generate a key if it does not exist
if not os.path.exists("crypt.key"):
    key = Fernet.generate_key()
    with open("crypt.key", "wb") as key_file:
        key_file.write(key)
else:
    key = open("crypt.key", "rb").read()

cipher = Fernet(key)  # Initialize Fernet with the key

PASSWORDS_FILE = "passwords.json"

# Ensure the JSON file exists
if not os.path.exists(PASSWORDS_FILE):
    with open(PASSWORDS_FILE, "w") as f:
        json.dump({}, f)

class PasswordManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager (PWM)")
        self.geometry("500x650")
        self.resizable(False, False)
        self.configure(bg="#1f1f1f")

        self.site_label = tk.Label(self, text="Site:", bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.site_label.pack(pady=10)

        self.site_entry = tk.Entry(self, bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.site_entry.pack(pady=10)

        self.password_label = tk.Label(self, text="Password:", bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.password_label.pack(pady=10)

        self.password_entry = tk.Entry(self, bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.password_entry.pack(pady=10)

        self.save_button = tk.Button(self, text="Save", bg="#2196f3", fg="white", font=("Arial", 16),
                                     command=self.save_gui_password)
        self.save_button.pack(pady=10)

        self.generate_button = tk.Button(self, text="Generate", bg="#2196f3", fg="white", font=("Arial", 16),
                                         command=self.generate_password)
        self.generate_button.pack(pady=10)

        self.delete_button = tk.Button(self, text="Delete", bg="#2196f3", fg="white", font=("Arial", 16),
                                       command=self.delete_gui_password)
        self.delete_button.pack(pady=10)
        
        self.view_passwords_button = tk.Button(self, text="View Passwords", bg="#2196f3", fg="white", font=("Arial", 16),
                                               command=self.view_passwords)
        self.view_passwords_button.pack(pady=10)
        
        self.support_button = tk.Button(self, text="Support me (Donation alerts)", bg="#2196f3", fg="white", font=("Arial", 16),
                                        command=self.support)
        
        self.support_button.pack(pady=10)
        
        
        self.order_button = tk.Button(self, text="Order a custom complex password", bg="#2196f3", fg="white", font=("Arial", 16),
                                      command=self.order)
        
        self.order_button.pack(pady=10)

    def generate_password(self):
        from tkinter.simpledialog import askinteger
        range_of = askinteger("Range", "Enter the range of characters (e.g., 10):")
        password = "".join(chr(rand.randint(33, 126)) for _ in range(range_of))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        
    def order(self):
        import webbrowser
        webbrowser.open(r"youremail@gmail.com?subject=Order%20a%20custom%20complex%20password") # Replace 'youremail' on your email
        
    def support(self):
        import webbrowser
        webbrowser.open("https://donationalerts.com/r/Yourname") # Replace 'Yourname' with your donation alerts name

    def save_password(self, site, password):
        if not site or not password:
            messagebox.showerror("Error", "Site and password fields cannot be empty!")
            return

        try:
            with open(PASSWORDS_FILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {}

        if site in data:
            messagebox.showerror("Error", "Password already exists for this site! First delete the existing password.")
            return

        encrypted_password = cipher.encrypt(password.encode()).decode()
        data[site] = encrypted_password

        with open(PASSWORDS_FILE, "w") as f:
            json.dump(data, f, indent=4)

        messagebox.showinfo("Success", "Password saved successfully!")

    def delete_password(self, site):
        try:
            with open(PASSWORDS_FILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {}

        if site not in data:
            messagebox.showerror("Error", "No password found for this site! First save a password for this site.")
            return

        del data[site]

        with open(PASSWORDS_FILE, "w") as f:
            json.dump(data, f, indent=4)

        messagebox.showinfo("Success", "Password deleted successfully!")

    def save_gui_password(self):
        site = self.site_entry.get()
        password = self.password_entry.get()
        self.save_password(site, password)

    def delete_gui_password(self):
        site = self.site_entry.get()
        self.delete_password(site)
        
    def copy_to_clipboard(self, site):
        import pyperclip
        try:
            with open(PASSWORDS_FILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {}

        if site not in data:
            messagebox.showerror("Error", "No password found for this site! First save a password for this site.")
            return

        password = cipher.decrypt(data[site].encode()).decode()
        pyperclip.copy(password)
        messagebox.showinfo("Success", "Password copied to clipboard!")
        
    def view_passwords(self):
        try:
            with open(PASSWORDS_FILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {"Error": cipher.encrypt("Error decoding passwords file.".encode()).decode()}

        if not data:
            messagebox.showinfo("No Passwords", "No passwords saved yet. First save a password, for any site to view it.")
            return

        # Create a new window for viewing passwords
        view_window = tk.Toplevel(self)
        view_window.title("View Passwords")
        view_window.geometry("500x500")
        view_window.configure(bg="#1f1f1f")

        # Create a canvas with a scrollbar
        canvas = tk.Canvas(view_window, bg="#1f1f1f")
        scrollbar = tk.Scrollbar(view_window, orient=tk.VERTICAL, command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg="#1f1f1f")

        # Configure scrollbar
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")

        # Populate with passwords
        for site, encrypted_password in data.items():
            password = cipher.decrypt(encrypted_password.encode()).decode()
            
            copy_button = tk.Button(scroll_frame, text=f"{site}: {password}", bg="#2196f3", fg="white", font=("Arial", 12), command=lambda site=site: self.copy_to_clipboard(site))
            copy_button.pack(side=tk.LEFT, padx=5)

        # Update scrollable region
        scroll_frame.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))

        # Bind mouse scrolling for better UX
        def on_mouse_scroll(event):
            canvas.yview_scroll(-1 * (event.delta // 120), "units")

        canvas.bind_all("<MouseWheel>", on_mouse_scroll)


if __name__ == "__main__":
    app = PasswordManager()
    app.mainloop()