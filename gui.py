import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttkbs
from ttkbootstrap.constants import *
import tkinter.simpledialog as simpledialog
from encryption_logic import encrypt_message, decrypt_message, password_complexity_check

def on_encrypt_button_click():
    message = message_text.get("1.0", tk.END).strip()
    password = private_key_entry.get()

    valid, error_message = password_complexity_check(password)
    if not valid:
        messagebox.showerror("Error", error_message)
        return

    try:
        encrypted_message = encrypt_message(message, password.encode())
        result = simpledialog.askstring("Copy", "Press Ctrl+C or Command+C to copy", initialvalue=encrypted_message)
        if result:
            window.clipboard_clear()
            window.clipboard_append(result)
            messagebox.showinfo("Copy Successful", "Encrypted message has been copied to the clipboard.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def on_decrypt_button_click():
    message_with_salt_and_iv = message_text.get("1.0", tk.END).strip()
    password = private_key_entry.get()

    valid, error_message = password_complexity_check(password)
    if not valid:
        messagebox.showerror("Error", error_message)
        return

    try:
        decrypted_message = decrypt_message(message_with_salt_and_iv, password.encode())
        messagebox.showinfo("Decrypted Message", "Decrypted message:\n" + decrypted_message)
    except Exception as e:
        messagebox.showerror("Error", str(e))

window = ttkbs.Window(themename="superhero")
window.geometry("400x350")
window.title("Message Encrypt-Decrypt Tool")

message_label = ttkbs.Label(window, text="Message:", bootstyle="warning")
message_label.pack(fill=tk.X)  # Fill the available horizontal space

text_frame = tk.Frame(window)
text_frame.pack(fill=tk.BOTH, expand=True)  # Fill and expand in both directions

message_text = ttkbs.Text(text_frame, height=10, width=40)  # Adjusted dimensions
message_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = ttkbs.Scrollbar(text_frame, command=message_text.yview, bootstyle="dark-round")
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
message_text.config(yscrollcommand=scrollbar.set)

private_key_label = ttkbs.Label(window, text="Private Key:", bootstyle="warning")
private_key_label.pack(fill=tk.X, anchor=tk.CENTER)  # Fill the available horizontal space

private_key_entry = ttkbs.Entry(window, show="*", width=30)
private_key_entry.pack(fill=tk.X, padx=20)  # Fill the available horizontal space, with padding

button_frame = ttkbs.Frame(window)
button_frame.pack()

encrypt_button = ttkbs.Button(button_frame, text="Encrypt", command=on_encrypt_button_click, bootstyle="success")
encrypt_button.grid(row=0, column=0, padx=5, pady=5)  # Added padding

decrypt_button = ttkbs.Button(button_frame, text="Decrypt", command=on_decrypt_button_click, bootstyle="danger")
decrypt_button.grid(row=0, column=1, padx=5, pady=5)  # Added padding

window.mainloop()
