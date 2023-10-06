import tkinter as tk
from tkinter import messagebox
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

window = tk.Tk()
window.title("Message Encrypt-Decrypt Tool")

message_label = tk.Label(window, text="Message:")
message_label.pack()
message_text = tk.Text(window, height=50, width=100)
message_text.pack()

private_key_label = tk.Label(window, text="Private Key:")
private_key_label.pack()
private_key_entry = tk.Entry(window, show="*", width=30)
private_key_entry.pack()

button_frame = tk.Frame(window)
button_frame.pack()

encrypt_button = tk.Button(button_frame, text="Encrypt", command=on_encrypt_button_click, bg="green", fg="white", height=3, width=10)
encrypt_button.grid(row=0, column=0)

decrypt_button = tk.Button(button_frame, text="Decrypt", command=on_decrypt_button_click, bg="red", fg="white", height=3, width=10)
decrypt_button.grid(row=0, column=1)

window.mainloop()
