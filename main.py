import tkinter as tk
from tkinter import filedialog, messagebox
import ctypes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import pyperclip  

def compute_sha256(file_path):
    try:
        sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        with open(file_path, "rb") as file:
            while chunk := file.read(4096):
                sha256.update(chunk)
        return sha256.finalize().hex()
    except Exception as e:
        return f"Error: {e}"

def select_file():
    file_path = filedialog.askopenfilename(title="Select a file")
    if file_path:
        entry_file_path.delete(0, tk.END)
        entry_file_path.insert(0, file_path)

def hash_file():
    file_path = entry_file_path.get()
    if not file_path:
        messagebox.showwarning("Warning", "Please select a file first!")
        return
    sha256_hash = compute_sha256(file_path)
    text_result.delete(1.0, tk.END)
    text_result.insert(tk.END, sha256_hash)

def copy_to_clipboard():
    hash_text = text_result.get(1.0, tk.END).strip()
    if hash_text:
        pyperclip.copy(hash_text)
        messagebox.showinfo("Copied", "SHA-256 hash copied to clipboard!")

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)  # Enable DPI awareness
except Exception:
    pass

root = tk.Tk()
root.title("File Hash Generator (SHA-256)")
root.geometry("500x300")
root.configure(bg="#1e1e1e")

frame = tk.Frame(root, bg="#1e1e1e")
frame.pack(pady=10)

entry_file_path = tk.Entry(frame, width=40, bg="#2d2d2d", fg="white", insertbackground="white")
entry_file_path.pack(side=tk.LEFT, padx=5)

btn_browse = tk.Button(frame, text="Browse", command=select_file, bg="#3a3a3a", fg="white")
btn_browse.pack(side=tk.LEFT)

btn_hash = tk.Button(root, text="Compute SHA-256", command=hash_file, bg="#007acc", fg="white")
btn_hash.pack(pady=10)

text_result = tk.Text(root, height=4, width=40, wrap=tk.WORD, bg="#2d2d2d", fg="white", insertbackground="white")
text_result.pack(pady=10)

btn_copy = tk.Button(root, text="Copy Hash", command=copy_to_clipboard, bg="#007acc", fg="white")
btn_copy.pack(pady=5)

root.mainloop()
