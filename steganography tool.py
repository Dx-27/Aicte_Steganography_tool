import base64
import cv2
import numpy as np
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import os
from cryptography.fernet import Fernet

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography Tool")
        self.root.geometry("600x400")
        self.create_ui() 

    def create_ui(self):
        self.tab_control = ttk.Notebook(self.root)

        # Encryption Tab
        self.encrypt_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.encrypt_tab, text="Encrypt Message")
        self.create_encrypt_ui()

        # Decryption Tab
        self.decrypt_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.decrypt_tab, text="Decrypt Message")
        self.create_decrypt_ui()

        self.tab_control.pack(expand=1, fill="both")

    def create_encrypt_ui(self):
        frame = ttk.Frame(self.encrypt_tab, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Image File:").grid(row=0, column=0, sticky='w')
        self.img_path = ttk.Entry(frame, width=40)
        self.img_path.grid(row=0, column=1)
        ttk.Button(frame, text="Browse", command=self.browse_image).grid(row=0, column=2)

        ttk.Label(frame, text="Message:").grid(row=1, column=0, sticky='w')
        self.message = tk.Text(frame, height=3, width=30)
        self.message.grid(row=1, column=1, columnspan=2, pady=5)

        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky='w')
        self.password = ttk.Entry(frame, width=40, show="*")
        self.password.grid(row=2, column=1, columnspan=2, pady=5)

        ttk.Button(frame, text="Encrypt Message", command=self.embed_message).grid(row=3, column=1, pady=10)

    def create_decrypt_ui(self):
        frame = ttk.Frame(self.decrypt_tab, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Image File:").grid(row=0, column=0, sticky='w')
        self.decrypt_img_path = ttk.Entry(frame, width=40)
        self.decrypt_img_path.grid(row=0, column=1)
        ttk.Button(frame, text="Browse", command=self.browse_decrypt_image).grid(row=0, column=2)

        ttk.Label(frame, text="Password:").grid(row=1, column=0, sticky='w')
        self.decrypt_password = ttk.Entry(frame, width=40, show="*")
        self.decrypt_password.grid(row=1, column=1, columnspan=2, pady=5)

        ttk.Button(frame, text="Decrypt Message", command=self.extract_message).grid(row=2, column=1, pady=10)

        self.decrypted_message = tk.Text(frame, height=3, width=30, state='disabled')
        self.decrypted_message.grid(row=3, column=0, columnspan=3, pady=5)

    def browse_image(self):
        filename = filedialog.askopenfilename()
        self.img_path.delete(0, tk.END)
        self.img_path.insert(0, filename)

    def browse_decrypt_image(self):
        filename = filedialog.askopenfilename()
        self.decrypt_img_path.delete(0, tk.END)
        self.decrypt_img_path.insert(0, filename)

    def generate_key(self, password):
        return hashlib.sha256(password.encode()).digest()

    def embed_message(self):
        img_path = self.img_path.get()
        message = self.message.get("1.0", tk.END).strip()
        password = self.password.get()

        if not img_path or not message or not password:
            messagebox.showerror("Error", "Image, message, and password are required!")
            return

        img = cv2.imread(img_path)
        if img is None:
            messagebox.showerror("Error", "Invalid image file")
            return

        key = self.generate_key(password)
        fernet = Fernet(base64.urlsafe_b64encode(key))
        encrypted_message = fernet.encrypt(message.encode())

        bin_message = ''.join(format(byte, '08b') for byte in encrypted_message) + '1111111111111110'  # Stop sequence
        index = 0

        for row in img:
            for pixel in row:
                for i in range(3):
                    if index < len(bin_message):
                        pixel[i] = (pixel[i] & 0xFE) | int(bin_message[index])
                        index += 1
                    else:
                        break

        output_path = os.path.splitext(img_path)[0] + "_encrypted.png"
        cv2.imwrite(output_path, img)
        messagebox.showinfo("Success", f"Message encrypted and saved as {output_path}")

    def extract_message(self):
        img_path = self.decrypt_img_path.get()
        password = self.decrypt_password.get()

        if not img_path or not password:
            messagebox.showerror("Error", "Select an image and enter password!")
            return

        img = cv2.imread(img_path)
        if img is None:
            messagebox.showerror("Error", "Invalid image file")
            return

        bin_message = ""

        for row in img:
            for pixel in row:
                for i in range(3):
                    bin_message += str(pixel[i] & 1)

        chars = [bin_message[i:i+8] for i in range(0, len(bin_message), 8)]
        extracted_message = ""

        for char in chars:
            if char == '11111111':
                break
            extracted_message += chr(int(char, 2))

        try:
            key = self.generate_key(password)
            fernet = Fernet(base64.urlsafe_b64encode(key))
            decrypted_message = fernet.decrypt(extracted_message.encode()).decode()
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed. Check password.")
            return

        self.decrypted_message.config(state='normal')
        self.decrypted_message.delete('1.0', tk.END)
        self.decrypted_message.insert('1.0', decrypted_message)
        self.decrypted_message.config(state='disabled')

        messagebox.showinfo("Success", "Message extracted and decrypted successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
