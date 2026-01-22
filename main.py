import tkinter as tk
from tkinter import ttk, messagebox
from aes_module import AESModule
from rsa_module import RSAModule
from ecc_module import ECCModule

aes = AESModule()
rsa = RSAModule()
ecc = ECCModule()

class CryptoApp:
    def __init__(self, root):
        self.root = root
        root.title("Cryptography Algorithm Evaluator")
        root.geometry("780x520")

        ttk.Label(root, text="Cryptography Algorithm Evaluation Tool",
                  font=("Arial", 16, "bold")).pack(pady=10)

        self.algo = ttk.Combobox(root, values=["AES", "RSA", "ECC"], state="readonly")
        self.algo.current(0)
        self.algo.pack()

        ttk.Label(root, text="Plaintext Input:").pack(pady=5)
        self.input_text = tk.Text(root, height=5)
        self.input_text.pack(pady=5)

        ttk.Button(root, text="Encrypt", command=self.encrypt).pack(pady=5)
        ttk.Button(root, text="Decrypt", command=self.decrypt).pack(pady=5)

        ttk.Label(root, text="Output:").pack(pady=5)
        self.output = tk.Text(root, height=12)
        self.output.pack(pady=5)

    def encrypt(self):
        text = self.input_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Input Error", "Please enter plaintext.")
            return

        algo = self.algo.get()
        try:
            if algo == "AES":
                self.cipher, self.iv, t = aes.encrypt(text)
            elif algo == "RSA":
                self.cipher, t = rsa.encrypt(text)
            else:
                self.cipher, t = ecc.encrypt(text)

            self.output.insert(tk.END,
                f"{algo} Encryption Time: {t:.5f} seconds\nCiphertext: {self.cipher}\n\n")

        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt(self):
        try:
            algo = self.algo.get()
            if algo == "AES":
                plain, t = aes.decrypt(self.cipher, self.iv)
            elif algo == "RSA":
                plain, t = rsa.decrypt(self.cipher)
            else:
                plain, t = ecc.decrypt(self.cipher)

            self.output.insert(tk.END,
                f"{algo} Decryption Time: {t:.5f} seconds\nRecovered Plaintext: {plain}\n\n")

        except Exception:
            messagebox.showwarning("Decryption Error", "No valid ciphertext available.")

root = tk.Tk()
CryptoApp(root)
root.mainloop()
