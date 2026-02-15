import tkinter as tk
from tkinter import ttk, messagebox
import time
from datetime import datetime

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
        root.geometry("820x620")

        ttk.Label(
            root,
            text="Cryptography Algorithm Evaluation Tool",
            font=("Arial", 16, "bold")
        ).pack(pady=10)

        self.algo = ttk.Combobox(root, values=["AES", "RSA", "ECC"], state="readonly")
        self.algo.current(0)
        self.algo.pack()

        ttk.Label(root, text="Plaintext Input:").pack(pady=5)
        self.input_text = tk.Text(root, height=5)
        self.input_text.pack(pady=5)

        ttk.Button(root, text="Encrypt", command=self.encrypt).pack(pady=5)
        ttk.Button(root, text="Decrypt", command=self.decrypt).pack(pady=5)

        ttk.Label(root, text="Output:").pack(pady=5)
        self.output = tk.Text(root, height=10)
        self.output.pack(pady=5)

        ttk.Label(root, text="Operation Audit Log:").pack(pady=5)
        self.log_box = tk.Text(root, height=8, state="disabled")
        self.log_box.pack(pady=5)

        self.cipher = None
        self.iv = None

    # ---------- VALIDATION LAYER ----------
    def validate_input(self, text, algorithm):
        if not text.strip():
            raise ValueError("Plaintext cannot be empty.")

        byte_length = len(text.encode("utf-8"))

        if algorithm == "RSA" and byte_length > 190:
            raise ValueError("RSA supports only small plaintext blocks (≤190 bytes).")

        if algorithm == "ECC" and byte_length > 128:
            raise ValueError("ECC payload size exceeded (≤128 bytes).")

        return text.strip()

    # ---------- BENCHMARKING ----------
    def benchmark(self, func, runs=5):
        times = []
        for _ in range(runs):
            start = time.perf_counter()
            func()
            end = time.perf_counter()
            times.append(end - start)
        return sum(times) / len(times)

    # ---------- LOGGING ----------
    def log_event(self, algo, operation, size, duration, status):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = (
            f"[{timestamp}] {algo} | {operation} | "
            f"{size} bytes | {duration:.5f}s | {status}\n"
        )

        self.log_box.configure(state="normal")
        self.log_box.insert(tk.END, log_entry)
        self.log_box.configure(state="disabled")

    # ---------- ENCRYPT ----------
    def encrypt(self):
        try:
            algo = self.algo.get()
            text = self.input_text.get("1.0", tk.END)

            text = self.validate_input(text, algo)
            size = len(text.encode("utf-8"))

            if algo == "AES":
                def task():
                    self.cipher, self.iv, _ = aes.encrypt(text)
            elif algo == "RSA":
                def task():
                    self.cipher, _ = rsa.encrypt(text)
            else:
                def task():
                    self.cipher, _ = ecc.encrypt(text)

            avg_time = self.benchmark(task)

            self.output.insert(
                tk.END,
                f"{algo} Encryption (avg of 5 runs): {avg_time:.5f}s\n"
                f"Ciphertext: {self.cipher}\n\n"
            )

            self.log_event(algo, "ENCRYPT", size, avg_time, "SUCCESS")

        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            self.log_event(self.algo.get(), "ENCRYPT", 0, 0, "FAILED")

    # ---------- DECRYPT ----------
    def decrypt(self):
        try:
            if self.cipher is None:
                raise ValueError("No ciphertext available for decryption.")

            algo = self.algo.get()

            if algo == "AES":
                def task():
                    plain, _ = aes.decrypt(self.cipher, self.iv)
            elif algo == "RSA":
                def task():
                    plain, _ = rsa.decrypt(self.cipher)
            else:
                def task():
                    plain, _ = ecc.decrypt(self.cipher)

            avg_time = self.benchmark(task)
            plain, _ = task()

            self.output.insert(
                tk.END,
                f"{algo} Decryption (avg of 5 runs): {avg_time:.5f}s\n"
                f"Recovered Plaintext: {plain}\n\n"
            )

            self.log_event(algo, "DECRYPT", len(plain.encode()), avg_time, "SUCCESS")

        except Exception as e:
            messagebox.showwarning("Decryption Error", str(e))
            self.log_event(self.algo.get(), "DECRYPT", 0, 0, "FAILED")


root = tk.Tk()
CryptoApp(root)
root.mainloop()
