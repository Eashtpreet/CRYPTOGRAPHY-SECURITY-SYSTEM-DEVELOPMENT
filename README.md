# 🔐 Cryptography Algorithm Evaluation Tool

A desktop-based Python application for **evaluating and benchmarking cryptographic algorithms** including **AES, RSA, and ECC**.  
The tool provides encryption/decryption functionality, execution-time benchmarking, input validation, and an audit log through a **Tkinter GUI**.

---

## 📌 Project Overview

This application allows users to:
- Encrypt and decrypt plaintext using **AES (symmetric)**, **RSA (asymmetric)**, and **ECC (elliptic-curve)** algorithms
- Measure average encryption/decryption time
- Validate input size and prevent algorithm misuse
- Compare cryptographic techniques in a controlled environment

The project is designed for **academic, learning, and demonstration purposes**.

---

## 🧠 Algorithms Implemented

### 🔹 AES (Advanced Encryption Standard)
- AES-256
- CBC mode with PKCS7 padding
- Suitable for large plaintext sizes

### 🔹 RSA
- 2048-bit key size
- OAEP padding with SHA-256
- Limited to small plaintext (≤190 bytes)

### 🔹 ECC
- Curve: SECP256R1
- Hybrid encryption using ECDH + AES-128
- Efficient key generation and encryption

---

## 🗂️ Project Structure

```
.
├── aes_module.py        # AES encryption/decryption logic
├── rsa_module.py        # RSA encryption/decryption logic
├── ecc_module.py        # ECC hybrid encryption logic
├── main_app.py          # Tkinter GUI application
├── README.md            # Project documentation
```

---

## 🖥️ Application Features

- Graphical User Interface (Tkinter)
- Algorithm selection (AES / RSA / ECC)
- Plaintext input validation
- Average execution time benchmarking (5 runs)
- Operation audit log with timestamps
- Error handling and user alerts

---

## ▶️ How to Run the Application

### 1. Install Dependencies
```bash
pip install cryptography
```

### 2. Run the Application
```bash
python main_app.py
```

---

## 🛡️ Input Validation Rules

- Plaintext cannot be empty
- RSA supports plaintext ≤190 bytes
- ECC supports plaintext ≤128 bytes
- Invalid inputs are blocked before encryption

---

## 📊 Benchmarking Method

- Each encryption/decryption is executed **5 times**
- Average execution time is calculated
- Results are displayed in the output window
- Operations are logged with timestamps

---

## ⚠️ Disclaimer

This tool is intended for **educational and experimental use only**.  
It is **not recommended for production-grade cryptographic deployment**.

---

## 📜 License

Released for academic and research use.
