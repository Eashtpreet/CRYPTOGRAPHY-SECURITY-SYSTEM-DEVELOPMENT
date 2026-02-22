# 📘 User Documentation  
## Cryptography Algorithm Evaluation Tool

---

## 1. Introduction

The **Cryptography Algorithm Evaluation Tool** is a desktop-based Python application that allows users to **encrypt, decrypt, and benchmark cryptographic algorithms** using a graphical interface.  
It supports **AES**, **RSA**, and **ECC** algorithms and is intended for **educational and academic evaluation purposes**.

This document explains how end users can effectively use the application.

---

## 2. System Requirements

### Hardware
- Any standard computer capable of running Python

### Software
- Python 3.8 or later
- Required Python library:
  - `cryptography`

Install dependency using:
```
pip install cryptography
```

---

## 3. Starting the Application

1. Ensure all project files are in the same directory:
   - `aes_module.py`
   - `rsa_module.py`
   - `ecc_module.py`
   - `main_app.py`
2. Open a terminal in the project folder
3. Run:
```
python main_app.py
```

The graphical interface will launch automatically.

---

## 4. User Interface Overview

The application window contains:

- **Algorithm Selector** – Choose AES, RSA, or ECC
- **Plaintext Input Area** – Enter text to encrypt
- **Encrypt Button** – Encrypts the plaintext
- **Decrypt Button** – Decrypts the last encrypted message
- **Output Window** – Displays ciphertext and decrypted text
- **Audit Log Panel** – Records all operations with timestamps

---

## 5. Using the Application

### 5.1 Selecting an Algorithm
Choose one of the following algorithms from the dropdown:
- AES (recommended for large data)
- RSA (for small plaintext only)
- ECC (efficient asymmetric encryption)

---

### 5.2 Encrypting Data
1. Enter plaintext in the input box
2. Select an algorithm
3. Click **Encrypt**
4. The output panel will display:
   - Average encryption time (5 runs)
   - Generated ciphertext

---

### 5.3 Decrypting Data
1. Click **Decrypt**
2. The application decrypts the most recent ciphertext
3. The recovered plaintext is shown in the output panel

⚠️ Decryption is only possible after successful encryption.

---

## 6. Input Validation Rules

To ensure correct and safe usage:

- Plaintext must not be empty
- **RSA** supports plaintext ≤ 190 bytes
- **ECC** supports plaintext ≤ 128 bytes
- Violations will trigger an error message

---

## 7. Benchmarking Explanation

- Each operation (encrypt/decrypt) runs **5 times**
- Average execution time is calculated
- Results are displayed to help compare algorithm performance

---

## 8. Audit Log

Every operation is recorded with:
- Timestamp
- Algorithm used
- Operation type (Encrypt / Decrypt)
- Input size
- Execution time
- Status (Success / Failed)

This log helps track usage and errors.

---

## 9. Error Handling

The application will alert users if:
- No plaintext is entered
- Input size exceeds algorithm limits
- Decryption is attempted without prior encryption

Clear messages guide the user to correct the issue.

---

## 10. Interpretation Guidelines

- Faster execution does not always mean better security
- RSA and ECC are intended for small data or key exchange
- AES is best suited for large data encryption
- Results are environment-dependent

---

## 11. Disclaimer

This application is for **learning and demonstration purposes only**.  
It is **not intended for production or real-world security deployment**.

---

## 12. End of Document
