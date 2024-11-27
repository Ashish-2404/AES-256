# AES256 Encryption and Decryption GUI Application

This is a Python-based graphical user interface (GUI) application for encrypting and decrypting text using the **AES256 encryption algorithm**. The application is designed to provide a user-friendly way to secure sensitive data with strong encryption, making it accessible to users without deep technical knowledge of cryptography.

---

## **Features**
- **Encrypt Text**: Convert plaintext into secure ciphertext using AES-256 encryption.
- **Decrypt Text**: Recover the original plaintext from the ciphertext using the correct secret key.
- **User-Friendly Interface**:
  - GUI built using `Tkinter` for ease of use.
  - Separate windows for encryption and decryption.
- **Password Protection**:
  - Derives a 256-bit encryption key using a passphrase and PBKDF2 (Password-Based Key Derivation Function 2).
  - Uses secure padding and encoding mechanisms for compatibility and safety.
- **File Integration**: Displays an image on the main screen for a visually appealing experience.

---

## **Technologies Used**
- **Programming Language**: Python
- **GUI Framework**: Tkinter
- **Cryptography**: `cryptography` library (AES encryption, PBKDF2 key derivation)
- **Image Handling**: `Pillow` (PIL)

---

## **Installation**

1. **Clone the Repository**
   ```bash
   git clone https://github.com/Ashish-2404/AES256.git
   cd AES256


## How the Code Works

### Encryption Process
1. The user inputs plaintext and a secret key (passphrase) via the GUI.
2. The passphrase is used to derive a 256-bit AES key using PBKDF2.
3. The plaintext is padded to ensure compatibility with AES block sizes.
4. The data is encrypted using AES256 in ECB mode and then encoded in Base64.

### Decryption Process
1. The user inputs the ciphertext and secret key via the GUI.
2. The passphrase is used to derive the same AES256 key.
3. The ciphertext is decrypted to retrieve the padded plaintext.
4. The padding is removed to recover the original plaintext.
