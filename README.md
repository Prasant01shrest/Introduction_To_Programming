# End-to-End Encrypted Chat Application
A laboratory demonstration of a secure chat system which integrates **RSA Encryption**, **OAEP Padding** with a simple **Tkinter GUI** for end-to=end communication. This project combines **cryptography** with **python** programming language into a project to simulate real-world scenario.

## Features
- **End-to-End Encryption**: Messages are encrypted with RSA and OAEP for confidentiality.
- **Key Management**: Server distributes public keys securely via JSON.
- **Multi-User Support**: Threaded server handles multiple clients simultaneously.
- **Graphical Interface**: Tkinter-based GUI for sending and receiving messages.
- **Modular Design**:
  - `server.py` → Networking and key distribution
  - `encrypt.py` → Cryptographic operations
  - `client.py` → GUI and user interaction

## Project Structure
```
secure-chat/
├── server.py          # Manages client connections, public key distribution, and message relaying
├── client.py          # Tkinter-based GUI client for sending and receiving encrypted messages
├── crypto_utils.py    # Handles RSA key generation, encryption, and decryption functions
├── requirements.txt   # Lists required Python dependencies (e.g., cryptography)
└── README.md          # Project documentation
```
