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

## Requirements

- Python 3.9 or newer
- Tkinter (comes bundled with standard Python on most systems)
- cryptography library

Install the dependency:

```Bash
pip install -r requirements.txt
```

## How to Run 
### 1. Start the Server
```Bash
python server.py
```
The server will start on 127.0.0.1 : 8000

### 2. Start the Clients
Open one or more new terminals and run:
```Bash
python client.py
```

Each client opens a GUI client window.

## Important Limitations
### RSA message size

This project encrypts chat messages directly with RSA.
With a 2048-bit RSA key and OAEP padding, the maximum message size is very small
(approximately 190 bytes).

Long messages may fail to encrypt.

### In real-world systems, the recommended design is:

RSA for key exchange
AES (symmetric encryption) for message encryption
