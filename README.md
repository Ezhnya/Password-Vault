# 🔒 Password Vault — Local Password Manager

Password Vault is a simple **local password manager** built with **PySide6**. It stores your passwords securely in an **encrypted SQLite database (AES-256-GCM)**. Designed to be ready-to-use right after download with minimal configuration.

---

## Features

- **Master Password**: Access protected by a master password.  
- **Password Generator**: Built-in generator with customizable options (length, symbols, avoid ambiguous characters).  
- **Store Details**: Save logins, passwords, URLs, and notes.  
- **Clipboard Copy**: Copy passwords to clipboard (auto-clears after 20 seconds).  
- **Local Only**: All data is stored locally, no cloud or external services.  
- **Secure**: If you forget the master password, recovery is impossible.  

## Installation

1. Install Python 3.10+  
2. Install dependencies: pip install -r requirements.txt


## Usage


Run the application:
Копіювати
Редагувати
python main.py

- On first launch, you will be asked to set a master password.
- Use the interface to add, edit, delete entries, or generate passwords.


## Project Structure

PasswordVault_Ezhnya/
├─ main.py                 # Entry point
├─ vault/
│   ├─ __init__.py
│   ├─ crypto.py           # AES-GCM + Scrypt key derivation
│   ├─ db.py               # SQLite database operations
│   ├─ generator.py        # Password generator
│   └─ ui.py               # PySide6 UI windows
├─ data/                   # Database stored here (vault.db)
├─ requirements.txt
├─ README.md
└─ LICENSE
## Author

Developed with by Ezhnya [GitHub](https://github.com/Ezhnya) | [Telegram Channel](https://t.me/+2MllMZSL7EQyNDA6)

## License
MIT License © Ezhnya
