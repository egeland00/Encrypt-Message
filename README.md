Message Encrypt-Decrypt Tool

A simple yet effective graphical user interface tool to encrypt and decrypt messages using the AES cipher in CBC mode. This tool provides additional security through key derivation and password complexity requirements, ensuring your messages remain confidential.

Code/Encrypt-Message/gui.png

    AES encryption in CBC mode.
    Key derivation using PBKDF2HMAC with SHA256.
    Password complexity checks.
    User-friendly graphical interface.
    Copy-to-clipboard functionality for easy sharing of encrypted messages.

Installation & Usage

    Clone the Repository

    bash

git clone https://github.com/egeland00/Encrypt-Message.git
cd Encrypt-Message


Install the Required Libraries

bash

pip install -r requirements.txt

Run the Application

bash

    python gui.py

Password Requirements

To ensure the security of your encrypted messages, the tool requires passwords to meet the following criteria:

    At least 8 characters long.
    Contains at least:
        One lowercase letter.
        One uppercase letter.
        One digit.
        One special character.

Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.
License

MIT