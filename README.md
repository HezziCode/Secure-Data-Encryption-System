****Secure Data Encryption System****

A web application built using Streamlit that allows users to securely store and retrieve sensitive data using encryption and password hashing. This system uses Fernet encryption from the cryptography package for data security and ensures privacy protection.

Features
User Registration & Login: Users can register and log in using a secure password.

Encrypted Data Storage: Store sensitive data that is encrypted using a passphrase.

Data Retrieval: Retrieve encrypted data by entering the correct decryption passphrase.

Security Measures: Includes features like password hashing, lockout after multiple failed login attempts, and encrypted data storage.

Installation
To run the project locally, follow these steps:

Prerequisites
Python 3.x

Virtual environment (recommended)

Steps to Install
Clone the repository:

bash
Copy
Edit
git clone <repository_url>
cd Secure-Data-Encryption-System
Create a virtual environment (optional but recommended):

bash
Copy
Edit
python -m venv venv
Activate the virtual environment:

For Windows (CMD):

bash
Copy
Edit
.\venv\Scripts\activate
For macOS/Linux:

bash
Copy
Edit
source venv/bin/activate
Install the required dependencies:

bash
Copy
Edit
pip install -r requirements.txt
Dependencies
streamlit

cryptography

Running the Application
After installing the dependencies, run the following command to start the Streamlit app:

bash
Copy
Edit
streamlit run main.py
The app will launch in your default web browser. You can register, log in, store encrypted data, and retrieve it using the provided encryption passphrase.

Features
User Registration
Create a username and a password.

Passwords are hashed using pbkdf2_hmac for security.

Data Storage
Users can store sensitive data, which is encrypted with a passphrase using Fernet.

The encrypted data is saved to a JSON file.

Data Retrieval
Users can retrieve their encrypted data by entering the correct decryption passphrase.

The app will decrypt and display the data if the passphrase matches.

Login Security
After 3 failed login attempts, the user is locked out for 60 seconds to prevent brute-force attacks.

File Structure
pgsql
Copy
Edit
.
├── main.py               # Main application script
├── requirements.txt      # Required Python packages
├── secure_data.json      # Data file to store encrypted data
└── README.md             # Project documentation (this file)
Security Considerations
Password Hashing: User passwords are securely hashed before being stored.

Encryption: All sensitive data is encrypted before being stored to ensure privacy.

Session Management: The app tracks failed login attempts and implements a temporary lockout mechanism.

Contributing
Feel free to fork this repository and submit pull requests. If you encounter any bugs or have suggestions for improvements, open an issue.

License
This project is licensed under the MIT License - see the LICENSE file for details.
