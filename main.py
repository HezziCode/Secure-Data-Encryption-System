import streamlit as st
import hashlib
import os
import json
import time
from cryptography.fernet import Fernet
import base64
from hashlib import pbkdf2_hmac
from base64 import urlsafe_b64encode


def main():
    print("Hello")

DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# login section details
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 1000000).hex()

# using cryptography fernet 
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

stored_data = load_data()

# Navigation bar!!! streamlit work now
st.set_page_config(page_title="🔐 Secure Data Storage", page_icon="🔒", layout="wide")
st.title("🔐 Secure Data Encryption System")
menu = ["🏠 Home", "📝 Register", "🔓 Login", "📥 Store Data", "📤 Retrieve Data"]
choice = st.sidebar.selectbox("🚀 Navigation", menu)

if choice == "🏠 Home":
    st.subheader("👋 Welcome to the 🔐 Secure Data Encryption System")
    st.markdown("This system allows you to **securely store** and **retrieve sensitive data** using encryption techniques and password hashing for added 🔐 **security** and 🛡️ **privacy protection** against unauthorized access and data breaches.")

elif choice == "📝 Register":  
    st.subheader("🆕 ✏ Please register or log in to continue.")
    username = st.text_input("👤 Choose Username")
    password = st.text_input("🔑 Choose Password", type="password")

    if st.button("✅ Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists. Please choose a different one.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("🎉 User registered successfully. You can now log in.")
    else:
        st.info("ℹ️ Please enter a username and password.")

elif choice == "🔓 Login":
    st.subheader("🔑 Please log in to access your data.")

    username = st.text_input("👤 Username")
    password = st.text_input("🔒 Password", type="password")

    if time.time() < st.session_state.lockout_time:
        remaining_time = st.session_state.lockout_time - time.time()
        st.warning(f"⌛ You are locked out. Please wait {int(remaining_time)} seconds.")
        st.stop()

    if st.button("🔓 Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome back, {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. You have {remaining} attempts left.")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🚫 Too many failed attempts. You are locked out for 60 seconds.")
                st.stop()

#  Store Data
elif choice == "📥 Store Data":
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please log in to store data.")
    else:
        st.subheader("🔐 Store Encrypted Data")
        data = st.text_input("📝 Enter data to store")
        passkey = st.text_input("🗝️ Encryption key (passphrase)", type="password")

        if st.button("💾 Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted) 
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully.")
            else:
                st.error("⚠️ Please enter data and a passphrase.")

# Retrieve Data Section
elif choice == "📤 Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please log in to retrieve data.")
    else:
        st.subheader("📂 Retrieve Your Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No data found for the logged-in user.")
        else:
            st.write("🔒 Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypt_input = st.text_area("🔐 Enter Encrypted Text")
            passkey = st.text_input("🗝️ Decryption key (passphrase)", type="password") 

            if st.button("🔓 Decrypt"):
                result = decrypt_text(encrypt_input, passkey)
                if result:
                    st.success(f"✅ Decrypted Data: {result}")
                else:
                    st.error("❌ Failed to decrypt the data. Please check your passphrase.")

if __name__ == "__main__":
    main()
