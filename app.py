import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import time
import base64
from datetime import datetime, timedelta

# --- Constants and Configuration ---
# For production, store this key securely outside source code
ENCRYPTION_PASSWORD = "my_super_secure_password_123!@#"  # Change this!

# --- Key Generation ---
def get_fernet_key():
    """Generate consistent Fernet key from password"""
    key = hashlib.sha256(ENCRYPTION_PASSWORD.encode()).digest()
    return base64.urlsafe_b64encode(key[:32])

# Initialize encryption system
KEY = get_fernet_key()
cipher = Fernet(KEY)

# --- Session State Initialization ---
def init_session_state():
    if 'stored_data' not in st.session_state:
        st.session_state.stored_data = {}

    if 'user_credentials' not in st.session_state:
        st.session_state.user_credentials = {}

    if 'failed_attempts' not in st.session_state:
        st.session_state.failed_attempts = 0

    if 'locked_out' not in st.session_state:
        st.session_state.locked_out = False

    if 'lockout_time' not in st.session_state:
        st.session_state.lockout_time = None

    if 'current_user' not in st.session_state:
        st.session_state.current_user = None

    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False

init_session_state()

# --- Security Functions ---
def hash_input(input_str):
    """Hash input string using SHA-256"""
    return hashlib.sha256(input_str.encode()).hexdigest()

def encrypt_data(text):
    """Encrypt text using Fernet encryption"""
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    """Decrypt text using Fernet encryption with error handling"""
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        st.error(f"❌ Decryption failed: {str(e)}")
        return None

# --- Data Persistence ---
def save_data():
    """Save all data to JSON files"""
    with open('encrypted_data.json', 'w') as f:
        json.dump(st.session_state.stored_data, f)
    with open('user_credentials.json', 'w') as f:
        json.dump(st.session_state.user_credentials, f)

def load_data():
    """Load data from JSON files"""
    try:
        with open('encrypted_data.json', 'r') as f:
            st.session_state.stored_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        st.session_state.stored_data = {}
    
    try:
        with open('user_credentials.json', 'r') as f:
            st.session_state.user_credentials = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        st.session_state.user_credentials = {}

# Load data at startup
load_data()

# --- Authentication Checks ---
def check_lockout():
    """Check if user is locked out and handle accordingly"""
    if st.session_state.locked_out and st.session_state.lockout_time:
        remaining_time = (st.session_state.lockout_time - datetime.now()).total_seconds()
        if remaining_time > 0:
            st.error(f"🔒 Account locked. Please try again in {int(remaining_time)} seconds.")
            st.stop()
        else:
            st.session_state.locked_out = False
            st.session_state.lockout_time = None
            st.session_state.failed_attempts = 0

check_lockout()

# --- Authentication Pages ---
def show_login_page():
    """Display login page"""
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if username and password:
            if username in st.session_state.user_credentials:
                hashed_password = hash_input(password)
                if st.session_state.user_credentials[username] == hashed_password:
                    st.session_state.current_user = username
                    st.session_state.authenticated = True
                    st.session_state.failed_attempts = 0
                    st.success("✅ Login successful!")
                    time.sleep(1)
                    st.rerun()
                else:
                    handle_failed_attempt()
            else:
                st.error("❌ Username not found!")
        else:
            st.error("⚠️ Both fields are required!")

def show_register_page():
    """Display registration page"""
    st.subheader("📝 Register New Account")
    new_username = st.text_input("Choose a username")
    new_password = st.text_input("Choose a password", type="password")
    confirm_password = st.text_input("Confirm password", type="password")
    
    if st.button("Register"):
        if new_username and new_password and confirm_password:
            if new_password == confirm_password:
                if new_username not in st.session_state.user_credentials:
                    hashed_password = hash_input(new_password)
                    st.session_state.user_credentials[new_username] = hashed_password
                    save_data()
                    st.success("✅ Registration successful! Please login.")
                else:
                    st.error("❌ Username already exists!")
            else:
                st.error("⚠️ Passwords do not match!")
        else:
            st.error("⚠️ All fields are required!")

def handle_failed_attempt():
    """Handle failed login attempts and lockout logic"""
    st.session_state.failed_attempts += 1
    attempts_remaining = 3 - st.session_state.failed_attempts
    st.error(f"❌ Incorrect password! Attempts remaining: {attempts_remaining}")
    
    if st.session_state.failed_attempts >= 3:
        st.session_state.locked_out = True
        st.session_state.lockout_time = datetime.now() + timedelta(minutes=5)
        st.warning("🔒 Too many failed attempts! Account locked for 5 minutes.")
        time.sleep(1)
        st.rerun()

# --- Main Application Pages ---
def show_home_page():
    """Display home page"""
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write(f"Hello {st.session_state.current_user}! Use this app to securely store and retrieve data.")
    st.write("### Features:")
    st.write("- 🔐 Secure encryption using Fernet (AES-128)")
    st.write("- 🔑 Passkey hashing with SHA-256")
    st.write("- 🛡️ Account lockout after 3 failed attempts")
    st.write("- 💾 Data persistence with JSON storage")

def show_store_data_page():
    """Display data storage page"""
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")
    data_name = st.text_input("Give this data a name (optional):")

    if st.button("Encrypt & Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("⚠️ Passkeys do not match!")
            else:
                hashed_passkey = hash_input(passkey)
                encrypted_text = encrypt_data(user_data)
                
                if not data_name:
                    data_name = f"data_{int(time.time())}"
                
                if st.session_state.current_user not in st.session_state.stored_data:
                    st.session_state.stored_data[st.session_state.current_user] = {}
                
                st.session_state.stored_data[st.session_state.current_user][data_name] = {
                    "encrypted_text": encrypted_text, 
                    "passkey_hash": hashed_passkey,
                    "timestamp": str(datetime.now())
                }
                save_data()
                st.success("✅ Data stored securely!")
                st.info(f"Data reference name: {data_name}")
        else:
            st.error("⚠️ All fields are required!")

def show_retrieve_data_page():
    """Display data retrieval page"""
    st.subheader("🔍 Retrieve Your Data")
    
    if st.session_state.current_user in st.session_state.stored_data and st.session_state.stored_data[st.session_state.current_user]:
        data_options = list(st.session_state.stored_data[st.session_state.current_user].keys())
        selected_data = st.selectbox("Select data to retrieve:", data_options)
        
        encrypted_text = st.session_state.stored_data[st.session_state.current_user][selected_data]["encrypted_text"]
        st.text_area("Encrypted Data (read-only):", encrypted_text, disabled=True)
    else:
        st.warning("No data available to retrieve.")
        selected_data = None
        encrypted_text = None
    
    passkey = st.text_input("Enter Passkey:", type="password", key="retrieve_passkey")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            if st.session_state.failed_attempts >= 3:
                st.session_state.locked_out = True
                st.session_state.lockout_time = datetime.now() + timedelta(minutes=5)
                st.warning("🔒 Too many failed attempts! Account locked for 5 minutes.")
                st.rerun()
            
            stored_hash = st.session_state.stored_data[st.session_state.current_user][selected_data]["passkey_hash"]
            input_hash = hash_input(passkey)
            
            if stored_hash == input_hash:
                decrypted_text = decrypt_data(encrypted_text)
                if decrypted_text:
                    st.session_state.failed_attempts = 0
                    st.success("✅ Decryption successful!")
                    st.text_area("Decrypted Data:", decrypted_text)
            else:
                st.session_state.failed_attempts += 1
                attempts_remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.locked_out = True
                    st.session_state.lockout_time = datetime.now() + timedelta(minutes=5)
                    st.warning("🔒 Too many failed attempts! Account locked for 5 minutes.")
                    st.rerun()
        else:
            st.error("⚠️ Both fields are required!")

def logout():
    """Handle logout process"""
    st.session_state.authenticated = False
    st.session_state.current_user = None
    st.success("✅ Logged out successfully!")
    time.sleep(1)
    st.rerun()

# --- Main Application Flow ---
st.title("🔒 Secure Data Encryption System")

# Show authentication pages if not logged in
if not st.session_state.authenticated:
    auth_option = st.sidebar.radio("Authentication", ["Login", "Register"])
    if auth_option == "Login":
        show_login_page()
    else:
        show_register_page()
    st.stop()

# Main app navigation for authenticated users
st.title(f"Welcome {st.session_state.current_user}!")
menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    show_home_page()
elif choice == "Store Data":
    show_store_data_page()
elif choice == "Retrieve Data":
    show_retrieve_data_page()
elif choice == "Logout":
    logout()