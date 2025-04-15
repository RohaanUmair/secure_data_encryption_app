import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json, base64
from datetime import datetime

# Constants
PASSWORD = "my_super_secure_password_123!@#"
KEY = base64.urlsafe_b64encode(hashlib.sha256(PASSWORD.encode()).digest()[:32])
cipher = Fernet(KEY)

# Initialize session state
if 'stored_data' not in st.session_state:
    st.session_state.update({
        'stored_data': {},
        'user_credentials': {},
        'login_attempts': 0,
        'decrypt_attempts': 0,
        'current_user': None,
        'authenticated': False
    })

# Helper functions
def hash(text): return hashlib.sha256(text.encode()).hexdigest()
def encrypt(text): return cipher.encrypt(text.encode()).decode()
def decrypt(text):
    try: return cipher.decrypt(text.encode()).decode()
    except: st.error("❌ Decryption failed"); return None

def save_data():
    json.dump(st.session_state.stored_data, open('encrypted_data.json', 'w'))
    json.dump(st.session_state.user_credentials, open('user_credentials.json', 'w'))

def load_data():
    for f, k in [('encrypted_data.json', 'stored_data'), ('user_credentials.json', 'user_credentials')]:
        try: st.session_state[k] = json.load(open(f))
        except: st.session_state[k] = {}

load_data()

# Auth pages
def login_page():
    st.subheader("🔑 Login")
    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")
    
    if st.button("Login") and user and pwd:
        if user in st.session_state.user_credentials:
            if st.session_state.user_credentials[user] == hash(pwd):
                st.session_state.update(current_user=user, authenticated=True, login_attempts=0, decrypt_attempts=0)
                st.success("✅ Login successful!"); st.rerun()
            else:
                st.session_state.login_attempts += 1
                if st.session_state.login_attempts >= 3:
                    st.session_state.update(authenticated=False, current_user=None)
                    st.warning("🔒 Too many attempts!"); st.rerun()
                st.error(f"❌ Wrong password! {3-st.session_state.login_attempts} tries left")
        else: st.error("❌ Username not found")

def register_page():
    st.subheader("📝 Register")
    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")
    conf = st.text_input("Confirm", type="password")
    
    if st.button("Register") and user and pwd and conf:
        if pwd != conf: st.error("⚠️ Passwords don't match")
        elif user in st.session_state.user_credentials: st.error("❌ Username taken")
        else:
            st.session_state.user_credentials[user] = hash(pwd)
            save_data()
            st.success("✅ Registered! Please login")

# Main pages
def home_page():
    st.subheader(f"🏠 Welcome {st.session_state.current_user}")
    st.write("### Features:", "- 🔐 Encryption\n- 🔑 Passkey protection\n- 🛡️ Auto logout\n- 💾 Secure storage")

def store_page():
    st.subheader("📂 Store Data")
    data = st.text_area("Data")
    passkey = st.text_input("Passkey", type="password")
    conf = st.text_input("Confirm", type="password")
    name = st.text_input("Name (optional)") or f"data_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    if st.button("Save") and data and passkey and conf:
        if passkey != conf: st.error("⚠️ Passkeys don't match")
        else:
            if st.session_state.current_user not in st.session_state.stored_data:
                st.session_state.stored_data[st.session_state.current_user] = {}
            
            st.session_state.stored_data[st.session_state.current_user][name] = {
                "encrypted_text": encrypt(data),
                "passkey_hash": hash(passkey),
                "timestamp": str(datetime.now())
            }
            save_data()
            st.success(f"✅ Saved as: {name}")

def retrieve_page():
    st.subheader("🔍 Retrieve Data")
    if st.session_state.current_user not in st.session_state.stored_data or not st.session_state.stored_data[st.session_state.current_user]:
        return st.warning("No data available")
    
    selected = st.selectbox("Select", list(st.session_state.stored_data[st.session_state.current_user].keys()))
    enc = st.session_state.stored_data[st.session_state.current_user][selected]["encrypted_text"]
    st.text_area("Encrypted", enc, disabled=True)
    passkey = st.text_input("Passkey", type="password", key="retrieve")
    
    if st.button("Decrypt") and passkey:
        if st.session_state.decrypt_attempts >= 3:
            st.session_state.update(authenticated=False, current_user=None)
            st.warning("🔒 Too many attempts!"); st.rerun()
        
        if hash(passkey) == st.session_state.stored_data[st.session_state.current_user][selected]["passkey_hash"]:
            if dec := decrypt(enc): 
                st.text_area("Decrypted", dec)
                st.session_state.decrypt_attempts = 0
        else:
            st.session_state.decrypt_attempts += 1
            st.error(f"❌ Wrong passkey! {3-st.session_state.decrypt_attempts} tries left")
            if st.session_state.decrypt_attempts >= 3:
                st.session_state.update(authenticated=False, current_user=None)
                st.warning("🔒 Too many attempts!"); st.rerun()

# App flow
st.title("🔒 Secure Data System")

if not st.session_state.authenticated:
    if st.sidebar.radio("Menu", ["Login", "Register"]) == "Login": login_page()
    else: register_page()
    st.stop()

st.title(f"Welcome {st.session_state.current_user}!")
choice = st.sidebar.selectbox("Navigation", ["Home", "Store Data", "Retrieve Data", "Logout"])

if choice == "Home": home_page()
elif choice == "Store Data": store_page()
elif choice == "Retrieve Data": retrieve_page()
elif choice == "Logout":
    st.session_state.update(authenticated=False, current_user=None)
    st.success("✅ Logged out!"); st.rerun()