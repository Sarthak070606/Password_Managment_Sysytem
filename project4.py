import streamlit as st
import mysql.connector  
import bcrypt
import base64
import secrets
import string 
import pandas as pd 
import numpy as np
import re
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC    
from streamlit.runtime.scriptrunner import RerunException
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def setup_database():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="1234",
        database="vault_db"
    )
    Database = conn.cursor()
    Database.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            username VARCHAR(100) UNIQUE NOT NULL,
            master_key VARCHAR(255) NOT NULL,
            salt VARBINARY(16) NOT NULL
        )
    """)
    Database.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INT PRIMARY KEY AUTO_INCREMENT,
            user_id INT NOT NULL,
            website VARCHAR(255),
            username VARCHAR(255),
            secret_password TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    return conn, Database

def secure_password(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())

def check_password(pw, hashed):
    if isinstance(hashed, str):
        hashed = hashed.encode()
    return bcrypt.checkpw(pw.encode(), hashed)

def create_key(pw, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(pw.encode()))
    return Fernet(key)

def lock_password(pw, cipher):
    return cipher.encrypt(pw.encode()).decode()

def unlock_password(enc, cipher):
    try:
        return cipher.decrypt(enc.encode()).decode()
    except:
        return "Cannot open"
#
def make_random_passwrod(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))
                                #
def check_master_powd(pw):
    if not pw:
        return False, "Cannot be empty"
    if not pw[0].isupper():
        return False, "First letter must be big"
    if len(re.findall(r"[0-9]", pw)) < 3:
        return False, "Need at least 3 numbers"
    if not re.search(r"[!@#$%^&*(),.?{}]", pw):
        return False, "Need 1 special char"
    return True, ""

def rerun():
    raise RerunException(None)

def get_user(cur, name):
    cur.execute("SELECT id, master_key, salt FROM users WHERE username=%s", (name,))
    return cur.fetchone()

def save_user(cur, conn, name, hashed, salt):
    cur.execute("INSERT INTO users (username, master_key, salt) VALUES (%s,%s,%s)", (name, hashed.decode(), salt))
    conn.commit()

def save_password(cur, conn, uid, site, login, enc):
    cur.execute("INSERT INTO passwords (user_id, website, username, secret_password) VALUES (%s,%s,%s,%s)", (uid, site, login, enc))
    conn.commit()

def delete_password(cur, conn, pid):
    cur.execute("DELETE FROM passwords WHERE id=%s", (pid,))
    conn.commit()
   
def main():
    
    st.set_page_config(page_title="Easy Password Keeper", page_icon="imp.png", layout="centered")
    st.title("🔒 Easy Password Keeper")

    if 'logged' not in st.session_state:
        st.session_state.logged = False
    if 'uid' not in st.session_state:
        st.session_state.uid = None
    if 'cipher' not in st.session_state:
        st.session_state.cipher = None
    if 'site_in' not in st.session_state:
        st.session_state.site_in = ""
    if 'login_in' not in st.session_state:
        st.session_state.login_in = ""
    if 'pass_in' not in st.session_state:
        st.session_state.pass_in = ""

    conn, cur = setup_database()

    if not st.session_state.logged:
        st.subheader("Login or Make Account")
        user_name = st.text_input("Your name")
        master_pw = st.text_input("Secret Key", type="password")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Login"):
                user = get_user(cur, user_name)
                if user and check_password(master_pw, user[1]):
                    st.session_state.logged = True
                    st.session_state.uid = user[0]
                    st.session_state.cipher = create_key(master_pw, user[2])
                    st.session_state.site_in = ""
                    st.session_state.login_in = ""
                    st.session_state.pass_in = ""
                    st.success("Yay! You are in!")
                else:
                    st.error("Wrong name or key!")
        with col2:
            if st.button("Register"):
                if user_name and master_pw:
                    valid, msg = check_master_powd(master_pw)
                    if valid:
                        salt = secrets.token_bytes(16)
                        hashed = secure_password(master_pw)
                        try:
                            save_user(cur, conn, user_name, hashed, salt)
                            st.success("You are Successfully Registered.")
                        except:
                            st.error("Name already stored or Registered!")
                    else:
                        st.error(msg)
    else:
        st.subheader("Your Secret Locker to store the Passwords")

        if st.button("Logout"):
            for key in ["logged","uid","cipher","site_in","login_in","pass_in"]:
                if key in st.session_state:
                    del st.session_state[key]
            st.success("Bye gise Logged out SuccessFully")
            rerun()
####
        tab1, tab2, tab3 = st.tabs(["See Saved Passwor", "Add Secret Passwords", "Generate Random Password"])

        with tab1:
            st.write("Your saved secrets")###
            search = st.text_input("Look for ypur site or usernme")
            cur.execute("SELECT id, website, username, secret_password FROM passwords WHERE user_id=%s", (st.session_state.uid,))
            items = cur.fetchall()

            for item in items:
                pid, site, login_name, enc_pw = item
                if search.lower() in site.lower() or search.lower() in login_name.lower() or not search:
                    real_pw = unlock_password(enc_pw, st.session_state.cipher)
                    with st.expander(f"{site} - {login_name}"):
                        st.code(real_pw)
                        c1, c2 = st.columns(2)
                        with c1:
                            if st.button("Copy", key=f"c_{pid}"):
                                st.experimental_set_query_params(pwd=real_pw)
                                st.info("Copied!")
                        with c2:
                            if st.button("Delete", key=f"d_{pid}"):
                                delete_password(cur, conn, pid)
                                st.success(f"{site} deleted")
                                rerun()

        with tab2:
            st.write("Add New Secret Passwords")
            site = st.text_input("Website", value=st.session_state.site_in)
            login_name = st.text_input("Username", type='default',  value=st.session_state.login_in)
            pw = st.text_input("Password", type="password", value=st.session_state.pass_in)

            st.session_state.site_in = site
            st.session_state.login_in = login_name
            st.session_state.pass_in = pw

            if st.button("Save"):
                if site and login_name and pw:
                    enc_pw = lock_password(pw, st.session_state.cipher)
                    save_password(cur, conn, st.session_state.uid, site, login_name, enc_pw)
                    st.success("Saved Secret Passwods!")
                    st.session_state.site_in = ""
                    st.session_state.login_in = ""
                    st.session_state.pass_in = ""
                else:
                    st.error("Fill all the blocks details!")

        with tab3:
            st.write("Make a Strong Password")
            length = st.slider("Select the lenght ", 8, 32, 12)
            if st.button("Make"):
                new_pw = make_random_passwrod(length)
                st.code(new_pw)
                st.info("Copy it and save in Add Secret Passwords ")

    st.markdown("---")
    st.markdown("<p style='text-align:center; color:purple; font-size:25px;'>Made by Sarthak Jain</p>", unsafe_allow_html=True)
    conn.close()

if __name__ == "__main__":
    main()
