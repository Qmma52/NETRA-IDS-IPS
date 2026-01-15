# services/auth.py
from __future__ import annotations
import streamlit as st

USERS = {
    "admin": {"role": "admin", "password": "admin123"},
    "viewer": {"role": "viewer", "password": "viewer123"},
}

AUTH_KEY = "ids_auth_v1"


def require_login():
    if AUTH_KEY not in st.session_state:
        st.session_state[AUTH_KEY] = None

    auth = st.session_state[AUTH_KEY]
    if auth:
        return auth

    st.sidebar.subheader("🔐 Login")
    u = st.sidebar.text_input("Username", key="login_user")
    p = st.sidebar.text_input("Password", type="password", key="login_pass")
    btn = st.sidebar.button("Login", use_container_width=True)

    if btn:
        if u in USERS and USERS[u]["password"] == p:
            st.session_state[AUTH_KEY] = {"username": u, "role": USERS[u]["role"]}
            st.rerun()
        else:
            st.sidebar.error("Invalid credentials")

    st.stop()


def logout_button():
    auth = st.session_state.get(AUTH_KEY)
    if auth:
        st.sidebar.caption(f"Logged in as: **{auth.get('username')}** ({auth.get('role')})")
        if st.sidebar.button("Logout", use_container_width=True):
            st.session_state[AUTH_KEY] = None
            st.rerun()


def is_admin() -> bool:
    auth = st.session_state.get(AUTH_KEY) or {}
    return (auth.get("role") == "admin")
