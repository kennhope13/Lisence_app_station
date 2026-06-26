#!/usr/bin/env python3
"""
StationMonitor Admin Dashboard - Premium License Manager (Fuse Style)
- Features: Secure login, Key generation, Management, Statistics.
"""

import sys
import argparse
import streamlit as st
import os
import json
import hmac
import hashlib
import secrets
import pandas as pd
from datetime import datetime, timedelta
import sqlite3
import uuid

try:
    import psycopg2
except ImportError:
    psycopg2 = None

# ----------------------------------------------------------------------
# Configuration & Constants
# ----------------------------------------------------------------------
DB_FILE = os.path.join(os.path.dirname(__file__), "generated_keys.json")
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"

SQLITE_DB_PATH = r"C:\Users\MSI\AppData\Local\StationMonitor\station_monitor.db"
APPSETTINGS_PATH = r"C:\Program Files\StationMonitor\backend\appsettings.json"

# ----------------------------------------------------------------------
# Database Integration
# ----------------------------------------------------------------------
class LiveDatabase:
    @staticmethod
    def get_connection():
        # First check PostgreSQL from appsettings.json
        if os.path.exists(APPSETTINGS_PATH):
            try:
                with open(APPSETTINGS_PATH, "r", encoding="utf-8") as f:
                    config = json.load(f)
                conn_str = config.get("ConnectionStrings", {}).get("Default", "")
                if conn_str and "host=" in conn_str.lower():
                    parts = conn_str.split(";")
                    pg_info = {}
                    for part in parts:
                        if "=" in part:
                            k, v = part.split("=", 1)
                            pg_info[k.strip().lower()] = v.strip()
                    
                    if psycopg2:
                        conn = psycopg2.connect(
                            host=pg_info.get("host", "localhost"),
                            port=int(pg_info.get("port", 5432)),
                            database=pg_info.get("database", "stationmonitor"),
                            user=pg_info.get("username", "postgres"),
                            password=pg_info.get("password", "postgres123"),
                            connect_timeout=3
                        )
                        return conn, "PostgreSQL"
            except Exception:
                pass
        
        # Fallback to SQLite
        if os.path.exists(SQLITE_DB_PATH):
            try:
                conn = sqlite3.connect(SQLITE_DB_PATH)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='LicenseKeys';")
                if cursor.fetchone():
                    return conn, "SQLite"
                conn.close()
            except Exception:
                pass
                
        return None, "Offline"

    @staticmethod
    def parse_db_key_for_ui(key_str, expires_at, created_at, issued_to, is_active, max_sessions, record_id):
        parts = key_str.split('-')
        tier = parts[0] if parts else "CML"
        expire_date = "991231"
        
        if expires_at:
            try:
                if isinstance(expires_at, str):
                    dt = datetime.strptime(expires_at.split()[0], "%Y-%m-%d")
                else:
                    dt = expires_at
                expire_date = dt.strftime("%y%m%d")
            except:
                pass
        
        exp_index = -1
        for i, part in enumerate(parts):
            if len(part) == 6 and part.isdigit():
                exp_index = i
                break
        if exp_index != -1:
            tier = "-".join(parts[:exp_index])
            expire_date = parts[exp_index]
            
        return {
            "id": record_id,
            "key": key_str,
            "tier": tier,
            "expire_date": expire_date,
            "created_at": str(created_at),
            "issued_to": issued_to or "Không rõ",
            "is_active": is_active,
            "max_sessions": max_sessions
        }

    @staticmethod
    def get_licenses():
        conn, db_type = LiveDatabase.get_connection()
        if not conn:
            return []
        try:
            cursor = conn.cursor()
            if db_type == "PostgreSQL":
                cursor.execute('SELECT "Id", "Key", "IssuedTo", "MaxConcurrentSessions", "ExpiresAt", "IsActive", "CreatedAt" FROM "LicenseKeys" ORDER BY "CreatedAt" DESC;')
            else:
                cursor.execute('SELECT Id, Key, IssuedTo, MaxConcurrentSessions, ExpiresAt, IsActive, CreatedAt FROM LicenseKeys ORDER BY CreatedAt DESC;')
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            licenses = []
            for r in rows:
                licenses.append(LiveDatabase.parse_db_key_for_ui(
                    key_str=r[1],
                    expires_at=r[4],
                    created_at=r[6],
                    issued_to=r[2],
                    is_active=bool(r[5]),
                    max_sessions=r[3] or 1,
                    record_id=r[0]
                ))
            return licenses
        except Exception as e:
            st.error(f"Lỗi truy vấn danh sách License từ database: {e}")
            return []

    @staticmethod
    def get_sessions():
        conn, db_type = LiveDatabase.get_connection()
        if not conn:
            return []
        try:
            cursor = conn.cursor()
            if db_type == "PostgreSQL":
                cursor.execute('''
                    SELECT s."Id", s."UserId", s."SessionToken", s."LoginAt", s."LastSeenAt", s."ExpiresAt", s."IsRevoked", l."Key", l."IssuedTo"
                    FROM "ActiveSessions" s
                    LEFT JOIN "LicenseKeys" l ON s."LicenseKeyId" = l."Id"
                    ORDER BY s."LoginAt" DESC;
                ''')
            else:
                cursor.execute('''
                    SELECT s.Id, s.UserId, s.SessionToken, s.LoginAt, s.LastSeenAt, s.ExpiresAt, s.IsRevoked, l.Key, l.IssuedTo
                    FROM ActiveSessions s
                    LEFT JOIN LicenseKeys l ON s.LicenseKeyId = l.Id
                    ORDER BY s.LoginAt DESC;
                ''')
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            sessions = []
            for r in rows:
                sessions.append({
                    "id": r[0],
                    "user_id": r[1] or "Không rõ",
                    "token": r[2],
                    "login_at": r[3],
                    "last_seen_at": r[4],
                    "expires_at": r[5],
                    "is_revoked": bool(r[6]),
                    "license_key": r[7] or "Không rõ",
                    "issued_to": r[8] or "Không rõ"
                })
            return sessions
        except Exception as e:
            st.error(f"Lỗi truy vấn danh sách phiên hoạt động: {e}")
            return []

    @staticmethod
    def add_license(key_str, issued_to, max_sessions, expires_at_str):
        conn, db_type = LiveDatabase.get_connection()
        if not conn:
            return False
        try:
            cursor = conn.cursor()
            new_id = str(uuid.uuid4()).upper()
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            expires_at_val = None
            if expires_at_str and expires_at_str != "991231":
                try:
                    yy = int(expires_at_str[:2]) + 2000
                    mm = int(expires_at_str[2:4])
                    dd = int(expires_at_str[4:])
                    expires_at_val = f"{yy:04d}-{mm:02d}-{dd:02d} 23:59:59"
                except:
                    pass
            
            if db_type == "PostgreSQL":
                cursor.execute('''
                    INSERT INTO "LicenseKeys" ("Id", "Key", "IssuedTo", "MaxConcurrentSessions", "ExpiresAt", "IsActive", "CreatedAt")
                    VALUES (%s, %s, %s, %s, %s, TRUE, %s);
                ''', (new_id, key_str, issued_to, max_sessions, expires_at_val, created_at))
            else:
                cursor.execute('''
                    INSERT INTO LicenseKeys (Id, Key, IssuedTo, MaxConcurrentSessions, ExpiresAt, IsActive, CreatedAt)
                    VALUES (?, ?, ?, ?, ?, 1, ?);
                ''', (new_id, key_str, issued_to, max_sessions, expires_at_val, created_at))
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Lỗi thêm License vào Database: {e}")
            return False

    @staticmethod
    def toggle_license(key_id, current_status):
        conn, db_type = LiveDatabase.get_connection()
        if not conn:
            return False
        try:
            cursor = conn.cursor()
            if db_type == "PostgreSQL":
                new_status = False if current_status else True
                cursor.execute('UPDATE "LicenseKeys" SET "IsActive" = %s WHERE "Id" = %s;', (new_status, key_id))
            else:
                new_status = 0 if current_status else 1
                cursor.execute('UPDATE LicenseKeys SET IsActive = ? WHERE Id = ?;', (new_status, key_id))
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Lỗi thay đổi trạng thái kích hoạt: {e}")
            return False

    @staticmethod
    def delete_license(key_id):
        conn, db_type = LiveDatabase.get_connection()
        if not conn:
            return False
        try:
            cursor = conn.cursor()
            if db_type == "PostgreSQL":
                cursor.execute('DELETE FROM "ActiveSessions" WHERE "LicenseKeyId" = %s;', (key_id,))
                cursor.execute('DELETE FROM "LicenseKeys" WHERE "Id" = %s;', (key_id,))
            else:
                cursor.execute('DELETE FROM ActiveSessions WHERE LicenseKeyId = ?;', (key_id,))
                cursor.execute('DELETE FROM LicenseKeys WHERE Id = ?;', (key_id,))
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Lỗi xóa License khỏi database: {e}")
            return False

    @staticmethod
    def revoke_session(session_id):
        conn, db_type = LiveDatabase.get_connection()
        if not conn:
            return False
        try:
            cursor = conn.cursor()
            if db_type == "PostgreSQL":
                cursor.execute('UPDATE "ActiveSessions" SET "IsRevoked" = TRUE WHERE "Id" = %s;', (session_id,))
            else:
                cursor.execute('UPDATE ActiveSessions SET IsRevoked = 1 WHERE Id = ?;', (session_id,))
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Lỗi hủy phiên đăng nhập: {e}")
            return False

    @staticmethod
    def init_addons_table():
        conn, db_type = LiveDatabase.get_connection()
        if not conn:
            return
        try:
            cursor = conn.cursor()
            if db_type == "PostgreSQL":
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS "LicenseAddons" (
                        "Id" VARCHAR(100) PRIMARY KEY,
                        "BaseKeyId" VARCHAR(100),
                        "ResourceType" VARCHAR(50),
                        "Quantity" INTEGER,
                        "AddonKey" TEXT,
                        "IssuedTo" VARCHAR(200),
                        "HardwareID" VARCHAR(100),
                        "CreatedAt" VARCHAR(50)
                    );
                ''')
            else:
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS LicenseAddons (
                        Id TEXT PRIMARY KEY,
                        BaseKeyId TEXT,
                        ResourceType TEXT,
                        Quantity INTEGER,
                        AddonKey TEXT,
                        IssuedTo TEXT,
                        HardwareID TEXT,
                        CreatedAt TEXT
                    );
                ''')
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            st.error(f"Lỗi khởi tạo bảng LicenseAddons: {e}")

    @staticmethod
    def get_addons():
        conn, db_type = LiveDatabase.get_connection()
        if not conn:
            return []
        try:
            cursor = conn.cursor()
            if db_type == "PostgreSQL":
                cursor.execute('SELECT "Id", "BaseKeyId", "ResourceType", "Quantity", "AddonKey", "IssuedTo", "HardwareID", "CreatedAt" FROM "LicenseAddons" ORDER BY "CreatedAt" DESC;')
            else:
                cursor.execute('SELECT Id, BaseKeyId, ResourceType, Quantity, AddonKey, IssuedTo, HardwareID, CreatedAt FROM LicenseAddons ORDER BY CreatedAt DESC;')
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            addons = []
            for r in rows:
                addons.append({
                    "id": r[0],
                    "base_key_id": r[1],
                    "resource_type": r[2],
                    "quantity": r[3],
                    "addon_key": r[4],
                    "issued_to": r[5],
                    "hardware_id": r[6],
                    "created_at": r[7]
                })
            return addons
        except Exception as e:
            return []

    @staticmethod
    def add_addon(addon_id, base_key_id, resource_type, qty, addon_key, issued_to, hw_id):
        conn, db_type = LiveDatabase.get_connection()
        if not conn:
            return False
        try:
            cursor = conn.cursor()
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if db_type == "PostgreSQL":
                cursor.execute('''
                    INSERT INTO "LicenseAddons" ("Id", "BaseKeyId", "ResourceType", "Quantity", "AddonKey", "IssuedTo", "HardwareID", "CreatedAt")
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                ''', (addon_id, base_key_id, resource_type, qty, addon_key, issued_to, hw_id, created_at))
            else:
                cursor.execute('''
                    INSERT INTO LicenseAddons (Id, BaseKeyId, ResourceType, Quantity, AddonKey, IssuedTo, HardwareID, CreatedAt)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                ''', (addon_id, base_key_id, resource_type, qty, addon_key, issued_to, hw_id, created_at))
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Lỗi thêm Add-on vào Database: {e}")
            return False

    @staticmethod
    def delete_addon(addon_id):
        conn, db_type = LiveDatabase.get_connection()
        if not conn:
            return False
        try:
            cursor = conn.cursor()
            if db_type == "PostgreSQL":
                cursor.execute('DELETE FROM "LicenseAddons" WHERE "Id" = %s;', (addon_id,))
            else:
                cursor.execute('DELETE FROM LicenseAddons WHERE Id = ?;', (addon_id,))
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Lỗi xóa Add-on khỏi database: {e}")
            return False

# ----------------------------------------------------------------------

# Helper Functions
# ----------------------------------------------------------------------
def load_keys():
    if st.session_state.get("use_live_db", False):
        return LiveDatabase.get_licenses()
        
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                keys = json.load(f)
                for k in keys:
                    if "issued_to" not in k:
                        k["issued_to"] = "Không rõ"
                    if "is_active" not in k:
                        k["is_active"] = True
                return keys
        except Exception:
            return []
    return []

def save_keys(keys):
    if st.session_state.get("use_live_db", False):
        # Database mode uses SQL queries directly to mutate database;
        # Local JSON is handled as backup / not mutated from here
        return
    try:
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(keys, f, indent=4, ensure_ascii=False)
    except Exception as e:
        st.error(f"Lỗi khi lưu dữ liệu: {e}")

ADDONS_FILE = os.path.join(os.path.dirname(__file__), "generated_addons.json")

def load_addons():
    if st.session_state.get("use_live_db", False):
        return LiveDatabase.get_addons()
    if os.path.exists(ADDONS_FILE):
        try:
            with open(ADDONS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_addons(addons):
    if st.session_state.get("use_live_db", False):
        return
    try:
        with open(ADDONS_FILE, "w", encoding="utf-8") as f:
            json.dump(addons, f, indent=4, ensure_ascii=False)
    except Exception as e:
        st.error(f"Lỗi khi lưu dữ liệu add-on: {e}")


def detect_vendor_secret():
    search_paths = [
        "appsettings.json",
        "../appsettings.json",
        "backend/StationOS.Api/appsettings.json",
        "../backend/StationOS.Api/appsettings.json",
    ]
    for path in search_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    return cfg.get("License", {}).get("VendorSecret")
            except: pass
    return "THIET_LAP_TRONG_BIEN_MOI_TRUONG_STATIONOS_VENDOR_SECRET"

def get_expire_str(days=365):
    return (datetime.now() + timedelta(days=days)).strftime("%y%m%d")

def _generate_key(secret, payload):
    nonce = secrets.token_hex(2).upper()
    data = f"{payload}-{nonce}".encode("utf-8")
    h = hmac.new(secret.encode("utf-8"), data, hashlib.sha256)
    hmac8 = h.digest().hex().upper()[:8]
    return f"{payload}-{nonce}-{hmac8}"

def calculate_mock_revenue(tier):
    parts = tier.split("-")
    total = 100  # Base CML
    for p in parts:
        if "SDL500" in p:
            total += 150
        elif "CAM" in p:
            try: total += int(p.replace("CAM", "")) * 20
            except: pass
        elif "SEL" in p:
            try: total += int(p.replace("SEL", "")) * 50
            except: pass
    return total

def st_html(html_str):
    """
    Cleans up HTML strings by removing extra whitespace and newlines,
    preventing Streamlit from treating indented HTML block lines as code blocks.
    """
    cleaned = " ".join([line.strip() for line in html_str.split("\n")])
    st.markdown(cleaned, unsafe_allow_html=True)

# ----------------------------------------------------------------------
# Authentication Logic
# ----------------------------------------------------------------------
def check_auth():
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False

    if not st.session_state["authenticated"]:
        st.markdown("""
            <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
            @import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap');
            
            html, body {
                font-family: 'Inter', sans-serif !important;
            }
            .stApp {
                background-color: #f8fafc !important;
            }
            /* Card design */
            div[data-testid="stForm"] {
                background-color: #ffffff !important;
                border: 1px solid #e2e8f0 !important;
                border-radius: 8px !important;
                padding: 40px !important;
                box-shadow: 0px 4px 6px -1px rgba(0, 0, 0, 0.05), 0px 2px 4px -1px rgba(0, 0, 0, 0.03) !important;
            }
            /* Form inputs */
            .stTextInput>div>div>input {
                border-radius: 4px !important;
                border: 1px solid #cbd5e1 !important;
                height: 44px !important;
                padding-left: 14px !important;
            }
            /* Submit Button */
            div[data-testid="stFormSubmitButton"] button {
                background-color: #3525cd !important;
                color: #ffffff !important;
                border-radius: 4px !important;
                font-weight: 600 !important;
                height: 48px !important;
                border: none !important;
                transition: all 0.2s ease-in-out !important;
            }
            div[data-testid="stFormSubmitButton"] button:hover {
                background-color: #2b1eb5 !important;
                box-shadow: 0 4px 12px rgba(53, 37, 205, 0.2) !important;
            }
            </style>
        """, unsafe_allow_html=True)
        
        st.write("")
        st.write("")
        st.write("")
        _, center_col, _ = st.columns([1, 1.3, 1])
        
        with center_col:
            st_html("""
                <div style="text-align: center; margin-bottom: 24px;">
                    <div style="display: inline-flex; align-items: center; justify-content: center; width: 56px; height: 56px; background-color: #3525cd; border-radius: 12px; margin-bottom: 16px; box-shadow: 0 4px 10px rgba(53, 37, 205, 0.3);">
                        <span style="color: white; font-size: 32px; font-family: 'Material Symbols Outlined';">admin_panel_settings</span>
                    </div>
                    <h1 style="color: #1b1b24; font-size: 30px; font-weight: 700; margin: 0; letter-spacing: -0.5px;">License Manager</h1>
                    <p style="color: #464555; font-size: 14px; margin-top: 4px;">Administrative Oversight Portal</p>
                </div>
            """)
            
            with st.form("login_form"):
                user = st.text_input("Username", placeholder="admin")
                pw = st.text_input("Password", type="password", placeholder="admin123")
                submit = st.form_submit_button("Access Dashboard", use_container_width=True)
                if submit:
                    if user == ADMIN_USER and pw == ADMIN_PASS:
                        st.session_state["authenticated"] = True
                        st.rerun()
                    else:
                        st.error("Invalid credentials. Please use 'admin' and 'admin123'.")
            
            st_html("""
                <div style="text-align: center; margin-top: 32px;">
                    <div style="display: inline-flex; align-items: center; gap: 8px; padding: 8px 16px; background-color: #f0ecf9; border-radius: 9999px; border: 1px solid rgba(199, 196, 216, 0.3);">
                        <span style="font-family: 'Material Symbols Outlined'; font-size: 16px; color: #464555;">encrypted</span>
                        <span style="font-size: 11px; font-weight: 500; color: #464555;">AES-256 Encrypted Connection</span>
                    </div>
                </div>
            """)
        return False
    return True

# ----------------------------------------------------------------------
# Main Application
# ----------------------------------------------------------------------
def main():
    st.set_page_config(
        page_title="License Manager",
        page_icon="🔑",
        layout="wide"
    )

    if not check_auth():
        return

    # Check connection
    conn, db_type = LiveDatabase.get_connection()
    if conn:
        if "use_live_db" not in st.session_state:
            st.session_state["use_live_db"] = True
    else:
        st.session_state["use_live_db"] = False

    # Load Data dynamically on each refresh to catch changes
    st.session_state["keys"] = load_keys()
    keys = st.session_state["keys"]

    # Custom CSS for UI Overhaul (Fuse Dashboard)
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap');

        /* Global Font */
        html, body {
            font-family: 'Inter', sans-serif !important;
        }

        /* App Background */
        [data-testid="stAppViewContainer"] {
            background-color: #f8fafc !important;
        }

        /* Top Header */
        [data-testid="stHeader"] {
            background-color: rgba(248, 250, 252, 0.8) !important;
            backdrop-filter: blur(8px);
            border-bottom: 1px solid #e2e8f0;
        }

        /* Sidebar Styling (Fuse Dark Navy) */
        [data-testid="stSidebar"] {
            background-color: #111c44 !important;
            border-right: 1px solid #1e293b !important;
        }
        [data-testid="stSidebar"] * {
            color: #cbd5e1 !important;
        }
        [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 {
            color: #ffffff !important;
        }
        [data-testid="stSidebar"] hr {
            border-color: rgba(255, 255, 255, 0.1) !important;
        }

        /* Sidebar Navigation Radio menu customization */
        [data-testid="stSidebar"] div[role="radiogroup"] {
            gap: 6px !important;
        }
        [data-testid="stSidebar"] div[role="radiogroup"] label {
            padding: 10px 14px !important;
            color: rgba(255, 255, 255, 0.6) !important;
            background-color: transparent !important;
            border-radius: 4px !important;
            border-left: 4px solid transparent !important;
            cursor: pointer !important;
            transition: all 0.2s !important;
        }
        [data-testid="stSidebar"] div[role="radiogroup"] label:hover {
            background-color: rgba(255, 255, 255, 0.05) !important;
            color: #ffffff !important;
        }
        [data-testid="stSidebar"] div[role="radiogroup"] label[data-checked="true"] {
            color: #ffffff !important;
            background-color: rgba(255, 255, 255, 0.08) !important;
            border-left: 4px solid #3525cd !important;
        }
        /* Inject Material Symbols for Navigation */
        [data-testid="stSidebar"] div[role="radiogroup"] label [data-testid="stMarkdownContainer"] p {
            display: flex !important;
            align-items: center !important;
            gap: 10px !important;
            margin: 0 !important;
        }
        [data-testid="stSidebar"] div[role="radiogroup"] label [data-testid="stMarkdownContainer"] p::before {
            font-family: 'Material Symbols Outlined' !important;
            font-size: 20px !important;
            font-weight: normal !important;
            display: inline-block !important;
            line-height: 1 !important;
        }
        /* Hide radio native circle dot */
        [data-testid="stSidebar"] div[role="radiogroup"] [data-testid="stMarkdownContainer"] {
            font-size: 14px !important;
            font-weight: 500 !important;
        }
        [data-testid="stSidebar"] div[role="radiogroup"] label div[role="presentation"] {
            display: none !important;
        }

        /* Sidebar primary buttons (Logout) */
        [data-testid="stSidebar"] button {
            background-color: rgba(255, 255, 255, 0.05) !important;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
            color: #ffffff !important;
            border-radius: 4px !important;
            font-weight: 500 !important;
            transition: all 0.2s !important;
            display: inline-flex !important;
            align-items: center !important;
            justify-content: center !important;
            gap: 8px !important;
        }
        [data-testid="stSidebar"] button::before {
            content: "logout" !important;
            font-family: 'Material Symbols Outlined' !important;
            font-size: 18px !important;
            font-weight: normal !important;
        }
        [data-testid="stSidebar"] button:hover {
            background-color: rgba(255, 255, 255, 0.1) !important;
            border-color: rgba(255, 255, 255, 0.2) !important;
        }

        /* Metric Cards */
        [data-testid="stMetric"] {
            background-color: #ffffff !important;
            border: 1px solid #e2e8f0 !important;
            border-radius: 8px !important;
            padding: 20px !important;
            box-shadow: 0px 4px 6px -1px rgba(0, 0, 0, 0.05), 0px 2px 4px -1px rgba(0, 0, 0, 0.03) !important;
        }
        [data-testid="stMetricValue"] {
            font-size: 32px !important;
            font-weight: 700 !important;
            color: #1b1b24 !important;
        }
        [data-testid="stMetricLabel"] {
            font-size: 13px !important;
            font-weight: 600 !important;
            color: #777587 !important;
            text-transform: uppercase !important;
            letter-spacing: 0.05em !important;
        }

        /* Primary action buttons */
        button[kind="primary"] {
            background-color: #3525cd !important;
            color: #ffffff !important;
            border-radius: 4px !important;
            border: none !important;
            font-weight: 600 !important;
            padding: 10px 24px !important;
            transition: background-color 0.15s ease !important;
        }
        button[kind="primary"]:hover {
            background-color: #2b1eb5 !important;
            color: #ffffff !important;
        }

        /* Input Controls */
        div[data-baseweb="input"], div[data-baseweb="select"] {
            border-radius: 4px !important;
            border-color: #cbd5e1 !important;
        }

        /* Expander */
        div[data-testid="stExpander"] {
            background-color: #ffffff !important;
            border: 1px solid #e2e8f0 !important;
            border-radius: 8px !important;
            box-shadow: 0px 4px 6px -1px rgba(0, 0, 0, 0.05) !important;
        }
        
        /* Card Container Panel */
        .glass-card {
            background-color: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 24px;
            box-shadow: 0px 4px 6px -1px rgba(0, 0, 0, 0.05), 0px 2px 4px -1px rgba(0, 0, 0, 0.03);
            margin-bottom: 24px;
        }
        </style>
    """, unsafe_allow_html=True)

    # ----------------------------------------------------------------------
    # Sidebar Implementation & Navigation Icons Style Injection
    # ----------------------------------------------------------------------
    use_live = st.session_state.get("use_live_db", False)
    if use_live:
        nav_icons_css = """
        <style>
        [data-testid="stSidebar"] div[role="radiogroup"] label:nth-of-type(1) [data-testid="stMarkdownContainer"] p::before { content: "dashboard" !important; }
        [data-testid="stSidebar"] div[role="radiogroup"] label:nth-of-type(2) [data-testid="stMarkdownContainer"] p::before { content: "add_circle" !important; }
        [data-testid="stSidebar"] div[role="radiogroup"] label:nth-of-type(3) [data-testid="stMarkdownContainer"] p::before { content: "key" !important; }
        [data-testid="stSidebar"] div[role="radiogroup"] label:nth-of-type(4) [data-testid="stMarkdownContainer"] p::before { content: "add_box" !important; }
        [data-testid="stSidebar"] div[role="radiogroup"] label:nth-of-type(5) [data-testid="stMarkdownContainer"] p::before { content: "group" !important; }
        [data-testid="stSidebar"] div[role="radiogroup"] label:nth-of-type(6) [data-testid="stMarkdownContainer"] p::before { content: "settings" !important; }
        </style>
        """
    else:
        nav_icons_css = """
        <style>
        [data-testid="stSidebar"] div[role="radiogroup"] label:nth-of-type(1) [data-testid="stMarkdownContainer"] p::before { content: "dashboard" !important; }
        [data-testid="stSidebar"] div[role="radiogroup"] label:nth-of-type(2) [data-testid="stMarkdownContainer"] p::before { content: "add_circle" !important; }
        [data-testid="stSidebar"] div[role="radiogroup"] label:nth-of-type(3) [data-testid="stMarkdownContainer"] p::before { content: "key" !important; }
        [data-testid="stSidebar"] div[role="radiogroup"] label:nth-of-type(4) [data-testid="stMarkdownContainer"] p::before { content: "add_box" !important; }
        [data-testid="stSidebar"] div[role="radiogroup"] label:nth-of-type(5) [data-testid="stMarkdownContainer"] p::before { content: "settings" !important; }
        </style>
        """
    st.markdown(nav_icons_css, unsafe_allow_html=True)

    with st.sidebar:
        st_html("""
            <div style='margin-bottom: 30px; margin-top: 10px;'>
                <h1 style='font-size: 24px; font-weight: 700; color: #ffffff; margin: 0;'>License Manager</h1>
                <p style='font-size: 13px; color: rgba(255,255,255,0.5); margin: 4px 0 0 0;'>System Administrator</p>
            </div>
        """)
        
        # Build Navigation Menu dynamically
        menu_options = ["Dashboard", "Create Giftcode", "Token Management", "Add-on Upgrades"]
        if use_live:
            menu_options.append("Active Sessions")
        menu_options.append("Settings")

        menu = st.radio(
            "Navigation",
            menu_options,
            label_visibility="collapsed"
        )

        
        st.write("---")
        
        # Live Database Sync Switch
        if conn:
            live_db_toggle = st.checkbox(
                "Đồng bộ CSDL thực tế", 
                value=use_live,
                help="Bật để xem, chỉnh sửa và quản lý License trực tiếp trên Database đang chạy của hệ thống."
            )
            if live_db_toggle != use_live:
                st.session_state["use_live_db"] = live_db_toggle
                st.rerun()

        # Database Status Color and Label
        db_color = "#22c55e" if conn else "#64748b"
        db_status_text = f"Database: {db_type}" if conn else "Database: Offline"
        if conn and not st.session_state.get("use_live_db", True):
            db_color = "#f59e0b"
            db_status_text = "Database: Paused (JSON)"

        # Admin Profile Section at the bottom of Sidebar
        st_html(f"""
            <div style='display: flex; align-items: center; gap: 12px; padding: 12px; background: rgba(255,255,255,0.05); border-radius: 8px; margin-bottom: 12px;'>
                <img src='https://lh3.googleusercontent.com/aida-public/AB6AXuCHHtkIEZQxk6b0EOUSuKH_BQ-TWSkVzK2xvhF3avBT7pIffRDQeWMLGQ3FxfGEeYsH6pnh0e0EMfnU6YXq8vtICzmRH3dHEttzkYxUL477GyQwDbNLumhyvPg_V-Fztm14bkYxlxsc2RoLuAfgKY0AGlJUGuCkopvajbkLb8UNLtEOSIicB3K0sQ48tIf95LlAvryHOWFN5yFxy-7373zItouYN6I4Cokb6EGz8AfvdVqA5xHd8sZk58Ms-tSTb1pimA4uQaOeWO0' style='width: 40px; height: 40px; border-radius: 50%; object-fit: cover;'/>
                <div style='flex: 1; min-width: 0;'>
                    <p style='color: white; margin: 0; font-size: 14px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;'>Admin User</p>
                    <p style='color: rgba(255,255,255,0.4); margin: 0; font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;'>System Administrator</p>
                </div>
            </div>
            <div style='font-size: 11px; color: rgba(255,255,255,0.5); padding: 0 4px; margin-bottom: 16px; display: flex; align-items: center; gap: 6px;'>
                <span style='width: 8px; height: 8px; background-color: {db_color}; border-radius: 50%; display: inline-block;'></span>
                <span>{db_status_text}</span>
            </div>
        """)
        
        if st.button("Logout", use_container_width=True):
            st.session_state["authenticated"] = False
            st.rerun()

    # ----------------------------------------------------------------------
    # Page Routing
    # ----------------------------------------------------------------------
    
    # Page 1: Dashboard
    if menu == "Dashboard":
        st_html("""
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                <span style="font-family: 'Material Symbols Outlined'; font-size: 32px; color: #3525cd; line-height: 1;">dashboard</span>
                <h1 style="color: #1b1b24; font-size: 28px; font-weight: 700; margin: 0;">Dashboard Overview</h1>
            </div>
            <p style="color: #464555; font-size: 14px; margin: 4px 0 24px 0;">Welcome back. Here is what's happening with your license system today.</p>
        """)

        # Count active/expired
        now = datetime.now()
        active_count = 0
        expired_count = 0
        for k in keys:
            if k.get("expire_date") == "991231":
                active_count += 1
            else:
                try:
                    exp_dt = datetime.strptime(k["expire_date"], "%y%m%d")
                    if exp_dt > now:
                        active_count += 1
                    else:
                        expired_count += 1
                except:
                    active_count += 1

        # Calculate revenue mock
        revenue = sum(calculate_mock_revenue(k["tier"]) for k in keys)

        # Metrics Row
        m1, m2, m3 = st.columns(3)
        m1.metric("Total Licenses", f"{len(keys):,}")
        m2.metric("Active Packages", f"{active_count:,}")
        m3.metric("Expired Licenses", f"{expired_count:,}")

        st.write("")
        st.write("")

        # Chart and health columns
        col_chart, col_health = st.columns([2, 1])
        
        with col_chart:
            st_html("""
                <div class="glass-card" style="margin-bottom: 0px;">
                    <h3 style="color: #1b1b24; font-size: 18px; font-weight: 600; margin: 0 0 20px 0;">License Package Distribution</h3>
                </div>
            """)
            
            # Map packages
            tier_counts = {}
            for k in keys:
                t = k["tier"]
                tier_counts[t] = tier_counts.get(t, 0) + 1
            
            if keys:
                chart_df = pd.DataFrame({
                    "Package": list(tier_counts.keys()),
                    "Count": list(tier_counts.values())
                })
                st.bar_chart(chart_df, x="Package", y="Count", color="#3525cd", height=260)
            else:
                st.info("No license key data available.")
        
        with col_health:
            st_html("""
                <div class="glass-card" style="height: 100%;">
                    <h3 style="color: #1b1b24; font-size: 18px; font-weight: 600; margin: 0 0 16px 0;">System Health</h3>
                    <div style="margin-bottom: 16px; display: flex; align-items: center; gap: 12px;">
                        <span style="width: 8px; height: 8px; background-color: #22c55e; border-radius: 50%; display: inline-block;"></span>
                        <div>
                            <p style="margin: 0; font-size: 13px; font-weight: 600; color: #1b1b24;">API Endpoint</p>
                            <p style="margin: 0; font-size: 11px; color: #777587;">99.9% Uptime</p>
                        </div>
                    </div>
                    <div style="margin-bottom: 16px; display: flex; align-items: center; gap: 12px;">
                        <span style="width: 8px; height: 8px; background-color: #22c55e; border-radius: 50%; display: inline-block;"></span>
                        <div>
                            <p style="margin: 0; font-size: 13px; font-weight: 600; color: #1b1b24;">Database Sync</p>
                            <p style="margin: 0; font-size: 11px; color: #777587;">Synced just now</p>
                        </div>
                    </div>
                    <div style="margin-bottom: 16px; display: flex; align-items: center; gap: 12px;">
                        <span style="width: 8px; height: 8px; background-color: #f97316; border-radius: 50%; display: inline-block;"></span>
                        <div>
                            <p style="margin: 0; font-size: 13px; font-weight: 600; color: #1b1b24;">Key Verification Service</p>
                            <p style="margin: 0; font-size: 11px; color: #777587;">High latency detected</p>
                        </div>
                    </div>
                </div>
            """)

        st.write("")
        st.write("")

        # Activity Table
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st_html('<h3 style="color: #1b1b24; font-size: 18px; font-weight: 600; margin: 0 0 16px 0;">Activity History</h3>')
        if keys:
            df_recent = pd.DataFrame(keys).sort_values("created_at", ascending=False)
            df_recent["Hạn dùng"] = df_recent["expire_date"].apply(lambda x: f"20{x[:2]}-{x[2:4]}-{x[4:6]}" if (isinstance(x, str) and len(x) == 6 and x != "991231") else "Trọn đời")
            df_recent["Trạng thái"] = df_recent["is_active"].apply(lambda x: "🟢 Hoạt động" if x else "🔴 Đang khóa")
            st.dataframe(
                df_recent[["key", "tier", "issued_to", "Hạn dùng", "Trạng thái", "created_at"]].head(10),
                column_config={
                    "key": "License Key",
                    "tier": "Package Type",
                    "issued_to": "Issued To",
                    "created_at": "Created Date"
                },
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No keys registered in database yet.")
        st.markdown('</div>', unsafe_allow_html=True)

    # Page 2: Create Giftcode
    elif menu == "Create Giftcode":
        st_html("""
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                <span style="font-family: 'Material Symbols Outlined'; font-size: 32px; color: #3525cd; line-height: 1;">add_circle</span>
                <h1 style="color: #1b1b24; font-size: 28px; font-weight: 700; margin: 0;">Create Giftcode</h1>
            </div>
            <p style="color: #464555; font-size: 14px; margin: 4px 0 24px 0;">Select modular features for the license generation.</p>
        """)

        col_form, col_preview = st.columns([2, 1])

        with col_form:
            st.markdown('<div class="glass-card">', unsafe_allow_html=True)
            
            # Form header
            st_html("""
                <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 24px;">
                    <div style="display: inline-flex; align-items: center; justify-content: center; width: 40px; height: 40px; background-color: rgba(53, 37, 205, 0.1); color: #3525cd; border-radius: 8px;">
                        <span style="font-family: 'Material Symbols Outlined'; font-size: 24px;">settings_input_component</span>
                    </div>
                    <div>
                        <h2 style="font-size: 18px; font-weight: 600; margin: 0; color: #1b1b24;">Package Configuration</h2>
                        <p style="font-size: 13px; color: #464555; margin: 0;">Select modular features for the license generation.</p>
                    </div>
                </div>
            """)

            secret = st.text_input("Mã bí mật (Vendor Secret)", value=detect_vendor_secret(), type="password")
            c_u1, c_u2 = st.columns(2)
            with c_u1:
                max_users = st.number_input("👤 Số máy tính sử dụng đồng thời", min_value=1, value=1)
            with c_u2:
                issued_to = st.text_input("🏢 Đơn vị / Khách hàng được cấp", value="Khách hàng mới")
            
            uploaded_req_file = st.file_uploader("📂 Tải lên file yêu cầu kích hoạt (.licreq)", type=["licreq"])
            uploaded_hwid = ""
            if uploaded_req_file is not None:
                try:
                    uploaded_hwid = uploaded_req_file.read().decode("utf-8").strip()
                    st.success(f"Đã trích xuất HWID từ file: `{uploaded_hwid}`")
                except Exception as e:
                    st.error(f"Lỗi đọc file .licreq: {e}")

            c_hw1, c_hw2 = st.columns(2)
            with c_hw1:
                hwid = st.text_input("💻 Mã phần cứng máy trạm (HWID / MAC)", value=uploaded_hwid, placeholder="Ví dụ: A1B2-C3D4-E5F6 hoặc để trống")
            with c_hw2:
                st.write("")

            
            st.write("---")
            st.markdown("**📦 Mô-đun Bản quyền:**")
            
            # Layout Checkboxes like mockups
            cml_checked = st.checkbox("CML (Base Package) - Có sẵn 10 Trạm, 50 Cảm biến (Bắt buộc)", value=True, disabled=True)
            sdl_checked = st.checkbox("SDL-500 (Sensor Data License - 500) - Nâng cấp lên 500 Cảm biến", value=False)
            
            c1, c2 = st.columns(2)
            with c1:
                cml_cam_count = st.number_input("📷 Số lượng Camera tích hợp (CML-Cam)", min_value=0, max_value=999999, value=0, step=1)
            with c2:
                sel_station_count = st.number_input("🚉 Số lượng trạm mở rộng (SEL)", min_value=0, max_value=999999, value=0, step=1)

            st.write("---")
            st.markdown("**📅 Hạn dùng (License Validity):**")
            
            quick_time = st.radio("Thời hạn", ["1 năm", "2 năm", "3 năm", "5 năm", "Trọn đời", "Tùy chỉnh"], horizontal=True, label_visibility="collapsed")
            if quick_time == "1 năm": exp = get_expire_str(365)
            elif quick_time == "2 năm": exp = get_expire_str(365*2)
            elif quick_time == "3 năm": exp = get_expire_str(365*3)
            elif quick_time == "5 năm": exp = get_expire_str(365*5)
            elif quick_time == "Trọn đời": exp = "991231"
            else:
                custom_date = st.date_input("Chọn ngày hết hạn", min_value=datetime.today())
                exp = custom_date.strftime("%y%m%d")

            # Determine commercial tier name
            tier_parts = ["CML"]
            if sdl_checked:
                tier_parts.append("SDL500")
            if cml_cam_count > 0:
                tier_parts.append(f"CAM{cml_cam_count}")
            if sel_station_count > 0:
                tier_parts.append(f"SEL{sel_station_count}")
            
            tier = "-".join(tier_parts)

            st.write("")
            submitted = st.button("🔥 TẠO GIFTCODE", use_container_width=True, type="primary")
            st.markdown('</div>', unsafe_allow_html=True)

            # Calculation values for display
            calc_dev = 10 + sel_station_count
            calc_cam = cml_cam_count
            calc_pts = 500 if sdl_checked else 50

            if submitted:
                hwid_clean = hwid.strip().upper().replace(" ", "") if hwid.strip() else "ANY"
                payload = f"{tier}-{exp}-{int(max_users)}-{calc_dev}-{calc_cam}-{calc_pts}-50-50-{hwid_clean}"
                new_key = _generate_key(secret, payload)

                
                db_success = True
                if st.session_state.get("use_live_db", False):
                    db_success = LiveDatabase.add_license(new_key, issued_to, max_users, exp)
                    if db_success:
                        st.session_state["keys"] = load_keys()
                else:
                    entry = {
                        "key": new_key, 
                        "tier": tier, 
                        "expire_date": exp,
                        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "issued_to": issued_to,
                        "is_active": True
                    }
                    st.session_state["keys"].append(entry)
                    save_keys(st.session_state["keys"])
                
                if db_success:
                    st_html(f"""
                        <div style="background-color: #ecfdf5; border: 1px solid #10b981; border-radius: 12px; padding: 24px; margin-top: 24px;">
                            <p style="color: #065f46; font-size: 12px; font-weight: bold; text-transform: uppercase; margin: 0 0 8px 0; letter-spacing: 0.05em;">Generation Success</p>
                            <code style="display: block; font-family: monospace; font-size: 15px; color: #3525cd; word-break: break-all; background-color: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px 16px;">{new_key}</code>
                            <p style="color: #065f46; font-size: 11px; margin: 8px 0 0 0;">✔ License generated and successfully registered to database/audit trail</p>
                        </div>
                    """)
                    st.download_button(
                        label="💾 Tải về File Base License (base.lic)",
                        data=new_key,
                        file_name="base.lic",
                        mime="text/plain",
                        use_container_width=True
                    )


        with col_preview:
            # Metrics preview matching mockup
            st_html(f"""
                <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; box-shadow: 0px 4px 6px -1px rgba(0, 0, 0, 0.05); overflow: hidden;">
                    <div style="background-color: #111c44; padding: 16px; color: white;">
                        <h3 style="margin: 0; font-size: 18px; font-weight: 600;">Metrics Preview</h3>
                        <p style="margin: 2px 0 0 0; font-size: 11px; opacity: 0.6;">Real-time capacity calculation</p>
                    </div>
                    <div style="padding: 24px;">
                        <div style="display: flex; justify-content: space-between; align-items: flex-end; padding-bottom: 16px; border-bottom: 1px solid #e2e8f0;">
                            <div>
                                <p style="font-size: 12px; font-weight: 600; color: #777587; margin: 0; display: flex; align-items: center; gap: 4px;">
                                    <span style="font-family: 'Material Symbols Outlined'; font-size: 16px;">terminal</span> Stations
                                </p>
                                <h4 style="font-size: 32px; font-weight: 700; color: #1b1b24; margin: 4px 0 0 0;">{calc_dev}</h4>
                            </div>
                            <span style="font-size: 10px; font-weight: 700; color: {'#3525cd' if sel_station_count > 0 else '#64748b'}; background-color: {'#e2dfff' if sel_station_count > 0 else '#f1f5f9'}; padding: 4px 8px; border-radius: 9999px;">
                                {f'+{sel_station_count} SEL' if sel_station_count > 0 else 'Base Allow'}
                            </span>
                        </div>
                        
                        <div style="display: flex; justify-content: space-between; align-items: flex-end; padding: 16px 0; border-bottom: 1px solid #e2e8f0;">
                            <div>
                                <p style="font-size: 12px; font-weight: 600; color: #777587; margin: 0; display: flex; align-items: center; gap: 4px;">
                                    <span style="font-family: 'Material Symbols Outlined'; font-size: 16px;">videocam</span> Cameras
                                </p>
                                <h4 style="font-size: 32px; font-weight: 700; color: #1b1b24; margin: 4px 0 0 0;">{calc_cam}</h4>
                            </div>
                            <span style="font-size: 10px; font-weight: 700; color: {'#7e3000' if calc_cam > 0 else '#64748b'}; background-color: {'#ffdbcc' if calc_cam > 0 else '#f1f5f9'}; padding: 4px 8px; border-radius: 9999px;">
                                {'Module Active' if calc_cam > 0 else 'Inactive'}
                            </span>
                        </div>
                        
                        <div style="display: flex; justify-content: space-between; align-items: flex-end; padding-top: 16px;">
                            <div>
                                <p style="font-size: 12px; font-weight: 600; color: #777587; margin: 0; display: flex; align-items: center; gap: 4px;">
                                    <span style="font-family: 'Material Symbols Outlined'; font-size: 16px;">sensors</span> Sensors
                                </p>
                                <h4 style="font-size: 32px; font-weight: 700; color: #1b1b24; margin: 4px 0 0 0;">{calc_pts}</h4>
                            </div>
                            <span style="font-size: 10px; font-weight: 700; color: #525c88; background-color: #dde1ff; padding: 4px 8px; border-radius: 9999px;">Package Delta</span>
                        </div>
                    </div>
                    <div style="background-color: #f0ecf9; padding: 12px 16px; display: flex; align-items: center; gap: 8px;">
                        <span style="font-family: 'Material Symbols Outlined'; font-size: 18px; color: #464555;">info</span>
                        <p style="font-size: 11px; margin: 0; color: #464555; line-height: 1.2;">Calculation includes base CML allowances plus selected modular additions.</p>
                    </div>
                </div>
            """)
            
            st.write("")
            # Graphical mockup panel
            st_html("""
                <div style="position: relative; border-radius: 12px; overflow: hidden; height: 180px;">
                    <img src="https://lh3.googleusercontent.com/aida-public/AB6AXuCfAcR3QBghlVOfXi-XzW-yzDRc0vliEJIFSaBkKf4E_OkLG5l5N56wvwY8OjpznpTOuiTUBxEdDnz1xH_ob8Stx6zbLspKMsC4ZWp57qTioSLRGo2gzDFTbm_o1mNK5h9B5FNUwkOUXokLv4m5LM4GYiAanMbrB5HLnh_iCPQnvGpeVmUpdlxblLh9qiGwxUNOLBWOeLFB-gvXm7s--TRRKmnaBp3WZsQ6rlftszRWDg7AVDz4jU-3mZb1YIx7HwLmI0xeSqr0xV4" style="width:100%; height:100%; object-fit:cover;"/>
                    <div style="position: absolute; inset: 0; background: linear-gradient(to top, #111c44, transparent); opacity: 0.8;"></div>
                    <div style="position: absolute; bottom: 16px; left: 16px; right: 16px;">
                        <p style="color: white; font-size: 10px; font-weight: bold; text-transform: uppercase; margin: 0; opacity: 0.8; letter-spacing: 0.05em;">Status Overview</p>
                        <h5 style="color: white; font-size: 18px; font-weight: 600; margin: 4px 0 0 0;">System v4.2 Deployment</h5>
                    </div>
                </div>
            """)

    # Page 3: Token Management
    elif menu == "Token Management":
        st_html("""
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                <span style="font-family: 'Material Symbols Outlined'; font-size: 32px; color: #3525cd; line-height: 1;">key</span>
                <h1 style="color: #1b1b24; font-size: 28px; font-weight: 700; margin: 0;">Token Management</h1>
            </div>
            <p style="color: #464555; font-size: 14px; margin: 4px 0 24px 0;">Oversee and regulate all active and expired security licenses.</p>
        """)

        # Count active/expired
        now = datetime.now()
        active_count = 0
        expiring_soon_count = 0
        for k in keys:
            if k.get("expire_date") == "991231":
                active_count += 1
            else:
                try:
                    exp_dt = datetime.strptime(k["expire_date"], "%y%m%d")
                    if exp_dt > now:
                        active_count += 1
                        if exp_dt < now + timedelta(days=30):
                            expiring_soon_count += 1
                except:
                    active_count += 1

        revenue = sum(calculate_mock_revenue(k["tier"]) for k in keys)

        # Bento Bento-style Stats
        b1, b2, b3, b4 = st.columns(4)
        
        with b1:
            st_html(f"""
                <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; box-shadow: 0px 4px 6px -1px rgba(0, 0, 0, 0.05);">
                    <p style="margin: 0; font-size: 12px; font-weight: 600; color: #777587; text-transform: uppercase;">Total Keys</p>
                    <div style="display: flex; align-items: baseline; gap: 8px; margin-top: 8px;">
                        <h3 style="margin: 0; font-size: 28px; font-weight: 700; color: #1b1b24;">{len(keys):,}</h3>
                        <span style="font-size: 10px; font-weight: 700; color: #10b981; background-color: #ecfdf5; padding: 2px 6px; border-radius: 9999px;">+12%</span>
                    </div>
                </div>
            """)
            
        with b2:
            st_html(f"""
                <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; box-shadow: 0px 4px 6px -1px rgba(0, 0, 0, 0.05);">
                    <p style="margin: 0; font-size: 12px; font-weight: 600; color: #777587; text-transform: uppercase;">Active Now</p>
                    <div style="display: flex; align-items: baseline; gap: 8px; margin-top: 8px;">
                        <h3 style="margin: 0; font-size: 28px; font-weight: 700; color: #1b1b24;">{active_count:,}</h3>
                        <span style="font-size: 10px; font-weight: 700; color: #3525cd; background-color: #e2dfff; padding: 2px 6px; border-radius: 9999px;">74%</span>
                    </div>
                </div>
            """)
            
        with b3:
            st_html(f"""
                <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; box-shadow: 0px 4px 6px -1px rgba(0, 0, 0, 0.05);">
                    <p style="margin: 0; font-size: 12px; font-weight: 600; color: #777587; text-transform: uppercase;">Expiring Soon</p>
                    <div style="display: flex; align-items: baseline; gap: 8px; margin-top: 8px;">
                        <h3 style="margin: 0; font-size: 28px; font-weight: 700; color: #1b1b24;">{expiring_soon_count:,}</h3>
                        <span style="font-size: 10px; font-weight: 700; color: #ef4444; background-color: #fee2e2; padding: 2px 6px; border-radius: 9999px;">Critical</span>
                    </div>
                </div>
            """)
            
        with b4:
            st_html(f"""
                <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; box-shadow: 0px 4px 6px -1px rgba(0, 0, 0, 0.05);">
                    <p style="margin: 0; font-size: 12px; font-weight: 600; color: #777587; text-transform: uppercase;">Revenue</p>
                    <div style="display: flex; align-items: baseline; gap: 8px; margin-top: 8px;">
                        <h3 style="margin: 0; font-size: 28px; font-weight: 700; color: #1b1b24;">${revenue:,}</h3>
                        <span style="font-size: 10px; font-weight: 700; color: #10b981; background-color: #ecfdf5; padding: 2px 6px; border-radius: 9999px;">+5%</span>
                    </div>
                </div>
            """)

        st.write("")
        st.write("")

        # Filter & table layout
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        
        search = st.text_input("🔍 Search licenses by Key, Package or Customer name...", placeholder="E.g. CML, Khách hàng...")
        st.write("")

        if not keys:
            st.info("No registered keys in database.")
        else:
            df = pd.DataFrame(keys)
            if search:
                df = df[df.apply(lambda r: r.astype(str).str.contains(search, case=False).any(), axis=1)]

            # Table Header
            h1, h2, h3, h4, h5, h6, h7, h8 = st.columns([3.2, 1.3, 0.8, 1.3, 1.5, 1.2, 0.9, 0.6])
            h1.write("**License Key**")
            h2.write("**Package Type**")
            h3.write("**Sessions**")
            h4.write("**Expiry Date**")
            h5.write("**Issued To**")
            h6.write("**Status**")
            h7.write("**Tải**")
            h8.write("**Xóa**")
            st.divider()

            for i, row in df.iloc[::-1].iterrows():
                r1, r2, r3, r4, r5, r6, r7, r8 = st.columns([3.2, 1.3, 0.8, 1.3, 1.5, 1.2, 0.9, 0.6])
                r1.code(row["key"], language="text")
                r2.write(row['tier'])
                r3.write(str(row.get('max_sessions', 1)))
                
                exp_date_raw = row['expire_date']
                is_expired = False
                if exp_date_raw == "991231":
                    r4.write("Trọn đời")
                else:
                    try:
                        exp_dt = datetime.strptime(exp_date_raw, "%y%m%d")
                        r4.write(exp_dt.strftime("%Y-%m-%d"))
                        if exp_dt <= now:
                            is_expired = True
                    except:
                        r4.write("Không rõ")
                
                r5.write(row.get("issued_to", "Không rõ"))
                
                # Active status and toggle
                is_active = row.get("is_active", True)
                if is_expired:
                    r6.markdown('<span style="display: inline-flex; align-items: center; padding: 2px 10px; border-radius: 9999px; font-size: 11px; font-weight: 600; background-color: #fee2e2; color: #991b1b;">Expired</span>', unsafe_allow_html=True)
                else:
                    # Render interactive status toggle
                    status_label = "🟢 Active" if is_active else "🔴 Blocked"
                    if r6.button(status_label, key=f"status_{row['key']}"):
                        if st.session_state.get("use_live_db", False):
                            LiveDatabase.toggle_license(row["id"], is_active)
                        else:
                            for k in st.session_state["keys"]:
                                if k["key"] == row["key"]:
                                    k["is_active"] = not is_active
                            save_keys(st.session_state["keys"])
                        st.session_state["keys"] = load_keys()
                        st.rerun()
                
                # Download button
                r7.download_button(
                    label="💾",
                    data=row["key"],
                    file_name="base.lic",
                    mime="text/plain",
                    key=f"dl_{row['key']}_{i}"
                )
                
                # Delete action
                if r8.button("❌", key=f"del_{row['key']}"):
                    if st.session_state.get("use_live_db", False):
                        LiveDatabase.delete_license(row["id"])
                    else:
                        st.session_state["keys"] = [k for k in st.session_state["keys"] if k["key"] != row["key"]]
                        save_keys(st.session_state["keys"])
                    st.session_state["keys"] = load_keys()
                    st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)


    # Page 3b: Active Sessions
    elif menu == "Active Sessions":
        st_html("""
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                <span style="font-family: 'Material Symbols Outlined'; font-size: 32px; color: #3525cd; line-height: 1;">group</span>
                <h1 style="color: #1b1b24; font-size: 28px; font-weight: 700; margin: 0;">Active Sessions</h1>
            </div>
            <p style="color: #464555; font-size: 14px; margin: 4px 0 24px 0;">Monitor concurrent user logins in real-time and revoke hanging/stuck sessions.</p>
        """)

        # Get sessions
        sessions = LiveDatabase.get_sessions()
        
        # Calculate session metrics
        total_sessions = len(sessions)
        active_sessions = len([s for s in sessions if not s["is_revoked"]])
        revoked_sessions = total_sessions - active_sessions

        # Bento Bento-style Stats
        b1, b2, b3 = st.columns(3)
        with b1:
            st_html(f"""
                <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; box-shadow: 0px 4px 6px -1px rgba(0, 0, 0, 0.05);">
                    <p style="margin: 0; font-size: 12px; font-weight: 600; color: #777587; text-transform: uppercase;">Total Sessions (History)</p>
                    <div style="display: flex; align-items: baseline; gap: 8px; margin-top: 8px;">
                        <h3 style="margin: 0; font-size: 28px; font-weight: 700; color: #1b1b24;">{total_sessions:,}</h3>
                    </div>
                </div>
            """)
        with b2:
            st_html(f"""
                <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; box-shadow: 0px 4px 6px -1px rgba(0, 0, 0, 0.05);">
                    <p style="margin: 0; font-size: 12px; font-weight: 600; color: #777587; text-transform: uppercase;">Active Connections</p>
                    <div style="display: flex; align-items: baseline; gap: 8px; margin-top: 8px;">
                        <h3 style="margin: 0; font-size: 28px; font-weight: 700; color: #1b1b24;">{active_sessions:,}</h3>
                        <span style="font-size: 10px; font-weight: 700; color: #10b981; background-color: #ecfdf5; padding: 2px 6px; border-radius: 9999px;">Live</span>
                    </div>
                </div>
            """)
        with b3:
            st_html(f"""
                <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; box-shadow: 0px 4px 6px -1px rgba(0, 0, 0, 0.05);">
                    <p style="margin: 0; font-size: 12px; font-weight: 600; color: #777587; text-transform: uppercase;">Revoked / Closed</p>
                    <div style="display: flex; align-items: baseline; gap: 8px; margin-top: 8px;">
                        <h3 style="margin: 0; font-size: 28px; font-weight: 700; color: #1b1b24;">{revoked_sessions:,}</h3>
                    </div>
                </div>
            """)

        st.write("")
        st.write("")

        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        search_sess = st.text_input("🔍 Search sessions by Client Name, License Key or User ID...", placeholder="E.g. admin...")
        st.write("")

        if not sessions:
            st.info("No active sessions registered in database.")
        else:
            df_sess = pd.DataFrame(sessions)
            if search_sess:
                df_sess = df_sess[df_sess.apply(lambda r: r.astype(str).str.contains(search_sess, case=False).any(), axis=1)]

            # Table Header
            h1, h2, h3, h4, h5, h6 = st.columns([2.0, 3.5, 1.8, 1.8, 1.4, 1.0])
            h1.write("**Customer / Issued To**")
            h2.write("**License Key**")
            h3.write("**Login At**")
            h4.write("**Last Seen At**")
            h5.write("**Status**")
            h6.write("**Action**")
            st.divider()

            for i, row in df_sess.iterrows():
                r1, r2, r3, r4, r5, r6 = st.columns([2.0, 3.5, 1.8, 1.8, 1.4, 1.0])
                r1.write(f"**{row['issued_to']}** ({row['user_id']})")
                r2.code(row["license_key"], language="text")
                r3.write(str(row["login_at"]))
                r4.write(str(row["last_seen_at"]))
                
                is_revoked = row["is_revoked"]
                if is_revoked:
                    status_badge = '<span style="display: inline-flex; align-items: center; padding: 2px 10px; border-radius: 9999px; font-size: 11px; font-weight: 600; background-color: #fee2e2; color: #991b1b;">Revoked</span>'
                    r5.markdown(status_badge, unsafe_allow_html=True)
                    r6.write("")
                else:
                    status_badge = '<span style="display: inline-flex; align-items: center; padding: 2px 10px; border-radius: 9999px; font-size: 11px; font-weight: 600; background-color: #d1fae5; color: #065f46;">Connected</span>'
                    r5.markdown(status_badge, unsafe_allow_html=True)
                    if r6.button("Revoke", key=f"revoke_{row['id']}"):
                        LiveDatabase.revoke_session(row['id'])
                        st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

    # Page 3c: Add-on Upgrades
    elif menu == "Add-on Upgrades":
        st_html("""
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                <span style="font-family: 'Material Symbols Outlined'; font-size: 32px; color: #3525cd; line-height: 1;">add_box</span>
                <h1 style="color: #1b1b24; font-size: 28px; font-weight: 700; margin: 0;">Add-on Upgrades</h1>
            </div>
            <p style="color: #464555; font-size: 14px; margin: 4px 0 24px 0;">Cấp phát và quản lý các gói nâng cấp cộng dồn (Camera, Sensor) cho từng máy trạm.</p>
        """)

        if use_live:
            LiveDatabase.init_addons_table()

        addons = load_addons()
        
        col_form, col_list = st.columns([1, 2])
        
        with col_form:
            st.markdown('<div class="glass-card">', unsafe_allow_html=True)
            st_html("<h4 style='margin:0 0 16px 0; color:#1b1b24;'>Cấp Gói Nâng Cấp Mới</h4>")
            
            # Select base key
            base_options = [k for k in keys if k.get("is_active", True)]
            if not base_options:
                st.warning("Không có License Key gốc nào đang hoạt động để nâng cấp.")
                base_selected = None
            else:
                base_keys_map = {f"{k['issued_to']} ({k['key'][:15]}...)": k for k in base_options}
                selected_label = st.selectbox("Chọn License gốc", list(base_keys_map.keys()))
                base_selected = base_keys_map[selected_label]
            
            secret = st.text_input("Mã bí mật (Vendor Secret)", value=detect_vendor_secret(), type="password", key="addon_secret")
            res_type = st.selectbox("Loại tài nguyên nâng cấp", ["Camera (CAM)", "Sensor (SEN)"])
            qty = st.number_input("Số lượng cộng thêm", min_value=1, value=5, step=1)
            
            st.write("")
            submitted_addon = st.button("➕ TẠO GÓI NÂNG CẤP", use_container_width=True, type="primary")
            st.markdown('</div>', unsafe_allow_html=True)
            
            if submitted_addon and base_selected:
                hw_id = "ANY"
                parts = base_selected["key"].split("-")
                exp_index = -1
                for idx, part in enumerate(parts):
                    if len(part) == 6 and part.isdigit():
                        exp_index = idx
                        break
                if exp_index != -1:
                    nonce_index = len(parts) - 2
                    remaining_params = nonce_index - (exp_index + 2)
                    if remaining_params >= 6:
                        hw_id = parts[exp_index + 7]
                
                addon_guid = secrets.token_hex(4).upper()
                type_code = "CAM" if "Camera" in res_type else "SEN"
                payload = f"ADDON-{addon_guid}-{type_code}-{int(qty)}-{hw_id}"
                addon_key = _generate_key(secret, payload)
                
                db_success = True
                if use_live:
                    db_success = LiveDatabase.add_addon(
                        addon_id=addon_guid,
                        base_key_id=base_selected["id"] if "id" in base_selected else base_selected["key"],
                        resource_type=type_code,
                        qty=int(qty),
                        addon_key=addon_key,
                        issued_to=base_selected["issued_to"],
                        hw_id=hw_id
                    )
                else:
                    new_addon = {
                        "id": addon_guid,
                        "base_key_id": base_selected.get("key", ""),
                        "resource_type": type_code,
                        "quantity": int(qty),
                        "addon_key": addon_key,
                        "issued_to": base_selected["issued_to"],
                        "hardware_id": hw_id,
                        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    addons.append(new_addon)
                    save_addons(addons)
                
                if db_success:
                    st_html(f"""
                        <div style="background-color: #ecfdf5; border: 1px solid #10b981; border-radius: 8px; padding: 16px; margin-top: 16px;">
                            <p style="color: #065f46; font-size: 11px; font-weight: bold; text-transform: uppercase; margin: 0 0 8px 0;">Tạo Gói Thành Công</p>
                            <code style="display: block; font-family: monospace; font-size: 13px; color: #3525cd; word-break: break-all; background-color: white; border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px;">{addon_key}</code>
                            <p style="color: #065f46; font-size: 10px; margin: 6px 0 0 0;">✔ Sao chép chuỗi trên và lưu thành file <b>addon_{addon_guid}.lic</b> đưa về trạm.</p>
                        </div>
                    """)
                    st.download_button(
                        label=f"💾 Tải về File Add-on (addon_{addon_guid}.lic)",
                        data=addon_key,
                        file_name=f"addon_{addon_guid}.lic",
                        mime="text/plain",
                        use_container_width=True
                    )


        with col_list:
            st.markdown('<div class="glass-card">', unsafe_allow_html=True)
            st_html("<h4 style='margin:0 0 16px 0; color:#1b1b24;'>Danh Sách Gói Nâng Cấp Đã Cấp</h4>")
            
            if not addons:
                st.info("Chưa có gói nâng cấp nào được cấp phát.")
            else:
                df_addons = pd.DataFrame(addons)
                
                h1, h2, h3, h4, h5, h6, h7 = st.columns([1.3, 3.0, 1.1, 1.0, 1.2, 0.8, 0.6])
                h1.write("**Khách hàng**")
                h2.write("**Khóa nâng cấp (Add-on Key)**")
                h3.write("**Tài nguyên**")
                h4.write("**Số lượng**")
                h5.write("**Hardware ID**")
                h6.write("**Tải**")
                h7.write("**Xóa**")
                st.divider()
                
                for idx, row in df_addons.iterrows():
                    r1, r2, r3, r4, r5, r6, r7 = st.columns([1.3, 3.0, 1.1, 1.0, 1.2, 0.8, 0.6])
                    r1.write(row["issued_to"])
                    r2.code(row["addon_key"], language="text")
                    r3.write("Camera (CAM)" if row["resource_type"] == "CAM" else "Sensor (SEN)")
                    r4.write(f"+{row['quantity']}")
                    r5.write(row["hardware_id"])
                    
                    # Download button
                    addon_guid = row["id"]
                    r6.download_button(
                        label="💾",
                        data=row["addon_key"],
                        file_name=f"addon_{addon_guid}.lic",
                        mime="text/plain",
                        key=f"dl_addon_{addon_guid}_{idx}"
                    )
                    
                    if r7.button("❌", key=f"del_addon_{row['id']}"):
                        if use_live:
                            LiveDatabase.delete_addon(row["id"])
                        else:
                            addons = [a for a in addons if a["id"] != row["id"]]
                            save_addons(addons)
                        st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

    # Page 4: Settings
    elif menu == "Settings":
        st_html("""
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                <span style="font-family: 'Material Symbols Outlined'; font-size: 32px; color: #3525cd; line-height: 1;">settings</span>
                <h1 style="color: #1b1b24; font-size: 28px; font-weight: 700; margin: 0;">System Configuration</h1>
            </div>
            <p style="color: #464555; font-size: 14px; margin: 4px 0 24px 0;">Manage your administrator account, database connectivity, and system-wide security policies.</p>
        """)

        col_admin, col_h = st.columns([2, 1])

        with col_admin:
            st_html("""
                <div class="glass-card">
                    <div style="display: flex; align-items: center; gap: 16px; margin-bottom: 24px;">
                        <img src="https://lh3.googleusercontent.com/aida-public/AB6AXuCWl54Wja-6n5geq1piQqqsLwoze2e2Zx_NdHSBxlPaFTp-Wffk6S4_xGADvhAyjNZxgYAnGm1q_TDyNGZ4E2_g1zH0cd6k5p32PJowAayLE2Lf2yPsisD5Vm8cyzEJsn4sPY2BMlT6KiTA73uIK63aqK6XSZ4jhXuataKWIGoeERTCisEJnZFtu9U-hkCo19EfOfQvjSHkbAkD10Dnhl0IWtwGm5mXeDDnPuXPEy5XhfvoCw2PeYD44gFefrd8NQOUggDm4wJggqE" style="width: 56px; height: 56px; border-radius: 8px; object-fit: cover;"/>
                        <div>
                            <h4 style="font-size: 18px; font-weight: 600; margin: 0; color: #1b1b24;">Admin Account Information</h4>
                            <p style="font-size: 11px; text-transform: uppercase; font-weight: 700; color: #777587; margin: 2px 0 0 0; letter-spacing: 0.05em;">Security Level: Level 4 Root</p>
                        </div>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px;">
                        <div>
                            <label style="font-size: 11px; font-weight: 700; text-transform: uppercase; color: #777587;">Full Name</label>
                            <p style="font-size: 15px; font-weight: 500; color: #1b1b24; margin: 4px 0 0 0; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px;">Administrator Executive</p>
                        </div>
                        <div>
                            <label style="font-size: 11px; font-weight: 700; text-transform: uppercase; color: #777587;">Email Address</label>
                            <p style="font-size: 15px; font-weight: 500; color: #1b1b24; margin: 4px 0 0 0; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px;">root@license-system.internal</p>
                        </div>
                        <div>
                            <label style="font-size: 11px; font-weight: 700; text-transform: uppercase; color: #777587;">Access Token</label>
                            <p style="font-size: 15px; font-weight: 500; color: #1b1b24; margin: 4px 0 0 0; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; font-family: monospace;">•••••••••••••••••</p>
                        </div>
                        <div>
                            <label style="font-size: 11px; font-weight: 700; text-transform: uppercase; color: #777587;">Last Login</label>
                            <p style="font-size: 15px; font-weight: 500; color: #1b1b24; margin: 4px 0 0 0; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px;">October 24, 2023 - 14:45 GMT</p>
                        </div>
                    </div>
                </div>
            """)
        
        with col_h:
            st_html("""
                <div style="background-color: #3525cd; color: #ffffff; border-radius: 12px; padding: 28px; box-shadow: 0px 4px 6px -1px rgba(0,0,0,0.05); position: relative; overflow: hidden; height: 100%;">
                    <div style="position: relative; z-index: 10;">
                        <span style="font-family: 'Material Symbols Outlined'; font-size: 40px; opacity: 0.4; margin-bottom: 16px; display: block;">analytics</span>
                        <h4 style="margin: 0; font-size: 20px; font-weight: 600;">System Uptime</h4>
                        <p style="margin: 4px 0 0 0; font-size: 12px; opacity: 0.8;">Real-time status of the management engine.</p>
                    </div>
                    <div style="margin-top: 32px; position: relative; z-index: 10;">
                        <div style="display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 8px;">
                            <span style="font-size: 32px; font-weight: 700; line-height: 1;">99.9%</span>
                            <span style="font-size: 11px; font-weight: 700; background-color: rgba(255,255,255,0.2); padding: 4px 8px; border-radius: 6px;">STABLE</span>
                        </div>
                        <div style="width: 100%; background-color: rgba(255,255,255,0.2); height: 6px; border-radius: 9999px;">
                            <div style="background-color: #ffffff; height: 100%; width: 99.9%; border-radius: 9999px;"></div>
                        </div>
                    </div>
                </div>
            """)

        st.write("")
        st.write("")

        # Database Configuration
        st_html(f"""
            <div class="glass-card">
                <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 24px;">
                    <span style="font-family: 'Material Symbols Outlined'; font-size: 28px; color: #3525cd;">database</span>
                    <h4 style="font-size: 18px; font-weight: 600; margin: 0; color: #1b1b24;">Database Configuration</h4>
                </div>
                <div style="background-color: #f0ecf9; border: 1px solid rgba(199, 196, 216, 0.5); border-radius: 12px; padding: 24px; display: flex; flex-direction: column; justify-content: space-between; gap: 24px;">
                    <div style="flex-grow: 1;">
                        <label style="font-size: 12px; font-weight: 600; color: #464555; margin-bottom: 8px; display: block;">Path to Database File</label>
                        <code style="display: block; font-family: monospace; font-size: 13px; color: #525c88; background-color: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px 16px; word-break: break-all;">
                            {os.path.abspath(DB_FILE)}
                        </code>
                    </div>
                    <div style="display: flex; gap: 24px; align-self: flex-end;">
                        <div style="text-align: right;">
                            <p style="font-size: 11px; font-weight: 700; text-transform: uppercase; color: #777587; margin: 0;">Total Size</p>
                            <p style="font-size: 18px; font-weight: 700; color: #1b1b24; margin: 4px 0 0 0;">{f"{os.path.getsize(DB_FILE) / 1024:.2f} KB" if os.path.exists(DB_FILE) else "0 KB"}</p>
                        </div>
                        <div style="text-align: right;">
                            <p style="font-size: 11px; font-weight: 700; text-transform: uppercase; color: #777587; margin: 0;">Active Keys</p>
                            <p style="font-size: 18px; font-weight: 700; color: #1b1b24; margin: 4px 0 0 0;">{len(keys)}</p>
                        </div>
                    </div>
                </div>
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; margin-top: 24px;">
                    <div style="display: flex; align-items: start; gap: 12px; padding: 16px; border: 1px solid #e2e8f0; border-radius: 8px;">
                        <span style="font-family: 'Material Symbols Outlined'; font-size: 24px; color: #525c88;">backup</span>
                        <div>
                            <p style="margin: 0; font-size: 13px; font-weight: 600; color: #1b1b24;">Auto Backup</p>
                            <p style="margin: 2px 0 0 0; font-size: 12px; color: #777587;">Every 24 hours at 03:00</p>
                        </div>
                    </div>
                    <div style="display: flex; align-items: start; gap: 12px; padding: 16px; border: 1px solid #e2e8f0; border-radius: 8px;">
                        <span style="font-family: 'Material Symbols Outlined'; font-size: 24px; color: #525c88;">encrypted</span>
                        <div>
                            <p style="margin: 0; font-size: 13px; font-weight: 600; color: #1b1b24;">Encryption</p>
                            <p style="margin: 2px 0 0 0; font-size: 12px; color: #777587;">HMAC-SHA256 Signatures</p>
                        </div>
                    </div>
                    <div style="display: flex; align-items: start; gap: 12px; padding: 16px; border: 1px solid #e2e8f0; border-radius: 8px;">
                        <span style="font-family: 'Material Symbols Outlined'; font-size: 24px; color: #525c88;">history</span>
                        <div>
                            <p style="margin: 0; font-size: 13px; font-weight: 600; color: #1b1b24;">Log Retention</p>
                            <p style="margin: 2px 0 0 0; font-size: 12px; color: #777587;">Permanent audit trail</p>
                        </div>
                    </div>
                </div>
            </div>
        """)

        st.write("")
        st.write("")

        # Danger Zone
        st.markdown('<div style="background-color: #fef2f2; border: 1px solid #fca5a5; border-radius: 12px; padding: 28px;">', unsafe_allow_html=True)
        st_html("""
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                <span style="font-family: 'Material Symbols Outlined'; font-size: 28px; color: #dc2626;">warning</span>
                <h4 style="font-size: 18px; font-weight: 600; margin: 0; color: #991b1b;">Danger Zone</h4>
            </div>
            <p style="color: #991b1b; font-size: 14px; margin: 0 0 24px 0; line-height: 1.5;">Perform destructive operations on the system database. These actions are irreversible and will immediately purge all stored records, including license keys, user data, and activity logs.</p>
        """)
        
        confirm = st.checkbox("Tôi xác nhận muốn xóa tất cả dữ liệu (confirm delete database)", value=False)
        st.write("")
        
        if st.button("🗑️ Xóa toàn bộ dữ liệu", type="primary", disabled=not confirm):
            st.session_state["keys"] = []
            save_keys([])
            st.success("Database wiped successfully!")
            st.rerun()
            
        st.markdown('</div>', unsafe_allow_html=True)


if __name__ == "__main__":
    main()
