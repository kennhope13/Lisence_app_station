import os
import sys
import json
import sqlite3

sys.stdout.reconfigure(encoding='utf-8')

def apply_sqlite(db_path, key_str, max_sessions=99999):
    if not os.path.exists(db_path):
        print(f"❌ Không tìm thấy file cơ sở dữ liệu SQLite tại: {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='LicenseKeys';")
        if not cursor.fetchone():
            print("❌ Bảng LicenseKeys không tồn tại trong CSDL SQLite này.")
            conn.close()
            return False
        
        # Check if key already exists
        cursor.execute("SELECT id FROM LicenseKeys WHERE Key = ?;", (key_str,))
        row = cursor.fetchone()
        if row:
            print(f"ℹ️ Key '{key_str}' đã tồn tại trong CSDL SQLite (ID: {row[0]}). Tiến hành cập nhật giới hạn...")
            cursor.execute("""
                UPDATE LicenseKeys 
                SET MaxConcurrentSessions = ?, ExpiresAt = NULL, IsActive = 1 
                WHERE Key = ?
            """, (max_sessions, key_str))
        else:
            import uuid
            new_id = str(uuid.uuid4()).upper()
            print(f"🔑 Đang thêm Key mới '{key_str}' với {max_sessions} phiên vào CSDL SQLite...")
            cursor.execute("""
                INSERT INTO LicenseKeys (Id, Key, IssuedTo, MaxConcurrentSessions, ExpiresAt, IsActive, CreatedAt)
                VALUES (?, ?, ?, ?, NULL, 1, datetime('now'))
            """, (new_id, key_str, "Enterprise Central Station", max_sessions))
            
        conn.commit()
        conn.close()
        print("✅ Đã áp dụng thành công trên SQLite!")
        return True
    except Exception as e:
        print(f"❌ Lỗi SQLite: {e}")
        return False

def apply_postgres(key_str, max_sessions=99999, host="localhost", port=5432, dbname="stationmonitor", user="postgres", password="postgres123"):
    try:
        import psycopg2
    except ImportError:
        print("Installing psycopg2-binary...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "psycopg2-binary"])
        import psycopg2
        
    try:
        print(f"Connecting to PostgreSQL ({host}:{port}/{dbname})...")
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=dbname,
            user=user,
            password=password
        )
        cursor = conn.cursor()
        
        # Check if key already exists
        cursor.execute('SELECT "Id" FROM "LicenseKeys" WHERE "Key" = %s;', (key_str,))
        row = cursor.fetchone()
        if row:
            print(f"ℹ️ Key '{key_str}' đã tồn tại trong PostgreSQL. Cập nhật...")
            cursor.execute("""
                UPDATE "LicenseKeys" 
                SET "MaxConcurrentSessions" = %s, "ExpiresAt" = NULL, "IsActive" = 1 
                WHERE "Key" = %s
            """, (max_sessions, key_str))
        else:
            import uuid
            new_id = str(uuid.uuid4()).upper()
            print(f"🔑 Đang thêm Key mới '{key_str}' vào PostgreSQL...")
            cursor.execute("""
                INSERT INTO "LicenseKeys" ("Id", "Key", "IssuedTo", "MaxConcurrentSessions", "ExpiresAt", "IsActive", "CreatedAt")
                VALUES (%s, %s, %s, %s, NULL, 1, NOW())
            """, (new_id, key_str, "Enterprise Central Station", max_sessions))
            
        conn.commit()
        cursor.close()
        conn.close()
        print("✅ Đã áp dụng thành công trên PostgreSQL!")
        return True
    except Exception as e:
        print(f"❌ Lỗi PostgreSQL: {e}")
        return False

def main():
    # Mặc định key vô hạn
    target_key = "STATION-MONITOR-ENTERPRISE-UNLIMITED"
    
    print("==================================================")
    print("   STATIONMONITOR LICENSE DEPLOYMENT TOOL")
    print("==================================================")
    print(f"Key cần áp dụng: {target_key}")
    print("--------------------------------------------------")
    
    # 1. Thử áp dụng trên SQLite (CSDL Debug/Local cũ)
    sqlite_db_path = r"C:\Users\MSI\AppData\Local\StationMonitor\station_monitor.db"
    if os.path.exists(sqlite_db_path):
        print("Found local SQLite database. Applying...")
        apply_sqlite(sqlite_db_path, target_key)
        
    # 2. Đọc cấu hình appsettings.json của backend để lấy thông tin kết nối Postgres
    appsettings_path = r"C:\Program Files\StationMonitor\backend\appsettings.json"
    pg_conn_info = None
    if os.path.exists(appsettings_path):
        try:
            with open(appsettings_path, "r", encoding="utf-8") as f:
                config = json.load(f)
                conn_str = config.get("ConnectionStrings", {}).get("Default", "")
                if conn_str and "host=" in conn_str.lower():
                    # Parse connection string
                    parts = conn_str.split(";")
                    pg_conn_info = {}
                    for part in parts:
                        if "=" in part:
                            k, v = part.split("=", 1)
                            pg_conn_info[k.strip().lower()] = v.strip()
        except Exception as e:
            print(f"Không thể đọc config appsettings.json: {e}")
            
    if pg_conn_info:
        print("\nFound PostgreSQL connection string in appsettings.json.")
        print(f"Target Database Host: {pg_conn_info.get('host')}:{pg_conn_info.get('port', 5432)}")
        
        # Chạy thử (nếu Postgres local đang chạy)
        apply_postgres(
            key_str=target_key,
            host=pg_conn_info.get("host", "localhost"),
            port=int(pg_conn_info.get("port", 5432)),
            dbname=pg_conn_info.get("database", "stationmonitor"),
            user=pg_conn_info.get("username", "postgres"),
            password=pg_conn_info.get("password", "postgres123")
        )
    else:
        print("\nKhông tìm thấy kết nối PostgreSQL cấu hình trong appsettings.json.")

if __name__ == "__main__":
    main()
