import sqlite3
import json

def check():
    db_path = r"C:\Users\MSI\AppData\Local\StationMonitor\station_monitor.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [t[0] for t in cursor.fetchall()]
    
    output = []
    
    # Search for all tables
    for table in tables:
        table_info = {"table": table}
        try:
            cursor.execute(f"PRAGMA table_info({table});")
            columns = [col[1] for col in cursor.fetchall()]
            table_info["columns"] = columns
            
            cursor.execute(f"SELECT * FROM {table};")
            rows = cursor.fetchall()
            table_info["rows"] = rows
        except Exception as e:
            table_info["error"] = str(e)
        output.append(table_info)
                
    conn.close()
    
    with open("db_output.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    check()
