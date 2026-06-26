import os

search_paths = [
    r"C:\Users\MSI\AppData\Local\StationMonitor",
    r"C:\Users\MSI\AppData\Local\com.stationmonitor.desktop",
    r"C:\Program Files\StationMonitor"
]

target = "SOLO-270617"
found = False

for path in search_paths:
    if not os.path.exists(path):
        continue
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            # Skip very large files or binary files if we want, but let's read up to 1MB
            if os.path.getsize(file_path) > 10 * 1024 * 1024: # Skip files > 10MB
                continue
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if target in content:
                        print(f"Found '{target}' in file: {file_path}")
                        found = True
            except Exception as e:
                pass

if not found:
    print("Could not find the key string in any files.")
