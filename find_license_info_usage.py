def find_usage():
    with open("search_js_output.txt", "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    for i, line in enumerate(lines):
        if "station_license_info" in line:
            print(f"Line {i+1}: {line[:180]}...")

if __name__ == "__main__":
    find_usage()
