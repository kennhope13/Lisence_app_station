import os

def find_ildasm():
    search_paths = [
        r"C:\Program Files",
        r"C:\Program Files (x86)"
    ]
    
    for path in search_paths:
        for root, dirs, files in os.walk(path):
            if "ildasm.exe" in files:
                print(f"Found: {os.path.join(root, 'ildasm.exe')}")
                return

if __name__ == "__main__":
    find_ildasm()
