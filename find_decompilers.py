import os

def search_decompilers():
    search_dirs = [
        r"C:\Users\MSI",
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"d:\Anh_Tung"
    ]
    
    keywords = ["dnspy", "ilspy", "ilspycmd", "reflector", "dotpeek"]
    
    found = []
    # Limit search depth or check specifically in Desktop/Downloads/Software folders
    for base_dir in search_dirs:
        if not os.path.exists(base_dir):
            continue
        print(f"Scanning {base_dir}...")
        for root, dirs, files in os.walk(base_dir):
            # Prune directory search to speed up
            if any(p in root.lower() for p in ["appdata", "node_modules", ".git", "packages", "windows"]):
                # Skip deep noisy system dirs
                dirs[:] = []
                continue
            
            for file in files:
                file_lower = file.lower()
                if file_lower.endswith(".exe") and any(kw in file_lower for kw in keywords):
                    path = os.path.join(root, file)
                    print(f"FOUND DECOMPILER: {path}")
                    found.append(path)
                    
            # Avoid too deep nesting in general scan
            if root.count(os.sep) - base_dir.count(os.sep) > 4:
                dirs[:] = []

if __name__ == "__main__":
    search_decompilers()
