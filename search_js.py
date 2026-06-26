import os

def search_js():
    assets_dir = r"C:\Program Files\StationMonitor\backend\wwwroot\assets"
    files = [f for f in os.listdir(assets_dir) if f.endswith(".js")]
    
    keywords = ["solo", "team", "ent"]
    
    output = []
    for filename in files:
        file_path = os.path.join(assets_dir, filename)
        output.append(f"\n================ Searching {filename} ================")
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        content_lower = content.lower()
        for kw in keywords:
            idx = 0
            while True:
                idx = content_lower.find(kw.lower(), idx)
                if idx == -1:
                    break
                # Print 100 characters around the match
                start = max(0, idx - 150)
                end = min(len(content), idx + len(kw) + 150)
                snippet = content[start:end].replace('\n', ' ')
                output.append(f"Match for '{kw}' at {idx}: ...{snippet}...")
                idx += len(kw)

    with open("search_js_output.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(output))

if __name__ == "__main__":
    search_js()
