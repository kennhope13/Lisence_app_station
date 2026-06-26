import os

def find_labels():
    assets_dir = r"C:\Program Files\StationMonitor\backend\wwwroot\assets"
    files = [f for f in os.listdir(assets_dir) if f.endswith(".js")]
    
    labels = ["Gói sản phẩm", "Số thiết bị tối đa", "Số camera tối đa", "Số điểm nhiệt tối đa"]
    
    for filename in files:
        file_path = os.path.join(assets_dir, filename)
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        for label in labels:
            idx = content.find(label)
            if idx != -1:
                print(f"Found '{label}' in {filename} at index {idx}")
                start = max(0, idx - 200)
                end = min(len(content), idx + len(label) + 300)
                print(content[start:end])
                print("-" * 50)

if __name__ == "__main__":
    find_labels()
