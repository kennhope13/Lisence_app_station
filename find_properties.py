import os
import re

def find_properties():
    dlls_dir = r"d:\Anh_Tung\Phần mềm\License\extracted_dlls"
    files = ["extracted_91.dll", "extracted_92.dll", "extracted_93.dll", "extracted_94.dll"]
    
    terms = [
        b"MaxDevices", b"MaxCameras", b"MaxPoints", b"MaxRoi", b"MaxPd", 
        b"maxDevices", b"maxCameras", b"maxPoints", b"maxRoi", b"maxPd",
        b"DevicesLimit", b"CamerasLimit", b"PointsLimit", b"RoiLimit", b"PdLimit",
        b"MaxUsers", b"maxUsers", b"MaxConcurrentSessions"
    ]
    
    for filename in files:
        file_path = os.path.join(dlls_dir, filename)
        if not os.path.exists(file_path):
            continue
        print(f"\n================ Properties in {filename} ================")
        with open(file_path, "rb") as f:
            data = f.read()
            
        for term in terms:
            if term in data:
                print(f"  Found property: {term.decode()}")

if __name__ == "__main__":
    find_properties()
