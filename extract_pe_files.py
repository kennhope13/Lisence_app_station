import os

def extract_pe_files(exe_path, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    with open(exe_path, "rb") as f:
        data = f.read()
        
    print(f"Total binary size: {len(data)} bytes")
    
    # PE files start with MZ (4D 5A) and usually have "This program cannot be run in DOS mode"
    # or we can look for MZ headers.
    mz_indices = []
    idx = 0
    while True:
        idx = data.find(b"MZ\x90\x00", idx)
        if idx == -1:
            break
        mz_indices.append(idx)
        idx += 4
        
    print(f"Found {len(mz_indices)} MZ headers.")
    
    # To find the end of each DLL, we can parse the PE header or just write from MZ to next MZ
    # and then parse the PE headers to get exact size. Let's do a simple approach first:
    # PE file size can be calculated from the PE headers (Optional Header -> SizeOfImage or Section Headers).
    # A simpler way is to use a basic PE size parser in Python:
    for i, start_idx in enumerate(mz_indices):
        # Read the PE offset
        pe_offset = int.from_bytes(data[start_idx + 0x3C : start_idx + 0x40], "little")
        pe_header_start = start_idx + pe_offset
        
        # Verify PE signature (PE\x00\x00)
        if data[pe_header_start : pe_header_start + 4] != b"PE\x00\x00":
            continue
            
        # Get number of sections
        num_sections = int.from_bytes(data[pe_header_start + 6 : pe_header_start + 8], "little")
        
        # Get optional header size
        opt_header_size = int.from_bytes(data[pe_header_start + 20 : pe_header_start + 22], "little")
        
        # Section headers start after COFF header (24 bytes) + optional header
        section_headers_start = pe_header_start + 24 + opt_header_size
        
        # Find the max pointer to raw data + size of raw data among all sections
        max_raw_end = 0
        for s in range(num_sections):
            sec_offset = section_headers_start + s * 40
            sec_name = data[sec_offset : sec_offset + 8].strip(b'\x00').decode('utf-8', errors='ignore')
            
            size_of_raw = int.from_bytes(data[sec_offset + 16 : sec_offset + 20], "little")
            pointer_to_raw = int.from_bytes(data[sec_offset + 20 : sec_offset + 24], "little")
            
            raw_end = pointer_to_raw + size_of_raw
            if raw_end > max_raw_end:
                max_raw_end = raw_end
                
        # The DLL size is max_raw_end
        dll_size = max_raw_end
        if dll_size > 0:
            dll_data = data[start_idx : start_idx + dll_size]
            # Let's save it
            dll_name = f"extracted_{i}.dll"
            # Try to see if we can find assembly name in Metadata header
            # Metadata header starts with BSJB (42 53 4A 42)
            bsjb_idx = dll_data.find(b"BSJB")
            if bsjb_idx != -1:
                # Assembly name is usually near the beginning of the metadata, let's scan for it
                # or just name it extracted_i.dll
                pass
            
            # Save DLL
            output_path = os.path.join(output_dir, dll_name)
            with open(output_path, "wb") as out_f:
                out_f.write(dll_data)
                
    print(f"Extraction completed in {output_dir}")

if __name__ == "__main__":
    extract_pe_files(
        r"C:\Program Files\StationMonitor\backend\StationMonitor.Api.exe",
        r"d:\Anh_Tung\Phần mềm\License\extracted_dlls"
    )
