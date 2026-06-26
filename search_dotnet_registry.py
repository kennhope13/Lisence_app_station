import winreg

def search_registry():
    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\dotnet\Setup\InstalledVersions"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    ]
    
    for hkey, subkey in keys:
        try:
            with winreg.OpenKey(hkey, subkey) as key:
                print(f"\nScanning key: {subkey}")
                if "Uninstall" in subkey:
                    # Search subkeys
                    i = 0
                    while True:
                        try:
                            name = winreg.EnumKey(key, i)
                            i += 1
                            with winreg.OpenKey(key, name) as sub:
                                try:
                                    disp, _ = winreg.QueryValueEx(sub, "DisplayName")
                                    if "SDK" in disp or ".NET" in disp:
                                        print(f"  {disp}")
                                except: pass
                        except OSError:
                            break
                else:
                    # Dump values
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(key, i)
                            print(f"  {name}: {val}")
                            i += 1
                        except OSError:
                            break
        except Exception as e:
            pass

if __name__ == "__main__":
    search_registry()
