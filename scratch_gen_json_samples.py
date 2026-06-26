import hmac
import hashlib
import json

def generate_signed_license(lic_data, secret):
    # 1. Extract values
    kind = lic_data.get("kind", "").upper()
    lic_id = lic_data.get("licenseId", "").upper()
    addon_id = lic_data.get("addonId", "").upper()
    base_lic_id = lic_data.get("baseLicenseId", "").upper()
    tier = lic_data.get("tier", "").upper()
    issued_at = lic_data.get("issuedAtUtc", "")
    expires_at = lic_data.get("expiresAtUtc", "")
    
    # 2. Compute fingerprintHash
    hw = lic_data.get("hardware", {})
    cpu_id = hw.get("cpuId", "ANY")
    mb_id = hw.get("mainboardUuid", "ANY")
    disk_id = hw.get("osDiskSerial", "ANY")
    raw_hw_str = f"{cpu_id}|{mb_id}|{disk_id}".upper().strip()
    fingerprint_hash = hashlib.sha256(raw_hw_str.encode('utf-8')).hexdigest().upper()
    
    # 3. Compute limits string: users,stations,cameras,roi_points,roi_regions,pd_regions
    limits = lic_data.get("limits", {})
    limits_str = f"{limits.get('users',0)},{limits.get('stations',0)},{limits.get('cameras',0)},{limits.get('roiPoints',0)},{limits.get('roiRegions',0)},{limits.get('pdRegions',0)}"
    
    # 4. Canonical string
    canonical = f"{kind}|{lic_id}|{addon_id}|{base_lic_id}|{tier}|{issued_at}|{expires_at}|{fingerprint_hash}|{limits_str}"
    
    # 5. Signature
    signature = hmac.new(secret.encode('utf-8'), canonical.encode('utf-8'), hashlib.sha256).hexdigest()[:8]
    lic_data["signature"] = signature
    return lic_data

secret = "station_monitor_default_secret_key"

# Base License
base_lic = {
    "version": 1,
    "kind": "base",
    "licenseId": "8fa8d39e-2144-4866-9e6b-0b29a28ebdf2",
    "tier": "CML-SDL500-CAM10-SEL2",
    "issuedAtUtc": "2026-06-26T08:00:00Z",
    "expiresAtUtc": "2029-12-31T23:59:59Z",
    "hardware": {
        "cpuId": "E6D14B20",
        "mainboardUuid": "178C9E23",
        "osDiskSerial": "4FA0102B"
    },
    "limits": {
        "users": 3,
        "stations": 12,
        "cameras": 10,
        "roiPoints": 500,
        "roiRegions": 50,
        "pdRegions": 50
    }
}

# Addon License
addon_lic = {
    "version": 1,
    "kind": "addon",
    "licenseId": "8fa8d39e-2144-4866-9e6b-0b29a28ebdf2",
    "addonId": "2fa4e891-b3b4-4b55-bc55-c53d4ffdb382",
    "baseLicenseId": "8fa8d39e-2144-4866-9e6b-0b29a28ebdf2",
    "tier": "ADDON-CAM",
    "issuedAtUtc": "2026-06-26T08:15:00Z",
    "expiresAtUtc": "2029-12-31T23:59:59Z",
    "hardware": {
        "cpuId": "E6D14B20",
        "mainboardUuid": "178C9E23",
        "osDiskSerial": "4FA0102B"
    },
    "limits": {
        "users": 0,
        "stations": 0,
        "cameras": 5,
        "roiPoints": 0,
        "roiRegions": 0,
        "pdRegions": 0
    }
}

# Sign
signed_base = generate_signed_license(base_lic, secret)
signed_addon = generate_signed_license(addon_lic, secret)

# Print and Save
print("BASE LIC:")
print(json.dumps(signed_base, indent=2))
print("\nADDON LIC:")
print(json.dumps(signed_addon, indent=2))

with open(r"d:\Anh_Tung\Phần mềm\License\samples\sample_base.lic", "w", encoding="utf-8") as f:
    json.dump(signed_base, f, indent=2)

with open(r"d:\Anh_Tung\Phần mềm\License\samples\sample_addon.lic", "w", encoding="utf-8") as f:
    json.dump(signed_addon, f, indent=2)
