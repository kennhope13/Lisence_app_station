import hmac
import hashlib
import json

def generate_signed_license(lic_data, secret):
    # 1. Create a copy of the dictionary without the signature field
    data_to_sign = lic_data.copy()
    if "signature" in data_to_sign:
        del data_to_sign["signature"]
        
    # 2. Serialize to canonical JSON (minified, sorted keys)
    canonical_json = json.dumps(data_to_sign, sort_keys=True, separators=(',', ':'))
    
    # 3. Compute HMAC-SHA256 signature
    signature = hmac.new(secret.encode('utf-8'), canonical_json.encode('utf-8'), hashlib.sha256).hexdigest()[:8]
    
    # 4. Inject signature back into the license dictionary
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
