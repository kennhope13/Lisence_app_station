# StationMonitor License Audit Report

This document provides a comprehensive security audit of the license verification and session control mechanisms in **StationMonitor**. It maps the relationships between compiled CIL services, the SQLite database schema, the Web API endpoints, and client-side assets, while verifying the utility of the custom Python license generators.

---

## 1. Executive Summary

Our forensic analysis of the StationMonitor decompiled assemblies (`extracted_92.dll`, `extracted_94.dll`), frontend bundles, and SQLite database schema reveals the following:

- **Verification Model**: StationMonitor uses a **database-backed validation model** rather than runtime cryptographic parsing. The application does not cryptographically verify or parse license keys at runtime. Instead, it performs string lookups against the SQLite `LicenseKeys` table.
- **Enforced Constraints**:
  - **Expiration**: Compared against UTC time (`ExpiresAt < UtcNow`).
  - **Active Session Limit**: Concurrent sessions are enforced by querying the `ActiveSessions` table and comparing active counts against `MaxConcurrentSessions`.
  - **Status Gating**: Only keys with `IsActive = 1` are accepted.
- **Resource Limits (Devices, Cameras, Points)**: There is **no enforcement** of resource limits (e.g., maximum devices, cameras, rules, or thermal points) or tier restrictions (SOLO, TEAM, ENT) in either the backend controllers or the client-side JavaScript bundle. The product tiers and advanced limits are functionally opaque.
- **License Generator Utility**: The custom Python generator tools (`generate_license_cli.py` / `generate_license_streamlit.py`) generate HMAC-SHA256 authenticated strings that look like typical enterprise keys, but the C# backend treats them as simple opaque strings. When creating keys through the API (`/api/v1/licenses`), the expiration date and session limits must be passed as explicit JSON fields.

---

## 2. Licensing Architecture & Database Schema

The licensing state is persisted in two core SQLite tables:

### `LicenseKeys` Table
Stores registered activation keys and their session/expiration metadata.
```sql
CREATE TABLE LicenseKeys (
    Id TEXT PRIMARY KEY,
    Key TEXT UNIQUE,
    IssuedTo TEXT,
    MaxConcurrentSessions INTEGER,
    ExpiresAt TEXT,
    IsActive INTEGER,
    CreatedAt TEXT
);
```

### `ActiveSessions` Table
Tracks active user logins to enforce concurrency limits.
```sql
CREATE TABLE ActiveSessions (
    Id TEXT PRIMARY KEY,
    UserId TEXT,
    LicenseKeyId TEXT,
    SessionToken TEXT,
    LoginAt TEXT,
    LastSeenAt TEXT,
    ExpiresAt TEXT,
    IsRevoked INTEGER,
    FOREIGN KEY(LicenseKeyId) REFERENCES LicenseKeys(Id)
);
```

---

## 3. Server-Side Validation Logic

### 3.1 Authentication & Login Validation
Authentication is processed by `StationMonitor.Services.Auth.AuthService.LoginAsync` (in `extracted_92.dll`). Below is the decompiled logic flow extracted from the CIL instructions:

```csharp
// 1. Retrieve the license key record from the database
var license = await _db.LicenseKeys.FirstOrDefaultAsync(l => l.Key == licenseKey && l.IsActive);
if (license == null)
{
    throw new Exception("License key không hợp lệ hoặc không hoạt động");
}

// 2. Validate expiration date
if (license.ExpiresAt.HasValue && license.ExpiresAt.Value < DateTime.UtcNow)
{
    throw new Exception("License key đã hết hạn");
}

// 3. Count concurrent active sessions
var activeSessionsCount = await _db.ActiveSessions.CountAsync(s => 
    s.LicenseKeyId == license.Id && 
    !s.IsRevoked && 
    s.ExpiresAt > DateTime.UtcNow
);

if (activeSessionsCount >= license.MaxConcurrentSessions)
{
    throw new Exception($"Đã đạt giới hạn phiên đăng nhập ({activeSessionsCount}/{license.MaxConcurrentSessions}). Vui lòng thử lại sau.");
}

// 4. Generate Session JWT & Insert ActiveSession record
var sessionToken = Guid.NewGuid().ToString();
var jwt = GenerateJwt(user, sessionToken);
...
```

### 3.2 License Creation API
Admin users can register new license keys using `LicenseController.CreateLicense` (`/api/v1/licenses` - POST).
As shown in the CIL disassembly of `<CreateLicense>d__3.MoveNext`, the API maps explicit DTO parameters into the entity columns:

```csharp
if (string.IsNullOrWhiteSpace(req.Key)) 
    return BadRequest("Key là bắt buộc");

if (await _db.LicenseKeys.AnyAsync(l => l.Key == req.Key)) 
    return BadRequest("License key đã tồn tại");

var license = new LicenseKey {
    Key = req.Key.ToUpper().Trim(),
    IssuedTo = req.IssuedTo ?? "Unknown",
    MaxConcurrentSessions = req.MaxConcurrentSessions,
    ExpiresAt = req.ExpiresAt,
    IsActive = true,
    CreatedAt = DateTime.UtcNow
};

_db.LicenseKeys.Add(license);
await _db.SaveChangesAsync();
```
*Note: No format validation, HMAC signature checking, or checksum validation is performed on the license key value before saving.*

---

## 4. Resource Limits & Tier Checking Audit

We performed a deep inspection of all controllers and worker assemblies (`extracted_93.dll` and `extracted_94.dll`) to check if any of the following parameters are enforced during device addition or monitoring:
- Device additions (`DevicesController.Create`)
- Thermal Point additions (`DevicesController.AddPoint`)
- Camera stream registration (`DeviceService.RegisterCameraStreamAsync`)
- Product Tiers (`SOLO`, `TEAM`, `ENT`)

### Findings:
1. **Device Creation**: `DevicesController.Create` saves the device entity directly to the DB without checking the active license key's limits or checking total device counts.
2. **Point Creation**: `DevicesController.AddPoint` performs coordinate binding but has no limit validation.
3. **No Reference Mapping**: Apart from `AuthService` and `LicenseController`, no service or controller in the application references the `LicenseKey` entity or reads the `LicenseInfo` settings.
4. **Client-Side Behavior**: The React/Vue frontend stores `licenseInfo` in `localStorage` under `station_license_info` but never reads or evaluates this object to gate features or hide navigation components.

---

## 5. Python License Key Generator Alignment

The custom Python generators (`generate_license_cli.py` and `generate_license_streamlit.py`) construct keys matching the pattern:
```
{Tier}-{Expiration}-{Limits}-{Nonce}-{HMAC_Hash}
```
### Key Alignment Table

| Generator Concept | Realized Backend Concept | Enforcement Status |
| :--- | :--- | :--- |
| **Tier** (`SOLO`, `TEAM`, `ENT`) | Not checked | **Opaque (Not Enforced)** |
| **Limits** (`max-devices`, `max-cameras`, etc.) | Not checked | **Opaque (Not Enforced)** |
| **HMAC Signature** (via `VendorSecret`) | Not verified at runtime | **Opaque (Not Enforced)** |
| **Expiration Date** (`expire_date`) | Parsed via `ExpiresAt` DB column | **Enforced in Login Flow** |
| **Max Concurrent Sessions** | Parsed via `MaxConcurrentSessions` DB column | **Enforced in Login Flow** |

### How to Correctly Provision Keys
Because the backend does not parse the key string itself, generating a structured key string is purely for cosmetic consistency. To provision a key:
1. Generate the license key string using the Python tool (to maintain corporate visual identity).
2. Insert the key into the database using `/api/v1/licenses` or by executing a SQLite query.
3. **Crucial**: You must manually populate the `ExpiresAt` and `MaxConcurrentSessions` attributes to your desired parameters during registration, as the backend will not automatically extract them from the key string.

---

## 6. Recommendations & Bypasses

For developers, auditors, or administrators looking to manage licenses or override limits:
- **Unlimited Key Creation**:
  ```sql
  INSERT INTO LicenseKeys (Id, Key, IssuedTo, MaxConcurrentSessions, ExpiresAt, IsActive, CreatedAt)
  VALUES ('unlimited-license-id-001', 'SM-UNLIMITED-LICENSE-KEY', 'Enterprise Admin', 99999, NULL, 1, '2026-06-22 00:00:00');
  ```
  Using the key `SM-UNLIMITED-LICENSE-KEY` will permit up to 99,999 concurrent sessions and will never expire, with zero restrictions on devices or features.
- **Session Reset**:
  If the session limit is reached (`MaxConcurrentSessions`), administrators can terminate stuck sessions by revoking records in the `ActiveSessions` table:
  ```sql
  UPDATE ActiveSessions SET IsRevoked = 1 WHERE LicenseKeyId = (SELECT Id FROM LicenseKeys WHERE Key = 'YOUR_KEY');
  ```
