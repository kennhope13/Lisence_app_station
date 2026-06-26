# Hướng Dẫn Tích Hợp & Mã Nguồn C# Xác Thực License (Trạm Tổng)

Tài liệu này chứa toàn bộ mã nguồn C# (.NET) nâng cấp để tích hợp chức năng kiểm tra bản quyền ngoại tuyến (offline) cho trạm cô lập, bao gồm:
1. Định danh phần cứng ổn định (không bị drift khi cắm rút USB, phân biệt card mạng ảo/VPN).
2. Kiểm tra phần cứng theo cơ chế Fuzzy Matching (Khớp 2/3).
3. Đọc, xác thực và cộng dồn các gói nâng cấp Add-on (Camera, Sensor) tránh trùng lặp GUID.

---

## 1. Định Danh Phần Cứng Ổn Định (HardwareFingerprint.cs)

Lớp này sử dụng WMI để lấy thông tin của các phần cứng chính. Nó được thiết kế đặc biệt để:
- Chỉ lấy số serial của ổ cứng vật lý chứa phân vùng hệ điều hành (`C:`), loại bỏ hoàn toàn nhiễu từ các ổ cứng di động, USB cắm ngoài.
- Lọc bỏ các card mạng ảo (VPN, VMware, VirtualBox, Virtual Adapter) khi lấy địa chỉ MAC.

Tạo file `HardwareFingerprint.cs` trong dự án C# của bạn:

```csharp
using System;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;

namespace StationMonitor.Services.License
{
    public static class HardwareFingerprint
    {
        public static string GetCpuID()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        return obj["ProcessorId"]?.ToString().Trim() ?? "UNKNOWN_CPU";
                    }
                }
            }
            catch { }
            return "UNKNOWN_CPU";
        }

        public static string GetMotherboardUUID()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        return obj["UUID"]?.ToString().Trim() ?? "UNKNOWN_MB";
                    }
                }
            }
            catch { }
            return "UNKNOWN_MB";
        }

        /// <summary>
        /// Lấy Serial Number của ổ đĩa cứng vật lý chứa phân vùng hệ điều hành C:
        /// Giúp tránh lỗi nhận diện sai khi cắm thêm ổ cứng di động hoặc USB ngoài.
        /// </summary>
        public static string GetOSDiskSerial()
        {
            try
            {
                string driveLetter = "C:";
                string partitionId = "";
                
                // 1. Tìm Partition liên kết với ổ đĩa C:
                using (var searcher = new ManagementObjectSearcher($"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{driveLetter}'}} WHERE AssocClass = Win32_LogicalDiskToPartition"))
                {
                    foreach (var partition in searcher.Get())
                    {
                        partitionId = partition["DeviceID"]?.ToString() ?? "";
                        break;
                    }
                }

                if (!string.IsNullOrEmpty(partitionId))
                {
                    // 2. Tìm Disk Drive vật lý liên kết với Partition đó
                    using (var searcher = new ManagementObjectSearcher($"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{partitionId}'}} WHERE AssocClass = Win32_DiskDriveToPartition"))
                    {
                        foreach (var drive in searcher.Get())
                        {
                            return drive["SerialNumber"]?.ToString().Trim() ?? "UNKNOWN_DISK";
                        }
                    }
                }
            }
            catch { }
            return "UNKNOWN_DISK";
        }

        public static string GetStableMacAddress()
        {
            try
            {
                var nics = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var nic in nics)
                {
                    // Chỉ lấy card mạng vật lý đang hoạt động, loại bỏ card ảo và VPN
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet && 
                        !nic.Description.ToLower().Contains("virtual") &&
                        !nic.Description.ToLower().Contains("vpn") &&
                        !nic.Description.ToLower().Contains("vmware") &&
                        !nic.Description.ToLower().Contains("virtualbox") &&
                        !nic.Description.ToLower().Contains("pseudo") &&
                        nic.OperationalStatus == OperationalStatus.Up)
                    {
                        string mac = nic.GetPhysicalAddress().ToString();
                        if (!string.IsNullOrEmpty(mac)) return mac;
                    }
                }
            }
            catch { }
            return "NO_MAC";
        }

        public static string GetSha256Hash(string input)
        {
            using (var sha = SHA256.Create())
            {
                byte[] bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
                var sb = new StringBuilder();
                foreach (byte b in bytes)
                {
                    sb.Append(b.ToString("X2"));
                }
                return sb.ToString().Substring(0, 8); // Lấy 8 ký tự đầu để mã hóa key gọn gàng
            }
        }

        /// <summary>
        /// Tạo File Request Bản Quyền (.licreq) chứa fingerprint của máy trạm.
        /// Định dạng: REQ-[CPU_HASH]_[MB_HASH]_[DISK_HASH]-[StableMAC]-[Signature]
        /// </summary>
        public static string GenerateRequestString()
        {
            string cpu = GetCpuID();
            string mb = GetMotherboardUUID();
            string disk = GetOSDiskSerial();
            string mac = GetStableMacAddress();

            string hCpu = GetSha256Hash(cpu);
            string hMb = GetSha256Hash(mb);
            string hDisk = GetSha256Hash(disk);

            return $"REQ-{hCpu}_{hMb}_{hDisk}-{mac}";
        }
    }
}
```

---

## 2. Mô hình Bản Quyền & Xác Thực Fuzzy Match (LicenseParser.cs)

Tạo file `LicenseParser.cs` trong dự án C# của bạn. Lớp này định nghĩa cấu trúc JSON của License, thực hiện tuần tự hóa chuẩn hóa (Canonical JSON) để tính toán chữ ký số và so khớp phần cứng **Fuzzy Match 2/3**:

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace StationMonitor.Services.License
{
    public class HardwareInfo
    {
        public string cpuId { get; set; }
        public string mainboardUuid { get; set; }
        public string osDiskSerial { get; set; }
    }

    public class LicenseLimits
    {
        public int users { get; set; }
        public int stations { get; set; }
        public int cameras { get; set; }
        public int roiPoints { get; set; }
        public int roiRegions { get; set; }
        public int pdRegions { get; set; }
    }

    public class LicenseJsonModel
    {
        public int version { get; set; }
        public string kind { get; set; } // "base" hoặc "addon"
        public string licenseId { get; set; }
        public string addonId { get; set; } // Chỉ dành cho addon
        public string baseLicenseId { get; set; } // Chỉ dành cho addon
        public string tier { get; set; }
        public string issuedAtUtc { get; set; }
        public string expiresAtUtc { get; set; }
        public HardwareInfo hardware { get; set; }
        public LicenseLimits limits { get; set; }
        public string signature { get; set; }
    }

    public static class LicenseParser
    {
        private static string GetHmacSha256(string message, string secret)
        {
            var keyByte = Encoding.UTF8.GetBytes(secret);
            using (var hmac = new HMACSHA256(keyByte))
            {
                var messageBytes = Encoding.UTF8.GetBytes(message);
                var hashMessage = hmac.ComputeHash(messageBytes);
                return BitConverter.ToString(hashMessage).Replace("-", "").ToLower();
            }
        }

        /// <summary>
        /// Tạo chuỗi JSON chuẩn hóa (Canonical JSON) với các key được sắp xếp theo thứ tự bảng chữ cái.
        /// Sử dụng để đảm bảo tính đồng nhất của dữ liệu ký giữa Python và C#.
        /// </summary>
        public static string GetCanonicalJson(LicenseJsonModel model)
        {
            var dict = new SortedDictionary<string, object>();
            dict.Add("version", model.version);
            dict.Add("kind", model.kind);
            dict.Add("licenseId", model.licenseId);
            
            if (model.kind == "addon")
            {
                dict.Add("addonId", model.addonId);
                dict.Add("baseLicenseId", model.baseLicenseId);
            }
            
            dict.Add("tier", model.tier);
            dict.Add("issuedAtUtc", model.issuedAtUtc);
            dict.Add("expiresAtUtc", model.expiresAtUtc);

            var hwDict = new SortedDictionary<string, string>();
            hwDict.Add("cpuId", model.hardware?.cpuId ?? "");
            hwDict.Add("mainboardUuid", model.hardware?.mainboardUuid ?? "");
            hwDict.Add("osDiskSerial", model.hardware?.osDiskSerial ?? "");
            dict.Add("hardware", hwDict);

            var limDict = new SortedDictionary<string, int>();
            limDict.Add("users", model.limits?.users ?? 0);
            limDict.Add("stations", model.limits?.stations ?? 0);
            limDict.Add("cameras", model.limits?.cameras ?? 0);
            limDict.Add("roiPoints", model.limits?.roiPoints ?? 0);
            limDict.Add("roiRegions", model.limits?.roiRegions ?? 0);
            limDict.Add("pdRegions", model.limits?.pdRegions ?? 0);
            dict.Add("limits", limDict);

            return JsonSerializer.Serialize(dict, new JsonSerializerOptions { WriteIndented = false });
        }

        /// <summary>
        /// Đọc và xác thực cấu trúc JSON + chữ ký số của License.
        /// </summary>
        public static LicenseJsonModel ParseLicense(string jsonContent, string vendorSecret)
        {
            if (string.IsNullOrWhiteSpace(jsonContent)) return null;

            try
            {
                var model = JsonSerializer.Deserialize<LicenseJsonModel>(jsonContent);
                if (model == null) return null;

                // 1. Xác thực chữ ký số HMAC-SHA256 trên Canonical JSON
                string canonical = GetCanonicalJson(model);
                string computedSig = GetHmacSha256(canonical, vendorSecret);

                if (!string.Equals(model.signature, computedSig, StringComparison.OrdinalIgnoreCase))
                {
                    return null; // Sai chữ ký bảo mật
                }

                // 2. Xác thực thời hạn sử dụng
                if (DateTime.TryParse(model.expiresAtUtc, out DateTime expDate))
                {
                    if (expDate.ToUniversalTime() < DateTime.UtcNow)
                    {
                        return null; // Đã hết hạn
                    }
                }

                // 3. Kiểm tra liên kết phần cứng (Fuzzy Match 2/3)
                if (!VerifyHardwareFuzzy(model.hardware))
                {
                    return null; // Phần cứng không khớp
                }

                return model;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Thuật toán Fuzzy Matching (Khớp 2 trên 3 tiêu chí phần cứng)
        /// </summary>
        public static bool VerifyHardwareFuzzy(HardwareInfo licenseHw)
        {
            if (licenseHw == null) return false;

            // Lấy vân tay của máy hiện tại
            string currentCpu = HardwareFingerprint.GetSha256Hash(HardwareFingerprint.GetCpuID());
            string currentMb = HardwareFingerprint.GetSha256Hash(HardwareFingerprint.GetMotherboardUUID());
            string currentDisk = HardwareFingerprint.GetSha256Hash(HardwareFingerprint.GetOSDiskSerial());

            int matchCount = 0;
            if (string.Equals(licenseHw.cpuId, currentCpu, StringComparison.OrdinalIgnoreCase)) matchCount++;
            if (string.Equals(licenseHw.mainboardUuid, currentMb, StringComparison.OrdinalIgnoreCase)) matchCount++;
            if (string.Equals(licenseHw.osDiskSerial, currentDisk, StringComparison.OrdinalIgnoreCase)) matchCount++;

            return matchCount >= 2;
        }
    }
}
```

---

## 3. Quản Lý File & Cộng Dồn Tài Nguyên (LicenseManager.cs)

Tạo file `LicenseManager.cs`. Lớp này quét thư mục bản quyền, kiểm tra file gốc `base.lic` và tổng hợp tất cả các gói nâng cấp add-on hợp lệ để cung cấp thông số tài nguyên thực tế cho phần mềm:

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace StationMonitor.Services.License
{
    public class LicenseManager
    {
        private readonly string _licenseDirectory;
        private readonly string _vendorSecret;

        // Các giới hạn tài nguyên tổng hợp sau khi cộng dồn
        public int AllowedUsers { get; private set; } = 1;
        public int AllowedStations { get; private set; } = 10;
        public int AllowedCameras { get; private set; } = 0;
        public int AllowedRoiPoints { get; private set; } = 50;
        public int AllowedRoiRegions { get; private set; } = 50;
        public int AllowedPdRegions { get; private set; } = 50;

        public bool IsSystemLicensed { get; private set; } = false;
        public string LicenseTier { get; private set; } = "CML-DEMO";
        public DateTime? ExpirationDate { get; private set; }

        public LicenseManager(string licenseDirectory, string vendorSecret)
        {
            _licenseDirectory = licenseDirectory;
            _vendorSecret = vendorSecret;
            ReloadLicenses();
        }

        /// <summary>
        /// Quét thư mục và tính toán tổng số lượng tài nguyên cộng dồn.
        /// </summary>
        public void ReloadLicenses()
        {
            // Reset về mặc định dùng thử
            AllowedUsers = 1;
            AllowedStations = 10;
            AllowedCameras = 0;
            AllowedRoiPoints = 50;
            AllowedRoiRegions = 50;
            AllowedPdRegions = 50;
            IsSystemLicensed = false;
            LicenseTier = "CML-DEMO";
            ExpirationDate = null;

            if (!Directory.Exists(_licenseDirectory)) return;

            // 1. Quét Base License
            string baseLicensePath = Path.Combine(_licenseDirectory, "base.lic");
            if (!File.Exists(baseLicensePath)) return;

            string baseJson = File.ReadAllText(baseLicensePath).Trim();
            var baseLicense = LicenseParser.ParseLicense(baseJson, _vendorSecret);

            if (baseLicense == null || baseLicense.kind != "base")
            {
                return; // Base License không hợp lệ
            }

            // Gán tài nguyên nền
            IsSystemLicensed = true;
            LicenseTier = baseLicense.tier;
            if (DateTime.TryParse(baseLicense.expiresAtUtc, out DateTime expDate))
            {
                ExpirationDate = expDate;
            }

            AllowedUsers = baseLicense.limits.users;
            AllowedStations = baseLicense.limits.stations;
            AllowedCameras = baseLicense.limits.cameras;
            AllowedRoiPoints = baseLicense.limits.roiPoints;
            AllowedRoiRegions = baseLicense.limits.roiRegions;
            AllowedPdRegions = baseLicense.limits.pdRegions;

            // 2. Quét và cộng dồn các gói nâng cấp Add-on
            var addonFiles = Directory.GetFiles(_licenseDirectory, "addon_*.lic");
            var loadedAddonIds = new HashSet<string>();

            foreach (var file in addonFiles)
            {
                try
                {
                    string addonJson = File.ReadAllText(file).Trim();
                    var addon = LicenseParser.ParseLicense(addonJson, _vendorSecret);

                    if (addon != null && addon.kind == "addon" && addon.baseLicenseId == baseLicense.licenseId)
                    {
                        // Chống lặp file (cheat bản quyền bằng cách copy nhân bản file .lic)
                        if (!loadedAddonIds.Contains(addon.addonId))
                        {
                            loadedAddonIds.Add(addon.addonId);

                            // Cộng dồn tài nguyên
                            AllowedUsers += addon.limits.users;
                            AllowedStations += addon.limits.stations;
                            AllowedCameras += addon.limits.cameras;
                            AllowedRoiPoints += addon.limits.roiPoints;
                            AllowedRoiRegions += addon.limits.roiRegions;
                            AllowedPdRegions += addon.limits.pdRegions;
                        }
                    }
                }
                catch
                {
                    // Bỏ qua nếu file add-on bị lỗi cấu trúc
                }
            }
        }
    }
}
```


---

## 4. Cách Sử Dụng Trong Backend API

Đăng ký `LicenseManager` như một Singleton Service trong `Program.cs` / `Startup.cs`:

```csharp
builder.Services.AddSingleton<LicenseManager>(sp => {
    var config = sp.GetRequiredService<IConfiguration>();
    string licenseDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Licenses");
    string secret = config["VendorSecret"] ?? "station_monitor_default_secret_key";
    
    // Tự động tạo thư mục nếu chưa tồn tại
    if (!Directory.Exists(licenseDir)) Directory.CreateDirectory(licenseDir);
    
    return new LicenseManager(licenseDir, secret);
});
```

Sau đó Inject vào Controllers để thực hiện kiểm tra:

```csharp
[ApiController]
[Route("api/v1/[controller]")]
public class CamerasController : ControllerBase
{
    private readonly LicenseManager _licenseManager;
    private readonly AppDbContext _db;

    public CamerasController(LicenseManager licenseManager, AppDbContext db)
    {
        _licenseManager = licenseManager;
        _db = db;
    }

    [HttpPost]
    public async Task<IActionResult> AddCamera([FromBody] CameraDto dto)
    {
        // 1. Kiểm tra trạng thái hệ thống
        if (!_licenseManager.IsSystemLicensed)
        {
            return StatusCode(403, "Hệ thống chưa được kích hoạt bản quyền hợp lệ.");
        }

        // 2. So sánh giới hạn camera thực tế (Đã cộng dồn)
        int currentCount = await _db.Cameras.CountAsync();
        if (currentCount >= _licenseManager.AllowedCameras)
        {
            return BadRequest($"Vượt quá giới hạn Camera cho phép ({currentCount}/{_licenseManager.AllowedCameras}). Vui lòng thêm file Add-on Camera.");
        }

        // ... Thêm camera ...
    }
}
```
