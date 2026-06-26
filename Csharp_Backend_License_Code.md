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

Cập nhật `LicenseParser.cs` để hỗ trợ giải mã Hardware ID và thực hiện thuật toán **Fuzzy Matching 2-out-of-3**:

```csharp
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace StationMonitor.Services.License
{
    public class LicenseModel
    {
        public string Tier { get; set; } = "CML";
        public DateTime? ExpiresAt { get; set; }
        public int MaxConcurrentSessions { get; set; } = 1;
        public int MaxDevices { get; set; } = 10;
        public int MaxCameras { get; set; } = 0;
        public int MaxPoints { get; set; } = 50;
        public int MaxRoi { get; set; } = 50;
        public int MaxPd { get; set; } = 50;
        public string BoundHardwareID { get; set; } = "ANY";
        public bool IsValid { get; set; } = false;
    }

    public class AddonModel
    {
        public string Guid { get; set; }
        public string ResourceType { get; set; } // "CAM" hoặc "SEN"
        public int Quantity { get; set; }
        public string BoundHardwareID { get; set; }
        public bool IsValid { get; set; }
    }

    public static class LicenseParser
    {
        private static string GetHmacSha256(string message, string secret)
        {
            var keyByte = Encoding.UTF8.GetBytes(secret);
            using (var hmac = new HMACSHA256(keyByte))
            {
                var messageBytes = Encoding.UTF8.GetBytes(message);
                var hashmessage = hmac.ComputeHash(messageBytes);
                return BitConverter.ToString(hashmessage).Replace("-", "").ToLower();
            }
        }

        /// <summary>
        /// Giải mã và xác thực chữ ký HMAC của Base License.
        /// </summary>
        public static LicenseModel ParseKey(string key, string vendorSecret)
        {
            var model = new LicenseModel { IsValid = false };
            if (string.IsNullOrWhiteSpace(key)) return model;

            try
            {
                var parts = key.Trim().Split('-');
                if (parts.Length < 6) return model;

                // Xác thực chữ ký HMAC (vị trí cuối cùng)
                string signature = parts.Last().ToLower();
                string payload = string.Join("-", parts.Take(parts.Length - 1));
                string computedSig = GetHmacSha256(payload, vendorSecret);

                if (signature != computedSig)
                {
                    return model; // Chữ ký HMAC sai
                }

                // Tìm vị trí ngày hết hạn (6 chữ số)
                int expIndex = -1;
                for (int i = 0; i < parts.Length; i++)
                {
                    if (parts[i].Length == 6 && parts[i].All(char.IsDigit))
                    {
                        expIndex = i;
                        break;
                    }
                }

                if (expIndex == -1) return model;

                model.Tier = string.Join("-", parts.Take(expIndex));
                string expStr = parts[expIndex];
                int yy = int.Parse(expStr.Substring(0, 2)) + 2000;
                int mm = int.Parse(expStr.Substring(2, 2));
                int dd = int.Parse(expStr.Substring(4, 2));
                model.ExpiresAt = new DateTime(yy, mm, dd, 23, 59, 59, DateTimeKind.Utc);

                model.MaxConcurrentSessions = int.Parse(parts[expIndex + 1]);

                int nonceIndex = parts.Length - 2;
                int remainingParams = nonceIndex - (expIndex + 2);

                if (remainingParams >= 6)
                {
                    model.MaxDevices = int.Parse(parts[expIndex + 2]);
                    model.MaxCameras = int.Parse(parts[expIndex + 3]);
                    model.MaxPoints = int.Parse(parts[expIndex + 4]);
                    model.MaxRoi = int.Parse(parts[expIndex + 5]);
                    model.MaxPd = int.Parse(parts[expIndex + 6]);
                    model.BoundHardwareID = parts[expIndex + 7]; // HASH_CPU_MB_DISK hoặc ANY
                }
                else
                {
                    model.MaxDevices = 10;
                    model.MaxCameras = 0;
                    model.MaxPoints = 50;
                    model.MaxRoi = 50;
                    model.MaxPd = 50;
                }

                // Kiểm tra Hardware ID (Fuzzy Match 2/3)
                if (model.BoundHardwareID != "ANY" && !VerifyHardwareFuzzy(model.BoundHardwareID))
                {
                    return model; // Hardware không trùng khớp
                }

                model.IsValid = true;
            }
            catch
            {
                model.IsValid = false;
            }

            return model;
        }

        /// <summary>
        /// Giải mã và xác thực gói nâng cấp Add-on.
        /// Định dạng: ADDON-[GUID]-[UpgradeType]-[Quantity]-[BoundHWID]-[Nonce]-[HMAC]
        /// </summary>
        public static AddonModel ParseAddonKey(string key, string vendorSecret)
        {
            var model = new AddonModel { IsValid = false };
            if (string.IsNullOrWhiteSpace(key)) return model;

            try
            {
                var parts = key.Trim().Split('-');
                if (parts.Length < 7 || parts[0] != "ADDON") return model;

                // Kiểm tra chữ ký HMAC
                string signature = parts.Last().ToLower();
                string payload = string.Join("-", parts.Take(parts.Length - 1));
                string computedSig = GetHmacSha256(payload, vendorSecret);

                if (signature != computedSig) return model;

                model.Guid = parts[1];
                model.ResourceType = parts[2]; // CAM hoặc SEN
                model.Quantity = int.Parse(parts[3]);
                model.BoundHardwareID = parts[4];
                
                // Xác thực Hardware Lock
                if (model.BoundHardwareID != "ANY" && !VerifyHardwareFuzzy(model.BoundHardwareID))
                {
                    return model;
                }

                model.IsValid = true;
            }
            catch
            {
                model.IsValid = false;
            }

            return model;
        }

        /// <summary>
        /// Thuật toán Fuzzy Matching (Khớp 2 trên 3 tiêu chí phần cứng)
        /// Tránh trường hợp đổi phần cứng nhỏ (ví dụ đổi ổ đĩa phụ, cắm thêm USB) làm rớt License.
        /// </summary>
        public static bool VerifyHardwareFuzzy(string licenseHwId)
        {
            if (licenseHwId == "ANY") return true;

            var licensedParts = licenseHwId.Split('_');
            if (licensedParts.Length != 3) return false;

            string licCpu = licensedParts[0];
            string licMb = licensedParts[1];
            string licDisk = licensedParts[2];

            // Lấy vân tay của máy hiện tại
            string currentCpu = HardwareFingerprint.GetSha256Hash(HardwareFingerprint.GetCpuID());
            string currentMb = HardwareFingerprint.GetSha256Hash(HardwareFingerprint.GetMotherboardUUID());
            string currentDisk = HardwareFingerprint.GetSha256Hash(HardwareFingerprint.GetOSDiskSerial());

            int matchCount = 0;
            if (licCpu.Equals(currentCpu, StringComparison.OrdinalIgnoreCase)) matchCount++;
            if (licMb.Equals(currentMb, StringComparison.OrdinalIgnoreCase)) matchCount++;
            if (licDisk.Equals(currentDisk, StringComparison.OrdinalIgnoreCase)) matchCount++;

            // Chỉ cần trùng khớp tối thiểu 2 trong số 3 tiêu chí phần cứng
            return matchCount >= 2;
        }
    }
}
```

---

## 3. Quản Lý File & Cộng Dồn Tài Nguyên (LicenseManager.cs)

Lớp này quét thư mục chứa License, lấy File bản quyền chính (`base.lic`) và toàn bộ file Add-on (`addon_*.lic`), sau đó thực hiện kiểm tra chữ ký, lọc trùng lặp GUID để tính toán tài nguyên thực tế được cấp phép:

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

        // Kết quả tài nguyên tổng hợp sau khi cộng dồn
        public int AllowedDevices { get; private set; } = 10; // Mặc định gói CML
        public int AllowedCameras { get; private set; } = 0;
        public int AllowedSensors { get; private set; } = 50;
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
        /// Đọc toàn bộ thư mục và tính toán tổng số lượng tài nguyên cộng dồn hợp lệ.
        /// </summary>
        public void ReloadLicenses()
        {
            // Reset tài nguyên mặc định
            AllowedDevices = 10;
            AllowedCameras = 0;
            AllowedSensors = 50;
            IsSystemLicensed = false;
            LicenseTier = "CML-DEMO";
            ExpirationDate = null;

            if (!Directory.Exists(_licenseDirectory))
            {
                return;
            }

            // 1. Quét tìm Base License
            string baseLicensePath = Path.Combine(_licenseDirectory, "base.lic");
            if (!File.Exists(baseLicensePath))
            {
                // Nếu không có file base.lic cụ thể, lấy file .lic có độ dài chuỗi dài nhất
                var licFiles = Directory.GetFiles(_licenseDirectory, "*.lic");
                baseLicensePath = licFiles.FirstOrDefault(f => !Path.GetFileName(f).StartsWith("addon_"));
            }

            if (baseLicensePath == null || !File.Exists(baseLicensePath))
            {
                return; // Không có Base License thì không thể cộng dồn Add-on
            }

            string baseKey = File.ReadAllText(baseLicensePath).Trim();
            var baseLicense = LicenseParser.ParseKey(baseKey, _vendorSecret);

            if (!baseLicense.IsValid)
            {
                return; // Base License không hợp lệ hoặc sai chữ ký
            }

            if (baseLicense.ExpiresAt.HasValue && baseLicense.ExpiresAt < DateTime.UtcNow)
            {
                return; // Base License đã hết hạn
            }

            // Gán tài nguyên gốc từ Base License
            IsSystemLicensed = true;
            LicenseTier = baseLicense.Tier;
            ExpirationDate = baseLicense.ExpiresAt;
            AllowedDevices = baseLicense.MaxDevices;
            AllowedCameras = baseLicense.MaxCameras;
            AllowedSensors = baseLicense.MaxPoints;

            // 2. Quét và cộng dồn các gói Add-on
            var addonFiles = Directory.GetFiles(_licenseDirectory, "addon_*.lic");
            var loadedAddonGuids = new HashSet<string>(); // Chống chép đè/sao chép nhiều file giống nhau

            foreach (var file in addonFiles)
            {
                try
                {
                    string addonKey = File.ReadAllText(file).Trim();
                    var addon = LicenseParser.ParseAddonKey(addonKey, _vendorSecret);

                    if (addon.IsValid)
                    {
                        // Kiểm tra xem GUID của add-on đã được đọc chưa để tránh lặp lại (copy cheat)
                        if (!loadedAddonGuids.Contains(addon.Guid))
                        {
                            loadedAddonGuids.Add(addon.Guid);

                            // Cộng dồn tài nguyên
                            if (addon.ResourceType == "CAM")
                            {
                                AllowedCameras += addon.Quantity;
                            }
                            else if (addon.ResourceType == "SEN")
                            {
                                AllowedSensors += addon.Quantity;
                            }
                        }
                    }
                }
                catch
                {
                    // Bỏ qua file addon bị hỏng
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
