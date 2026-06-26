# BÁO CÁO TRIỂN KHAI HỆ THỐNG LICENSE OFFLINE & CỘNG DỒN (ADD-ON)
*Hệ thống Giám sát StationMonitor — Lập bởi Antigravity AI*

Tài liệu này tóm tắt ngắn gọn và chi tiết các nâng cấp kỹ thuật đã thực hiện trên Admin Dashboard (Python/Streamlit) và Backend (C#) để triển khai cơ chế bản quyền ngoại tuyến an toàn, chống drift phần cứng và hỗ trợ nâng cấp tài nguyên cộng dồn.

---

## 1. Các File Đã Cập Nhật & Vai Trò

| Tên File | Loại Thay Đổi | Chi Tiết Thực Hiện |
| :--- | :--- | :--- |
| **generate_license_streamlit.py** | **Code Python** | <ul><li>Thêm trường nhập **Hardware ID / MAC** khi tạo Base License.</li><li>Tích hợp trang **Add-on Upgrades** cho phép tạo khóa nâng cấp cộng dồn (Camera/Sensor) dựa theo Base Key.</li><li>Thêm bảng `LicenseAddons` vào database để lưu vết các nâng cấp đã cấp.</li></ul> |
| **Csharp_Backend_License_Code.md** | **Tài liệu Hướng dẫn & Code C#** | <ul><li>**HardwareFingerprint.cs**: Định danh phần cứng bằng CPU ID, Mainboard UUID và Serial của ổ cứng chứa hệ điều hành `C:` (loại bỏ USB/External Disk), lọc card mạng ảo/VPN.</li><li>**LicenseParser.cs**: Xác thực chữ ký HMAC và kiểm tra **Fuzzy Match (Khớp 2/3)**.</li><li>**LicenseManager.cs**: Quét thư mục License, lọc trùng GUID nâng cấp và cộng dồn giới hạn tài nguyên.</li></ul> |

---

## 2. Định Dạng Payload Chuỗi Key

### A. Khóa Bản Quyền Chính (Base License Key)
Được ký bằng HMAC-SHA256, cấu trúc gồm 12 phần được ngăn cách bằng dấu `-`:
`[Tier]-[Expiry]-[Sessions]-[Devices]-[Cameras]-[Sensors]-[Roi]-[Pd]-[HWID]-[Nonce]-[HMAC]`

*   **HWID**: Định dạng `[CPU_HASH]_[MB_HASH]_[DISK_HASH]` (mỗi phần 8 ký tự mã hóa SHA256) hoặc `ANY` (không khóa cứng).
*   **Ví dụ**: `CML-SDL500-291231-3-15-10-500-50-50-A1B2C3D4_E5F67890_99998888-F8E2-6ea4cff2...`

### B. Khóa Nâng Cấp Cộng Dồn (Add-on Key)
Sử dụng tiền tố `ADDON`, hỗ trợ nạp nhiều file nâng cấp mà không cần đổi file bản quyền gốc:
`ADDON-[GUID]-[UpgradeType]-[Quantity]-[BoundHWID]-[Nonce]-[HMAC]`

| Trường | Giải Thích | Ví dụ |
| :--- | :--- | :--- |
| **GUID** | Chuỗi định danh duy nhất của gói nâng cấp để chống sao chép file. | `ADD8A9F` |
| **UpgradeType** | Loại tài nguyên cộng thêm: `CAM` (Camera) hoặc `SEN` (Sensor). | `CAM` |
| **Quantity** | Số lượng tài nguyên được cộng thêm vào hệ thống. | `5` (cộng thêm 5 camera) |
| **BoundHWID** | Khóa HWID đi kèm để đảm bảo gói nâng cấp chỉ chạy trên máy trạm đó. | `A1B2C3D4_E5F67890_99998888` |

---

## 3. Quy Trình Xác Thực Phần Cứng Fuzzy Match (Khớp 2/3)

Để khắc phục hiện tượng lỗi nhận diện khi cắm/rút thiết bị lưu trữ ngoài hoặc thay ổ đĩa phụ, hệ thống thực hiện so khớp 3 thành phần độc lập:

| Thành Phần Phần Cứng | Cơ Chế Lấy Thông Tin (C# WMI) | Cách Thức Chống Drift / Lọc Nhiễu |
| :--- | :--- | :--- |
| **1. CPU ID** | Query trường `ProcessorId` từ lớp `Win32_Processor`. | Cố định, không đổi trừ khi thay CPU. |
| **2. Motherboard UUID** | Query trường `UUID` từ lớp `Win32_ComputerSystemProduct`. | Vân tay bo mạch chủ, cố định vĩnh viễn. |
| **3. OS Disk Serial** | Truy vấn qua liên kết: `LogicalDisk C:` -> `DiskPartition` -> `Physical Disk Serial`. | Chỉ lấy serial của ổ đĩa vật lý chứa hệ điều hành, **không bị ảnh hưởng khi cắm/rút USB hay ổ cứng ngoài**. |

> [!IMPORTANT]
> **Thuật toán Fuzzy Match C#**: So sánh 3 mã băm (SHA256) trên máy trạm với mã băm lưu trong License Key. Chỉ cần **tối thiểu 2 trên 3 thành phần trùng khớp**, License được chấp nhận là hợp lệ.

---

## 4. Cấu Trúc Bảng Dữ Liệu Lưu Trữ Add-on (`LicenseAddons`)

Bảng này được tự động tạo trong SQLite/PostgreSQL để quản lý lịch sử phân phối các gói nâng cấp:

| Tên Cột | Kiểu Dữ Liệu | Khóa | Mô Tả |
| :--- | :--- | :--- | :--- |
| **Id** | VARCHAR(100) | Primary Key | GUID duy nhất của gói Add-on. |
| **BaseKeyId** | VARCHAR(100) | Foreign Key | ID hoặc Key của License gốc được nâng cấp. |
| **ResourceType** | VARCHAR(50) | - | `CAM` hoặc `SEN` |
| **Quantity** | INTEGER | - | Số lượng camera hoặc cảm biến cộng thêm. |
| **AddonKey** | TEXT | - | Toàn bộ chuỗi key đã ký HMAC. |
| **IssuedTo** | VARCHAR(200) | - | Tên đơn vị / khách hàng nhận gói nâng cấp. |
| **HardwareID** | VARCHAR(100) | - | HWID của máy trạm được khóa. |
| **CreatedAt** | VARCHAR(50) | - | Thời gian cấp phát (YYYY-MM-DD HH:MM:SS). |

---

## 5. Cơ Chế Cộng Dồn Tài Nguyên Tại Trạm Tổng (C# Service)

Lập trình viên khi triển khai lớp `LicenseManager.cs` sẽ nạp tài nguyên theo quy trình sau:
1. Đọc và giải mã file bản quyền gốc `base.lic`. Lưu các thông số gốc (Ví dụ: `BaseCameras = 0`, `BaseSensors = 50`).
2. Quét toàn bộ các file `addon_*.lic` trong thư mục bản quyền.
3. Với mỗi file Add-on hợp lệ (đúng chữ ký HMAC và đúng HWID):
   - Đọc `GUID` của Add-on. Nếu GUID này **chưa từng được đọc**, thêm vào bộ nhớ tạm để tránh cộng dồn lặp lại (Chống chép đè file gian lận).
   - Cộng dồn: `AllowedCameras = BaseCameras + Sum(Addon.Quantity)`.
4. Toàn bộ API nghiệp vụ (thêm trạm, thêm camera) sẽ gọi `LicenseManager.AllowedCameras` và `LicenseManager.AllowedSensors` để kiểm soát giới hạn.
