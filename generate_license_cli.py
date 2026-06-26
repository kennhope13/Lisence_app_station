#!/usr/bin/env python3
"""
Trình tạo Giftcode (bản quyền) – Phiên bản dòng lệnh (CLI).

Ví dụ sử dụng:
  # Cung cấp mã bí mật vendor secret
  python generate_license_cli.py --secret YOUR_VENDOR_SECRET

  # Với các tùy chọn nâng cao
  python generate_license_cli.py \
      --secret YOUR_VENDOR_SECRET \
      --tier SOLO \
      --expire 231231 \
      --max-devices 2 \
      --max-cameras 5 \
      --max-points 5 \
      --max-roi 5 \
      --max-pd 5
"""

import argparse
import json
import os
import secrets
from datetime import datetime, timedelta
import hmac
import hashlib

# ----------------------------------------------------------------------
# Đường dẫn & mặc định
# ----------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_FILE = os.path.join(BASE_DIR, "generated_keys.json")


def load_keys() -> list:
    """Tải danh sách các key hiện có từ file JSON."""
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_keys(keys: list) -> None:
    """Lưu danh sách key vào file JSON."""
    try:
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(keys, f, indent=4, ensure_ascii=False)
    except Exception as e:
        raise RuntimeError(f"Không thể ghi file dữ liệu: {e}")


def default_expire(days: int = 365) -> str:
    """Trả về chuỗi YYMMDD cho ngày sau `days` ngày."""
    future = datetime.now() + timedelta(days=days)
    return future.strftime("%y%m%d")

def detect_vendor_secret():
    """Tìm kiếm file appsettings.json ở các vị trí tương đối phổ biến."""
    search_paths = [
        "appsettings.json",
        "../appsettings.json",
        "../backend/StationOS.Api/appsettings.json",
        "backend/StationOS.Api/appsettings.json",
    ]
    try:
        # Thử tìm từ thư mục cha của thư mục hiện tại (thường là root của project)
        base_dir = os.path.dirname(BASE_DIR)
        search_paths.append(os.path.join(base_dir, "backend", "StationOS.Api", "appsettings.json"))
    except:
        pass

    for path in search_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    secret = cfg.get("License", {}).get("VendorSecret")
                    if secret and secret != "THIET_LAP_TRONG_BIEN_MOI_TRUONG_STATIONOS_VENDOR_SECRET":
                        return secret
            except Exception:
                pass
    return None

# ----------------------------------------------------------------------
# Xử lý đối số
# ----------------------------------------------------------------------
def parse_args():
    detected_secret = detect_vendor_secret()
    parser = argparse.ArgumentParser(
        description="Tạo Giftcode (mã bản quyền) cho StationMonitor."
    )
    parser.add_argument(
        "--secret",
        default=detected_secret,
        required=not detected_secret,
        help="Mã bí mật (Vendor secret) dùng để tạo HMAC. Mặc định tự tìm trong appsettings.json.",
    )
    parser.add_argument(
        "--tier",
        choices=["SOLO", "TEAM", "ENT"],
        default="SOLO",
        help="Cấp độ sản phẩm (Tier). Mặc định: SOLO.",
    )
    parser.add_argument(
        "--expire",
        default=default_expire(),
        help="Ngày hết hạn định dạng YYMMDD. Mặc định: 1 năm kể từ hôm nay.",
    )
    # Các giới hạn nâng cao
    parser.add_argument("--max-devices", type=int, default=None, help="Số thiết bị tối đa.")
    parser.add_argument("--max-cameras", type=int, default=None, help="Số camera tối đa.")
    parser.add_argument("--max-points", type=int, default=None, help="Số điểm nhiệt tối đa.")
    parser.add_argument("--max-roi", type=int, default=None, help="Số vùng nhiệt tối đa.")
    parser.add_argument("--max-pd", type=int, default=None, help="Số vùng phóng điện tối đa.")
    return parser.parse_args()

# ----------------------------------------------------------------------
# Tạo mã
# ----------------------------------------------------------------------
def build_payload(args) -> str:
    """Xây dựng chuỗi payload."""
    if any(
        v is not None
        for v in (
            args.max_devices,
            args.max_cameras,
            args.max_points,
            args.max_roi,
            args.max_pd,
        )
    ):
        limits = [
            str(args.max_devices or 5),
            str(args.max_cameras or 5),
            str(args.max_points or 5),
            str(args.max_roi or 5),
            str(args.max_pd or 5),
        ]
        return f"{args.tier.upper()}-{args.expire}-{'-'.join(limits)}"
    else:
        return f"{args.tier.upper()}-{args.expire}"


def generate_key(secret: str, payload: str) -> str:
    """Tạo key cuối cùng với hậu tố HMAC 8 ký tự."""
    nonce = secrets.token_hex(2).upper()
    data_bytes = f"{payload}-{nonce}".encode("utf-8")
    h = hmac.new(secret.encode("utf-8"), data_bytes, hashlib.sha256)
    hmac8 = h.digest().hex().upper()[:8]
    return f"{payload}-{nonce}-{hmac8}"

# ----------------------------------------------------------------------
# Điểm chạy chính
# ----------------------------------------------------------------------
def main():
    args = parse_args()

    payload = build_payload(args)
    final_key = generate_key(args.secret, payload)

    entry = {
        "key": final_key,
        "tier": args.tier.upper(),
        "expire_date": args.expire,
        "nonce": final_key.split("-")[-2],
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    keys = load_keys()
    keys.append(entry)
    save_keys(keys)

    print("\n✅ Tạo mã bản quyền thành công!\n")
    print(f"Mã (Key): {final_key}\n")
    print("Chi tiết:")
    print(f"  • Cấp độ (Tier)  : {entry['tier']}")
    print(f"  • Hết hạn        : 20{entry['expire_date'][:2]}-{entry['expire_date'][2:4]}-{entry['expire_date'][4:6]}")
    print(f"  • Mã ngẫu nhiên  : {entry['nonce']}")
    print(f"  • Thời điểm tạo  : {entry['created_at']}\n")

if __name__ == "__main__":
    main()
