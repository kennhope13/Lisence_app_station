@echo off
title Lay Ma Yeu Cau Kich Hoat Ban Quyen
color 0A
powershell -NoProfile -ExecutionPolicy Bypass -Command "^
$cpu = (Get-CimInstance Win32_Processor).ProcessorId.Trim();^
$mb = (Get-CimInstance Win32_ComputerSystemProduct).UUID.Trim();^
$c_disk_num = (Get-Partition -DriveLetter C).DiskNumber;^
$disk = (Get-PhysicalDisk | Where-Object DeviceId -eq $c_disk_num).SerialNumber.Trim();^
$mac = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.ConnectorPresent -eq $true -and $_.InterfaceDescription -notmatch 'Virtual|VMware|VirtualBox|VPN|pseudo'} | Select-Object -ExpandProperty MacAddress -First 1).Replace('-', '').Replace(':', '');^
function Get-Hash8($val) {^
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($val);^
    $sha = [System.Security.Cryptography.SHA256]::Create();^
    $hashBytes = $sha.ComputeHash($bytes);^
    $hashStr = [System.BitConverter]::ToString($hashBytes).Replace('-', '');^
    return $hashStr.Substring(0, 8);^
}^
$h_cpu = Get-Hash8 $cpu;^
$h_mb = Get-Hash8 $mb;^
$h_disk = Get-Hash8 $disk;^
$hwid_req = 'REQ-' + $h_cpu + '_' + $h_mb + '_' + $h_disk + '-' + $mac;^
Write-Host '=============================================' -ForegroundColor Green;^
Write-Host 'MA YEU CAU KICH HOAT BAN QUYEN (HARDWARE ID):' -ForegroundColor Green;^
Write-Host $hwid_req -ForegroundColor Cyan;^
Write-Host '=============================================' -ForegroundColor Green;^
[System.IO.File]::WriteAllText('Request.licreq', $hwid_req);^
Write-Host 'Da tao file Request.licreq trong thu muc nay.' -ForegroundColor Yellow;^
"
pause
