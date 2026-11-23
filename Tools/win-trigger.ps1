<#
=====================================================================
 win-trigger.ps1  -  Tu dong sinh hanh vi kiem thu rule Wazuh
 May: DESKTOP-GP6L2M8 (agent 013, Windows 10, 192.168.19.130)
 CHI DUNG TRONG LAB. Moi payload vo hai.

 Chay bang PowerShell "Run as administrator":
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\win-trigger.ps1 prep        # tao tai khoan local thu, chep curl
   .\win-trigger.ps1 1.1         # chay 1 ca
   .\win-trigger.ps1 hv1         # chay 1 hanh vi
   .\win-trigger.ps1 all         # cac hanh vi KHONG pha hoai (1,2,3,4,5,10,15)
   .\win-trigger.ps1 hv6         # hanh vi pha hoai (Defender/agent/log) - rieng, co hoan tac

 Payload chay qua file .cmd tam -> tien trinh moi, cha la cmd.exe, Sysmon ghi dong lenh.
 Dashboard:  agent.id: "013" and rule.id: <ID>   (Last 15 minutes)
=====================================================================
#>
param([string]$cmd = "")

$DC  = "192.168.19.131"
$DOM = "RODUYGOLAB"
$PW  = "Lab@123456"
$GAP = 3
$script:LOG = Join-Path (Get-Location) ("trigger-win-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".csv")

$B64_1 = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABjAGEALQA1AC0AMQA="
$B64_2 = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABjAGEALQA1AC0AMgA="
$B64_9 = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABjAGEALQA1AC0AOQA="

function Mark($ca,$rule,$desc){
  $t = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host ""
  Write-Host (">>> {0} | [{1}] rule mong doi: {2}" -f $t,$ca,$rule) -ForegroundColor Cyan
  Write-Host ("    " + $desc)
  if(-not (Test-Path $script:LOG)){ '"thoi_gian","host","ca","rule_mong_doi","mo_ta"' | Out-File -Encoding utf8 $script:LOG }
  ('"{0}","{1}","{2}","{3}","{4}"' -f $t,$env:COMPUTERNAME,$ca,$rule,$desc) | Out-File -Append -Encoding utf8 $script:LOG
}
# chay mot dong lenh bang cach ghi ra .cmd tam roi goi cmd.exe (giu nguyen dau nhay)
function Run($cmdline){
  $bat = [IO.Path]::Combine($env:TEMP, ("lt_" + [Guid]::NewGuid().ToString("N").Substring(0,8) + ".cmd"))
  Set-Content -Path $bat -Value ("@echo off`r`n" + $cmdline) -Encoding Ascii
  & cmd.exe /c $bat 2>$null | Out-Null
  Remove-Item $bat -Force -ErrorAction SilentlyContinue
}
function Pause(){ Start-Sleep -Seconds $GAP }

# =====================================================================
# CHUAN BI
# =====================================================================
function Do-Prep(){
  Write-Host "== Tao tai khoan local thu labgrp (HV4) =="
  Run "net user labgrp $PW /add"
  Write-Host "== Chep curl.exe (HV15) =="
  Run "if not exist C:\LabTools mkdir C:\LabTools"
  Run "copy /Y C:\Windows\System32\curl.exe C:\LabTools\labcurl.exe"
  Run "copy /Y C:\Windows\System32\curl.exe C:\Users\Public\labcurl.exe"
  Write-Host "Xong. labuser1..6 la tai khoan MIEN - tao bang dc-trigger.ps1 prep tren DC01."
}
function Do-Clean(){
  Run "net user labgrp /delete"
  Run "del /q C:\LabTools\labcurl.exe C:\Users\Public\labcurl.exe"
  Write-Host "Da xoa tai khoan/tep thu local."
}

# =====================================================================
# HV1 - brute force (net use tu Win10 vao DC01). Can labuser1..6 tren mien.
# =====================================================================
function c_1_1(){ Mark 1.1 "100110,100113" "12 lan dang nhap SMB sai vao DC01 (labuser1)"
  1..12 | ForEach-Object { Run ('net use \\{0}\IPC$ /user:{1}\labuser1 SaiMatKhau{2}' -f $DC,$DOM,$_) }
  Run "net use * /delete /y" }
function c_1_2(){ Mark 1.2 100115 "password spraying: 1 mat khau cho 6 tai khoan"
  1..6 | ForEach-Object { Run ('net use \\{0}\IPC$ /user:{1}\labuser{2} Spring2026!' -f $DC,$DOM,$_); Start-Sleep 3 }
  Run "net use * /delete /y" }
function c_1_3(){ Mark 1.3 100118 "doan cham: 20 lan sai cach nhau 20 giay (labuser2)"
  1..20 | ForEach-Object { Run ('net use \\{0}\IPC$ /user:{1}\labuser2 SaiMatKhau{2}' -f $DC,$DOM,$_); Start-Sleep 20 }
  Run "net use * /delete /y" }
function hv1(){ c_1_1; Pause; c_1_2 }

# =====================================================================
# HV2 - dang nhap thanh cong sau nhieu lan sai (vao DC01)
# =====================================================================
function c_2_1(){ Mark 2.1 100120 "sai 6 lan roi dang nhap dung (labuser3)"
  1..6 | ForEach-Object { Run ('net use \\{0}\IPC$ /user:{1}\labuser3 Sai{2}' -f $DC,$DOM,$_) }
  Run ('net use \\{0}\IPC$ /user:{1}\labuser3 {2}' -f $DC,$DOM,$PW)
  Run "net use * /delete /y" }
function c_2_3(){ Mark 2.3 100122 "dang nhap dung trong 1 gio sau canh bao do mat khau (labuser5)"
  Run ('net use \\{0}\IPC$ /user:{1}\labuser5 {2}' -f $DC,$DOM,$PW)
  Run "net use * /delete /y" }
function hv2(){ c_2_1 }

# =====================================================================
# HV3 - tao/xoa tai khoan (local tren Win10)
# =====================================================================
function c_3_1(){ Mark 3.1 "100303,100309,100310" "tao tai khoan local net user"
  Run "net user labtest1 $PW /add" }
function c_3_2(){ Mark 3.2 100302 "tao tai khoan an (ten ket thuc bang dollar)"
  Run "net user labhidden$ $PW /add"; Run "net user labhidden$ /delete" }
function c_3_3(){ Mark 3.3 100304 "vo hieu hoa va xoa tai khoan"
  Run "net user labtest1 /active:no"; Run "net user labtest1 /delete" }
function c_3_5(){ Mark 3.5 100306 "tao hang loat 5 tai khoan"
  1..5 | ForEach-Object { Run ("net user labbulk{0} $PW /add" -f $_) }
  1..5 | ForEach-Object { Run ("net user labbulk{0} /delete" -f $_) } }
function c_3_7(){ Mark 3.7 100308 "tao tai khoan roi them vao Administrators"
  Run "net user labtest2 $PW /add"; Run "net localgroup Administrators labtest2 /add"
  Run "net localgroup Administrators labtest2 /delete"; Run "net user labtest2 /delete" }
function hv3(){ c_3_1; Pause; c_3_2; Pause; c_3_3; Pause; c_3_5; Pause; c_3_7 }

# =====================================================================
# HV4 - them vao nhom dac quyen (local). Can labgrp (prep).
# =====================================================================
function c_4_1(){ Mark 4.1 "100320,100326" "them labgrp vao Administrators"
  Run "net localgroup Administrators labgrp /add"; Run "net localgroup Administrators labgrp /delete" }
function c_4_4(){ Mark 4.4 "100320,100326" "them labgrp vao Backup Operators"
  Run 'net localgroup "Backup Operators" labgrp /add'; Run 'net localgroup "Backup Operators" labgrp /delete' }
function c_4_5(){ Mark 4.5 "100323,100324" "them roi go trong 30 phut"
  Run "net localgroup Administrators labgrp /add"; Run "net localgroup Administrators labgrp /delete" }
function hv4(){ c_4_1; Pause; c_4_4; Pause; c_4_5 }

# =====================================================================
# HV5 - PowerShell bat thuong (chay tren Win10)
# =====================================================================
function c_5_1(){ Mark 5.1 100346 "PowerShell -enc (base64)"; Run "powershell.exe -nop -enc $B64_1" }
function c_5_2(){ Mark 5.2 100341 "base64 kem cua so an"; Run "powershell.exe -w hidden -enc $B64_2" }
function c_5_3(){ Mark 5.3 100347 "ExecutionPolicy Bypass kem cua so an"
  Run 'powershell.exe -ep bypass -w hidden -c "Write-Output ca-5-3"' }
function c_5_5(){ Mark 5.5 100350 "giai ma base64 roi chay trong script"
  Run ("powershell.exe -c `"iex ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$B64_9')))`"") }
function c_5_6(){ Mark 5.6 100348 "chuoi nhac toi AMSI trong script block"
  Run 'powershell.exe -c "Write-Output ''kiem tra chuoi AmsiScanBuffer''"' }
function c_5_7(){ Mark 5.7 100345 "ha phien ban -Version 2"
  Run 'powershell.exe -Version 2 -c "Write-Output ca-5-7"' }
function c_5_8(){ Mark 5.8 100344 "ban sao powershell.exe doi ten"
  Run "copy /Y C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe C:\Users\Public\labps.exe"
  Run 'C:\Users\Public\labps.exe -c "Write-Output ca-5-8"'; Run "del /q C:\Users\Public\labps.exe" }
function c_5_9(){ Mark 5.9 "100340,100343" "PowerShell do wscript sinh ra (cha la)"
  Set-Content -Path C:\Users\Public\lab1.vbs -Encoding Ascii -Value 'CreateObject("WScript.Shell").Run "powershell.exe -c Write-Output ca-5-9a", 0'
  Set-Content -Path C:\Users\Public\lab2.vbs -Encoding Ascii -Value ("CreateObject(`"WScript.Shell`").Run `"powershell.exe -w hidden -enc $B64_9`", 0")
  Run "wscript C:\Users\Public\lab1.vbs"; Run "wscript C:\Users\Public\lab2.vbs"
  Start-Sleep 2; Remove-Item C:\Users\Public\lab1.vbs,C:\Users\Public\lab2.vbs -Force -ErrorAction SilentlyContinue }
function hv5(){ c_5_1; Pause; c_5_2; Pause; c_5_3; Pause; c_5_5; Pause; c_5_6; Pause; c_5_7; Pause; c_5_8; Pause; c_5_9
  Write-Host "    (5.4 tai-roi-chay can web server tren ubuntu-lab - bo qua)" -ForegroundColor Yellow }

# =====================================================================
# HV10 - service va scheduled task. Co don dep.
# =====================================================================
function c_10_1(){ Mark 10.1 "100440,100451" "scheduled task thuong (calc.exe)"
  Run "schtasks /create /tn LabTask1 /tr C:\Windows\System32\calc.exe /sc once /st 23:59 /f" }
function c_10_2(){ Mark 10.2 "100441,100452" "task chay PowerShell"
  Run 'schtasks /create /tn LabTask2 /tr "powershell.exe -c Write-Output lab" /sc once /st 23:59 /f' }
function c_10_3(){ Mark 10.3 100442 "task chay bang SYSTEM"
  Run 'schtasks /create /tn LabTask3 /tr "powershell.exe -c Write-Output lab" /sc once /st 23:59 /ru SYSTEM /f' }
function c_10_5(){ Mark 10.5 "100445,100446,100450,100453,100454" "tao 2 dich vu (notepad / cmd echo)"
  Run 'sc.exe create LabSvc1 binPath= "C:\Windows\System32\notepad.exe"'
  Run 'sc.exe create LabSvc2 binPath= "cmd.exe /c echo lab"' }
function c_10_7(){ Mark 10.7 "100441,100456" "tao task bang PowerShell (Register-ScheduledTask)"
  Run 'powershell.exe -Command "$a = New-ScheduledTaskAction -Execute ''powershell.exe'' -Argument ''-c Write-Output lab''; Register-ScheduledTask -TaskName LabTask4 -Action $a -Force"' }
function hv10(){ c_10_1; Pause; c_10_2; Pause; c_10_3; Pause; c_10_5; Pause; c_10_7
  Write-Host "    Don dep HV10..." -ForegroundColor Yellow
  "LabTask1","LabTask2","LabTask3","LabTask4" | ForEach-Object { Run ("schtasks /delete /tn {0} /f" -f $_) }
  "LabSvc1","LabSvc2" | ForEach-Object { Run ("sc.exe delete {0}" -f $_) } }

# =====================================================================
# HV15 - ket noi ra ngoai (can Internet + curl). prep da chep labcurl.
# =====================================================================
function c_15_1(){ Mark 15.1 100542 "PowerShell Invoke-WebRequest ra 1.1.1.1"
  Run 'powershell.exe -NoProfile -Command "try { Invoke-WebRequest https://1.1.1.1 -UseBasicParsing -TimeoutSec 3 | Out-Null } catch {}; Start-Sleep 2"' }
function c_15_2(){ Mark 15.2 100543 "tien trinh tu thu muc Public ket noi ra ngoai"
  Copy-Item "$PSHOME\powershell.exe" "C:\Users\Public\labpub.exe" -Force -ErrorAction SilentlyContinue
  Run 'C:\Users\Public\labpub.exe -NoProfile -Command "try { Invoke-WebRequest https://1.1.1.1 -UseBasicParsing -TimeoutSec 3 | Out-Null } catch {}; Start-Sleep 2"'
  Remove-Item "C:\Users\Public\labpub.exe" -Force -ErrorAction SilentlyContinue }
function c_15_3(){ Mark 15.3 100544 "ket noi toi cong 4444"
  Copy-Item "$PSHOME\powershell.exe" "C:\LabTools\labudp.exe" -Force -ErrorAction SilentlyContinue
  Run 'C:\LabTools\labudp.exe -NoProfile -Command "$u=New-Object Net.Sockets.UdpClient; $b=[Text.Encoding]::ASCII.GetBytes(''test''); [void]$u.Send($b,$b.Length,''1.1.1.1'',4444); Start-Sleep 2; $u.Close()"'
  Remove-Item "C:\LabTools\labudp.exe" -Force -ErrorAction SilentlyContinue }
function c_15_5(){ Mark 15.5 100547 "dong lenh tao duong ham (chi in chuoi)"
  Run "cmd.exe /c echo ssh -R 9000:localhost:22 lab@example.com" }
function c_15_6(){ Mark 15.6 100548 "truy van DNS toi Dynamic DNS"
  Run 'powershell.exe -Command "Resolve-DnsName lab-test.duckdns.org"' }
function c_15_4(){ Mark 15.4 100546 "beaconing: 16 ket noi cung IP trong 5 phut"
  1..16 | ForEach-Object { Run "C:\LabTools\labcurl.exe -s https://1.1.1.1 -o NUL"; Start-Sleep 5 } }
function hv15(){ c_15_1; Pause; c_15_2; Pause; c_15_3; Pause; c_15_5; Pause; c_15_6
  Write-Host "    (15.4 beaconing ~80s, 15.7 chuoi C2 - chay rieng khi can)" -ForegroundColor Yellow }

# =====================================================================
# HANH VI PHA HOAI (rieng, co hoan tac) - KHONG trong 'all'
# =====================================================================
function hv6(){ Write-Host "== HV6 Defender (tat roi bat lai real-time protection) ==" -ForegroundColor Yellow
  Mark 6.1 "100360,100361,100368/100369" "tat Real-time protection"
  Run 'powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $true"'; Start-Sleep 3
  Run 'powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $false"'; Pause
  Mark 6.2 "100362,100363" "them ngoai le quet"
  Run "if not exist C:\LabExclude mkdir C:\LabExclude"
  Run 'powershell.exe -Command "Add-MpPreference -ExclusionPath C:\LabExclude"'
  Run 'powershell.exe -Command "Add-MpPreference -ExclusionExtension .ps1"'
  Run 'powershell.exe -Command "Remove-MpPreference -ExclusionPath C:\LabExclude"'
  Run 'powershell.exe -Command "Remove-MpPreference -ExclusionExtension .ps1"'; Run "rmdir C:\LabExclude"; Pause
  Mark 6.3 "100364,100365" "ghi registry tat Defender"
  Run 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f'
  Run 'reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f'; Pause
  Mark 6.4 100370 "lenh dung dich vu WinDefend (Windows se tu choi)"
  Run "sc.exe stop WinDefend" }

function hv7(){ Write-Host "== HV7 agent stopped (agent dung roi bat lai) ==" -ForegroundColor Yellow
  Mark 7.1 "100380,100384" "dung em agent"
  Run "net stop WazuhSvc"; Start-Sleep 3; Run "net start WazuhSvc"; Start-Sleep 5; Pause
  Mark 7.3 "100384,100386" "doi service agent sang disabled roi auto"
  Run "sc.exe config WazuhSvc start= disabled"; Run "sc.exe config WazuhSvc start= auto"; Pause
  Mark 7.5 100390 "chan cong 1514 bang tuong lua roi xoa ngay"
  Run "netsh advfirewall firewall add rule name=LabBlockWazuh dir=out action=block protocol=TCP remoteport=1514"
  Run "netsh advfirewall firewall delete rule name=LabBlockWazuh"
  Run "net start WazuhSvc" }

function hv8(){ Write-Host "== HV8 xoa event log (log cuc bo mat; log da gui ve manager van con) ==" -ForegroundColor Yellow
  Mark 8.1 "100400,100404" "xoa kenh Security"; Run "wevtutil cl Security"; Pause
  Mark 8.2 "100401,100402,100404" "xoa Application va Windows PowerShell"
  Run "wevtutil cl Application"; Run 'wevtutil cl "Windows PowerShell"'; Pause
  Mark 8.3 "100401,100405" "xoa log bang PowerShell"
  Run 'powershell.exe -Command "Clear-EventLog -LogName Application"'; Pause
  Mark 8.5 100406 "lenh dung dich vu EventLog (bi tu choi)"; Run "sc.exe stop EventLog"; Pause
  Mark 8.6 "100407,60112" "tat chinh sach audit roi bat lai"
  Run 'auditpol /set /subcategory:"Logon" /failure:disable'
  Run 'auditpol /set /subcategory:"Logon" /failure:enable' }

# =====================================================================
# DIEU PHOI
# =====================================================================
function Run-All(){ hv1; Pause; hv2; Pause; hv3; Pause; hv4; Pause; hv5; Pause; hv10; Pause; hv15 }

switch ($cmd.ToLower()) {
  "prep"  { Do-Prep }
  "clean" { Do-Clean }
  "all"   { Run-All }
  "hv1"   { hv1 }
  "hv2"   { hv2 }
  "hv3"   { hv3 }
  "hv4"   { hv4 }
  "hv5"   { hv5 }
  "hv10"  { hv10 }
  "hv15"  { hv15 }
  "hv6"   { hv6 }
  "hv7"   { hv7 }
  "hv8"   { hv8 }
  "1.1"   { c_1_1 }
  "1.2"   { c_1_2 }
  "1.3"   { c_1_3 }
  "2.1"   { c_2_1 }
  "2.3"   { c_2_3 }
  "3.1"   { c_3_1 }
  "3.2"   { c_3_2 }
  "3.3"   { c_3_3 }
  "3.5"   { c_3_5 }
  "3.7"   { c_3_7 }
  "4.1"   { c_4_1 }
  "4.4"   { c_4_4 }
  "4.5"   { c_4_5 }
  "5.1"   { c_5_1 }
  "5.2"   { c_5_2 }
  "5.3"   { c_5_3 }
  "5.5"   { c_5_5 }
  "5.6"   { c_5_6 }
  "5.7"   { c_5_7 }
  "5.8"   { c_5_8 }
  "5.9"   { c_5_9 }
  "10.1"  { c_10_1 }
  "10.2"  { c_10_2 }
  "10.3"  { c_10_3 }
  "10.5"  { c_10_5 }
  "10.7"  { c_10_7 }
  "15.1"  { c_15_1 }
  "15.2"  { c_15_2 }
  "15.3"  { c_15_3 }
  "15.4"  { c_15_4 }
  "15.5"  { c_15_5 }
  "15.6"  { c_15_6 }
  default {
    Write-Host "Dung: .\win-trigger.ps1 {prep|clean|all|hv1..hv5,hv10,hv15|hv6,hv7,hv8(pha hoai)|<ma ca>}"
    Write-Host "Vi du: .\win-trigger.ps1 prep   roi   .\win-trigger.ps1 all"
    exit 1
  }
}
if(Test-Path $script:LOG){ Write-Host "`n== Bang chung ghi vao: $script:LOG ==" -ForegroundColor Green }
Write-Host 'Mo Dashboard, loc:  agent.id: "013" and rule.id: <ID>  (Last 15 minutes)'
