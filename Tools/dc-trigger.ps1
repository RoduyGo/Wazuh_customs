<#
=====================================================================
 dc-trigger.ps1  -  Tu dong sinh hanh vi MIEN kiem thu rule Wazuh
 May: DC01 (agent 012, Windows Server 2022, 192.168.19.131), mien RODUYGOLAB
 CHI DUNG TRONG LAB. Moi payload vo hai.

 Chay bang PowerShell "Run as administrator" tren DC01.
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\dc-trigger.ps1 prep     # tao labuser1..6 (CAN cho HV1/HV2 cua win-trigger)
   .\dc-trigger.ps1 all      # chay cac ca mien (3.8, 4.2, 4.3, + tao/xoa admin mien)
   .\dc-trigger.ps1 4.2      # chay 1 ca
   .\dc-trigger.ps1 clean    # xoa labuser1..6 va cac tai khoan thu

 Dashboard:  agent.id: "012" and rule.id: <ID>   (Last 15 minutes)
=====================================================================
#>
param([string]$cmd = "")

$PW  = "Lab@123456"
$GAP = 3
$script:LOG = Join-Path (Get-Location) ("trigger-dc-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".csv")

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

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# =====================================================================
# CHUAN BI: tao labuser1..6 (win-trigger dung cho brute force)
# =====================================================================
function Do-Prep(){
  Write-Host "== Tao labuser1..6 tren mien (bo qua neu da co) =="
  1..6 | % {
    $u = "labuser$_"
    if(-not (Get-ADUser -Filter "SamAccountName -eq '$u'" -ErrorAction SilentlyContinue)){
      New-ADUser -Name $u -SamAccountName $u -AccountPassword (ConvertTo-SecureString $PW -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
    }
  }
  Get-ADUser -Filter "Name -like 'labuser*'" | Select-Object Name,Enabled | Format-Table
  Write-Host "Luu y: net accounts /domain - neu Lockout threshold khac Never thi tai khoan co the bi khoa giua chung."
}
function Do-Clean(){
  "labuser1","labuser2","labuser3","labuser4","labuser5","labuser6","labdom1","labdomadm" | % {
    Get-ADUser -Filter "SamAccountName -eq '$_'" -ErrorAction SilentlyContinue | Remove-ADUser -Confirm:$false -ErrorAction SilentlyContinue
  }
  Write-Host "Da xoa tai khoan thu tren mien."
}

# =====================================================================
# HV3 - tao tai khoan mien (100303 + dong lenh)
# =====================================================================
function c_3_8(){ Mark 3.8 "100303,100309/100310" "tao tai khoan mien bang New-ADUser qua powershell.exe"
  Run "powershell.exe -Command `"New-ADUser -Name labdom1 -SamAccountName labdom1 -AccountPassword (ConvertTo-SecureString '$PW' -AsPlainText -Force) -Enabled `$true`""
  Start-Sleep 2
  Run "powershell.exe -Command `"Remove-ADUser -Identity labdom1 -Confirm:`$false`"" }

# tao tai khoan mien roi cap Domain Admins (bien the HV3/HV4 phia mien)
function c_dom_admin(){ Mark 3.x "100303,100320,100308" "tao labdomadm roi them vao Domain Admins roi go"
  Run "powershell.exe -Command `"New-ADUser -Name labdomadm -SamAccountName labdomadm -AccountPassword (ConvertTo-SecureString '$PW' -AsPlainText -Force) -Enabled `$true`""
  Start-Sleep 2
  Run "powershell.exe -Command `"Add-ADGroupMember -Identity 'Domain Admins' -Members labdomadm`""
  Start-Sleep 2
  Run "powershell.exe -Command `"Remove-ADGroupMember -Identity 'Domain Admins' -Members labdomadm -Confirm:`$false`""
  Run "powershell.exe -Command `"Remove-ADUser -Identity labdomadm -Confirm:`$false`"" }

# =====================================================================
# HV4 - them vao nhom dac quyen mien (Script Block 4104 + Event 4728/4756)
# =====================================================================
function c_4_2(){ Mark 4.2 "100320,100326,100327" "them labuser1 vao Domain Admins"
  Run "powershell.exe -Command `"Add-ADGroupMember -Identity 'Domain Admins' -Members labuser1`""
  Start-Sleep 2
  Run "powershell.exe -Command `"Remove-ADGroupMember -Identity 'Domain Admins' -Members labuser1 -Confirm:`$false`"" }
function c_4_3(){ Mark 4.3 100321 "them labuser1 vao Enterprise Admins"
  Run "powershell.exe -Command `"Add-ADGroupMember -Identity 'Enterprise Admins' -Members labuser1`""
  Start-Sleep 2
  Run "powershell.exe -Command `"Remove-ADGroupMember -Identity 'Enterprise Admins' -Members labuser1 -Confirm:`$false`"" }

# =====================================================================
# DIEU PHOI
# =====================================================================
function Run-All(){ c_3_8; Pause; c_dom_admin; Pause; c_4_2; Pause; c_4_3 }

switch ($cmd.ToLower()) {
  "prep"  { Do-Prep }
  "clean" { Do-Clean }
  "all"   { Run-All }
  "3.8"   { c_3_8 }
  "3.x"   { c_dom_admin }
  "4.2"   { c_4_2 }
  "4.3"   { c_4_3 }
  default {
    Write-Host "Dung: .\dc-trigger.ps1 {prep|clean|all|3.8|3.x|4.2|4.3}"
    Write-Host "Chay 'prep' TRUOC khi dung win-trigger HV1/HV2 (can labuser1..6)."
    exit 1
  }
}
if(Test-Path $script:LOG){ Write-Host "`n== Bang chung ghi vao: $script:LOG ==" -ForegroundColor Green }
Write-Host "Mo Dashboard, loc:  agent.id: `"012`" and rule.id: <ID>  (Last 15 minutes)"
