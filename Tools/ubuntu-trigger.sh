#!/usr/bin/env bash
# =====================================================================
# ubuntu-trigger.sh  (v2)  -  Tu dong sinh hanh vi kiem thu rule Wazuh
# May: ubuntu-lab (agent 014, 192.168.19.129, Ubuntu 24.04)
# CHI DUNG TRONG LAB. Payload vo hai.
#
# v2: dung EXPECT lai terminal that (go mat khau nhu nguoi) de tai hien
#     dung log ma rule can. Sua logic mat khau cho cac ca sudoers/su.
#
# Cach dung (root):
#   sudo ./ubuntu-trigger.sh prep     # tao tai khoan thu + cai sshpass, expect
#   sudo ./ubuntu-trigger.sh 13.1     # chay 1 ca
#   sudo ./ubuntu-trigger.sh hv13     # chay ca hanh vi
#   sudo ./ubuntu-trigger.sh all
#   sudo ./ubuntu-trigger.sh clean
#
# Dashboard:  agent.id: "014" and rule.id: <ID>
# =====================================================================
set -u

SELF_IP="192.168.19.129"
TESTPW="Lab@123456"
GAP=3
LOG="trigger-ubuntu-$(date +%Y%m%d-%H%M%S).csv"

if [ "$(id -u)" -ne 0 ]; then echo "Phai chay bang root: sudo $0 $*"; exit 1; fi

mark() {
  local t; t=$(date '+%Y-%m-%d %H:%M:%S')
  printf '\n>>> %s | [%s] rule mong doi: %s\n    %s\n' "$t" "$1" "$2" "$3"
  if [ ! -f "$LOG" ]; then echo '"thoi_gian","host","ca","rule_mong_doi","mo_ta"' > "$LOG"; fi
  printf '"%s","ubuntu-lab","%s","%s","%s"\n' "$t" "$1" "$2" "$3" >> "$LOG"
}
pause() { sleep "$GAP"; }

# chay mot kich ban expect duoi danh nghia <user> (qua pty that, khong can mat khau cua user do vi dang la root)
exp_as() { # <user> <expect-program>
  local u="$1" prog="$2"
  local f="/tmp/lt_$$_${RANDOM}.exp"
  printf '%s\n' "$prog" > "$f"; chmod 644 "$f"
  runuser -u "$u" -- expect -f "$f" >/dev/null 2>&1
  rm -f "$f"
}

# =====================================================================
# CHUAN BI
# =====================================================================
do_prep() {
  echo "== Cai cong cu =="
  apt-get update -qq
  apt-get install -y -qq sshpass expect netcat-traditional >/dev/null 2>&1
  echo "== Tao tai khoan thu =="
  id labsudo     >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo labsudo
  id labnosudo   >/dev/null 2>&1 || useradd -m -s /bin/bash labnosudo
  id labrestrict >/dev/null 2>&1 || useradd -m -s /bin/bash labrestrict
  echo "labsudo:$TESTPW"     | chpasswd
  echo "labnosudo:$TESTPW"   | chpasswd
  echo "labrestrict:$TESTPW" | chpasswd
  echo 'labrestrict ALL=(ALL) /usr/bin/ls' > /etc/sudoers.d/labrestrict
  chmod 440 /etc/sudoers.d/labrestrict
  # dam bao sshd cho dang nhap bang mat khau (can cho brute force)
  if ! grep -qE '^\s*PasswordAuthentication\s+yes' /etc/ssh/sshd_config; then
    sed -i 's/^#\?\s*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    systemctl restart ssh 2>/dev/null
  fi
  visudo -c >/dev/null && echo "sudoers OK. Xong chuan bi."
}
do_clean() {
  rm -f /etc/sudoers.d/labrestrict
  userdel -r labsudo 2>/dev/null; userdel -r labnosudo 2>/dev/null; userdel -r labrestrict 2>/dev/null
  echo "Da xoa tai khoan thu."
}

# =====================================================================
# HV13 - sudo/su that bai  (EXPECT = pty that)
# =====================================================================
# gui sai mat khau N lan roi bo cuoc (Ctrl-C) -> sinh "N incorrect password attempts"
c_13_1(){ mark 13.1 100500 "sudo sai 1 lan roi bo cuoc (labsudo)"
  exp_as labsudo 'spawn sudo -k id
expect "assword"
send "saibet1\r"
expect "assword"
send "\003"
expect eof'; }

c_13_2(){ mark 13.2 100501 "sudo sai 3 lan trong 1 lenh (labsudo)"
  exp_as labsudo 'spawn sudo -k id
expect "assword"
send "saibet1\r"
expect "assword"
send "saibet2\r"
expect "assword"
send "saibet3\r"
expect eof'; }

c_13_3(){ mark 13.3 100504 "4 luot sudo that bai trong 5 phut (labsudo)"
  for i in 1 2 3 4; do c_once_fail labsudo; sleep 2; done; }
c_once_fail(){ exp_as "$1" 'spawn sudo -k id
expect "assword"
send "saibet\r"
expect "assword"
send "\003"
expect eof'; }

c_13_4(){ mark 13.4 "100502,100505" "labnosudo go DUNG mat khau nhung khong co quyen sudo (3 lan)"
  for i in 1 2 3; do
    exp_as labnosudo "spawn sudo -k id
expect \"assword\"
send \"$TESTPW\r\"
expect eof"
    sleep 2
  done; }

c_13_5(){ mark 13.5 100503 "labrestrict chay lenh khong duoc phep (cat /etc/shadow)"
  exp_as labrestrict "spawn sudo -k cat /etc/shadow
expect \"assword\"
send \"$TESTPW\r\"
expect eof"; }

c_13_6(){ mark 13.6 100506 "tai khoan dich vu www-data thu sudo"
  exp_as www-data 'spawn sudo -k id
expect "assword"
send "saibet\r"
expect "assword"
send "\003"
expect eof'; }

c_13_7(){ mark 13.7 100507 "sudo thanh cong ngay sau chuoi that bai (labsudo)"
  c_once_fail labsudo; sleep 1; c_once_fail labsudo; sleep 1
  exp_as labsudo "spawn sudo -k id
expect \"assword\"
send \"$TESTPW\r\"
expect eof"; }

c_13_8(){ mark 13.8 "100508,100509,100510" "su that bai: 1 lan len labsudo + 5 lan len root"
  exp_as labnosudo 'spawn su - labsudo
expect "assword"
send "saibet\r"
expect eof'
  for i in 1 2 3 4 5; do
    exp_as labnosudo 'spawn su - root
expect "assword"
send "saibet\r"
expect eof'
    sleep 1
  done; }

hv13(){ c_13_1;pause;c_13_2;pause;c_13_3;pause;c_13_4;pause;c_13_5;pause;c_13_6;pause;c_13_7;pause;c_13_8; }

# =====================================================================
# HV1 ca 1.5 / HV12 - SSH brute force (sshpass, tai khoan LOCAL labsudo)
# srcip = 192.168.19.129 (tu-thu).
# =====================================================================
ssh_fail(){ sshpass -p "sai$RANDOM" ssh -o PreferredAuthentications=password \
  -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$1@$SELF_IP" true >/dev/null 2>&1; }
c_1_5(){ mark 1.5 "100112,100114" "12 lan SSH sai tai khoan labsudo (lan 10 -> 100114)"
  for i in $(seq 1 12); do ssh_fail labsudo; done; }
c_12_1(){ mark 12.1 100487 "6 lan SSH root sai mat khau (100480/100482 la rule dang nhap root THANH CONG, khong ap dung)"
  for i in $(seq 1 6); do ssh_fail root; sleep 1; done; }
hv1_ssh(){ c_1_5; }
hv12(){ c_12_1; }

# =====================================================================
# HV5 Linux
# =====================================================================
c_5_11(){ mark 5.11 100357 "sudo chay chuoi curl|sh (vo hai, ket noi bi tu choi)"
  exp_as labsudo "spawn sudo -k sh -c {curl -s http://127.0.0.1:9/x | sh}
expect \"assword\"
send \"$TESTPW\r\"
expect eof"; }
c_5_12(){ mark 5.12 "100356,100357" "nc.traditional -e (reverse shell gia) + qua sudo"
  nc.traditional -e /bin/true 127.0.0.1 9 >/dev/null 2>&1
  exp_as labsudo "spawn sudo -k nc.traditional -e /bin/true 127.0.0.1 9
expect \"assword\"
send \"$TESTPW\r\"
expect eof"; }
hv5_linux(){ c_5_11; pause; c_5_12; }

# =====================================================================
run_all(){ hv13; pause; hv1_ssh; pause; hv12; pause; hv5_linux; }

case "${1:-}" in
  prep) do_prep ;; clean) do_clean ;; all) run_all ;;
  hv13) hv13 ;; hv12) hv12 ;; hv5) hv5_linux ;; 1.5) c_1_5 ;;
  13.1) c_13_1 ;; 13.2) c_13_2 ;; 13.3) c_13_3 ;; 13.4) c_13_4 ;;
  13.5) c_13_5 ;; 13.6) c_13_6 ;; 13.7) c_13_7 ;; 13.8) c_13_8 ;;
  12.1) c_12_1 ;; 5.11) c_5_11 ;; 5.12) c_5_12 ;;
  *) echo "Dung: sudo $0 {prep|clean|all|hv13|hv12|hv5|13.1..13.8|12.1|1.5|5.11|5.12}"; exit 1 ;;
esac
[ -f "$LOG" ] && echo && echo "== Bang chung: $(pwd)/$LOG =="
echo 'Dashboard: agent.id: "014" and rule.id: <ID>  (Last 15 minutes)'
