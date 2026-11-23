# Nhật ký thay đổi rule

Ghi lại mọi thay đổi rule/decoder/script: sửa gì, vì sao, bằng chứng, trạng thái triển khai lên manager.

---

## 2026-11-23 — Sửa rule Linux không bắn (HV12, HV13)

Nhánh `ai/01-fix-linux-rules`, commit `0162f1c`.
Phát hiện khi chạy `Tools/ubuntu-trigger.sh` trên ubuntu-lab (agent 014) ngày 2026-11-22, khung 19:45–19:52, đối chiếu `alerts.json` trên manager và `wazuh-logtest` với đúng dòng log gốc.

### 1. `ssh_root_login.xml` — 100487, 100488 (SSH root sai nhiều lần)

| | Trước | Sau |
|---|---|---|
| Điều kiện cha | `<if_matched_group>authentication_failed</if_matched_group>` | `<if_matched_sid>100112</if_matched_sid>` |

**Vì sao:** Rule `if_matched_group` trở thành con của các rule trong nhóm đó (5716, 5760). Nhưng 100112 (`brute_force_failure.xml`, nạp trước) cũng là con của 5716/5760 và không có điều kiện thêm, nên luôn khớp trước; 100487/100488 không bao giờ được xét.
**Bằng chứng:** logtest 5 dòng `Failed password for root from 192.168.19.129` liên tiếp → chỉ ra 100112, 100112, 100112, 100114, 100112. Không có 100487.
**Ghi chú:** 100114 (ngưỡng 10) cũng là con của 100112 và nạp trước, nên từ lần thứ 10 trở đi 100114 sẽ thắng; 100487 (ngưỡng 4) bắn trước đó.

### 2. `sudo_failures.xml` — 100507 (sudo thành công sau chuỗi thất bại)

| | Trước | Sau |
|---|---|---|
| `if_sid` | `5402,5407` | `5402,5403,5407` |

**Vì sao:** Lần sudo thành công **đầu tiên** của một user ra rule 5403 ("First time user executed sudo", cơ chế FTS), không phải 5402. Kẻ tấn công đoán đúng mật khẩu một tài khoản chưa từng sudo sẽ lọt qua.
**Bằng chứng:** alert 19:49:53, `labsudo : TTY=pts/1 ... COMMAND=/usr/bin/id` → rule 5403, không có 100507.

### 3. `sudo_failures.xml` — 100508, 100509 (su thất bại / su lên root thất bại)

| Rule | Trước | Sau |
|---|---|---|
| 100508 | `if_sid 5301` (không điều kiện) | `if_sid 5301` + `<match negate="yes">FAILED SU (to root)\| user=root</match>` |
| 100509 | `if_sid 5302` | `if_sid 5301` + `<match>FAILED SU (to root)\| user=root</match>` |

**Vì sao (2 lỗi chồng nhau):**
1. 100508 là con của 5301 không có điều kiện → bắt hết mọi su thất bại, nên rule gốc 5302 (và 100509 treo vào 5302) không bao giờ được xét.
2. Rule gốc 5302 lọc bằng `<user>^root</user>`, nhưng decoder `su` **không tách trường user** từ dòng Ubuntu 24.04 `FAILED SU (to root) labnosudo on pts/1` (logtest Phase 2 chỉ có `name: 'su'`). Nên kể cả không bị 100508 che, 5302 cũng không khớp. Phải lọc bằng `match` trên nội dung dòng log.

**Bằng chứng:** 5 lần `FAILED SU (to root)` lúc 19:49:59–19:50:13 → toàn bộ ra 100508; logtest cũng ra 100508.

### 4. Script `Tools/ubuntu-trigger.sh` (v2)

- **Lỗi:** `exp_as` gọi `runuser -u <user> -s /bin/bash -c ...` → `runuser` báo `options --{shell,...} and --user are mutually exclusive` và thoát ngay; output bị đẩy vào `/dev/null` nên không ai thấy. Mọi ca dùng expect (HV13, 5.11, 5.12) **không sinh log nào**.
  **Sửa:** `runuser -u "$u" -- expect -f "$f"`.
- **Ca 12.1:** đổi rule mong đợi từ `100480,100482` → `100487`. 100480/100482 là rule đăng nhập root **thành công** (con của 5715), không thể bắn từ đăng nhập sai.

### Vấn đề chưa sửa — agent 014 làm rơi log journald (không tái hiện khi chạy lại 2026-11-23)

2 dòng log có trong journald ubuntu-lab nhưng **không về manager** (log auditd cùng giây vẫn về):
- 19:49:28 `labnosudo : user NOT in sudoers` (lần 1/3 của ca 13.4) → 100505 thiếu 1 lần nên không đủ ngưỡng 3.
- 19:49:37 `labrestrict : command not allowed` (ca 13.5) → mất 100503. Logtest với dòng này ra 100503 đúng, tức rule không sai.

Chưa rõ nguyên nhân (nghi bộ đọc journald của logcollector). Nếu chạy lại vẫn rơi: cho agent đọc `/var/log/auth.log` thay journald cho log xác thực.

### Đã kiểm tra, không phải lỗi
- Decoder `0320-sudo_decoders_soc.xml` đã nằm đúng `etc/decoders/`, bản gốc đã `decoder_exclude` → trường `src_user` có đủ.
- `soc-allow-ip` chỉ có `127.0.0.1`, `soc-allow-account` chỉ có `healthcheck_svc` → không chặn tài khoản/IP thử.

### Trạng thái triển khai lên manager (192.168.88.245)
- [x] 2026-11-23 09:15 chép `sudo_failures.xml`, `ssh_root_login.xml` vào `/var/ossec/etc/rules/` (bản cũ lưu `*.bak-20261123`)
- [x] `wazuh-analysisd -t` OK, restart `wazuh-manager` → active
- [x] Logtest lại với dòng log gốc:
  - 5 lần `Failed password for root` → 100112, 100112, 100112, **100487**, 100112
  - `FAILED SU (to root)` → **100509**; `FAILED SU (to labsudo)` → 100508
  - 3 lần sudo sai rồi sudo thành công → 100500 ×3, **100507**
- [x] 2026-11-23 09:32 chạy lại trigger thật, đối chiếu `alerts.json` — **cả 5 ca ĐẠT**:
  - 13.4 → 100502 ×2, **100505** (lần thứ 3 thay bằng 100505)
  - 13.5 → **100503** (lần này log journald không bị rơi)
  - 13.7 → 100500 ×2, **100507**
  - 13.8 → 100508 ×2 (su lên labsudo), **100509** ×4, **100510**
  - 12.1 → 100112 ×3, **100487**, 100112 …


---

## 2026-11-23 — Sửa rule HV2 và script HV15 trên Win10 (chưa deploy)

Nhánh `ai/hv2-hv15-fix`.
Phát hiện khi chạy `Tools/win-trigger.ps1 all` trên `win10-lab` (agent 013) ngày 2026-11-23, khung 11:34–11:37, đối chiếu `alerts.json` trên manager (23/28 ca Đạt ngay; 5 ca thiếu: `2.1`, `15.1`, `15.2`, `15.3`, `15.6`).

### 1. `brute_force_success.xml` — 100120, 100121, 100122 (HV2 Windows)

| | Trước | Sau |
|---|---|---|
| `if_sid` | `60106` | `60106,92657` |

**Vì sao:** Khi `labuser3` đăng nhập SMB (`logonType: 3`) thành công vào DC01 sau 6 lần sai (`100110`), Event `4624` bị rule mặc định **`92657`** của Wazuh (cùng là con của `60106`) bắt trước, khiến `100120`/`100121`/`100122` không được xét.
**Bằng chứng:** `alerts.json` lúc `11:35:13` trên agent `012` ghi nhận `rule: 92657, eid: 4624, lt: 3, ip: 192.168.19.130` ngay sau chuỗi `100110` (`4625`), nhưng không có `100120`.

### 2. Script `Tools/win-trigger.ps1` — Ca 15.1, 15.2, 15.3 (HV15)

- **Ca `15.1` (`100542`) và `15.2` (`100543`):**
  - **Vì sao:** `alerts.json` có nổ `100540` (Sysmon Event 3 ra `1.1.1.1:443`) nhưng trường `win.eventdata.image` bị ghi là `<unknown process>` do `powershell.exe` / `labcurl.exe` thoát quá nhanh trước khi Sysmon kịp tra tên tiến trình.
  - **Sửa:** Giữ tiến trình sống thêm 2 giây (`Start-Sleep 2`) sau khi mở kết nối; riêng `15.2` chạy bản sao `C:\Users\Public\labpub.exe` kèm `Start-Sleep 2` rồi xóa ngay sau đó.
- **Ca `15.3` (`100544` — kết nối cổng 4444):**
  - **Vì sao:** Không thấy Event 3 nào tới cổng `4444` khi dùng `labcurl.exe` gọi `portquiz.net:4444`.
  - **Sửa:** Dùng `System.Net.Sockets.TcpClient` trong PowerShell mở kết nối TCP trực tiếp tới `1.1.1.1:4444` (chờ 2s + `Start-Sleep 2`) để Sysmon chắc chắn ghi Event 3 tới cổng `4444`.

### 3. Ghi chú ca 15.6 (`100548` — DNS Dynamic DNS)

- **Bằng chứng:** `alerts.json` lúc `11:37:29` trên agent `013` có sự kiện Sysmon Event 22 cho `lab-test.duckdns.org`, nhưng bị rule tương quan `100553` (level 14, ngưỡng 5 `soc_c2_alert` trong 10 phút) thay thế trên sự kiện thứ 5. Không phải lỗi rule `100548`; cần chạy lại riêng `15.6` ngoài khung 10 phút trùng dồn nhiều cảnh báo `soc_c2_alert`.

### Trạng thái triển khai
- [ ] Chờ người dùng chép `Rules/brute_force_success.xml` lên `wazuh-mgr` (`/var/ossec/etc/rules/`) và restart `wazuh-manager`
- [ ] Chép `Tools/win-trigger.ps1` lên `win10-lab` (`C:\win-trigger.ps1`) và chạy lại `2.1`, `15.1`, `15.2`, `15.3`, `15.6`

### 4. `outbound_connection.xml` — 100540, 100543 & `win-trigger.ps1` 15.3 (bổ sung sau lần chạy 14:01)

- **Kết quả chạy lại 14:01:** `2.1` (**100120** lúc `14:01:20` trên `012`) và `15.6` (**100548** lúc `14:01:59` trên `013`) đã **ĐẠT**.
- **`100540` (`15.1` — `100542`):** Đổi `<if_sid>61605</if_sid>` → `<if_sid>61605,92101</if_sid>`.
  - **Vì sao:** Rule mặc định `92101` (`0810-sysmon_id_3.xml`, `level="0"`) bắt im lặng mọi kết nối TCP của `powershell.exe` trước `100540`, khiến Sysmon Event 3 của `powershell.exe` (xác nhận có ghi lúc `14:01:25` tới `1.1.1.1:443`) không bao giờ tới được `100540` và `100542`.
- **`100543` (`15.2`):** Đổi `\\` trong regex đường dẫn thành `\\+` (`(?i)^c:\\+(users\\+public\\+|...)`).
  - **Vì sao:** Decoder `windows_eventchannel` giữ 2 dấu gạch chéo ngược (`C:\\Users\\Public\\labpub.exe`) trong `win.eventdata.image`; bằng chứng log thô `100540` lúc `14:01:43` có `"image":"C:\\\\Users\\\\Public\\\\labpub.exe"` nên `^c:\\users\\public\\` không khớp.
- **`win-trigger.ps1` (`15.3`):** Dùng bản sao `C:\LabTools\labudp.exe` gửi UDP tới `1.1.1.1:4444` kèm `Start-Sleep 2` (vì TCP `:4444` ra ngoài bị timeout nên Windows không hoàn tất bắt tay TCP và Sysmon Event 3 không ghi log, còn nếu dùng `powershell.exe` chuẩn sẽ bị `100542` level 12 đè `100544` level 11).

### Trạng thái triển khai (đã hoàn tất 28/28 ca `win-trigger.ps1 all`)
- [x] `brute_force_success.xml` và `outbound_connection.xml` đã chép vào `/var/ossec/etc/rules/` trên `wazuh-mgr` (bản cũ lưu `*.bak-20261123`), `wazuh-analysisd -t` OK, `wazuh-manager` active.
- [x] `Tools/win-trigger.ps1` đã đồng bộ sang `win10-lab` (`C:\win-trigger.ps1`).
- [x] Xác nhận `alerts.json` đã bắn thật toàn bộ 5 ca từng thiếu: `2.1` (`100120` @ `14:01:20`), `15.6` (`100548` @ `14:01:59`), `15.1` (`100542` @ `14:09:51`), `15.2` (`100543` @ `14:09:56`), `15.3` (`100544` @ `14:21:15`).
- [ ] Ghi chú nhiễu mới: `100543` khớp cả `C:\ProgramData\...` nên `MsMpEng.exe` (Windows Defender) có bắn `100543` — cân nhắc thêm vào `etc/lists/soc-allow-outbound-apps` sau.


---

## 2026-11-23 — Mở rộng `ubuntu-trigger.sh` & sửa rule Linux bị rule mặc định nuốt (HV2, HV3, HV12, HV15)

Nhánh `ai/linux-hv2-3-4-10-12-15`.
Phát hiện khi chạy `ubuntu-trigger.sh linux_extra` trên `ubuntu-lab` (agent 014) khung `15:40–15:43` (7 rule mới đạt ngay: `100312–100315`, `100328–100330`).

### 1. `brute_force_success.xml` — 100123, 100124, 100125 (HV2 Linux)
- **Sửa:** `<if_sid>5715</if_sid>` → `<if_sid>5715,40112</if_sid>`.
- **Vì sao:** Sau chuỗi SSH sai, đăng nhập thành công (`5715`) bị rule mặc định `40112` (*Multiple authentication failures followed by a success*) bắt trước lúc `15:41:26`, khiến `100123–100125` không được xét.

### 2. `ssh_root_login.xml` — 100480, 100486, 100489 (HV12 Linux)
- **Sửa:** `100480` và `100486` đổi `<if_sid>5715</if_sid>` → `<if_sid>5715,40112</if_sid>`; `100489` đổi `<if_matched_group>authentication_failed</if_matched_group>` → `<if_matched_sid>100112</if_matched_sid>`.
- **Vì sao:** Đăng nhập SSH `root` thành công lúc `15:42:28` và `15:42:46` đều bị `40112` nuốt mất `5715`; còn `100489` dùng `authentication_failed` bị `100112` che giống lỗi cũ của `100487`.

### 3. `account_manager.xml` — 100311 (HV3 Linux — tạo tài khoản UID 0)
- **Sửa:** `<if_sid>5902</if_sid>` → `<if_sid>5902,40501</if_sid>`.
- **Vì sao:** Lệnh `useradd -o -u 0` lúc `15:41:29` bị rule mặc định `40501` (*Attacks followed by the addition of an user*) nuốt mất `5902`.

### 4. `outbound_connection.xml` — 100552 (HV15 Linux — auditd execve reverse shell)
- **Sửa:** `<if_sid>80700</if_sid>` → `<if_sid>80700,80792</if_sid>`.
- **Vì sao:** Rule mặc định `80792` bắt mọi sự kiện auditd `execve` trước `80700`.

### 5. `Tools/ubuntu-trigger.sh` (mở rộng `linux_extra`)
- Bổ sung 12 ca mới: `2.4`, `2.5`, `3.9`, `3.10`, `3.11`, `4.6`, `4.7`, `10.8`, `10.9`, `12.2`, `12.3`, `15.8`.

### Trạng thái triển khai (đã hoàn tất Chặng 1 Linux)
- [x] 4 file XML (`brute_force_success.xml`, `ssh_root_login.xml`, `account_manager.xml`, `outbound_connection.xml`) đã chép vào `/var/ossec/etc/rules/` trên `wazuh-mgr`, `wazuh-analysisd -t` OK, `wazuh-manager` active.
- [x] Đã bật auditd (`99-soc-outbound.rules`, khóa `soc_outbound_connect`) và FIM realtime + `report_changes` (`/etc/sudoers.d,/etc/cron.d,/etc/systemd/system`) trên `ubuntu-lab`.
- [x] Xác nhận `alerts.json` đã bắn thật 14 rule Linux mới (`100311–100315`, `100328–100330`, `100420`, `100457`, `100486`, `100489`, `100549`, `100551`) và đã tự động chụp + dán 8 ảnh vào Google Docs (`HV3`, `HV4`, `HV10`, `HV12`, `HV15`).


---

## 2026-11-23 — Chặng 3: Mở rộng `win-trigger.ps1` & `ubuntu-trigger.sh` cho HV9, HV11, HV14, HV16

Nhánh `ai/chang3-hv9-11-14-16`.
- Bổ sung lệnh `chang3` vào `Tools/win-trigger.ps1` (`hv9`, `hv11`, `hv16`) và `Tools/ubuntu-trigger.sh` (`hv9`, `hv14`), đồng bộ sang `trigger/` và 2 agent.
- Trên `ubuntu-lab`: gỡ `/etc/audit/rules.d/99-soc-outbound.rules` (hết nhiễu `100549`), thêm `99-soc-webshell.rules` (khóa `webshell_command_exec` cho uid 33 `www-data`), mở rộng FIM `realtime="yes" report_changes="yes"` cho đường dẫn HV9 & `/var/www/html`.
- **Kết quả xác nhận trong `alerts.json` (+17 rule mới → tổng 115 / 229 rule, đã phủ ảnh 16 / 16 Google Docs):**
  - HV9 Windows: `100436` (`9.13`).
  - HV9 Linux: `100422` (`9.3`), `100423` (`9.4`), `100426` & `100433` (`9.7`), `100427` & `100428` (`9.8`), `100429` (`9.1`), `100431` (`9.9`).
  - HV11: `100473` (`11.3`), `100476` (`11.4`), `100474` & `100475` (`11.6`).
  - HV14: `100531` (`14.6`).
  - HV16: `100609` (`16.8` — Defender bắt EICAR Event 1116), `100611` (`16.5`), `100613` (`16.6`).
- Đã tự động chụp headless và dán thêm 14 ảnh (`9.1, 9.3, 9.4, 9.7, 9.8, 9.9, 9.13, 11.3, 11.4, 11.6, 14.6, 16.5, 16.6, 16.8`) + `15.4` (`100546`) vào Google Docs (tổng **76 ảnh** trên **16 / 16 Google Docs**).

---

## 2026-11-24 — Đợt kiểm thử bổ sung HV7 Linux, HV14, HV5 (5.4), HV11 & điền mục IV

Nhánh `ai/20261124-hv7-hv14-hv5-hv11`.
- **`Tools/ubuntu-trigger.sh`:** Thêm `c_7_7` (`100388` — dùng `sudo systemctl disable wazuh-agent` rồi `enable` lại ngay để tránh dừng agent trước khi đẩy log), `c_7_8` (`100391` — `sudo iptables` chặn cổng 1514 rồi gỡ ngay), bổ sung `/bin/ls /tmp` trong `c_14_6` (`100530`). Đồng bộ sang `trigger/ubuntu-trigger.sh` và `ubuntu-lab`.
- **Kết quả xác minh bắn thật trong `alerts.json` (+9 rule mới, tổng 138 rule `100xxx` đã bắn thật):**
  - HV7 Linux (`ubuntu-lab`, 014): **`100388`** (`7.7`, 01:15:25), **`100391`** (`7.8`, 01:14:44).
  - HV14 (`ubuntu-lab`, 014): **`100530`** (`14.6`, 01:13:24 — `/usr/bin/ls`).
  - HV5 (`win10-lab`, 013): **`100342`** & **`100349`** (`5.4`, 01:18:24–01:18:34 — PowerShell download cradle).
  - HV11 (`win10-lab`, 013): **`100460`** (`11.1`, 01:18:35 — `PSEXESVC`), **`100461`** (`smbexec`, 01:18:35), **`100465`** (`wmiexec/dcomexec`, 01:20:04), **`100466`** (`atexec`, 01:20:04).
- **Ghi nhận kỹ thuật:**
  - `100462` bị rule mặc định `92650` của Wazuh bắt trước (kể cả khi dùng `%systemroot%` chữ thường).
  - `100465`/`100466` nếu gọi `cmd.exe` từ `powershell.exe` sẽ bị `92004` nuốt `61603`; chạy trực tiếp qua `cmd.exe` sẽ nổ đúng `100465`/`100466`.
  - `100467` (WinRM) bị `AccessDenied` qua phiên SSH key không có vé Kerberos; `100601` bị `100600` (MD5) khớp trước trên cùng tệp mẫu; `100608` chưa cài ClamAV trên `ubuntu-lab`.
- Đã tự động chụp Dashboard và dán thêm 5 ảnh (`7.7`, `7.8`, `14.6`, `5.4`, `11.1`) vào Google Docs (tổng **93 ảnh** trên **16 / 16 Google Docs**), đồng thời điền tự động **mục IV (Bảng ghi kết quả)** cho toàn bộ **16 / 16 Google Docs** (bao gồm tạo mới bảng 9×5 còn thiếu ở HV13).
