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
