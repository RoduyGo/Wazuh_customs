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

### Vấn đề chưa sửa — agent 014 làm rơi log journald

2 dòng log có trong journald ubuntu-lab nhưng **không về manager** (log auditd cùng giây vẫn về):
- 19:49:28 `labnosudo : user NOT in sudoers` (lần 1/3 của ca 13.4) → 100505 thiếu 1 lần nên không đủ ngưỡng 3.
- 19:49:37 `labrestrict : command not allowed` (ca 13.5) → mất 100503. Logtest với dòng này ra 100503 đúng, tức rule không sai.

Chưa rõ nguyên nhân (nghi bộ đọc journald của logcollector). Nếu chạy lại vẫn rơi: cho agent đọc `/var/log/auth.log` thay journald cho log xác thực.

### Đã kiểm tra, không phải lỗi
- Decoder `0320-sudo_decoders_soc.xml` đã nằm đúng `etc/decoders/`, bản gốc đã `decoder_exclude` → trường `src_user` có đủ.
- `soc-allow-ip` chỉ có `127.0.0.1`, `soc-allow-account` chỉ có `healthcheck_svc` → không chặn tài khoản/IP thử.

### Trạng thái triển khai lên manager (192.168.88.245)
- [ ] Chép `sudo_failures.xml`, `ssh_root_login.xml` vào `/var/ossec/etc/rules/` (bản cũ lưu `*.bak-20261123`)
- [ ] `wazuh-analysisd -t` OK
- [ ] Restart `wazuh-manager`
- [ ] Logtest lại + chạy lại ca 12.1, 13.4, 13.5, 13.7, 13.8
