# PhantomScanner V16

Safe, authorized, passive/low-impact web security posture auditing.

Checks include security headers, cookie attributes, CORS wildcard signals, mixed-content references, HTTP form actions, server disclosure, source-map references, possible directory listings, and discovery/inventory.

It does **not** brute-force, fuzz, exploit, attack authentication, or use destructive payloads.

Example:

# install

```bash
pkg update && pkg upgrade -y
```

```bash
pkg install git -y
```

```bash
git clone https://github.com/Elfajree07/PhantomScanner-V15.git
```

```bash
cd PhantomScanner-V15
```

```bash
pip install -r requirements.txt
```

# cek menu help

```bash
python phantomscanner_v16.py --help
```

# scan all

```bash
python phantomscanner_v16.py -u https://TARGET.com --max--pages 100 --delay 5 --scope domain -o reports/NAMA-HASIL
```

# jika ingin menggunakan update terbaru yang lebih gacor

```bash
python phantomscanner_v16_1.py
```

atau

```bash
python phantom_triage_v161.py
```

# WARNING!!!

gunakan tool ini untuk website yang emang kamu punya izin untuk test

sekian dari saya.

Author:
elfajree
