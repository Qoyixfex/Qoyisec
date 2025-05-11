# 🛠️ MULTITOLL WITH OSINT BY QOYISEC

> **EDUCATIONAL PURPOSE ONLY**  
> This tool is intended for **educational** and **ethical hacking** purposes. Always get **permission** before scanning or testing any system.

---

## ⚙️ Features

- 🔐 Password hash cracking (MD5, SHA1, SHA256, SHA512, NTLM)
- 🚪 SSH Brute Forcing
- 🕵️ OSINT modules for emails & phone numbers
- 🔍 Vulnerability scanning using Nmap
- 🔍 HaveIBeenPwned integration
- 📱 Phone number lookup (region, carrier, timezone)
- 🧠 Beautiful CLI interface

---

## 📦 Requirements

Install required Python packages:

```bash
pip install -r requirements.txt
```

Make sure you have `nmap` installed:

- Debian/Ubuntu: `sudo apt install nmap`
- macOS: `brew install nmap`
- Windows: [Download Nmap](https://nmap.org/download.html)

---

## 🔑 API Keys

Replace these placeholders in `ultimate_toolkit.py` with your actual keys:

```python
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
HIBP_API_KEY = "YOUR_HIBP_API_KEY"
```

---

🐧 Debian/Ubuntu/Kali Linux
# 1. Update and install dependencies
sudo apt update && sudo apt install -y python3 python3-pip nmap git

# 2. Clone the repository
git clone https://github.com/Qoyixfex/Qoyisec
cd Qoyisec

# 3. Install Python packages
pip3 install -r requirements.txt

# 4. Run the tool
python3 tool.py (go to usage Read.Md if u want to use it)




---



📱 Termux (Android)

# 1. Update packages and install essentials
pkg update && pkg upgrade -y
pkg install -y python git nmap openssh

# 2. Clone the repository
git clone https://github.com/Qoyixfex/Qoyisec
cd Qoyisec

# 3. Install pip packages
pip install --upgrade pip
pip install -r requirements.txt

# 4. Run the tool
python3 tool.py (if u want to use it, go to usage Read.Md)




---





## 🚀 Usage

```bash
python3 tool.py [command] [options]
```

### 🔓 Crack a hash

```bash
python3 tool.py crack -w wordlist.txt -t sha256 <hash>
```

### 💥 SSH Brute Force

```bash
python3 tool.py brute -u root -w passwords.txt <target_ip>
```

### 🔍 Vulnerability Scan

```bash
python3 tool.py scan <target_ip>
```

### 📱 Phone Number OSINT

```bash
python3 tool.py phone "+14155552671"
```

### 📧 Email Breach Check

```bash
python3 tool.py email "example@example.com"
```

---

## 📁 File Structure

```text
.
├── tool.py
├── requirements.txt
└── README.md
```

---

## ⚠️ Legal Disclaimer

This project is intended **only for educational and ethical testing** purposes.  
**Do not use** this tool to attack or access systems without proper authorization.  
By using this toolkit, you agree to use it **at your own risk**.

---

## 🤖 owner
CREDITS:
QoyiSec
Zam
Foxus

Made with Python.
