# 🛠️ Multitool With OSINT

> **⚠️ EDUCATIONAL PURPOSES ONLY**  
> This tool is intended for **educational** and **ethical hacking** use only.  
> **Always obtain proper authorization** before scanning or testing any system.

---

## ⚙️ Features

- 🔐 Password hash cracking (MD5, SHA1, SHA256, SHA512, NTLM)
- 🚪 SSH brute forcing
- 🕵️ OSINT modules for emails & phone numbers
- 🔍 Vulnerability scanning using Nmap
- 📧 HaveIBeenPwned integration
- 📱 Phone number lookup (region, carrier, timezone)
- 🎨 Colorful and user-friendly CLI interface

---

## 📦 Requirements

Install the required Python packages:

```bash
pip install -r requirements.txt
```

Make sure you have `nmap` installed:

- **Debian/Ubuntu/Kali**:  
  ```bash
  sudo apt install nmap
  ```
- **macOS**:  
  ```bash
  brew install nmap
  ```
- **Windows**:  
  [Download from official site](https://nmap.org/download.html)

---

## 🔑 API Keys

Edit `tool.py` and replace the following:

```python
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
HIBP_API_KEY = "YOUR_HIBP_API_KEY"
```

Get free API keys from:

- [VirusTotal](https://www.virustotal.com/)
- [HaveIBeenPwned](https://haveibeenpwned.com/API/v3)

---

## 🐧 Installation on Debian/Ubuntu/Kali

### 1. Update and install dependencies
```bash
sudo apt update && sudo apt install -y python3 python3-pip nmap git
```

### 2. Clone the repository
```bash
git clone https://github.com/Qoyixfex/Qoyisec
cd Qoyisec
```

### 3. Install Python packages
```bash
pip3 install -r requirements.txt
```

### 4. Run the tool
```bash
python3 tool.py
```

---

## 📱 Installation on Termux (Android)

### 1. Update packages and install essentials
```bash
pkg update && pkg upgrade -y
pkg install -y python git nmap openssh
```

### 2. Clone the repository
```bash
git clone https://github.com/Qoyixfex/Qoyisec
cd Qoyisec
```

### 3. Install Python packages
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run the tool
```bash
python3 tool.py
```

---

## 🚀 Usage

```bash
python3 tool.py [command] [options]
```

### 🔓 Crack a hash
```bash
python3 tool.py crack -w wordlist.txt -t sha256 <hash>
```

### 💥 SSH brute force
```bash
python3 tool.py brute -u root -w passwords.txt <target_ip>
```

### 🔍 Vulnerability scan
```bash
python3 tool.py scan <target_ip>
```

### 📱 Phone number OSINT
```bash
python3 tool.py phone "+14155552671"
```

### 📧 Email breach check
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

This project is intended **only for educational and authorized security testing**.  
Do **NOT** use this tool to access or attack systems without **explicit permission**.  
By using this software, you agree to assume **full responsibility** for any actions performed with it.

---

## ⭐ Credits

ZamSec
QoyiSec
Foxus

If u like the tool, please share it.
