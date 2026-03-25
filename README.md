# Cyber Risk & Threat Intelligence Scanner

This module performs automated risk scoring by chaining an OS/Service analysis (`Nmap`) with a threat intelligence lookup (`VirusTotal`). The results are automatically persisted locally into an SQLite database.

## 🚀 Setup Instructions

### 1. Prerequisites
- **Python 3.8+**
- **Nmap**: You MUST install Nmap on your system for the scanner to function.
  - Windows: [Download from nmap.org](https://nmap.org/download) it usually installs to `C:\Program Files (x86)\Nmap\`
  - Mac: `brew install nmap`
  - Linux: `sudo apt install nmap`

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Environment Variables
Copy the `.env.example` file to create your own local `.env`:
```bash
cp .env.example .env
```
Inside your new `.env` file:
1. Add your VirusTotal API key: `VT_API_KEY="yourApiKeyHere"`
2. If `nmap` is not in your system PATH automatically, add its full path: `NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe`

### 4. Running the Scanner
The `main.py` file is the entry point. Simply run:
```bash
python main.py
```
*(Note for Windows users: Nmap OS detection `-O` requires running your terminal as **Administrator**. Without admin rights, the scan will still finish but will skip OS detection.)*

## 🗄️ Database
All scans are automatically saved into a local SQLite database at `db/scanner_db.sqlite`. You don't need to run a server. You can view the data using any standard SQLite viewer (like the *SQLite Viewer* extension in VS Code).
