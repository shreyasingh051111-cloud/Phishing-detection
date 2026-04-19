# 🛡️ PhishGuard 2.0 — Phishing URL Detector

A Flask-based web application that analyses URLs for phishing, malware, and suspicious patterns using 12 detection methods including Google Safe Browsing API integration.

---

## 📸 Features

- ✅ 12-point URL risk analysis
- 🌐 Google Safe Browsing API integration
- 🗄️ MySQL blacklist database check
- 📅 Domain age verification via WHOIS
- 📜 Full check history with CSV export
- 🎨 Dark-themed responsive UI

---

## 🧠 Detection Methods

| # | Check | Risk Score |
|---|-------|-----------|
| 1 | Blacklisted URL (database) | +100 |
| 2 | IP address used instead of domain | +20 |
| 3 | New domain (< 6 months old) | +20 |
| 4 | Google Safe Browsing flagged | +50 |
| 5 | @ symbol in URL | +10 |
| 6 | Very long URL (> 75 chars) | +10 |
| 7 | URL shortener detected | +15 |
| 8 | Suspicious keywords (login, verify, bank...) | +5 each |
| 9 | Hyphen in domain name | +5 |
| 10 | Too many subdomains | +5 |
| 11 | Not using HTTPS | +5 |
| 12 | High URL entropy (randomised look) | +5 |

**Verdict:**
- 🚨 **Phishing** — Score ≥ 60
- ⚠️ **Suspicious** — Score ≥ 30
- ✅ **Safe** — Score < 30

---

## 📁 Project Structure

```
phishing detection 2.0/
├── .venv/                  # Virtual environment (don't share)
├── static/
│   └── style.css           # All UI styling
├── templates/
│   ├── base.html           # Shared layout & navbar
│   ├── index.html          # Home / URL input page
│   ├── result.html         # Analysis result page
│   └── history.html        # Check history page
├── app.py                  # Main Flask application
├── config.py               # API keys & DB settings (don't share)
├── setup.sql               # Database setup script
├── .gitignore
└── README.md
```

---

## ⚙️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/phishguard.git
cd phishguard
```

### 2. Create & Activate Virtual Environment
```bash
# Create
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Activate (Mac/Linux)
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install flask mysql-connector-python python-whois requests
```

### 4. Set Up the Database
Make sure MySQL is running, then:
```bash
mysql -u root -p < setup.sql
```
This creates the `phishing2_db` database and both required tables automatically.

### 5. Configure API Key & Database
Open `config.py` and fill in your details:
```python
# config.py

GOOGLE_API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"

DB_HOST     = "localhost"
DB_USER     = "root"
DB_PASSWORD = "your_mysql_password"
DB_NAME     = "phishing2_db"
```

### 6. Get Google Safe Browsing API Key
1. Go to [https://console.cloud.google.com](https://console.cloud.google.com)
2. Create a new project
3. Navigate to **APIs & Services → Library**
4. Search for **Safe Browsing API** and click **Enable**
5. Go to **APIs & Services → Credentials**
6. Click **Create Credentials → API Key**
7. Copy the key and paste it into `config.py`

### 7. Run the App
```bash
python app.py
```
Then open your browser and go to: **http://127.0.0.1:5000**

---

## 🗄️ Database Tables

### `blacklisted2_urls`
Stores known malicious URLs. Any URL matching this list gets +100 risk score instantly.

| Column | Type | Description |
|--------|------|-------------|
| id | INT | Primary key |
| url | VARCHAR(2048) | Blacklisted URL |
| reason | VARCHAR(255) | Why it was blacklisted |
| added_at | TIMESTAMP | Date added |

### `url2_history`
Logs every URL checked through the app.

| Column | Type | Description |
|--------|------|-------------|
| id | INT | Primary key |
| url | VARCHAR(2048) | Checked URL |
| result | VARCHAR(50) | Phishing / Suspicious / Safe |
| score | INT | Risk score |
| checked_at | TIMESTAMP | When it was checked |

---

## 🌐 App Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET, POST | Home page — submit URL for analysis |
| `/history` | GET | View all previously checked URLs |
| `/export_history` | GET | Download history as CSV file |

---

## 🧪 Test URLs

| URL | Expected Result |
|-----|----------------|
| `https://google.com` | ✅ Safe |
| `http://192.168.1.1/login` | 🚨 Phishing |
| `http://secure-login-bank-verify.com/account` | 🚨 Phishing |
| `http://bit.ly/somepage` | ⚠️ Suspicious |
| `http://malware.testing.google.test/testing/malware/` | 🚨 Phishing (Google test URL) |

---

## 🔒 Security Notes

- **Never commit `config.py`** — it contains your API key and DB password
- Add it to `.gitignore` (see below)
- Keep `debug=True` only during development — set to `False` in production

### .gitignore
```
config.py
.venv/
__pycache__/
*.pyc
.env
```

---

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| `flask` | Web framework |
| `mysql-connector-python` | MySQL database connection |
| `python-whois` | Domain age lookup |
| `requests` | Google Safe Browsing API calls |

All other modules (`re`, `math`, `csv`, `io`, `datetime`, `urllib`, `collections`) are built into Python 3.

---

## 👩‍💻 Built With

- **Python 3.13**
- **Flask** — Web framework
- **MySQL** — Database
- **Google Safe Browsing API** — Threat intelligence
- **WHOIS** — Domain age verification

---

## 📄 License

This project is for educational purposes only.  
Do not use for commercial purposes without proper licensing of the APIs used.