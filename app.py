from flask import Flask, render_template, request, Response
import mysql.connector
import re
from urllib.parse import urlparse
import whois
from datetime import datetime
import math
from collections import Counter
import io
import csv
import requests
import socket

# ── IMPORT CONFIG ─────────────────────────────────
from config import GOOGLE_API_KEY, DB_HOST, DB_USER, DB_PASSWORD, DB_NAME

app = Flask(__name__)

# ── DATABASE CONNECTION ───────────────────────────
db = mysql.connector.connect(
    host=DB_HOST,
    user=DB_USER,
    password=DB_PASSWORD,
    database=DB_NAME
)

def get_cursor():
    global db
    try:
        db.ping(reconnect=True, attempts=3, delay=2)
    except mysql.connector.Error:
        db = mysql.connector.connect(
            host=DB_HOST, user=DB_USER,
            password=DB_PASSWORD, database=DB_NAME
        )
    return db.cursor()


# ── HELPER: IS IP ADDRESS? ────────────────────────
def is_ip_address(domain):
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain))


# ── WHITELIST OF KNOWN SAFE DOMAINS ──────────────
WHITELIST = [
    "google.com", "youtube.com", "facebook.com", "amazon.com",
    "microsoft.com", "apple.com", "twitter.com", "instagram.com",
    "linkedin.com", "github.com", "wikipedia.org", "reddit.com",
    "netflix.com", "yahoo.com", "bing.com", "whatsapp.com",
    "zoom.us", "dropbox.com", "adobe.com", "stackoverflow.com",
]

def is_whitelisted(domain):
    if is_ip_address(domain):
        return False
    domain = domain.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    for safe in WHITELIST:
        if domain == safe or domain.endswith("." + safe):
            return True
    return False


# ── SUSPICIOUS TLDs ───────────────────────────────
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",   # free domains, heavily abused
    ".xyz", ".top", ".club", ".online",
    ".icu", ".buzz", ".pw", ".cc",
    ".st", ".to", ".ws", ".biz"           # .st is sci-hub's TLD
]

# ── SUSPICIOUS SITE KEYWORDS (full domain) ───────
SUSPICIOUS_SITE_KEYWORDS = [
    "sci-hub", "scihub", "pirate", "warez", "crack", "keygen",
    "torrent", "nulled", "darkweb", "onion", "freebitcoin",
    "crypto-earn", "free-money", "win-prize", "click-here-now"
]


# ── DOMAIN AGE CHECK ──────────────────────────────
def check_domain_age(domain):
    if is_ip_address(domain):
        return 0, "IP address — domain age not applicable"
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return 0, "Domain age could not be determined"
        age = (datetime.now() - creation_date).days
        if age < 180:
            return 20, f"New domain — only {age} days old (less than 6 months)"
        else:
            return 0, f"Established domain — {age} days old"
    except Exception:
        return 0, "Domain age lookup unavailable (not penalised)"


# ── GOOGLE SAFE BROWSING CHECK ────────────────────
def google_safe_check(url):
    if not GOOGLE_API_KEY or GOOGLE_API_KEY == "YOUR_GOOGLE_SAFE_BROWSING_API_KEY":
        print("[GSB] ⚠️  API key not set in config.py — skipping check.")
        return False, "Google Safe Browsing skipped — API key not configured"

    print(f"[GSB] Checking URL: {url}")
    print(f"[GSB] Using key   : {GOOGLE_API_KEY[:8]}...")

    endpoint = (
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    )
    payload = {
        "client": {"clientId": "phishing-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        },
    }
    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        print(f"[GSB] HTTP Status : {response.status_code}")
        print(f"[GSB] Response    : {response.json()}")
        data = response.json()

        if "error" in data:
            msg = data["error"].get("message", "Unknown API error")
            print(f"[GSB] API Error: {msg}")
            return False, f"Google Safe Browsing API error: {msg}"

        if data.get("matches"):
            threat_type = data["matches"][0].get("threatType", "Unknown threat")
            return True, f"Google Safe Browsing flagged this URL — threat type: {threat_type}"

        return False, "Google Safe Browsing: No threats found"

    except Exception as e:
        print(f"[GSB] Exception: {e}")
        return False, f"Google Safe Browsing check failed: {str(e)}"


# ── URL ENTROPY ───────────────────────────────────
def entropy(string):
    prob = [n_x / len(string) for _, n_x in Counter(string).items()]
    return -sum(p * math.log2(p) for p in prob)


# ── MAIN PHISHING DETECTION ───────────────────────
def check_phishing(url):
    score = 0
    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Strip port if present
    if ":" in domain:
        domain = domain.split(":")[0]

    # ── CHECK 1: IP ADDRESS (before whitelist) ────
    if is_ip_address(domain):
        score += 30
        reasons.append(f"⚠ IP address used instead of domain name ({domain})")
        reasons.append("⚠ Legitimate websites always use domain names, not raw IPs")

    # ── CHECK 2: BLACKLIST ────────────────────────
    cursor = get_cursor()
    cursor.execute("SELECT * FROM blacklisted2_urls WHERE url=%s", (url,))
    if cursor.fetchone():
        score += 100
        reasons.append("🚫 URL found in local blacklist database")

    # ── WHITELIST SHORTCUT ────────────────────────
    if is_whitelisted(domain):
        gsb_hit, gsb_reason = google_safe_check(url)
        reasons.append(f"[GSB] {gsb_reason}")
        if gsb_hit:
            score += 50
            return "Phishing", score, reasons
        if score == 0:
            reasons.insert(0, "✅ Domain is on trusted whitelist")
            return "Safe", 0, reasons

    # ── CHECK 3: SUSPICIOUS TLD ───────────────────
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 15
            reasons.append(f"⚠ Suspicious top-level domain: '{tld}' — heavily abused by phishing sites")
            break

    # ── CHECK 4: SUSPICIOUS SITE KEYWORDS ─────────
    for keyword in SUSPICIOUS_SITE_KEYWORDS:
        if keyword in domain:
            score += 20
            reasons.append(f"⚠ Domain contains suspicious keyword: '{keyword}'")
            break

    # ── CHECK 5: @ SYMBOL ─────────────────────────
    if "@" in url:
        score += 10
        reasons.append("⚠ @ symbol in URL — browser ignores everything before it")

    # ── CHECK 6: URL LENGTH ───────────────────────
    if len(url) > 75:
        score += 10
        reasons.append(f"⚠ Unusually long URL ({len(url)} characters)")

    # ── CHECK 7: SUSPICIOUS KEYWORDS IN DOMAIN ────
    keywords = ["login", "verify", "secure", "account", "bank",
                "signin", "password", "confirm", "update", "webscr", "ebayisapi"]
    for word in keywords:
        if word in domain:
            score += 8
            reasons.append(f"⚠ Suspicious keyword in domain: '{word}'")

    # ── CHECK 8: URL SHORTENER ────────────────────
    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
                  "is.gd", "buff.ly", "adf.ly", "bit.do", "rebrand.ly"]
    for s in shorteners:
        if s in domain:
            score += 15
            reasons.append(f"⚠ URL shortener detected: {s}")
            break

    # ── CHECK 9: HYPHENS IN DOMAIN ────────────────
    hyphen_count = domain.count("-")
    if hyphen_count >= 2:
        score += 10
        reasons.append(f"⚠ Multiple hyphens in domain ({hyphen_count}) — common phishing pattern")
    elif hyphen_count == 1:
        score += 3
        reasons.append("⚠ Hyphen in domain name")

    # ── CHECK 10: TOO MANY SUBDOMAINS ─────────────
    subdomain_count = domain.count(".")
    if subdomain_count > 3:
        score += 10
        reasons.append(f"⚠ Excessive subdomains ({subdomain_count} dots)")
    elif subdomain_count > 2:
        score += 3
        reasons.append(f"⚠ Multiple subdomains ({subdomain_count} dots)")

    # ── CHECK 11: HTTPS ───────────────────────────
    if parsed.scheme != "https":
        score += 5
        reasons.append("⚠ Not using HTTPS — connection is unencrypted")
    else:
        reasons.append("✅ Uses HTTPS")

    # ── CHECK 12: DOMAIN AGE ──────────────────────
    age_score, age_reason = check_domain_age(domain)
    score += age_score
    prefix = "⚠" if age_score > 0 else "✅"
    reasons.append(f"{prefix} {age_reason}")

    # ── CHECK 13: URL ENTROPY ─────────────────────
    url_entropy = entropy(url)
    if url_entropy > 4.5:
        score += 5
        reasons.append(f"⚠ High URL entropy ({url_entropy:.2f}) — looks randomly generated")
    else:
        reasons.append(f"✅ URL entropy normal ({url_entropy:.2f})")

    # ── CHECK 14: GOOGLE SAFE BROWSING ────────────
    gsb_hit, gsb_reason = google_safe_check(url)
    reasons.append(f"[GSB] {gsb_reason}")
    if gsb_hit:
        score += 50

    # ── VERDICT ───────────────────────────────────
    if score >= 60:
        result = "Phishing"
    elif score >= 30:
        result = "Suspicious"
    else:
        result = "Safe"

    return result, score, reasons


# ── ROUTES ────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"].strip()
        result, score, reasons = check_phishing(url)
        cursor = get_cursor()
        cursor.execute(
            "INSERT INTO url2_history (url, result, score) VALUES (%s, %s, %s)",
            (url, result, score),
        )
        db.commit()
        return render_template(
            "result.html", url=url, result=result, score=score, reasons=reasons
        )
    return render_template("index.html")


@app.route("/history")
def history():
    cursor = get_cursor()
    cursor.execute("SELECT * FROM url2_history ORDER BY checked_at DESC")
    data = cursor.fetchall()
    return render_template("history.html", data=data)


@app.route("/export_history")
def export_history():
    cursor = get_cursor()
    cursor.execute("SELECT * FROM url2_history ORDER BY checked_at DESC")
    data = cursor.fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["URL", "Result", "Score", "Checked At"])
    for row in data:
        writer.writerow(row)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=history.csv"},
    )


if __name__ == "__main__":
    app.run(debug=True)