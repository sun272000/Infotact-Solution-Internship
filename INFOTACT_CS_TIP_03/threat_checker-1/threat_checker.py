import requests
import json
import sqlite3

#--- CONFIGURATION ---
# IMPORTANT: PASTE YOUR ABUSEIPDB API KEY HERE
API_KEY = 'YOUR_API_KEY_HERE'
DB_FILE = 'threat_intel.db'

def setup_database():
    """Create the SQLite database and table if they don't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        ip_address TEXT PRIMARY KEY,
        abuse_confidence INTEGER,
        country_code TEXT
    )
    """)
    conn.commit()
    conn.close()

def fetch_threat_feed():
    """Fetch a list of malicious IPs from AbuseIPDB and store them."""
    print("Fetching latest threat intelligence...")
    headers = {'Accept': 'application/json', 'Key': API_KEY}
    params = {'limit': 1000}  # Fetch 1000 most recently reported IPs
    
    # Check if API_KEY is still the default placeholder
    if API_KEY == 'YOUR_API_KEY_HERE' or not API_KEY:
        print("Error: API_KEY has not been set. Please edit the script and add your key.")
        return

    try:
        response = requests.get('https://api.abuseipdb.com/api/v2/blacklist', headers=headers, params=params)
        response.raise_for_status() # Raise an exception for bad status codes (like 401 for bad API key)
        data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    count = 0
    for record in data['data']:
        # Use INSERT OR IGNORE to avoid errors on duplicate IPs
        cursor.execute("INSERT OR IGNORE INTO iocs (ip_address, abuse_confidence, country_code) VALUES (?, ?, ?)",
                       (record['ipAddress'], record['abuseConfidenceScore'], record['countryCode']))
        if cursor.rowcount > 0:
            count += 1
    conn.commit()
    conn.close()
    print(f"Database updated. Added {count} new IPs.")

def check_logs(log_file):
    """Check IPs from a log file against the threat database."""
    print(f"\nScanning log file: {log_file}...")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        with open(log_file, 'r') as f:
            for line in f:
                # This is a simple example; real log parsing would be more complex
                ip = line.strip()
                cursor.execute("SELECT ip_address, abuse_confidence FROM iocs WHERE ip_address = ?", (ip,))
                result = cursor.fetchone()
                if result:
                    print(f" (!) ALERT: Malicious IP found in logs: {result[0]} (Confidence: {result[1]}%)")
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
    finally:
        conn.close()

if __name__ == "__main__":
    # 1. Setup the local database
    setup_database()

    # 2. Fetch the latest threats and populate the database
    fetch_threat_feed()

    # 3. Create a fake log file for demonstration
    print("\nCreating a sample log file: access.log...")
    with open('access.log', 'w') as f:
        f.write("192.168.1.1\n")
        f.write("185.191.171.12\n")  # Example of a potentially malicious IP
        f.write("8.8.8.8\n")
        f.write("206.189.123.45\n")  # Another example

    # 4. Check the logs against our database
    check_logs('access.log')
