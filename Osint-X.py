import requests
import json
import socket
import ssl
import subprocess
import threading
import dns.resolver
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import time

report = {}

# Store API keys here, filled by user at runtime
API_KEYS = {
    "hibp": None,
    "shodan": None,
    "securitytrails": None,
    "pastebin": None,
    "linkedin": None,
    "twitter_bearer": None,
    "google_cse_key": None,
    "google_cse_id": None,
    "pipl": None
}

def print_banner():
    banner = r"""
  ___       _          ____             _       ____      _               
 / _ \  ___| |_ ___   |  _ \  __ _ _ __| | __  / ___|   _| |__   ___ _ __ 
| | | |/ __| __/ _ \  | | | |/ _` | '__| |/ / | |  | | | | '_ \ / _ \ '__|
| |_| | (__| || (_) | | |_| | (_| | |  |   <  | |__| |_| | |_) |  __/ |   
 \___/ \___|\__\___/  |____/ \__,_|_|  |_|\_\  \____\__, |_.__/ \___|_|   
                                                    |___/                 
 ____                            _ 
/ ___|  __ _ _   _  __ _ _ __ __| |
\___ \ / _` | | | |/ _` | '__/ _` |
 ___) | (_| | |_| | (_| | | | (_| |
|____/ \__, |\__,_|\__,_|_|  \__,_|
          |_|                      

    🛠️  Octo Dark Cyber Squad Osint-X
    👤 Made by: Ariyan Bin Bappy
    ☠️  Group: Octo Dark Cyber Squad
    ⚠️  For authorized testing only 
"""
    print(banner)

def extract_domain(input_url):
    parsed = urlparse(input_url if "://" in input_url else "http://" + input_url)
    domain = parsed.netloc or parsed.path
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.strip("/")

def wait():
    input("\n[↩️ ] Press Enter to return to menu...")

def format_dict(data):
    return "\n".join(f"{k}: {v}" for k, v in data.items())

# WHOIS lookup
def whois_lookup(domain):
    try:
        result = subprocess.check_output(["whois", domain], stderr=subprocess.STDOUT, timeout=10).decode()
        return result
    except Exception as e:
        return f"[!] WHOIS failed: {e}"

# DNS Records
def dns_records(domain):
    records = {}
    try:
        for record_type in ["A", "AAAA", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except:
                records[record_type] = []
    except Exception as e:
        records["error"] = str(e)
    return records

# IP Geolocation
def ip_geolocation(ip):
    try:
        data = requests.get(f"http://ip-api.com/json/{ip}").json()
        if data.get("status") != "success":
            return "[!] Failed to retrieve geolocation data."
        output = f"""
🌐 IP Geolocation Information:
----------------------------------
📍 IP Address      : {data.get('query')}
🌍 Country          : {data.get('country')} ({data.get('countryCode')})
🏙️  Region          : {data.get('regionName')}
🏠 City             : {data.get('city')}
📫 ZIP Code         : {data.get('zip')}
🛰️  ISP              : {data.get('isp')}
🏢 Organization     : {data.get('org')}
🔀 ASN              : {data.get('as')}
🕒 Timezone         : {data.get('timezone')}
"""
        return output.strip()
    except Exception as e:
        return f"[!] Error retrieving IP info: {e}"

# SSL info
def ssl_info(domain):
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()
        return json.dumps(cert, indent=2)
    except Exception as e:
        return f"[!] SSL Error: {e}"

# Metadata extractor
def extract_metadata_from_url(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        return json.dumps({
            "title": soup.title.string if soup.title else None,
            "meta_tags": [tag.get("content") for tag in soup.find_all("meta") if tag.get("content")]
        }, indent=2)
    except Exception as e:
        return f"[!] Metadata extraction error: {e}"

# TCP Port Scan
def port_scan(domain, ports=[21,22,80,443,8080]):
    open_ports = []
    def scan(p):
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((domain, p))
            open_ports.append(p)
            sock.close()
        except:
            pass
    threads = []
    for port in ports:
        t = threading.Thread(target=scan, args=(port,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    return f"🔓 Open Ports: {', '.join(map(str, open_ports))}" if open_ports else "🔒 No open ports found."

# Cloudflare WAF detection
def detect_cloudflare(domain):
    try:
        ip = socket.gethostbyname(domain)
        if ip.startswith("104.") or "cloudflare" in socket.gethostbyaddr(ip)[0]:
            return "☁️ Cloudflare Detected"
        return "❌ No Cloudflare"
    except:
        return "[!] Could not detect Cloudflare"

# CVE Search from NVD API
def search_cve(keyword):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}"
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            if "vulnerabilities" in data:
                results = []
                for item in data["vulnerabilities"][:5]:  # Limit to 5 results
                    cve_id = item["cve"]["id"]
                    desc = item["cve"]["descriptions"][0]["value"] if item["cve"]["descriptions"] else "No description"
                    results.append(f"{cve_id}: {desc}")
                return "\n\n".join(results)
            else:
                return "No CVE results found."
        else:
            return f"[!] NVD API Error: HTTP {resp.status_code}"
    except Exception as e:
        return f"[!] CVE Search error: {e}"

# HaveIBeenPwned Email Breach Check
def email_breach_check(email):
    key = API_KEYS.get("hibp")
    if not key:
        return "[!] HIBP API key not set. Use option 21 to enter API keys."
    headers = {
        "hibp-api-key": key,
        "user-agent": "Osint-X-Tool"
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            breaches = resp.json()
            if not breaches:
                return f"No breaches found for {email}."
            output = f"Breaches found for {email}:\n"
            for breach in breaches:
                output += f"- {breach['Title']} ({breach['BreachDate']}), Data compromised: {', '.join(breach.get('DataClasses',[]))}\n"
            return output
        elif resp.status_code == 404:
            return f"No breaches found for {email}."
        else:
            return f"[!] HIBP API error: HTTP {resp.status_code} - {resp.text}"
    except Exception as e:
        return f"[!] HIBP API call failed: {e}"

# Shodan Host Info
def shodan_host_info(ip):
    key = API_KEYS.get("shodan")
    if not key:
        return "[!] Shodan API key not set. Use option 21 to enter API keys."
    url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            output = f"Shodan Host Info for {ip}:\n"
            output += f"Org: {data.get('org')}\n"
            output += f"ISP: {data.get('isp')}\n"
            output += f"Operating System: {data.get('os')}\n"
            output += f"Open Ports: {', '.join(str(p) for p in data.get('ports', []))}\n"
            output += f"Last Update: {data.get('last_update')}\n"
            return output
        else:
            return f"[!] Shodan API error: HTTP {resp.status_code} - {resp.text}"
    except Exception as e:
        return f"[!] Shodan API call failed: {e}"

# SecurityTrails Subdomains
def securitytrails_subdomains(domain):
    key = API_KEYS.get("securitytrails")
    if not key:
        return "[!] SecurityTrails API key not set. Use option 21 to enter API keys."
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            subdomains = data.get("subdomains", [])
            if subdomains:
                return f"Subdomains found for {domain}:\n" + "\n".join([f"{sd}.{domain}" for sd in subdomains])
            else:
                return f"No subdomains found for {domain}."
        else:
            return f"[!] SecurityTrails API error: HTTP {resp.status_code} - {resp.text}"
    except Exception as e:
        return f"[!] SecurityTrails API call failed: {e}"

# Pastebin Recent Pastes for a keyword (requires API key, otherwise simple scraping fallback)
def pastebin_search(keyword):
    key = API_KEYS.get("pastebin")
    if not key:
        return "[!] Pastebin API key not set. Use option 21 to enter API keys."
    # Pastebin API is limited; for demo, fallback to scrape trending pastes
    try:
        resp = requests.get("https://pastebin.com/archive", timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        pastes = soup.find_all("a", class_="i_p0")
        matches = []
        for paste in pastes:
            if keyword.lower() in paste.text.lower():
                matches.append("https://pastebin.com" + paste.get("href"))
            if len(matches) >= 5:
                break
        if matches:
            return "Pastebin recent pastes matching keyword:\n" + "\n".join(matches)
        else:
            return "No recent Pastebin pastes matching the keyword."
    except Exception as e:
        return f"[!] Pastebin search failed: {e}"

# LinkedIn Public Profile Search (Simple scrape)
def linkedin_public_search(name):
    # Note: LinkedIn restricts scraping; this is a basic Google search link only.
    return f"LinkedIn public profile search URL for '{name}':\nhttps://www.google.com/search?q=site:linkedin.com/in+\"{name}\""

# Twitter Recent Tweets Search (API v2)
def twitter_recent_tweets(username):
    bearer_token = API_KEYS.get("twitter_bearer")
    if not bearer_token:
        return "[!] Twitter Bearer token not set. Use option 21 to enter API keys."
    headers = {"Authorization": f"Bearer {bearer_token}"}
    try:
        # First get user id
        user_resp = requests.get(f"https://api.twitter.com/2/users/by/username/{username}", headers=headers)
        if user_resp.status_code != 200:
            return f"[!] Twitter API user lookup error: {user_resp.status_code} - {user_resp.text}"
        user_id = user_resp.json()["data"]["id"]
        tweets_resp = requests.get(f"https://api.twitter.com/2/users/{user_id}/tweets?max_results=5", headers=headers)
        if tweets_resp.status_code != 200:
            return f"[!] Twitter API tweets fetch error: {tweets_resp.status_code} - {tweets_resp.text}"
        tweets = tweets_resp.json().get("data", [])
        if not tweets:
            return f"No recent tweets found for @{username}."
        output = f"Recent tweets for @{username}:\n"
        for tweet in tweets:
            output += f"- {tweet['text']}\n"
        return output
    except Exception as e:
        return f"[!] Twitter API call failed: {e}"

# Google Custom Search (limited)
def google_custom_search(query):
    key = API_KEYS.get("google_cse_key")
    cse_id = API_KEYS.get("google_cse_id")
    if not key or not cse_id:
        return "[!] Google CSE API key or Search Engine ID not set. Use option 21 to enter API keys."
    url = f"https://www.googleapis.com/customsearch/v1?q={query}&key={key}&cx={cse_id}&num=5"
    try:
        resp = requests.get(url)
        if resp.status_code != 200:
            return f"[!] Google CSE API error: HTTP {resp.status_code} - {resp.text}"
        data = resp.json()
        if "items" not in data:
            return "No results found."
        results = []
        for item in data["items"]:
            results.append(f"{item['title']}\n{item['link']}\n")
        return "\n".join(results)
    except Exception as e:
        return f"[!] Google CSE API call failed: {e}"

# ExploitDB search (scrape)
def exploitdb_search(keyword):
    try:
        url = f"https://www.exploit-db.com/search?cve={keyword}"
        resp = requests.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        rows = soup.select("table.table tbody tr")
        if not rows:
            return "No exploits found."
        results = []
        for row in rows[:5]:
            cols = row.find_all("td")
            if len(cols) >= 5:
                title = cols[1].text.strip()
                date = cols[2].text.strip()
                platform = cols[3].text.strip()
                link = "https://www.exploit-db.com" + cols[1].find("a")["href"]
                results.append(f"{title} [{platform}] ({date})\n{link}")
        return "\n\n".join(results)
    except Exception as e:
        return f"[!] ExploitDB search error: {e}"

# Pipl Identity Graph (requires paid API key)
def pipl_search(name, email=None, phone=None):
    key = API_KEYS.get("pipl")
    if not key:
        return "[!] Pipl API key not set. Use option 21 to enter API keys."
    url = "https://api.pipl.com/search/v5/"
    params = {
        "key": key,
        "names": name,
        "email": email,
        "phone": phone,
        "pretty": "true"
    }
    try:
        resp = requests.get(url, params=params, timeout=15)
        if resp.status_code != 200:
            return f"[!] Pipl API error: HTTP {resp.status_code} - {resp.text}"
        data = resp.json()
        return json.dumps(data, indent=2)
    except Exception as e:
        return f"[!] Pipl API call failed: {e}"

def collect_api_keys():
    print("\n--- Enter Your API Keys (Leave blank to skip) ---")
    for k in API_KEYS.keys():
        val = input(f"Enter {k} API key/token: ").strip()
        if val:
            API_KEYS[k] = val
    print("[✔️] API keys updated.")
    wait()

def menu():
    print_banner()
    print("Select an option:")
    print(" 1) Domain WHOIS Lookup")
    print(" 2) DNS Records")
    print(" 3) IP Geolocation")
    print(" 4) SSL Certificate Info")
    print(" 5) Metadata Extractor from URL")
    print(" 6) TCP Port Scan")
    print(" 7) Cloudflare WAF Detection")
    print(" 8) CVE Search")
    print(" 9) Email Breach Check (HaveIBeenPwned)")
    print("10) Shodan Host Info")
    print("11) SecurityTrails Subdomains")
    print("12) Pastebin Search")
    print("13) LinkedIn Public Profile Search")
    print("14) Twitter Recent Tweets")
    print("15) Google Custom Search")
    print("16) ExploitDB Search")
    print("17) Pipl Identity Search")
    print("21) Enter/Update API Keys")
    print(" 0) Exit")

def main():
    while True:
        menu()
        choice = input("Your choice: ").strip()
        if choice == "0":
            print("Goodbye!")
            break
        elif choice == "1":
            domain = extract_domain(input("Enter domain: "))
            print("\nWHOIS Lookup Result:\n")
            print(whois_lookup(domain))
            wait()
        elif choice == "2":
            domain = extract_domain(input("Enter domain: "))
            print("\nDNS Records:\n")
            print(json.dumps(dns_records(domain), indent=2))
            wait()
        elif choice == "3":
            ip = input("Enter IP address: ").strip()
            print(ip_geolocation(ip))
            wait()
        elif choice == "4":
            domain = extract_domain(input("Enter domain: "))
            print("\nSSL Certificate Info:\n")
            print(ssl_info(domain))
            wait()
        elif choice == "5":
            url = input("Enter full URL: ").strip()
            print("\nMetadata:\n")
            print(extract_metadata_from_url(url))
            wait()
        elif choice == "6":
            domain = extract_domain(input("Enter domain or IP: "))
            ports = input("Enter ports (comma separated) or press Enter for default [21,22,80,443,8080]: ")
            if ports:
                try:
                    port_list = [int(p.strip()) for p in ports.split(",")]
                except:
                    port_list = [21,22,80,443,8080]
            else:
                port_list = [21,22,80,443,8080]
            print("\nPort Scan Result:\n")
            print(port_scan(domain, port_list))
            wait()
        elif choice == "7":
            domain = extract_domain(input("Enter domain: "))
            print(detect_cloudflare(domain))
            wait()
        elif choice == "8":
            keyword = input("Enter keyword for CVE search: ").strip()
            print("\nCVE Search Results:\n")
            print(search_cve(keyword))
            wait()
        elif choice == "9":
            email = input("Enter email address to check breaches: ").strip()
            print(email_breach_check(email))
            wait()
        elif choice == "10":
            ip = input("Enter IP address for Shodan info: ").strip()
            print(shodan_host_info(ip))
            wait()
        elif choice == "11":
            domain = extract_domain(input("Enter domain for subdomain enumeration: "))
            print(securitytrails_subdomains(domain))
            wait()
        elif choice == "12":
            keyword = input("Enter keyword for Pastebin search: ").strip()
            print(pastebin_search(keyword))
            wait()
        elif choice == "13":
            name = input("Enter full name to search LinkedIn profiles: ").strip()
            print(linkedin_public_search(name))
            wait()
        elif choice == "14":
            username = input("Enter Twitter username (without @): ").strip()
            print(twitter_recent_tweets(username))
            wait()
        elif choice == "15":
            query = input("Enter Google Custom Search query: ").strip()
            print(google_custom_search(query))
            wait()
        elif choice == "16":
            keyword = input("Enter CVE or keyword to search ExploitDB: ").strip()
            print(exploitdb_search(keyword))
            wait()
        elif choice == "17":
            name = input("Enter full name: ").strip()
            email = input("Enter email (optional): ").strip() or None
            phone = input("Enter phone (optional): ").strip() or None
            print(pipl_search(name, email, phone))
            wait()
        elif choice == "21":
            collect_api_keys()
        else:
            print("[!] Invalid option. Try again.")
            time.sleep(1)

if __name__ == "__main__":
    main()
