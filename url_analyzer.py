import ipaddress
from urllib.parse import urlparse

def analyze_url(url):
    findings = []
    score = 0
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
    except ValueError:
        return ["URL is malformed or invalid"], 1
    if not hostname:
        return ["URL has an invalid or missing hostname"], 1

    if url.startswith("https://"):
        pass

    else:
        findings.append("URL does not use HTTPS")
        score = score + 1


    try:
        ipaddress.ip_address(hostname)
        findings.append("URL uses an IP address")
        score = score + 1
    except ValueError:
        pass

    if len(url) > 100:
        findings.append("URL is unusually long")   
        score = score + 1 
    if "@" in url:
        findings.append("URL contains @ character")
        score = score + 1

    suspicious_hostname_words = [
    "login",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "confirmation",
    "password",
    "signin",
    "authenticate",
    "claim",
    "reward",
    "freecash",
    "free-money",
    "bonus",
    "prize"
]
    suspicious_hostname_words_found = False
    for word in suspicious_hostname_words:
        if word in hostname:
           suspicious_hostname_words_found = True
           break
    if suspicious_hostname_words_found:
        findings.append("URL hostname is suspicious")
        score = score + 1
    if hostname.count(".") > 3:
        findings.append("URL domain name is suspicious")
        score = score + 1

    if "%" in url:
        findings.append("URL has a suspicious percent encoded sequences")
        score = score + 1



    
    return findings, score         
