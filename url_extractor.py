from url_analyzer import analyze_url
from threat_intelligence import check_url_reputation
import re


def extract_urls(message):
    url_pattern = r"https?://\S+"
    urls = re.findall(url_pattern, message)
    if len(urls) > 5:
        raise ValueError("Too many URLS in one request. Maximum is 5.")
    url_results = []

    for url in urls:
 
        findings, score = analyze_url(url)
        threat_intelligence = check_url_reputation(url)

        url_results.append({
            "url": url,
            "findings": findings,
            "score": score,
            "threat_intelligence": threat_intelligence
        })

    return urls, url_results