import requests
import os 
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
if api_key:
    endpoint = f"{endpoint}?key={api_key}"


def check_url_reputation(url):
    data = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes":["MALWARE",
            "SOCIAL_ENGINEERING"
            ],
            "platformTypes": ["WINDOWS"],
            "threatEntryTypes": [
                "URL"
            ],
            "threatEntries": [
                {
                    "url": url
                }
            ]
        }
    }
    try:
        response = requests.post(
        endpoint,
        json = data,
        headers={"Content-Type": "application/json"},
        timeout=10
        )
        result = response.json()

    except requests.RequestException:
        return{
              "matched": False,
              "threat_type": None,
               "available": False  
          }
    if "matches" in result:
        matches = result["matches"]
        match = matches[0]
        threat_type = match["threatType"]
        return {
            "matched": True,
            "threat_type" : threat_type,
            "available": True
        }
    else:
         return {
                    "matched": False,
                    "threat_type" : None,
                    "available": True
                }
    
