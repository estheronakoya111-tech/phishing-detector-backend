# Phishing Detector — Backend

A FastAPI backend that analyzes suspicious messages and URLs for common phishing indicators and returns an explainable risk assessment.

The backend combines **message analysis, URL analysis, and Google Safe Browsing threat intelligence** to identify potentially suspicious content.

> **Note:** This project is a security-analysis tool, not a guarantee that a message or URL is safe.

---

## Features

* Analyze suspicious message content for common phishing indicators.
* Detect urgent and pressure-based language.
* Detect threats involving account suspension, closure, or loss of access.
* Detect requests for passwords, PINs, OTPs, and other credentials.
* Detect financial and payment-related requests.
* Detect possible impersonation language.
* Detect common suspicious spelling patterns.
* Extract URLs from submitted messages.
* Analyze URLs for common structural warning signs.
* Check extracted URLs against Google Safe Browsing.
* Combine multiple indicators when determining risk.
* Return an explainable risk level:

  * **Low**
  * **Moderate**
  * **High**
* Provide a human-readable security recommendation.
* Handle malformed URLs without crashing.
* Limit requests to a maximum of **5 URLs per message**.
* Limit message size to **10,000 characters**.
* Rate-limit the `/analyze` endpoint to **10 requests per minute per client IP**.
* Continue local analysis when the Google Safe Browsing service is unavailable.
* Return controlled error responses for unexpected server errors.

---

## How It Works

The analysis follows this flow:

```text
User Message
     │
     ▼
FastAPI API
     │
     ├── Message Analysis
     │       ├── Urgency
     │       ├── Threats
     │       ├── Credential Requests
     │       ├── Financial Requests
     │       └── Other Indicators
     │
     ├── URL Extraction
     │
     ├── URL Analysis
     │       ├── HTTPS
     │       ├── IP Address
     │       ├── URL Length
     │       ├── Suspicious Characters
     │       └── Suspicious Hostname Structure
     │
     ├── Google Safe Browsing
     │
     ▼
Risk Assessment
     │
     ▼
Security Recommendation
     │
     ▼
Structured JSON Response
```

---

## Risk Assessment

The backend does **not** present its internal score as a probability.

Instead, the final result is represented using three understandable risk levels:

### Low

No major phishing indicators were detected.

This does **not** guarantee that the message or URL is safe.

### Moderate

Multiple suspicious indicators were detected, but the available evidence does not meet the conditions for a high-risk result.

### High

Strong indicators or combinations of indicators were detected.

A URL identified as a known threat by Google Safe Browsing is also treated as **High risk**.

---

## Security Analysis

### Message Analysis

The backend checks for indicators such as:

* Urgent language
* Pressure to act quickly
* Threats or consequences
* Account verification requests
* Credential requests
* Financial requests
* Possible impersonation
* Suspicious spelling patterns

A single keyword does not automatically classify a message as phishing. The detected indicators are considered together.

### URL Analysis

Extracted URLs are checked for characteristics such as:

* Whether HTTPS is used
* IP addresses used instead of domain names
* Unusually long URLs
* `@` characters
* Suspicious hostname keywords
* Unusual domain structures
* Percent-encoded sequences

These characteristics are treated as warning signs rather than automatic proof of malicious intent.

### Threat Intelligence

URLs are checked against **Google Safe Browsing** for known threats.

The backend distinguishes between:

```text
Known threat
No known match
Service unavailable
```

A URL that is not found by the service is **not treated as proof that the URL is safe**.

---

## API

### `POST /analyze`

Analyzes a submitted message.

#### Request

```json
{
  "message": "Your account will be suspended. Verify your account immediately and enter your password. https://example.com"
}
```

#### Response

```json
{
  "risk_level": "High",
  "findings": [
    "suspicious urgency indicator",
    "your account will be suspended",
    "enter your password",
    "credential request pattern"
  ],
  "urls": [
    {
      "url": "https://example.com",
      "findings": [],
      "score": 0,
      "threat_intelligence": {
        "matched": false,
        "threat_type": null,
        "available": true
      }
    }
  ],
  "recommendation": "Do not enter or share your password, PIN, OTP, or other sensitive information..."
}
```

The exact response depends on the indicators detected in the submitted message and URLs.

---

## Input Protection

The API includes several protections around incoming requests.

### Message Size

Messages are limited to **10,000 characters**.

Requests exceeding this limit are rejected by the API.

### URL Limit

A maximum of **5 URLs** can be processed in a single request.

Requests containing more than 5 URLs return:

```json
{
  "detail": "Too many URLs in one request. Maximum is 5."
}
```

### Rate Limiting

The `/analyze` endpoint is limited to:

```text
10 requests per minute per client IP
```

Requests exceeding the limit receive HTTP `429 Too Many Requests`.

### Error Handling

The backend handles:

* Invalid input
* Excessive message size
* Too many URLs
* Malformed URLs
* Google Safe Browsing failures
* Network errors
* Unexpected server errors

Unexpected server errors return a generic response rather than exposing internal implementation details.

---

## Environment Variables

The Google Safe Browsing API key is stored in a local `.env` file.

Create:

```text
.env
```

and add:

```env
GOOGLE_SAFE_BROWSING_API_KEY=your_api_key_here
```

The `.env` file should **never be committed to GitHub**.

It is included in `.gitignore`.

---

## Installation

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd phishing-detector-backend
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the virtual environment

Windows:

```bash
.venv\Scripts\activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure environment variables

Create a `.env` file and add your Google Safe Browsing API key.

---

## Running the Backend

Start the development server with:

```bash
uvicorn main:app --reload
```

The API will be available locally at:

```text
http://127.0.0.1:8000
```

FastAPI's interactive API documentation is available at:

```text
http://127.0.0.1:8000/docs
```

---

## Project Structure

```text
phishing-detector-backend/
│
├── main.py
├── analyzer.py
├── url_extractor.py
├── url_analyzer.py
├── threat_intelligence.py
├── risk_assessment.py
├── models.py
├── requirements.txt
├── .env
├── .gitignore
└── README.md
```

### File Responsibilities

**`main.py`**

Handles the FastAPI application, `/analyze` endpoint, rate limiting, and error handling.

**`analyzer.py`**

Analyzes the message itself for phishing indicators.

**`url_extractor.py`**

Extracts URLs from submitted messages and coordinates URL analysis.

**`url_analyzer.py`**

Analyzes the structure and characteristics of extracted URLs.

**`threat_intelligence.py`**

Communicates with Google Safe Browsing to check URLs against known threats.

**`risk_assessment.py`**

Combines the analysis results and determines the final risk level and recommendation.

**`models.py`**

Defines the request and response data models using Pydantic.

---

## Technologies

* **Python**
* **FastAPI**
* **Pydantic**
* **Requests**
* **SlowAPI**
* **python-dotenv**
* **Google Safe Browsing API**
* **Uvicorn**

---

## Current Limitations

This project currently focuses on rule-based analysis.

It does not currently include:

* Machine learning
* Email file uploads
* Image/OCR analysis
* User accounts
* Analysis history
* Database storage
* Background job queues
* Browser-based URL execution
* Full website content analysis

The absence of a detected indicator should not be interpreted as proof that a message or URL is safe.

---

## Future Improvements

Potential future improvements include:

* More sophisticated URL and domain analysis
* Additional threat-intelligence sources
* Better natural-language analysis
* Expanded detection rules
* Improved explanation of individual findings
* Additional security testing
* Production deployment and monitoring

---

## Disclaimer

This project is intended for **educational and defensive security purposes**.

It provides an automated assessment based on available indicators and threat-intelligence results. It should not be treated as a definitive determination that a message or URL is malicious or safe.
