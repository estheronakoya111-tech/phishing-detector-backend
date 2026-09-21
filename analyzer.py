def analyze_message(message):
    message= message.lower()
    findings = []
    score = 0

    suspicious_keywords = [
    "urgent",
    "immediately",
    "act now",
    "verify",
    "confirm",
    "suspended",
    "locked",
    "security alert",
    "unusual activity",
    "click here",
    "update your account",
    "reset your password",
    "claim your reward"
] 
    urgency_phrases = [
    "urgent",
    "immediately",
    "act now",
    "right away",
    "as soon as possible",
    "within 24 hours",
    "last warning",
    "final notice",
    "do not delay"
]
    suspicious_keywords_found = False
    urgency_phrases_found = False
    for keyword in suspicious_keywords:
        if keyword in message:
            suspicious_keywords_found = True
            break
    for phrase in urgency_phrases:
        if phrase in message:
            urgency_phrases_found = True
            break
    if suspicious_keywords_found or urgency_phrases_found:
        findings.append("suspicious urgency indicator")
        score = score + 1


    
    mispelt_words = [
        "congratula",
        "congradulations",
        "verfy",
        "acount",
        "pasword",
        "securty"
    ]

    for word in mispelt_words:
        if word in message:
            findings.append(word)
            score = score + 1
    threat_phrases = [
    "your account will be closed",
    "your account will be suspended",
    "legal action",
    "your account will be terminated",
    "you will lose access",
    "failure to comply",
    "your account will be deleted"
]
    for phrase in threat_phrases:
        if phrase in message:
            findings.append(phrase)
            score = score + 1
    sensitive_requests = [
    "enter your password",
    "provide your password",
    "send your password",
    "enter your pin",
    "provide your pin",
    "share your otp",
    "enter your otp",
    "confirm your bank details",
    "provide your card details"
]
    for request in sensitive_requests:
        if request in message:
            findings.append(request)
            score = score + 1
    financial_requests = [
    "make a payment",
    "send money",
    "transfer money",
    "pay immediately",
    "confirm payment",
    "update your payment information",
    "enter your card number",
    "enter your cvv",
    "claim your refund",
    "pay the money",
    "send us the money",
    "credit card information",
    "credit card details",
    "large sum of money",
    "payment is required"
]
    for request in financial_requests:
        if request in message:
            findings.append(request)
            score = score + 1

    impersonation_phrases = [
    "dear customer",
    "dear user",
    "security team",
    "account department",
    "bank support",
    "customer service",
    "official notification",
    "your bank"
]
    for phrase in impersonation_phrases:
        if phrase in message:
            findings.append(phrase)
            score = score + 1

    financial_actions = [
    "send",
    "transfer",
    "pay",
    "deposit",
    "purchase",
    "submit",
    "claim",
    "receive"
]
        

    financial_terms = [
    "money",
    "payment",
    "cash",
    "naira",
    "dollar",
    "refund",
    "fee",
    "funds",
    "amount",
    "bank",
    "card",
    "account"
]
    financial_actions_found = False
    financial_terms_found = False

    for action in financial_actions:
        if action in message:
            financial_actions_found = True
            break
    for term in financial_terms:
        if term in message:
            financial_terms_found = True
            break
    if financial_actions_found and financial_terms_found:
        findings.append("financial request pattern")
        score = score +  1
        
       

    credential_actions = [
    "enter",
    "provide",
    "submit",
    "share",
    "confirm",
    "verify",
    "update"
]
    
    credential_terms = [
    "password",
    "pin",
    "otp",
    "username",
    "login",
    "credentials",
    "card details",
    "bank details"
]
    credential_actions_found = False
    credential_terms_found = False
    for action in credential_actions:
        if action in message:
            credential_actions_found = True
            break
    for term in credential_terms:
        if term in message:
            credential_terms_found = True
            break
    if credential_terms_found and credential_actions_found:
        findings.append("credential request pattern")
        score = score + 1
    return findings, score


