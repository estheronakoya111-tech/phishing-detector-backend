
def assess_risk(message_score, message_findings, url_results):
    total_score = message_score
    all_findings = message_findings.copy()

    credential_request = "credential request pattern" in all_findings
    financial_request = "financial request pattern" in all_findings
    urgency = "suspicious urgency indicator" in all_findings

    threat = any(
        finding in all_findings
        for finding in [
            "your account will be suspended",
            "your account will be closed",
            "legal action",
            "your account will be terminated",
            "you will lose access",
            "failure to comply",
            "your account will be deleted"
        ]
    )

    safe_browsing_match = False

    for result in url_results:
        total_score = total_score + result["score"]
        all_findings.extend(result["findings"])

        threat_intelligence = result["threat_intelligence"]

        if threat_intelligence["matched"]:
            safe_browsing_match = True

    # Combination rules
    if credential_request and any(
        finding in all_findings
        for finding in [
            "URL hostname is suspicious",
            "URL uses an IP address",
            "URL contains @ character",
            "URL is unusually long",
            "URL does not use HTTPS"
        ]
    ):
        total_score = total_score + 3

    if financial_request and urgency:
        total_score = total_score + 2

    if credential_request and threat:
        total_score = total_score + 2

    # Known threat from Safe Browsing
    if safe_browsing_match:
        risk_level = "High"
    elif total_score <= 2:
        risk_level = "Low"
    elif total_score <= 5:
        risk_level = "Moderate"
    else:
        risk_level = "High"

    # Recommendation
    if safe_browsing_match:
        recommendation = (
            "Do not click or interact with the flagged link. "
            "It has been identified as a known security threat. "
            "Do not enter personal information, login credentials, or payment details."
        )

    elif credential_request and (
        "URL hostname is suspicious" in all_findings
        or "URL uses an IP address" in all_findings
        or "URL contains @ character" in all_findings
        or "URL is unusually long" in all_findings
        or "URL does not use HTTPS" in all_findings
    ):
        recommendation = (
            "Do not enter your password, PIN, OTP, or other sensitive information. "
            "The message is asking for credentials and contains a suspicious link. "
            "If you need to access your account, open the official website or app yourself."
        )

    elif financial_request and (urgency or threat):
        recommendation = (
            "Do not send money or provide bank or card details. "
            "The message combines a financial request with pressure or a threat. "
            "Confirm the request through an official channel before taking any action."
        )

    elif credential_request:
        recommendation = (
            "Do not enter or share your password, PIN, OTP, or other login credentials. "
            "If the request is legitimate, confirm it through the organization's official "
            "website, app, or support channel."
        )

    elif financial_request:
        recommendation = (
            "Do not send money or provide bank or card details based on this message alone. "
            "Confirm the request through an official channel before making any payment."
        )

    elif urgency or threat:
        recommendation = (
            "Do not let the message pressure you into acting quickly. "
            "Take time to verify the sender and the request through an official channel "
            "before doing anything."
        )

    elif (
        "URL hostname is suspicious" in all_findings
        or "URL uses an IP address" in all_findings
        or "URL contains @ character" in all_findings
        or "URL is unusually long" in all_findings
        or "URL does not use HTTPS" in all_findings
    ):
        recommendation = (
            "Avoid clicking the link for now. "
            "If you need to access the service, open its official website or app directly "
            "instead of using the link in the message."
        )

    else:
        recommendation = (
            "No major phishing indicators were detected. "
            "However, this does not guarantee that the message is safe. "
            "Be cautious with unexpected messages and verify the sender when necessary."
        )

    return risk_level, all_findings, recommendation

