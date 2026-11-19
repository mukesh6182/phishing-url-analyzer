
import re
import ipaddress
from urllib.parse import urlparse

def analyze_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.hostname or ""
    checks = []
    score = 0

    if parsed.scheme == "https":
        checks.append(("HTTPS", "Passed"))
    else:
        checks.append(("HTTPS", "Not Used"))
        score += 10

    try:
        ipaddress.ip_address(domain)
        checks.append(("IP Address", "Detected"))
        score += 25
    except ValueError:
        checks.append(("IP Address", "Not Detected"))

    keywords = ["login", "verify", "update", "secure", "account", "banking"]
    found = [word for word in keywords if word in url.lower()]

    if found:
        checks.append(("Suspicious Keywords", ", ".join(found)))
        score += min(len(found) * 10, 20)
    else:
        checks.append(("Suspicious Keywords", "Not Detected"))

    if len(url) > 75:
        checks.append(("URL Length", "Unusually Long"))
        score += 15
    else:
        checks.append(("URL Length", "Normal"))

    if "@" in parsed.netloc:
        checks.append(("URL Contains @", "Detected"))
        score += 20
    else:
        checks.append(("URL Contains @", "Not Detected"))

    if domain.count(".") > 3:
        checks.append(("Subdomains", "Unusually Many"))
        score += 10
    else:
        checks.append(("Subdomains", "Normal"))

    if "-" in domain:
        checks.append(("Hyphen in Domain", "Detected"))
        score += 5
    else:
        checks.append(("Hyphen in Domain", "Not Detected"))

    score = min(score, 100)

    if score >= 50:
        risk = "HIGH"
    elif score >= 25:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    print("\n" + "=" * 45)
    print("           PHISHING URL ANALYZER")
    print("=" * 45)

    print("\nURL:", url)
    print("\nANALYSIS RESULTS")
    print("-" * 45)

    for name, result in checks:
        print(f"{name:<23}: {result}")

    print("-" * 45)
    print(f"Risk Score : {score}/100")
    print(f"Risk Level : {risk}")
    print("=" * 45)

    print("\nNote: This is a basic heuristic analysis.")
    print("It cannot confirm whether a URL is malicious.")


print("=" * 45)
print("           PHISHING URL ANALYZER")
print("=" * 45)

while True:
    url = input("\nEnter URL (or 'exit' to quit): ").strip()

    if url.lower() == "exit":
        print("Exiting Analyzer...")
        break

    if not url or " " in url:
        print("Please enter a valid URL.")
        continue

    analyze_url(url)
