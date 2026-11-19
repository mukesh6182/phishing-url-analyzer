# Phishing URL Analyzer

A simple Python command-line tool that checks a URL for common phishing signs and gives it a risk score from 0 to 100.

The tool works offline. It never opens the link, it only studies the text of the URL.

## Features
- Accepts a URL with or without `http://` or `https://`
- Runs 7 checks and shows the result of each
- Gives a risk score and a LOW, MEDIUM or HIGH level
- Lets you test many URLs in one session (type `exit` to quit)

## Checks

| Check | What it looks for | Score |
|---|---|---|
| HTTPS | URL does not use a secure connection | +10 |
| IP Address | Domain is an IP address instead of a name | +25 |
| Suspicious Keywords | login, verify, update, secure, account, banking | up to +20 |
| URL Length | More than 75 characters | +15 |
| @ Symbol | `@` in the address, which can hide the real domain | +20 |
| Subdomains | More than 3 dots in the domain | +10 |
| Hyphen | Hyphen in the domain | +5 |

## Risk Levels

| Score | Level |
|---|---|
| 0 - 24 | LOW |
| 25 - 49 | MEDIUM |
| 50 - 100 | HIGH |

## Requirements
- Python 3.8 or newer
- No extra packages needed

## How to Run
1. Open a terminal in the project folder.
2. Start the program:
   ```
   python phishing_url_analyzer.py
   ```
3. Enter a URL and press Enter.
4. Type `exit` to close the program.

On Linux or macOS, use `python3` instead of `python`.

## Example

```
Enter URL (or 'exit' to quit): http://192.168.10.5/login

URL: http://192.168.10.5/login

ANALYSIS RESULTS
---------------------------------------------
HTTPS                  : Not Used
IP Address             : Detected
Suspicious Keywords    : login
URL Length             : Normal
URL Contains @         : Not Detected
Subdomains             : Normal
Hyphen in Domain       : Not Detected
---------------------------------------------
Risk Score : 45/100
Risk Level : MEDIUM
```

## Limitations
- This is a basic rule-based check and cannot confirm that a URL is malicious.
- A safe site can score high, and a clever phishing site can score low.
- It does not check domain age, blacklists or page content.

## Documentation
See `Phishing_URL_Analyzer_Documentation.docx` for the full project document with screenshots.

## Disclaimer
This project is for learning purposes only.
