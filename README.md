# Web Cache Deception Detection Script
A lightweight, Python-based tool designed to detect potential cache deception vulnerabilities. This script automates checks against various endpoints, appending cache-busters, and probing for common weaknesses that could leave a website’s private content cached and publicly accessible.

---

## Features

- **Automatically Detect Cache Rules**  
  Automatically fetches a list of commonly cached files and paths to see if they exist and are cached (`robots.txt`, `favicon.ico`).

- **Delimiter + Extension Payloads**  
  Generates requests by inserting special delimiters (`;`, `/`, or `%00`) and file extensions (`.js`, `.css`, `.php`, etc.) to detect how caching layers respond under different URL structures.

- **Cookie vs. No-Cookie Tests**  
  Compares responses with and without cookies to determine if private content could be cached and served to unauthenticated users.

- **Marker Detection**  
  Searches for user supplied markers in the response body (e.g., `email`) to highlight potential exposure of sensitive data.

---

## Requirements

- Required Python packages:
  - `requests`
  - `termcolor`
  - `tldextract`
- For better organization and to avoid dependency conflicts, consider creating a virtual environment:

  ```bash
  # Create a virtual environment
  python -m venv venv
  
  # Activate the virtual environment
  # macOS/Linux
  source venv/bin/activate
  
  # Windows
  venv\Scripts\activate

- Use the following browser extension to export your cookies to json
  - https://chromewebstore.google.com/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm
 
 ---

## How It Works

### Command-Line Options

- **`--advanced-delimiters`**  
  Use an expanded set of delimiters.

- **`--advanced-extensions`**  
  Use an expanded set of file extensions (e.g., .zip, .rar, .json) for broader coverage.

- **`--custom`**  
  Turn on automatic file/path caching detection using a user supplied wordlist specified by the `CUSTOM_NORMALIZE_ENDPOINTS` variable.

- **`--builtin`**  
  Turn on automatic file/path caching detection using the built in wordlist.

- **`--help`**  
  Shows the help menu.

### Required Files

1. **`urls.txt`**  
   This file lists the URLs to be tested for cache deception vulnerabilities. It is recommended to include URLs that might expose sensitive information, such as profile pages or other endpoints with private data. Potential targets could also include those exposing CSRF tokens, CSP nonces, or OAuth state parameters. Each URL must be listed on a separate line, and any line beginning with # will be treated as a comment and ignored during processing. Make sure urls.txt is stored in the same directory as the script.

2. **`cookies.json`**  
   A JSON file containing cookies for authenticated requests. Ensure this file is located in the same directory as the script.
   
  ---

## Tips

- Test it on **PortSwigger’s [Web Cache Deception labs](https://portswigger.net/web-security/web-cache-deception)** available in the **Burp Academy**. This tool should be capable of helping you identify and solve **all** the labs in the cache deception category.

---

## References
 - https://www.usenix.org/system/files/sec22summer_mirheidari.pdf
