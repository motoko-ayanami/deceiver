# Web Cache Deception Detection Script
A lightweight, Python-based tool designed to detect potential cache deception vulnerabilities. This script automates checks against various endpoints, appending cache-busters, and probing for common weaknesses that could leave a website’s private content cached and publicly accessible.

---

## Features

- **Normalization Checks**  
  Automatically fetches a list of known “normalization endpoints” (e.g., `robots.txt`) to see if the cache can be fooled.

- **Delimiter + Extension Payloads**  
  Generates requests by inserting special delimiters and file extensions to detect how caching layers respond.

- **Cookie vs. No-Cookie Tests**  
  Compares responses to determine if private content might be served publicly when cache is enabled.

- **Markers Detection**  
  Searches for predefined markers (e.g., `email`) in the response body.

- **Logging**  
  Logs important events in a structured, human-friendly way:
  - `INFO` – general information  
  - `WARNING` – potential issues, but not necessarily vulnerabilities  
  - `VULNERABILITY` – discovered vulnerabilities, highlighted in green  
  - `HIT` – indicates a cache hit was found  

---

## Requirements

- Required Python packages:
  - `requests`
  - `termcolor`
- Use the following browser extension to export your cookies to json
  - https://chromewebstore.google.com/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm
 
 ---

## How It Works

### Command-Line Options

- **`--advanced-delimiters`**  
  Use an expanded set of delimiters.

- **`--advanced-extensions`**  
  Use an expanded set of file extensions.

- **`--normalize`**  
  Run normalization checks.

- **`--builtin-normalize`**  
  Use the `BUILT_IN_NORMALIZE_ENDPOINTS` for normalization.

- **`--url <URL>`**  
  Base URL for normalization checks (required if `--normalize` or `--builtin-normalize` is used).

- **`--help`**  
  Shows the help menu.

### Required Files

1. **`urls.txt`**  
   A text file containing the list of URLs to test. Each URL should be on a new line. Lines starting with `#` are ignored as comments. Ensure this file is located in the same directory as the script.

2. **`cookies.json`**  
   A JSON file containing cookies for authenticated requests. Ensure this file is located in the same directory as the script.
   
  ---

## Tips

- **Try It on Burp Academy**
  Test it on **PortSwigger’s [Web Cache Deception labs](https://portswigger.net/web-security/web-cache-deception)** available in the **Burp Academy**. This tool should be capable of helping you identify and solve **all** the labs in the cache deception category. 
