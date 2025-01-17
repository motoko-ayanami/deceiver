import requests
import hashlib
import json
import argparse
import sys
from typing import Dict, List, Tuple
from urllib.parse import urlsplit, urlparse

from termcolor import colored
import tldextract

# GLOBAL Cache Buster Counter
CB_COUNTER = 0  # Increments after each new payload

# Track potential vulnerabilities to show them at the end
DETECTED_VULNERABILITIES = []

# Define the user agent near the top to allow easy changes
CUSTOM_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# File configuration
INPUT_FILE = "urls.txt"
COOKIE_FILE = "cookies.json"

# Predefined markers to detect in content
MARKERS = ["email"]

# Custom Normalization endpoints
CUSTOM_NORMALIZE_ENDPOINTS: List[str] = ["robots.txt"]

# Extension sets
BASIC_EXTENSIONS = ["js", "css", "ico"]
ADVANCED_EXTENSIONS = [
    "7z", "csv", "gif", "midi", "png", "tif", "zip", "avi", "doc", "gz", "mkv", "ppt", "tiff", "zst", "avif",
    "docx", "ico", "mp3", "pptx", "ttf", "apk", "dmg", "iso", "mp4", "ps", "webm", "bin", "ejs", "jar", "ogg",
    "rar", "webp", "bmp", "eot", "jpg", "otf", "svg", "woff", "bz2", "eps", "jpeg", "pdf", "svgz", "woff2",
    "class", "exe", "js", "pict", "swf", "xls", "css", "flac", "mid", "pls", "tar", "xlsx", "html", "htm",
    "json", "xml", "txt", "xhtml", "rss", "atom", "php", "asp", "jsp", "wasm", "ts", "tsx", "jsx", "md"
]

# Delimiter sets
BASIC_DELIMITERS = ["/", ";", "%00", "!","%23"]
ADVANCED_DELIMITERS = [
    "!", "\"", "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", ":", ";", "<", "=", ">", "?",
    "@", "[", "\\", "]", "^", "_", "`", "{", "|", "}", "~", "%21", "%22", "%23", "%24", "%25", "%26",
    "%27", "%28", "%29", "%2A", "%2B", "%2C", "%2D", "%2E", "%2F", "%3A", "%3B", "%3C", "%3D", "%3E",
    "%3F", "%40", "%5B", "%5C", "%5D", "%5E", "%5F", "%60", "%7B", "%7C", "%7D", "%7E", "%0A", "%00", "%09"
]

# Built in Normalization endpoints
BUILT_IN_NORMALIZE_ENDPOINTS: List[str] = [
    "404.html", "500.html", "about.html", "ads.txt", "android-chrome-192x192.png",
    "android-chrome-512x512.png", "angular.min.js", "api-schema.json", "app.js",
    "apple-touch-icon.png", "apple-touch-icon-precomposed.png", "asset-manifest.json",
    "assets", "background.jpg", "background.mp3", "background.ogg", "background.png",
    "background.webm", "backup.tar", "backup.tgz", "BingSiteAuth.xml", "bootstrap.min.css",
    "browserconfig.xml", "chatbot.js", "contact.html", "crossdomain.xml", "data.tar.gz",
    "data.tgz", "data.zip", "Dockerfile", ".dockerignore", ".env", "favicon-16x16.png",
    "favicon-192x192.png", "favicon-32x32.png", "favicon-96x96.png", "favicon.ico",
    "fb-pixel.js", "fontawesome-webfont.ttf", "fontawesome-webfont.woff",
    "fontawesome-webfont.woff2", "font.css", "ga.js", ".gitignore",
    "google-site-verification.html", "hero-banner.jpg", "home.html", ".htaccess",
    "humans.txt", "image01.png", "image02.jpg", "index.htm", "index.html", "intercom.js",
    "jquery.min.js", "jwks.json", "LICENSE.txt", "logo.png", "logo.svg", "main.css",
    "main.js", "manifest.json", "media", "mstile-144x144.png", "mstile-150x150.png",
    "mstile-310x150.png", "mstile-310x310.png", "mstile-70x70.png", "offline.html",
    "offline-plugin-app-shell-fallback.html", "og-image.jpg", "open-graph-image.png",
    "open-sans.ttf", "open-sans.woff", "open-sans.woff2", "paypal.js", "polyfill.js",
    "precache-manifest.js", "precache-manifest.json", "print.css", "privatekey.pem",
    "Procfile", "public", "publickey.pem", "react.min.js", "README.md", "resources",
    "roboto.ttf", "roboto.woff", "roboto.woff2", "robots.txt", "script.js", "security.txt",
    "segment.js", "service-worker.js", "shared", "site-backup.zip", "site-logo.webp",
    "sitemap.xml", "site-verification.txt", "static", "stripe.js", "style.css",
    "swagger.yaml", "sw.js", "theme.css", "twitter-card-image.png", "vendor.js",
    "video.mp4", "vue.min.js", "webpack-runtime.js", "worker.js", "wp-content"
]

###############################################################################
# Helper to simplify (sanitize) the URL
###############################################################################
def simplify_url(url: str) -> str:
    """
    Removes everything except the scheme, subdomain, domain, and TLD from the URL.
    Example:
      https://sub.example.com/some/path -> https://sub.example.com
    """
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme

    extracted = tldextract.extract(parsed_url.netloc)
    subdomain = f"{extracted.subdomain}." if extracted.subdomain else ""
    domain = extracted.domain
    suffix = extracted.suffix

    # Reconstruct simplified URL
    simplified_url = f"{scheme}://{subdomain}{domain}.{suffix}"
    return simplified_url


###############################################################################
# Logging helper
###############################################################################
def log(level: str, message: str) -> None:
    """
    Prints a nicely formatted log message.
    - 'VULNERABILITY' messages go to the screen in green and are stored for summary output.
    - 'HIT' messages (e.g., normalization cache hits) also go to the screen in green (but not stored).
    - All other levels are printed in plain text.
    """
    global DETECTED_VULNERABILITIES

    icon_map = {
        "INFO": "[ + ]",
        "WARNING": "[ ! ]",
        "ERROR": "[ x ]",
        "VULNERABILITY": "[!!!]",
        "HIT": "[HIT]",
    }

    prefix = icon_map.get(level, "[ * ]")

    if level == "VULNERABILITY":
        print(colored(f"{prefix} {message}", "green"))
        DETECTED_VULNERABILITIES.append(message)
    elif level == "HIT":
        # Display in green but do NOT add to DETECTED_VULNERABILITIES
        print(colored(f"{prefix} {message}", "green"))
    else:
        print(f"{prefix} {message}")


###############################################################################
# Core logic helpers
###############################################################################
def load_cookies(cookie_file: str) -> Dict[str, str]:
    """
    Load cookies from a JSON file. Each cookie entry is expected to have
    a "name" and "value" field in the JSON structure.
    """
    try:
        with open(cookie_file, "r") as file:
            cookies = json.load(file)
            return {cookie["name"]: cookie["value"] for cookie in cookies}
    except FileNotFoundError:
        log("WARNING", f"Cookie file '{cookie_file}' not found. Proceeding without cookies.")
        return {}
    except json.JSONDecodeError:
        log("ERROR", f"Invalid JSON format in cookie file '{cookie_file}'.")
        return {}


def fetch_url(url: str, cookies: Dict[str, str], allow_error_status: bool = False) -> Tuple[str, Dict[str, str], int]:
    """
    Fetch a URL using our custom user agent and return (content, headers, status_code).
    If allow_error_status is False, will raise for a non-2xx status.
    """
    try:
        custom_headers = {"User-Agent": CUSTOM_USER_AGENT}
        response = requests.get(
            url,
            cookies=cookies,
            allow_redirects=True,
            timeout=10,
            headers=custom_headers
        )
        if not allow_error_status:
            response.raise_for_status()
        return response.text, response.headers, response.status_code
    except requests.RequestException as e:
        status_code = e.response.status_code if hasattr(e, "response") and e.response else 0
        if allow_error_status and status_code != 0:
            # We can still return the response body if we specifically allow error status
            return e.response.text, e.response.headers, status_code

        log("ERROR", f"Failed to fetch {url}: {e}")
        return "", {}, status_code


def detect_markers(content: str, markers: List[str]) -> bool:
    """Check if content contains any predefined markers."""
    return any(marker in content for marker in markers)


def hash_content(content: str) -> str:
    """Generate a SHA-256 hash of the provided content."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def is_hit(headers: Dict[str, str]) -> bool:
    """
    Checks 'X-Cache', 'Cf-Cache-Status', 'Age', and 'X-Status' headers for caching behavior.
    Returns True if any indicate a cache hit, the 'Age' header is present, or
    'Cf-Cache-Status' is 'REVALIDATED'.
    """
    x_cache = headers.get("X-Cache", "").lower()
    cf_cache = headers.get("Cf-Cache-Status", "").lower()
    x_status = headers.get("X-Status", "").lower()
    age_header = headers.get("Age")

    return (
        ("hit" in x_cache)
        or ("hit" in cf_cache)
        or (cf_cache == "revalidated")
        or (age_header is not None)
        or ("hit" in x_status)
    )


###############################################################################
# Normalization checks
###############################################################################
def run_normalization_checks(base_url: str, norm_endpoints: List[str]) -> List[str]:
    """
    Check the specified endpoints for caching behavior.
    Returns a list of endpoints that returned a cache hit.
    """
    log("INFO", f"Running normalization checks for {base_url}")
    hit_endpoints = []

    for endpoint in norm_endpoints:
        full_url = f"{base_url.rstrip('/')}/{endpoint}"
        log("INFO", f"Checking endpoint: {full_url}")

        response1 = fetch_url(full_url, {}, allow_error_status=True)
        response2 = fetch_url(full_url, {}, allow_error_status=True)

        cache1_hit = is_hit(response1[1])
        cache2_hit = is_hit(response2[1])

        if cache1_hit or cache2_hit:
            log("HIT", f"Cache HIT detected for {full_url}")
            hit_endpoints.append(endpoint)
        else:
            log("INFO", f"No cache hit for {full_url}")

    return hit_endpoints


###############################################################################
# Cache-buster logic
###############################################################################
def generate_cachebuster_value() -> str:
    """
    Returns a unique string to append as a cache-buster.
    Each new payload iteration gets a new value.
    But the same payload uses the same value for with/without cookies fetches.
    """
    global CB_COUNTER
    CB_COUNTER += 1
    return str(CB_COUNTER)


def add_cache_buster(url: str, cb_value: str) -> str:
    """
    Append ?cb=<value> or &cb=<value> to the URL, depending on whether '?' is present.
    """
    delimiter = "&" if "?" in url else "?"
    return f"{url}{delimiter}cb={cb_value}"


###############################################################################
# Supplemental Tests
###############################################################################
def run_supplemental_test(url: str, cookies: Dict[str, str]) -> None:
    """
    Fetch the given URL with cookies and without cookies, compare results.
    If identical, log a potential cache vulnerability.
    """
    log("INFO", f"Supplemental test -> {url}")

    content_with, _, status_with = fetch_url(url, cookies, allow_error_status=True)
    if status_with != 200:
        log("WARNING", f"Skipping (with cookies) due to non-200 status: {status_with}")
        return

    content_without, _, status_without = fetch_url(url, {}, allow_error_status=True)
    if status_without != 200:
        log("WARNING", f"Skipping (without cookies) due to non-200 status: {status_without}")
        return

    if content_with == content_without:
        log("VULNERABILITY", f"Potential cache vulnerability detected at {url}")
    else:
        log("INFO", f"No supplemental cache vulnerability for {url}")


def test_supplemental_payloads(
    base_domain: str,
    original_path: str,
    cache_hit_endpoints: List[str],
    delimiters: List[str],
    cookies: Dict[str, str]
) -> None:
    """
    Perform extra tests if any normalization endpoint was a cache hit.
    Patterns tested:
      A) https://example.net/robots.txt<delim><payload><clean_path>
      B) https://example.net/my-account<delim><payload><endpoint>
    """
    domain = base_domain.rstrip("/")
    clean_path = original_path.lstrip("/")
    special_payloads = ["..%2f", "%2f..%2f", "%2f%2e%2e%2f"]

    for endpoint in cache_hit_endpoints:
        endpoint = endpoint.lstrip("/")
        for payload in special_payloads:
            for delim in delimiters:
                # A) <domain>/<endpoint><delim><payload><clean_path>
                cb_a = generate_cachebuster_value()
                test_url_a = f"{domain}/{endpoint}{delim}{payload}{clean_path}"
                test_url_a = add_cache_buster(test_url_a, cb_a)
                run_supplemental_test(test_url_a, cookies)

                # B) <domain>/<clean_path><delim><payload><endpoint>
                cb_b = generate_cachebuster_value()
                test_url_b = f"{domain}/{clean_path}{delim}{payload}{endpoint}"
                test_url_b = add_cache_buster(test_url_b, cb_b)
                run_supplemental_test(test_url_b, cookies)


###############################################################################
# Main cache-deception testing routine
###############################################################################
def test_cache_deception(
    base_url: str,
    cookies: Dict[str, str],
    extensions: List[str],
    delimiters: List[str],
    cache_hit_endpoints: List[str]
) -> None:
    """
    Perform cache deception tests on the given URL:
      1) Base fetch (twice) to see if there's any immediate difference or marker
      2) Delimiter + extension tests (with unique cachebuster each time)
      3) Supplemental tests if any normalization endpoints had a cache hit
    """
    log("INFO", f"Testing base URL: {base_url}")

    splitted = urlsplit(base_url)
    domain = f"{splitted.scheme}://{splitted.netloc}"
    original_path = splitted.path

    # Step 1 - Base checks
    base_content, _, base_status = fetch_url(base_url, cookies)
    base_hash = hash_content(base_content) if base_status == 200 else None

    second_content, _, second_status = fetch_url(base_url, cookies)
    second_hash = hash_content(second_content) if second_status == 200 else None

    # Decide if further tests are required
    if base_hash == second_hash:
        if not detect_markers(base_content, MARKERS):
            log("INFO", f"No difference or markers found for {base_url}. Skipping further tests.")
            return
        else:
            # MODIFICATION #1: Highlight that markers were detected in GREEN
            log("WARNING", colored(f"Markers detected; proceeding with deeper testing for {base_url}.", "green"))
    else:
        # MODIFICATION #2: Highlight that a deviation was detected in GREEN
        log("INFO", colored(f"Deviation detected between first and second requests for {base_url}. Proceeding.", "green"))

    # Step 2 - Delimiters + Extensions checks
    for delimiter in delimiters:
        for ext in extensions:
            test_url = f"{base_url}{delimiter}.{ext}"
            cb_val = generate_cachebuster_value()
            test_url = add_cache_buster(test_url, cb_val)

            log("INFO", f"Testing {test_url} (with cookies).")
            content_with, _, status_with = fetch_url(test_url, cookies)
            if status_with != 200:
                log("WARNING", f"Skipping {test_url}; non-200 status code: {status_with}")
                continue

            log("INFO", f"Testing {test_url} (without cookies).")
            content_without, _, status_without = fetch_url(test_url, {})
            if status_without != 200:
                log("WARNING", f"Skipping {test_url}; non-200 status code: {status_without}")
                continue

            if content_with == content_without:
                log("VULNERABILITY", f"Potential cache vulnerability detected for {test_url}.")
            else:
                log("INFO", f"No cache vulnerability detected for {test_url}.")

    # Step 3 - Supplemental tests if normalization found any cache-hits
    if cache_hit_endpoints:
        log("INFO", f"Running supplemental tests for normalization cache hits on {base_url}.")
        if not domain:
            log("WARNING", f"Could not parse domain from {base_url}. Skipping.")
            return
        test_supplemental_payloads(domain, original_path, cache_hit_endpoints, delimiters, cookies)
    else:
        log("INFO", f"No normalization-based cache-hit endpoints for {base_url}. Skipping supplemental tests.")


###############################################################################
# Main entry point
###############################################################################
def main():
    # Handle Ctrl+C gracefully
    try:
        parser = argparse.ArgumentParser(description="Cache Deception Detection Script")
        parser.add_argument("--advanced-delimiters", action="store_true", help="Use advanced delimiters for testing.")
        parser.add_argument("--advanced-extensions", action="store_true", help="Use advanced extensions for testing.")
        parser.add_argument("--normalize", action="store_true", help="Run normalization checks using custom endpoints.")
        parser.add_argument(
            "--builtin-normalize",
            action="store_true",
            help="Use the built-in list of normalization endpoints."
        )
        # REMOVED: --url argument and its help text
        args = parser.parse_args()

        # Decide which normalization endpoints to use
        if args.builtin_normalize:
            norm_endpoints = BUILT_IN_NORMALIZE_ENDPOINTS
        else:
            norm_endpoints = CUSTOM_NORMALIZE_ENDPOINTS

        # Delimiters + extensions
        delimiters = ADVANCED_DELIMITERS if args.advanced_delimiters else BASIC_DELIMITERS
        extensions = ADVANCED_EXTENSIONS if args.advanced_extensions else BASIC_EXTENSIONS

        log("INFO", "Starting cache deception detection...")

        cookies = load_cookies(COOKIE_FILE)

        # Load URLs from input file
        try:
            with open(INPUT_FILE, "r") as file:
                urls = [
                    line.strip() for line in file
                    if line.strip() and not line.startswith("#")
                ]
        except FileNotFoundError:
            log("ERROR", f"Input file '{INPUT_FILE}' not found.")
            return

        if not urls:
            log("ERROR", f"No valid URLs found in '{INPUT_FILE}'.")
            return

        # If normalization is turned on, we'll use the FIRST URL from urls.txt
        # but sanitized.
        cache_hit_endpoints = []
        if args.normalize:
            first_url = urls[0]
            simplified_url = simplify_url(first_url)
            cache_hit_endpoints = run_normalization_checks(simplified_url, norm_endpoints)

        # Process each URL
        for url in urls:
            test_cache_deception(url, cookies, extensions, delimiters, cache_hit_endpoints)

        log("INFO", "Cache deception detection completed.")

        # Summarize potential vulnerabilities at the end
        if DETECTED_VULNERABILITIES:
            print(colored("\n[ + ] Summary of Potential Cache Deception Vulnerabilities:", "green"))
            for v in DETECTED_VULNERABILITIES:
                print(colored(f"    [!!!] {v}", "green"))

    except KeyboardInterrupt:
        # Graceful exit on Ctrl+C
        log("INFO", "User interrupted. Exiting script.")
        sys.exit(0)


if __name__ == "__main__":
    main()
