#!/usr/bin/env python3
"""
WebScan - A fast and minimal web directory scanner for appsec testing
Enhanced version with multiple discovery methods and vulnerability testing
"""

import argparse
import requests
import concurrent.futures
import sys
import webbrowser
import os
from urllib.parse import urljoin
from colorama import Fore, Style, init

# Enable color output (works cross-platform)
init(autoreset=True)

def path_safe(url):
    """Convert URL to a safe filename"""
    return "".join([c if c.isalnum() else "_" for c in url])

def scan_path(base_url, path, extensions, timeout=5, methods=None):
    urls = [urljoin(base_url + '/', path)]
    if extensions:
        urls += [urljoin(base_url + '/', f"{path}.{ext}") for ext in extensions]

    results = []
    methods = methods or ["GET"]
    
    for url in urls:
        for method in methods:
            try:
                if method == "GET":
                    response = requests.get(url, timeout=timeout)
                elif method == "POST":
                    response = requests.post(url, data={}, timeout=timeout)
                elif method == "HEAD":
                    response = requests.head(url, timeout=timeout)
                else:
                    continue
                    
                code = response.status_code
                size = len(response.content) if method != "HEAD" else 0

                # Save responses except 404s
                if code != 404:
                    # Create result object with all necessary data
                    result = {
                        "url": url,
                        "method": method,
                        "code": code,
                        "size": size,
                        "redirect": response.headers.get('Location') if code in [301, 302, 307, 308] else None
                    }
                    
                    # Also extract links from HTML content if it's HTML
                    if method == "GET" and code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                        from bs4 import BeautifulSoup
                        try:
                            soup = BeautifulSoup(response.content, 'html.parser')
                            result["links"] = [a.get('href') for a in soup.find_all('a', href=True)]
                            result["scripts"] = [s.get('src') for s in soup.find_all('script', src=True)]
                            result["forms"] = [f.get('action') for f in soup.find_all('form', action=True)]
                        except:
                            pass
                    
                    # Create formatted string for display
                    if code == 200:
                        formatted = f"[{Fore.GREEN}{code}{Style.RESET_ALL}] {method} {url} ({size} bytes)"
                    elif code in [301, 302, 307, 308]:
                        formatted = f"[{Fore.CYAN}{code}{Style.RESET_ALL}] {method} {url} → {response.headers.get('Location')}"
                    elif code == 403:
                        formatted = f"[{Fore.RED}{code}{Style.RESET_ALL}] {method} {url} ({size} bytes)"
                    elif code == 405:
                        formatted = f"[{Fore.MAGENTA}{code}{Style.RESET_ALL}] {method} {url} (Method Not Allowed)"
                    else:
                        formatted = f"[{Fore.YELLOW}{code}{Style.RESET_ALL}] {method} {url} ({size} bytes)"
                    
                    result["formatted"] = formatted
                    results.append(result)
            except requests.RequestException:
                pass
    
    return results

def extract_paths_from_html(html_content):
    """Extract potential paths from HTML content"""
    from bs4 import BeautifulSoup
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        paths = set()

        # Extract paths from links
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.startswith('/') or href.startswith('#') or href == '':
                paths.add(href.lstrip('/').split('#')[0].split('?')[0])

        # Extract paths from forms
        for form in soup.find_all('form', action=True):
            action = form['action']
            if action and (action.startswith('/') or action == ''):
                paths.add(action.lstrip('/').split('?')[0])

        # Extract paths from scripts
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src.startswith('/'):
                parts = src.lstrip('/').split('/')
                if parts and parts[0]:
                    paths.add(parts[0])

        # Extract from element IDs that look like page sections
        for element in soup.find_all(id=True):
            id_val = element.get("id", "")
            if id_val.endswith("Page") and len(id_val) > 4:
                route = id_val[:-4].lower()  # e.g. loginPage -> login
                if route:
                    paths.add(route)

        # Extract potential API endpoints or routes from JavaScript
        for script in soup.find_all('script'):
            if script.string:
                # Look for common patterns in JS that might indicate routes/endpoints
                js_text = script.string.lower()
                import re
                api_pattern = r'["\']\/([a-zA-Z0-9_\-\/]+)["\']'
                matches = re.findall(api_pattern, js_text)
                for match in matches:
                    if match:
                        paths.add(match.lstrip('/').split('/')[0])

                # Specifically look for common endpoints
                for endpoint in ['api', 'admin', 'login', 'logout', 'dashboard', 'profile', 'account', 'settings']:
                    if f'/{endpoint}' in js_text or f'"{endpoint}"' in js_text or f"'{endpoint}'" in js_text:
                        paths.add(endpoint)

        return list(paths)
    except Exception as e:
        print(f"{Fore.RED}Error parsing HTML: {str(e)}")
        return []


def extract_js_routes(base_url, timeout=5):
    """Extract routes from JavaScript files"""
    try:
        # Try to find app.js or main.js
        js_files = ['/static/js/app.js', '/static/js/main.js', '/js/app.js', '/js/main.js', '/assets/js/app.js']
        found_routes = set()
        
        for js_file in js_files:
            try:
                js_url = urljoin(base_url, js_file)
                response = requests.get(js_url, timeout=timeout)
                
                if response.status_code == 200:
                    js_content = response.text
                    
                    # Look for route patterns using regex
                    import re
                    # Match route definitions like '/route' or '/api/endpoint'
                    route_patterns = [
                        r'["\']\/([a-zA-Z0-9_\-\/]+)["\']',  # Quoted routes
                        r'path\s*:\s*["\']\/([a-zA-Z0-9_\-\/]+)["\']',  # React router style
                        r'route\s*\(["\']\/([a-zA-Z0-9_\-\/]+)["\']',  # Express.js style
                        r'href\s*=\s*["\']\/([a-zA-Z0-9_\-\/]+)["\']',  # href attributes
                    ]
                    
                    for pattern in route_patterns:
                        matches = re.findall(pattern, js_content)
                        for match in matches:
                            if match:
                                # Get the first part of the path
                                route = match.split('/')[0]
                                if route:
                                    found_routes.add(route)
                    
                    # Look for common endpoint names
                    common_endpoints = ['api', 'admin', 'login', 'logout', 'dashboard', 'profile', 'account', 
                                       'settings', 'register', 'reset', 'password', 'forgot', 'user', 'users',
                                       'products', 'orders', 'cart', 'checkout', 'payment', 'search', 'help',
                                       'support', 'contact', 'about', 'blog', 'docs', 'documentation']
                    
                    for endpoint in common_endpoints:
                        # Check for various patterns that might indicate an endpoint
                        endpoint_patterns = [
                            f'/{endpoint}',
                            f'"{endpoint}"',
                            f"'{endpoint}'",
                            f'.{endpoint}',
                            f'#{endpoint}',
                        ]
                        
                        for pattern in endpoint_patterns:
                            if pattern in js_content:
                                found_routes.add(endpoint)
                                
                    print(f"{Fore.GREEN}Found JavaScript file: {js_file} - Extracted {len(found_routes)} potential routes")
            except requests.RequestException:
                pass
                
        return list(found_routes)
    except Exception as e:
        print(f"{Fore.RED}Error analyzing JavaScript: {str(e)}")
        return []

def run_scanner(base_url, wordlist, extensions=None, threads=10, timeout=5, methods=None, crawl=True):
    try:
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            paths = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}Error: Could not find wordlist: {wordlist}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error reading wordlist: {str(e)}")
        sys.exit(1)

    print(f"🌐 WebScan started on: {base_url}")
    print(f"📄 Paths loaded: {len(paths)} | Threads: {threads}")
    
    if methods and len(methods) > 1:
        print(f"🔍 Testing HTTP methods: {', '.join(methods)}")
    
    if crawl:
        print(f"🕸️ Crawling enabled: Will extract additional paths from HTML responses\n")
    else:
        print("")

    all_results = []
    discovered_paths = set(paths)
    paths_to_scan = list(discovered_paths)
    
    # First, scan the homepage to find potential paths
    if crawl:
        try:
            print(f"{Fore.BLUE}Analyzing homepage for additional paths...")
            response = requests.get(base_url, timeout=timeout)
            if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                new_paths = extract_paths_from_html(response.content)
                
                if new_paths:
                    print(f"{Fore.GREEN}Found {len(new_paths)} potential paths from homepage analysis")
                    for path in new_paths:
                        if path and path not in discovered_paths and path != '#':
                            discovered_paths.add(path)
                            paths_to_scan.append(path)
        except requests.RequestException:
            pass
    
    # Main scanning loop
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_path, base_url, path, extensions, timeout, methods) for path in paths_to_scan]
        
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            
            # Print progress every 10 paths
            if completed % 10 == 0:
                print(f"{Fore.BLUE}Progress: {completed}/{len(paths_to_scan)} paths scanned", end='\r')
            
            results = future.result()
            for result in results:
                print(result["formatted"])
                all_results.append(result)
                
                # If crawling is enabled and this is an HTML page, extract more paths
                if crawl and result.get("code") == 200 and "links" in result:
                    new_paths = set()
                    for link in result.get("links", []):
                        if link and link.startswith('/'):
                            # Extract the first part of the path
                            path_part = link.lstrip('/').split('/')[0]
                            if path_part and path_part not in discovered_paths:
                                new_paths.add(path_part)
                    
                    # Add form submission endpoints
                    for form in result.get("forms", []):
                        if form and form.startswith('/'):
                            path_part = form.lstrip('/').split('/')[0]
                            if path_part and path_part not in discovered_paths:
                                new_paths.add(path_part)
                    
                    # Scan new paths if any were found
                    if new_paths:
                        new_futures = []
                        for path in new_paths:
                            discovered_paths.add(path)
                            new_futures.append(executor.submit(scan_path, base_url, path, extensions, timeout, methods))
                        
                        # Add the new futures to our tracking
                        futures.extend(new_futures)
    
    print(f"\n✅ Scan complete. Found {len(all_results)} results.")
    return all_results


def interact_with_results(results):
    """Interactive mode to view and connect to found pages"""
    if not results:
        print(f"{Fore.YELLOW}No results to interact with.")
        return
    
def show_indexed_results(results):
    """Print indexed list of found results."""
    print("\nAvailable results:")
    for i, result in enumerate(results, 1):
        code_str = str(result['code'])
        method = result.get('method', 'GET')
        url = result['url']
        print(f"{i}. [{code_str}] {method} {url}")

def list_results():
    print("\n=== Found Results ===")
    for i, result in enumerate(results, 1):
        code_str = f"{result['code']}"
        if result['code'] == 200:
            code_color = Fore.GREEN
        elif result['code'] in [301, 302, 307, 308]:
            code_color = Fore.CYAN
        elif result['code'] == 403:
            code_color = Fore.RED
        elif result['code'] == 405:
            code_color = Fore.MAGENTA
        else:
            code_color = Fore.YELLOW
        method = result.get('method', 'GET')
        print(f"{i}. [{code_color}{code_str}{Style.RESET_ALL}] {method} {result['url']} ({result['size']} bytes)")



    while True:
        print(f"\n{Fore.CYAN}=== Interactive Mode ===")
        print(f"Found {len(results)} results. What would you like to do?")
        print("1. List results")
        print("2. Open URL in browser")
        print("3. View URL content")
        print("4. Search within results")
        print("5. Test for vulnerabilities")
        print("6. Extract links from page")
        print("7. Export results to file")
        print("0. Exit")
        
        try:
            choice = input("\nChoose (0-7): ")
            
            if choice == "0":
                break
            elif choice == "1":
                print("\n=== Found Results ===")
                for i, result in enumerate(results, 1):
                    code_str = f"{result['code']}"
                    
                    if result['code'] == 200:
                        code_color = Fore.GREEN
                    elif result['code'] in [301, 302, 307, 308]:
                        code_color = Fore.CYAN
                    elif result['code'] == 403:
                        code_color = Fore.RED
                    elif result['code'] == 405:
                        code_color = Fore.MAGENTA
                    else:
                        code_color = Fore.YELLOW
                    
                    method = result.get('method', 'GET')
                    print(f"{i}. [{code_color}{code_str}{Style.RESET_ALL}] {method} {result['url']} ({result['size']} bytes)")
            
            elif choice == "2":
              
                try:
                    list_results()
                    idx = int(input(f"Enter index (1-{len(results)}): ")) - 1
                    if 0 <= idx < len(results):
                        url = results[idx]["url"]
                        print(f"{Fore.BLUE}Opening {url} in browser...")
                        webbrowser.open(url)
                    else:
                        print(f"{Fore.RED}Invalid index!")
                except ValueError:
                    print(f"{Fore.RED}Please enter a valid number!")
                    
            elif choice == "3":
                try:
                    idx = int(input(f"Enter index (1-{len(results)}): ")) - 1
                    if 0 <= idx < len(results):
                        url = results[idx]["url"]
                        try:
                            print(f"{Fore.BLUE}Fetching content from {url}...")
                            response = requests.get(url, timeout=10)
                            
                            # Show basic information
                            print(f"\n{Fore.CYAN}=== Page Information ===")
                            print(f"URL: {url}")
                            print(f"Status: {response.status_code}")
                            print(f"Size: {len(response.content)} bytes")
                            print(f"Content-Type: {response.headers.get('Content-Type', 'unknown')}")
                            
                            # Show headers
                            print(f"\n{Fore.CYAN}=== Headers ===")
                            for key, value in response.headers.items():
                                print(f"{key}: {value}")
                            
                            # Show part of the content (first 3000 characters)
                            print(f"\n{Fore.CYAN}=== Content ===")
                            content_to_show = response.text[:3000]
                            print(content_to_show)
                            
                            if len(response.text) > 3000:
                                print(f"\n{Fore.YELLOW}[Truncated] Showing first 3000 characters of {len(response.text)} total.")
                                
                                save_option = input("\nSave full content to file? (y/n): ").lower()
                                if save_option == 'y':
                                    filename = f"webscan_content_{path_safe(url)}.txt"
                                    with open(filename, 'w', encoding='utf-8', errors='ignore') as f:
                                        f.write(response.text)
                                    print(f"{Fore.GREEN}Content saved to {filename}")
                        except requests.RequestException as e:
                            print(f"{Fore.RED}Error fetching content: {str(e)}")
                    else:
                        print(f"{Fore.RED}Invalid index!")
                except ValueError:
                    print(f"{Fore.RED}Please enter a valid number!")
                    
            elif choice == "4":
                search_term = input("Enter search term: ")
                if not search_term:
                    continue







                
                print(f"\n{Fore.CYAN}=== Search Results for '{search_term}' ===")
                found = False
                
                for i, result in enumerate(results, 1):
                    if search_term.lower() in result['url'].lower():
                        code_str = f"{result['code']}"
                        
                        if result['code'] == 200:
                            code_color = Fore.GREEN
                        elif result['code'] in [301, 302, 307, 308]:
                            code_color = Fore.CYAN
                        elif result['code'] == 403:
                            code_color = Fore.RED
                        else:
                            code_color = Fore.YELLOW
                        
                        method = result.get('method', 'GET')
                        print(f"{i}. [{code_color}{code_str}{Style.RESET_ALL}] {method} {result['url']} ({result['size']} bytes)")
                        found = True
                
                if not found:
                    print(f"{Fore.YELLOW}No results matching '{search_term}'")
                    
            elif choice == "5":
                print(f"\n{Fore.CYAN}=== Vulnerability Testing ===")
                print("1. SQL Injection (Basic Tests)")
                print("2. XSS Detection")
                print("3. LFI/Path Traversal Check")
                print("4. Open Redirect Test")
                print("5. Check for Common Vulnerabilities")
                print("0. Back to main menu")
                
                vuln_choice = input("\nSelect test (0-5): ")
                
                if vuln_choice == "0":
                    continue
                elif vuln_choice == "1":
                    try:
                        idx = int(input(f"Enter index of URL to test (1-{len(results)}): ")) - 1
                        if 0 <= idx < len(results):
                            url = results[idx]["url"]
                            print(f"{Fore.BLUE}Testing {url} for SQL injection vulnerabilities...")
                            
                            # Simple SQL injection test
                            sql_payloads = ["'", "' OR '1'='1", "' OR '1'='1' --", "1' OR '1'='1", "\" OR \"\"=\""]
                            
                            for payload in sql_payloads:
                                test_url = url
                                if "?" in url:
                                    # URL has parameters
                                    test_url = url.split("?")[0] + "?" + url.split("?")[1].replace("=", f"={payload}")
                                else:
                                    # Try adding a parameter
                                    test_url = url + f"?id={payload}"
                                
                                try:
                                    print(f"{Fore.BLUE}Testing payload: {payload}")
                                    response = requests.get(test_url, timeout=10)
                                    
                                    # Look for SQL error messages
                                    sql_errors = [
                                        "sql syntax", "unclosed quotation", "sql error", 
                                        "ORA-", "mysql_fetch", "mysqli_fetch", "pg_fetch",
                                        "SQL syntax error", "SQLSTATE[", "syntax error"
                                    ]
                                    
                                    if any(error.lower() in response.text.lower() for error in sql_errors):
                                        print(f"{Fore.RED}[VULNERABLE] SQL error detected with payload: {payload}")
                                        print(f"Test URL: {test_url}")
                                    else:
                                        print(f"{Fore.GREEN}[OK] No obvious SQL injection with payload: {payload}")
                                        
                                except requests.RequestException as e:
                                    print(f"{Fore.YELLOW}Error testing payload {payload}: {str(e)}")
                        else:
                            print(f"{Fore.RED}Invalid index!")
                    except ValueError:
                        print(f"{Fore.RED}Please enter a valid number!")
                
                elif vuln_choice == "2":
                    try:
                        idx = int(input(f"Enter index of URL to test (1-{len(results)}): ")) - 1
                        if 0 <= idx < len(results):
                            url = results[idx]["url"]
                            print(f"{Fore.BLUE}Testing {url} for XSS vulnerabilities...")
                            
                            # Simple XSS test vectors
                            xss_payloads = [
                                "<script>alert(1)</script>",
                                "\"><script>alert(1)</script>",
                                "javascript:alert(1)",
                                "<img src=x onerror=alert(1)>",
                                "<svg onload=alert(1)>"
                            ]
                            
                            for payload in xss_payloads:
                                test_url = url
                                if "?" in url:
                                    # URL has parameters
                                    test_url = url.split("?")[0] + "?" + url.split("?")[1].replace("=", f"={payload}")
                                else:
                                    # Try adding a parameter
                                    test_url = url + f"?s={payload}"
                                
                                try:
                                    print(f"{Fore.BLUE}Testing payload: {payload}")
                                    response = requests.get(test_url, timeout=10)
                                    
                                    # Check if the payload is reflected in the response
                                    if payload in response.text:
                                        print(f"{Fore.RED}[POTENTIAL XSS] Payload reflected in response: {payload}")
                                        print(f"Test URL: {test_url}")
                                    else:
                                        print(f"{Fore.GREEN}[OK] Payload not reflected: {payload}")
                                        
                                except requests.RequestException as e:
                                    print(f"{Fore.YELLOW}Error testing payload {payload}: {str(e)}")
                        else:
                            print(f"{Fore.RED}Invalid index!")
                    except ValueError:
                        print(f"{Fore.RED}Please enter a valid number!")
                        
                elif vuln_choice == "3":
                    try:
                        idx = int(input(f"Enter index of URL to test (1-{len(results)}): ")) - 1
                        if 0 <= idx < len(results):
                            url = results[idx]["url"]
                            print(f"{Fore.BLUE}Testing {url} for LFI/Path Traversal vulnerabilities...")
                            
                            # LFI/Path Traversal test vectors
                            lfi_payloads = [
                                "../../../etc/passwd",
                                "..%2f..%2f..%2fetc%2fpasswd",
                                "....//....//....//etc/passwd",
                                "/etc/passwd",
                                "C:\\Windows\\win.ini",
                                "file:///etc/passwd"
                            ]
                            
                            for payload in lfi_payloads:
                                test_url = url
                                if "?" in url:
                                    # URL has parameters
                                    test_url = url.split("?")[0] + "?" + url.split("?")[1].replace("=", f"={payload}")
                                else:
                                    # Try adding a parameter
                                    test_url = url + f"?file={payload}"
                                
                                try:
                                    print(f"{Fore.BLUE}Testing payload: {payload}")
                                    response = requests.get(test_url, timeout=10)
                                    
                                    # Check for common file contents
                                    lfi_indicators = [
                                        "root:x:", "www-data", "[boot loader]", "[fonts]",
                                        "/bin/bash", "/usr/sbin", "daemon:", ":/root:"
                                    ]
                                    
                                    if any(indicator in response.text for indicator in lfi_indicators):
                                        print(f"{Fore.RED}[VULNERABLE] LFI/Path Traversal detected with payload: {payload}")
                                        print(f"Test URL: {test_url}")
                                    else:
                                        print(f"{Fore.GREEN}[OK] No obvious LFI with payload: {payload}")
                                        
                                except requests.RequestException as e:
                                    print(f"{Fore.YELLOW}Error testing payload {payload}: {str(e)}")
                        else:
                            print(f"{Fore.RED}Invalid index!")
                    except ValueError:
                        print(f"{Fore.RED}Please enter a valid number!")
                
                elif vuln_choice == "4":
                    try:
                        idx = int(input(f"Enter index of URL to test (1-{len(results)}): ")) - 1
                        if 0 <= idx < len(results):
                            url = results[idx]["url"]
                            print(f"{Fore.BLUE}Testing {url} for Open Redirect vulnerabilities...")
                            
                            # Open Redirect test vectors
                            redirect_payloads = [
                                "https://example.com",
                                "//example.com",
                                "\\\\example.com",
                                "https:example.com",
                                "https://example.com@evil.com"
                            ]
                            
                            for payload in redirect_payloads:
                                test_url = url
                                if "?" in url:
                                    # URL has parameters
                                    params = url.split("?")[1].split("&")
                                    new_params = []
                                    redirect_param_found = False
                                    
                                    for param in params:
                                        param_name = param.split("=")[0].lower()
                                        if param_name in ["redirect", "url", "next", "goto", "return", "returnurl", "returnto", "path"]:
                                            new_params.append(f"{param_name}={payload}")
                                            redirect_param_found = True
                                        else:
                                            new_params.append(param)
                                    
                                    if not redirect_param_found:
                                        new_params.append(f"redirect={payload}")
                                        
                                    test_url = url.split("?")[0] + "?" + "&".join(new_params)
                                else:
                                    # Try adding a parameter
                                    test_url = url + f"?redirect={payload}"
                                
                                try:
                                    print(f"{Fore.BLUE}Testing payload: {payload}")
                                    response = requests.get(test_url, timeout=10, allow_redirects=False)
                                    
                                    # Check for potential redirect
                                    if response.status_code in [301, 302, 303, 307, 308]:
                                        redirect_url = response.headers.get('Location', '')
                                        if any(p in redirect_url for p in redirect_payloads):
                                            print(f"{Fore.RED}[VULNERABLE] Open Redirect detected with payload: {payload}")
                                            print(f"Test URL: {test_url}")
                                            print(f"Redirects to: {redirect_url}")
                                        else:
                                            print(f"{Fore.GREEN}[OK] No open redirect with payload: {payload}")
                                    else:
                                        print(f"{Fore.GREEN}[OK] No redirect response with payload: {payload}")
                                        
                                except requests.RequestException as e:
                                    print(f"{Fore.YELLOW}Error testing payload {payload}: {str(e)}")
                        else:
                            print(f"{Fore.RED}Invalid index!")
                    except ValueError:
                        print(f"{Fore.RED}Please enter a valid number!")
                
                elif vuln_choice == "5":
                    print(f"{Fore.BLUE}Checking all endpoints for common vulnerabilities...")
                    
                    # Check all 200 OK responses
                    vulnerable_endpoints = []
                    checked_count = 0
                    
                    for i, result in enumerate(results):
                        if result['code'] == 200:
                            url = result['url']
                            checked_count += 1
                            print(f"{Fore.BLUE}Checking {url} ({checked_count}/{len([r for r in results if r['code'] == 200])})")
                            
                            try:
                                response = requests.get(url, timeout=10)
                                
                                # Check for information disclosure
                                info_disc_patterns = [
                                    "password", "username", "admin", "root", "SELECT",
                                    "mysqli_", "SQLSTATE", "ORA-", "PG::", "traceback",
                                    "DEBUG", "error", "warning", "stack trace", "exception"
                                ]
                                
                                for pattern in info_disc_patterns:
                                    if pattern.lower() in response.text.lower():
                                        vulnerable_endpoints.append({
                                            "url": url,
                                            "issue": f"Potential information disclosure: '{pattern}'",
                                            "severity": "Medium"
                                        })
                                        break
                                
                                # Check for security headers
                                security_headers = {
                                    "X-Frame-Options": "Missing X-Frame-Options header (clickjacking)",
                                    "X-XSS-Protection": "Missing X-XSS-Protection header",
                                    "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                                    "Content-Security-Policy": "Missing Content-Security-Policy header",
                                    "Strict-Transport-Security": "Missing HSTS header"
                                }
                                
                                for header, issue in security_headers.items():
                                    if header not in response.headers:
                                        vulnerable_endpoints.append({
                                            "url": url,
                                            "issue": issue,
                                            "severity": "Low"
                                        })
                                        
                            except requests.RequestException:
                                pass
                    
                    # Display results
                    if vulnerable_endpoints:
                        print(f"\n{Fore.RED}=== Vulnerability Scan Results ===")
                        print(f"Found {len(vulnerable_endpoints)} potential issues:\n")
                        
                        for i, vuln in enumerate(vulnerable_endpoints, 1):
                            severity_color = Fore.RED if vuln['severity'] == 'High' else (
                                Fore.YELLOW if vuln['severity'] == 'Medium' else Fore.BLUE)
                                
                            print(f"{i}. [{severity_color}{vuln['severity']}{Style.RESET_ALL}] {vuln['issue']}")
                            print(f"   URL: {vuln['url']}\n")
                    else:
                        print(f"{Fore.GREEN}No obvious vulnerabilities detected in the scanned endpoints.")
                        
            elif choice == "6":
                try:
                    idx = int(input(f"Enter index of URL to extract links from (1-{len(results)}): ")) - 1
                    if 0 <= idx < len(results):
                        url = results[idx]["url"]
                        try:
                            print(f"{Fore.BLUE}Extracting links from {url}...")
                            response = requests.get(url, timeout=10)
                            
                            if 'text/html' in response.headers.get('Content-Type', ''):
                                from bs4 import BeautifulSoup
                                soup = BeautifulSoup(response.content, 'html.parser')
                                
                                # Extract different types of links
                                links = {
                                    "a_tags": [a.get('href') for a in soup.find_all('a', href=True)],
                                    "forms": [form.get('action') for form in soup.find_all('form', action=True)],
                                    "scripts": [script.get('src') for script in soup.find_all('script', src=True)],
                                    "images": [img.get('src') for img in soup.find_all('img', src=True)],
                                    "css": [link.get('href') for link in soup.find_all('link', href=True, rel="stylesheet")],
                                }
                                
                                print(f"\n{Fore.CYAN}=== Extracted Links ===")
                                
                                # Display links by category
                                for category, items in links.items():
                                    if items:
                                        clean_items = [i for i in items if i]  # Remove None values
                                        if clean_items:
                                            print(f"\n{Fore.YELLOW}{category.replace('_', ' ').title()} ({len(clean_items)}):")
                                            for i, link in enumerate(clean_items[:20], 1):
                                                print(f"  {i}. {link}")
                                            
                                            if len(clean_items) > 20:
                                                print(f"  ... and {len(clean_items) - 20} more")
                                
                                # Find potential endpoints in JavaScript
                                js_links = []
                                for script in soup.find_all('script'):
                                    if script.string:
                                        js_text = script.string
                                        # Find anything that looks like a URL path
                                        import re
                                        js_endpoints = re.findall(r'["\']\/([a-zA-Z0-9_\-\/]+)["\']', js_text)
                                        js_links.extend([f"/{endpoint}" for endpoint in js_endpoints])
                                
                                if js_links:
                                    print(f"\n{Fore.YELLOW}Potential Endpoints from JavaScript ({len(js_links)}):")
                                    unique_js_links = sorted(set(js_links))
                                    for i, link in enumerate(unique_js_links[:20], 1):
                                        print(f"  {i}. {link}")
                                    
                                    if len(unique_js_links) > 20:
                                        print(f"  ... and {len(unique_js_links) - 20} more")
                                
                                # Option to save all links
                                save_option = input("\nSave all extracted links to file? (y/n): ").lower()
                                if save_option == 'y':
                                    filename = f"webscan_links_{path_safe(url)}.txt"
                                    with open(filename, 'w', encoding='utf-8') as f:
                                        for category, items in links.items():
                                            f.write(f"\n--- {category.replace('_', ' ').title()} ---\n")
                                            for link in items:
                                                if link:
                                                    f.write(f"{link}\n")
                                        
                                        if js_links:
                                            f.write("\n--- Potential JavaScript Endpoints ---\n")
                                            for link in sorted(set(js_links)):
                                                f.write(f"{link}\n")
                                    
                                    print(f"{Fore.GREEN}Links saved to {filename}")
                            else:
                                print(f"{Fore.YELLOW}The content is not HTML. Cannot extract links.")
                        except requests.RequestException as e:
                            print(f"{Fore.RED}Error fetching content: {str(e)}")
                        except ImportError:
                            print(f"{Fore.RED}Error: BeautifulSoup is required for this feature.")
                            print("Install it with: pip install beautifulsoup4")
                    else:
                        print(f"{Fore.RED}Invalid index!")
                except ValueError:
                    print(f"{Fore.RED}Please enter a valid number!")
            
            elif choice == "7":
                export_format = input("Export format (txt/csv/html/json): ").lower()
                filename = input("Enter filename (without extension): ") or "webscan_results"
                
                if export_format == "txt":
                    with open(f"{filename}.txt", 'w', encoding='utf-8') as f:
                        f.write(f"WebScan Results\n")
                        f.write(f"===============\n\n")
                        for result in results:
                            method = result.get('method', 'GET')
                            f.write(f"[{result['code']}] {method} {result['url']} ({result['size']} bytes)\n")
                    
                    print(f"{Fore.GREEN}Results exported to {filename}.txt")
                
                elif export_format == "csv":
                    import csv
                    with open(f"{filename}.csv", 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        writer.writerow(["URL", "Method", "Status Code", "Size", "Redirect"])
                        for result in results:
                            writer.writerow([
                                result['url'], 
                                result.get('method', 'GET'),
                                result['code'],
                                result['size'],
                                result.get('redirect', '')
                            ])
                    
                    print(f"{Fore.GREEN}Results exported to {filename}.csv")
                
                elif export_format == "html":
                    with open(f"{filename}.html", 'w', encoding='utf-8') as f:
                        f.write('<!DOCTYPE html>\n<html>\n<head>\n')
                        f.write('<title>WebScan Results</title>\n')
                        f.write('<style>\n')
                        f.write('body { font-family: Arial, sans-serif; margin: 20px; }\n')
                        f.write('h1 { color: #333; }\n')
                        f.write('table { border-collapse: collapse; width: 100%; }\n')
                        f.write('th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n')
                        f.write('th { background-color: #f2f2f2; }\n')
                        f.write('tr:nth-child(even) { background-color: #f9f9f9; }\n')
                        f.write('.code-200 { color: green; }\n')
                        f.write('.code-3xx { color: blue; }\n')
                        f.write('.code-4xx { color: red; }\n')
                        f.write('.code-5xx { color: orange; }\n')
                        f.write('</style>\n</head>\n<body>\n')
                        f.write('<h1>WebScan Results</h1>\n')
                        f.write('<table>\n')
                        f.write('<tr><th>URL</th><th>Method</th><th>Status</th><th>Size</th><th>Redirect</th></tr>\n')
                        
                        for result in results:
                            method = result.get('method', 'GET')
                            code = result['code']
                            code_class = 'code-200' if code == 200 else (
                                'code-3xx' if 300 <= code < 400 else (
                                'code-4xx' if 400 <= code < 500 else 'code-5xx'
                            ))
                            redirect = result.get('redirect', '')
                            
                            f.write(f'<tr>\n')
                            f.write(f'  <td><a href="{result["url"]}" target="_blank">{result["url"]}</a></td>\n')
                            f.write(f'  <td>{method}</td>\n')
                            f.write(f'  <td class="{code_class}">{code}</td>\n')
                            f.write(f'  <td>{result["size"]}</td>\n')
                            f.write(f'  <td>{redirect}</td>\n')
                            f.write(f'</tr>\n')
                        
                        f.write('</table>\n')
                        f.write('</body>\n</html>')
                    
                    print(f"{Fore.GREEN}Results exported to {filename}.html")
                
                elif export_format == "json":
                    import json
                    with open(f"{filename}.json", 'w', encoding='utf-8') as f:
                        json.dump(results, f, indent=2)
                    
                    print(f"{Fore.GREEN}Results exported to {filename}.json")
                
                else:
                    print(f"{Fore.RED}Invalid format. Please choose txt, csv, html, or json.")
            else:
                print(f"{Fore.RED}Invalid option!")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Returning to main menu...")
            continue

if __name__ == "__main__":
    banner = f"""
{Fore.CYAN}██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║
╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Style.RESET_ALL}
                                               
{Fore.GREEN}[ WebScan v2.0 - Fast and Enhanced Web Directory Scanner ]{Style.RESET_ALL}
    """
    print(banner)

    parser = argparse.ArgumentParser(
        prog="WebScan",
        description="WebScan - Enhanced web directory scanner with multiple discovery methods"
    )
    parser.add_argument("-u", "--url", required=True, help="Base URL to scan (e.g. http://localhost:8000)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-e", "--extensions", help="Comma-separated list of extensions (e.g. php,html,js)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Enable interactive mode after scanning")
    parser.add_argument("-o", "--output", help="Save results to output file")
    parser.add_argument("--methods", help="HTTP methods to test (comma-separated, e.g. GET,POST)", default="GET")
    parser.add_argument("--crawl", action="store_true", help="Enable crawling to discover additional paths")
    parser.add_argument("--js-analysis", action="store_true", help="Analyze JavaScript files for additional routes")
    parser.add_argument("--full", action="store_true", help="Enable all discovery features (crawling, JS analysis, etc)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--version", action="version", version="WebScan v2.0")

    args = parser.parse_args()
    
    # If no-color is specified, disable colorama
    if args.no_color:
        init(autoreset=True, strip=True)
        
    ext_list = args.extensions.split(",") if args.extensions else None
    method_list = args.methods.split(",") if args.methods else ["GET"]

    try:
        additional_paths = []
        
        # If JS analysis is enabled, try to extract routes from JS files
        if args.js_analysis or args.full:
            print(f"{Fore.BLUE}Analyzing JavaScript files for additional routes...")
            js_routes = extract_js_routes(args.url, timeout=args.timeout)
            if js_routes:
                print(f"{Fore.GREEN}Found {len(js_routes)} potential routes from JavaScript analysis")
                additional_paths.extend(js_routes)
        
        # If additional paths were found, add them to the wordlist
        if additional_paths:
            # Create a temporary wordlist with original + new paths
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp_file:
                # First read the original wordlist
                with open(args.wordlist, 'r', encoding='utf-8', errors='ignore') as original:
                    original_paths = [line.strip() for line in original if line.strip()]
                    for path in original_paths:
                        tmp_file.write(f"{path}\n")
                
                # Add the new paths
                for path in additional_paths:
                    if path and path not in original_paths:
                        tmp_file.write(f"{path}\n")
                
                tmp_wordlist = tmp_file.name
            
            # Use the temporary wordlist for scanning
            wordlist_to_use = tmp_wordlist
            print(f"{Fore.GREEN}Using enhanced wordlist with {len(original_paths) + len(additional_paths)} paths")
        else:
            wordlist_to_use = args.wordlist
        
        # Run the scan
        results = run_scanner(
            args.url, 
            wordlist_to_use, 
            extensions=ext_list, 
            threads=args.threads, 
            timeout=args.timeout,
            methods=method_list,
            crawl=args.crawl or args.full
        )
        
        # Clean up the temporary file if it was created
        if additional_paths:
            import os
            try:
                os.unlink(tmp_wordlist)
            except:
                pass
        
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    for result in results:
                        f.write(f"{result['code']} {result['method']} {result['url']} ({result['size']} bytes)\n")
                print(f"{Fore.GREEN}Results saved to {args.output}")
            except Exception as e:
                print(f"{Fore.RED}Error saving results: {str(e)}")
        
        if args.interactive and results:
            list_results()
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user")
        sys.exit(1)