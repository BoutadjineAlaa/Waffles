import sys
import requests
import re
import argparse
import urllib
import time
from urllib.parse import urlparse, parse_qs
def Colors(text, color):
    if color == 'red':
        sys.stderr.write(f"\033[31m{text}\033[0m")
    elif color == 'green':
        sys.stderr.write(f"\033[32m{text}\033[0m")
    elif color == 'blue':
        sys.stderr.write(f"\033[34m{text}\033[0m")
def Get_Parameters(params):
    if params:
        Colors("\n------------------ Parameters Found ------------------\n\n", "green")
        for param, values in params.items():
            print(f" {param}: {values}\n")
        Colors("------------------------------------------------------\n\n", "green")
    else:
        Colors("\nNo parameters found in the URL. Try using Arjun\n\n", "red")
        exit(1)
def get_params(url):
    with open('OS_Payloads.txt', "r") as file3:
        os_payloads = file3.readlines()
    with open('SQL_Payloads.txt', "r") as file2:
        sql_payloads = file2.readlines()
    with open('XSS_Payloads.txt', "r") as file:
        xss_payloads = file.readlines()
    url_parts = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(url_parts.query)
    print(
        f'\033[32m------------------------------ Trying XSS Protection Bypass! ------------------------------ \033[0m')
    for payload in xss_payloads:
        xss_params = query_params.copy()
        for key in query_params:
            xss_params[key] = [payload.strip()]
        new_url = urllib.parse.urlunparse((url_parts.scheme, url_parts.netloc, url_parts.path, url_parts.params, urllib.parse.urlencode(xss_params), url_parts.fragment))
        yield new_url
    print(
        f'\033[32m------------------------------ Trying SQL Injection Protection Bypass! ------------------------------ \033[0m')
    for payload in sql_payloads:
        sql_params = query_params.copy()
        for key in query_params:
            sql_params[key] = [payload.strip()]
        new_url = urllib.parse.urlunparse((url_parts.scheme, url_parts.netloc, url_parts.path, url_parts.params, urllib.parse.urlencode(sql_params), url_parts.fragment))
        yield new_url
    print(
        f'\033[32m------------------------------ Trying OS Injection Protection Bypass! ------------------------------ \033[0m')
    for payload in os_payloads:
        os_params = query_params.copy()
        for key in query_params:
            os_params[key] = [payload.strip()]
        new_url = urllib.parse.urlunparse((url_parts.scheme, url_parts.netloc, url_parts.path, url_parts.params, urllib.parse.urlencode(os_params), url_parts.fragment))
        yield new_url

def WAF_Check(url):
    response = requests.get(url, allow_redirects=True)
    response_headers = response.headers

    waf_patterns = {
        "Cloudflare": [
            r"cloudflare",
            r"cloudflare-nginx",
            r"cf-",
            r"CloudFlare Ray ID",
        ],
        "Incapsula": [
            r"incapsula",
        ],
        "Akamai": [
            r"akam",
            r"akamai",
            r"akamaiedge",
            r"AkamaiGHost",
        ],
        "Fastly": [
            r"Fastly",
            r"fastly-player",
        ],
        "Sucuri": [
            r"sucuri",
        ],
        "Distil": [
            r"distil",
        ],
        "Varnish": [
            r"varnish",
        ],
    }

    waf_details = {}

    for header in response_headers:
        if header.lower() == "server":
            server_header = response_headers[header]
            for waf_name, patterns in waf_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, server_header, re.IGNORECASE):
                        waf_details[waf_name] = {"status": True}
                        if "Cloudflare" in waf_name:
                            waf_details[waf_name]["cf_ray_id"] = response_headers.get("Cf-Ray", "")

                            version_pattern = r"cloudflare|cfnginx|cloudflare-nginx/(\d+\.\d+)"
                            version_search = re.search(version_pattern, server_header)
                            if version_search:
                                waf_details[waf_name]["version"] = version_search.group(1)
    return waf_details
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="URL to test")
    parser.add_argument("--time", type=int, default=0, help="Time delay between requests (SECONDS)")
    args = parser.parse_args()
    url = args.url
    delay = args.time
    if args.url :
        print("""\033[31m\n\n
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠄⣿⢿⠿⣯⣇⠀⢹⢀⡴⡠⠂⣠⢾⣹⠟⠁⠀⣀⣨⣶⣻⣼⣫⢷⣻⣭⢿⡵⣯⣟⣾⣻⣟⡿⣾⡽
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣌⢻⡏⠀⠈⠉⠓⡿⠏⠛⢰⠿⢻⢺⡿⢖⣾⠿⣟⣿⡽⣃⣉⠉⠉⢙⢓⣊⢿⡽⣛⣾⢷⣻⣽⡳⡟
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⢂⠍⡉⣹⣻⢾⣽⣏⣯⣟⣾⢯⡽⣿⢽⣫⣷⡿⠝⣓
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠃⠌⢒⠠⠱⣭⣿⣳⣟⣾⡽⣞⡯⣟⣞⣯⣷⣿⡽⣟⣉
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠜⡀⢣⠘⡠⣽⣿⣽⣫⡽⢯⣽⣏⡿⣞⣟⣮⣽⠷⠋
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⡀⠣⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⠁⡌⠄⢣⠐⡉⢿⣯⢿⣽⣻⣧⡿⣽⣿⣻⣷⠗⡂⠠
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠰⠬⠝⣖⠀⠀⠀⢠⢔⣂⡭⢅⠰⠠⢆⡙⠲⢥⣂⠅⡒⡘⣿⠟⢈⡤⡙⣿⣽⢾⡷⢁⣀⣤⣤
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢆⠀⠀⠩⠀⠀⠀⠀⠉⠒⠐⠢⠭⣭⠖⣂⡅⢂⠌⡡⢐⡐⢃⠞⡓⡗⡍⢿⡾⣯⠿⠛⠉⠉⠀
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢰⠁⠀⠆⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⢀⠁⡆⠸⢀⠁⢆⢹⣆⡰⢹⠇⣿⡿⠷⠀⠀⠀⠀⠀
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠈⠀⠌⠀⢀⠀⠀⠀⠀⠀⠀⣸⠀⠀⠀⠅⠂⢌⠂⡅⢊⢤⣞⡄⠜⢫⡼⠋⠀⠀⠀⠀⠀⠀⠀
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⡊⠀⡠⠊⡁⢄⠀⠀⠀⠀⢻⠀⠀⢠⢈⠰⢈⠒⡈⢤⡎⢀⣤⡾⠟⣁⣀⣀⠀⠤⠠⠄⠒⣂
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠈⠪⠡⠐⠁⠀⠀⠀⠀⠛⠀⠀⡀⠂⡌⢂⡑⣨⡣⢂⣿⣿⡧⠵⠶⠖⠒⠚⠛⠋⠉⠉⠉
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠒⠂⠀⠠⠄⡀⠀⠀⠀⢀⠡⠡⡐⠂⣔⣾⠑⣺⣿⣿⡇⢰⡀⠦⠀⠀⠀⠀⠀⠀⠀
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠱⠒⢂⣀⠄⠀⠀⠀⠀⡌⠠⢁⡴⢋⢹⡁⢂⣿⣿⣿⡧⣧⣼⠧⠴⠬⠤⠤⣤⠤⠤
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⡂⠀⠈⠈⠀⠀⠀⠀⡠⢊⣠⠕⢋⡐⢤⢫⢀⢃⣿⣿⣿⣟⣿⣿⣯⡔⣽⡼⡩⣥⠇⣀
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢟⠋⢸⡏⢆⠀⠀⠀⠀⠠⣊⠔⡋⠄⢌⡐⢄⢎⠅⣂⣾⡿⣿⣿⣿⣿⣿⣳⡗⣾⣗⣧⢹⡆⡥
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢻⡋⠘⢆⠈⠻⢷⣗⣶⢶⣳⢮⣥⣜⣤⣮⣔⣤⣾⣼⢿⣟⣯⣿⣟⣿⣿⣿⣿⣳⡝⣶⡽⣹⣞⡳⣵
        ⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠋⠀⢐⡇⢰⡀⢂⠉⠢⠤⢈⣉⣛⡙⢿⣺⡽⣞⡷⣯⣟⣾⡽⣿⢾⣻⢾⣽⡾⣯⡙⠻⢷⣭⣳⠟⣽⡧⣟⣽
        --------{ Coded By Boutadjine Alaa }--------------\033[0m""")
        print("\033[31m        @Boutadjine36264\033[0m")
    delay = args.time
    responsefirst = requests.get(url)
    saved_code = responsefirst.status_code
    saved_length = len(responsefirst.content)
    print(f"\n\033[34mOriginal URL:\033[0m {url}   \033[31mStatus Code : \033[0m[{saved_code}] \033[31m Content-Length : \033[0m[{saved_length}]")
    Colors(f"\nUsing Random-Agents By Default ...\n", "red")
    waf = WAF_Check(url)
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    Get_Parameters(query)



    if waf:
        Colors("\n------------------ WAF Details -------------------", "green")
        for waf_name, details in waf.items():
            Colors(f"\n- {waf_name}: Detected","green")
            if "cf_ray_id" in details:  
                Colors(f"\n  CF-Ray ID: {details['cf_ray_id']}","green")
            if "version" in details:
                Colors(f"\n  Version: {details['version']}","green")
        Colors("\n--------------------------------------------------\n\n","green")
    else:
        Colors("\nNo WAF detected. Starting Anyway !\n\n\n", "red")
    user_agents = [
        "Mozilla/5.0 (Linux; Android 13; CPH2273 Build/TP1A.220905.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/110.0.5481.65 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/419.0.0.37.71;]",
        "TuneIn Radio/25.7.2; iPhone11,8; iOS/16.5.1",
        "Mozilla/5.0 (Linux; Android 12; moto g(60) Build/S2RIS32.32-20-7-11; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/114.0.5735.130 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/419.0.0.37.71;]",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 11; moto g(9) play Build/RPXS31.Q2-58-17-7-3; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/114.0.5735.60 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 12; 21061119DG Build/SP1A.210812.016) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/114.0.5735.131 Mobile Safari/537.36 GNews Android/2022129690",
        "TuneIn Radio/22.8.0; iPhone8,4; iOS/15.7.6",
        "Mozilla/5.0 (Linux; Android 12; Galaxy Note 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.48 Mobile Safari/537.46",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 YaBrowser/23.3.0 Yowser/2.5 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 12; Redmi Note 9S) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36 EdgA/114.0.1823.56",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "TuneIn Radio/25.7.2; iPhone11,2; iOS/16.5.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0",]
    i = 0
    for url in get_params(url):
        if delay > 0:
            time.sleep(delay)
        user_agent = user_agents[i]
        headers = {"User-Agent": user_agent}
        response = requests.get(url, headers=headers)
        code = response.status_code
        time_taken = response.elapsed.total_seconds()
        length = len(response.content)
        print(
            f'\033[31m - Payload : \033[0m {url} \033[31mStatus Code : \033[0m[{code}] \033[31mContent-Length : \033[0m[{length}] \033[31m Time : \033[0m[{time_taken}]')
        if saved_code != code:
            print(
                f'\033[32mPayload : \033[0m {url} \033[32mStatus Code : \033[0m[{code}] \033[32mContent-Length : \033[0m[{length}]')
            print(f'\033[32mThis One is Different! Check it Out! ... \033[0m')
        i += 1
        if i == len(user_agents):
          i = 0
if __name__ == "__main__":
    main()



