
import base64
import hashlib
import json
import os
import re
import time
import threading
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup
import tls_client
from utils import load_accounts, log
import uuid
import html
import pkce
email_data = []

class TMOutlook:
    def __init__(self, account):
        self.data = account
        self.session = None
        self.code_verifier = None
        self.request_id = str(uuid.uuid4())
        self.code_challenge = None

    def run(self):
        try:
            self.session = tls_client.Session(
                client_identifier="chrome_131",
                force_http1=True,
                random_tls_extension_order=True,
                header_order=header_order,
                supported_signature_algorithms=[
                    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
                ]
            )
            self.code_verifier = pkce.generate_code_verifier(length=43)
            self.code_challenge = pkce.get_code_challenge(self.code_verifier)
                      
            state_data = {
                "id": os.urandom(8).hex(),
                "meta": {"interactionType": "redirect"}
            }
            state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()
            nonce = str(uuid.uuid4())
            
            print("code_verifier:", self.code_verifier)
            print("state:", state)
            print("nonce:", nonce)
            self.login(self.data[0], self.data[1],state, nonce)
        except Exception as e:
            log(f"[ERROR] Exception occurred in run loop: {e}")
        finally:
            log("Close Tls Client Session...")
            self.session.close()
            

    def login(self, username, password,state, nonce):
        log(f"Trying to login... username:{username} password: {password}")
        first_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Referer': 'https://login.microsoftonline.com/',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'cross-site',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-ch-ua-platform-version': '"10.0.0"'
        }
        params = {
            "client_id": "9199bf20-a13f-4107-85dc-02114787ef48",
            "scope": "https://outlook.office.com/.default openid profile offline_access",
            "redirect_uri": "https://outlook.live.com/mail/",
            "response_type": "code",
            "state": state,
            "response_mode": "fragment",
            "nonce": nonce,
            "code_challenge": f"{self.code_challenge}",
            "code_challenge_method": "S256",
            "x-client-SKU": "msal.js.browser",
            "x-client-Ver": "4.4.0",
            "uaid": self.request_id,
            "msproxy": "1",
            "issuer": "mso",
            "tenant": "common",
            "ui_locales": "en-US",
            "client_info": "1",
            "jshs": "1",
            "fl": "dob,flname,wld",
            "cobrandid": "ab0455a0-8d03-46b9-b18b-df2f57b9e44c",
            "claims": '{"access_token":{"xms_cc":{"values":["CP1"]}}}',
            "username": f"{username}",
            "login_hint": f"{username}",
        }
        response  = self.session.get("https://login.live.com/oauth20_authorize.srf", params = params, headers = first_headers)
        if response.status_code == 200:
            print("Go to next step")
            with open('login.html', 'w', encoding='utf-8') as file:
                file.write(response.text)
            pass_headers ={
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Cache-Control': 'max-age=0',
                    'Connection': 'keep-alive',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Origin': 'https://login.live.com',
                    'referer': response.url,
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
                    'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-ch-ua-platform-version': '"10.0.0"',
                }
            ppft_input = re.search(r'name="PPFT"\s+id="[^"]*"\s+value="([^"]+)"', response.text)
            if ppft_input:
                ppft_value = ppft_input.group(1)
                print("PPFT:", ppft_value)
                match = re.search(r"urlPostMsa:\s*'([^']+)'", response.text)
                if match:
                    url_post_msa = match.group(1)
                    print("urlPostMsa:", url_post_msa)
                    form_data = {
                        "ps":2,
                        "psRNGCDefaultType":"",
                        "psRNGCEntropy":"",
                        "psRNGCSLK":"",
                        "canary":"",
                        "ctx":"",
                        "hpgrequestid":"",
                        "PPFT":ppft_value,
                        "PPSX":"Pas",
                        "NewUser":"1",
                        "FoundMSAs":"",
                        "fspost":0,
                        "i21":0,
                        "CookieDisclosure":0,
                        "IsFidoSupported":1,
                        "isSignupPost":0,
                        "isRecoveryAttemptPost":0,
                        "i13":0,
                        "login":username,
                        "loginfmt":username,
                        "type":11,
                        "LoginOptions":3,
                        "lrt":"",
                        "lrtPartition":"",
                        "hisRegion":"",
                        "hisScaleUnit":"",
                        "passwd":password,
                    }
                    pass_response = self.session.post(url_post_msa, headers = pass_headers, data = form_data)
                    print("pass_response.status_code",pass_response.status_code)
                    with open('password.html', 'w', encoding='utf-8') as file:
                        file.write(pass_response.text)
                    if pass_response.status_code == 200:
                        sErrTxt_match = re.search(r"sErrTxt:\s*'([^']+)'", pass_response.text)
                        if sErrTxt_match:
                            sErrTxt = sErrTxt_match.group(1)
                            if "incorrect account or password." in sErrTxt or "account or password is incorrect"  in sErrTxt:
                                print("We can't sign you in")    
                        else:
                            log(f"Successfully signed in with username :{username}")
                            match = re.search(r"sFT:\s*'([^']+)'", pass_response.text)
                            if match:
                                form_Data = {
                                    "PPFT":match.group(1),
                                    "canary":"",
                                    "LoginOptions":3,
                                    "type":28,
                                    "hpgrequestid":"",
                                    "ctx":"",
                                }
                                ppsecure_headers = {
                                    'Cache-Control': 'max-age=0',
                                    'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
                                    'sec-ch-ua-mobile': '?0',
                                    'sec-ch-ua-platform': '"Windows"',
                                    'sec-ch-ua-platform-version': '"10.0.0"',
                                    'Origin': 'https://login.live.com',
                                    'Upgrade-Insecure-Requests': '1',
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
                                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                                    'Sec-Fetch-Site': 'same-origin',
                                    'Sec-Fetch-Mode': 'navigate',
                                    'Sec-Fetch-User': '?1',
                                    'Sec-Fetch-Dest': 'document',
                                    'Accept-Language': 'en-US,en;q=0.9',
                                    'Content-Type': 'application/x-www-form-urlencoded',
                                    'referer':pass_response.url
                                }
                                ppsecure_response = self.session.post(url_post_msa, headers = ppsecure_headers, data = form_Data)
                                print(ppsecure_response.status_code)
                                if ppsecure_response.status_code == 200:
                                    if "continue" in ppsecure_response.text:
                                        print("Continuing")
                                        soup  = BeautifulSoup(ppsecure_response.text,'html.parser')
                                        data = {}
                                        for input_tag in soup.find_all('input'):
                                            name = input_tag.get('name')
                                            value = input_tag.get('value')
                                            data[name] = value

                                        print(data)
                                        final_headers = {
                                            'cache-control': 'max-age=0',
                                            'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
                                            'sec-ch-ua-mobile': '?0',
                                            'sec-ch-ua-platform': '"Windows"',
                                            'origin': 'https://login.live.com',
                                            'content-type': 'application/x-www-form-urlencoded',
                                            'upgrade-insecure-requests': '1',
                                            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
                                            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                                            'sec-fetch-site': 'cross-site',
                                            'sec-fetch-mode': 'navigate',
                                            'sec-fetch-dest': 'document',
                                            'referer': 'https://login.live.com/',
                                            'accept-language': 'en-US,en;q=0.9',
                                            'priority': 'u=0, i'
                                        }
                                        final_response = self.session.post("https://login.microsoftonline.com/consumers/savestate", data = data, headers = final_headers)
                                        if final_response.status_code == 302:
                                            log("Successfully signd in to site")     
                                            print(final_response.text)                
                                elif ppsecure_response.status_code == 302:
                                    print("redirected",ppsecure_response.headers.get("Location"))
                                    self.redirect_mail(ppsecure_response.headers.get("Location"))
                            else:
                                match_ppft = re.search(r'name="PPFT"\s+id="[^"]*"\s+value="([^"]+)"', pass_response.text)
                                if match_ppft:
                                    log("You've tried to sign in too many times")
                                else:
                                    soup = BeautifulSoup(pass_response.text,'html.parser')   
                                    form = soup.find("form")   
                                    form_action = form.get("action")
                                    form_data = {}    
                                    for input_tag in soup.find_all('input'):
                                        name = input_tag.get('name')
                                        value = input_tag.get('value')
                                        form_data[name] = value
                                    headers = {
                                        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                                        'accept-language': 'en-US,en;q=0.9',
                                        'cache-control': 'max-age=0',
                                        'content-type': 'application/x-www-form-urlencoded',
                                        'origin': 'https://login.live.com',
                                        'priority': 'u=0, i',
                                        'referer': 'https://login.live.com/',
                                        'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
                                        'sec-ch-ua-mobile': '?0',
                                        'sec-ch-ua-platform': '"Windows"',
                                        'sec-fetch-dest': 'document',
                                        'sec-fetch-mode': 'navigate',
                                        'sec-fetch-site': 'same-site',
                                        'upgrade-insecure-requests': '1',
                                        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
                                    }
                                    response = self.session.post(form_action, headers = headers, data = form_data)
                                    print(response.status_code)
                                    with open('stay.html', 'w', encoding='utf-8') as file:
                                                file.write(response.text)
                                    if response.status_code == 200:
                                        # find skipUrl
                                        skip_url_match = re.search(r'"skipUrl"\s*:\s*"([^"]+)"', response.text)
                                        if skip_url_match:
                                            skip_url = html.unescape(skip_url_match.group(1))
                                            print("skipUrl:", skip_url)
                                            oauth_response = self.session.get(skip_url, headers = headers )
                                            print(oauth_response.status_code)
                                            with open('oauth.html', 'w', encoding='utf-8') as file:
                                                file.write(oauth_response.text)
                                            urlPost_match = re.search(r"urlPost:\s*'([^']+)'", oauth_response.text)
                                            sFT_match = re.search(r"sFT:\s*'([^']+)'", oauth_response.text)
                                            if urlPost_match and sFT_match:
                                                urlPost = urlPost_match.group(1)
                                                
                                                url_post_form_data = {
                                                    "PPFT":sFT_match.group(1),
                                                    "canary":"",
                                                    "LoginOptions":3,
                                                    "type":28,
                                                    "hpgrequestid":"",
                                                    "ctx":"",
                                                }
                                                headers = {
                                                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                                                    'Accept-Language': 'en-US,en;q=0.9',
                                                    'Cache-Control': 'max-age=0',
                                                    'Connection': 'keep-alive',
                                                    'Content-Type': 'application/x-www-form-urlencoded',
                                                    'Origin': 'https://login.live.com',
                                                    'Referer': oauth_response.url ,
                                                    'Sec-Fetch-Dest': 'document',
                                                    'Sec-Fetch-Mode': 'navigate',
                                                    'Sec-Fetch-Site': 'same-origin',
                                                    'Sec-Fetch-User': '?1',
                                                    'Upgrade-Insecure-Requests': '1',
                                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
                                                    'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
                                                    'sec-ch-ua-mobile': '?0',
                                                    'sec-ch-ua-platform': '"Windows"',
                                                    'sec-ch-ua-platform-version': '"10.0.0"',
                                                }
                                                urlPost_response = self.session.post(urlPost, headers = headers,data = url_post_form_data)
                                                print(urlPost_response.status_code)
                                                
                                                print(urlPost_response.headers.get("Location"))
                                                if urlPost_response.status_code == 302:
                                                    print("second redirect",urlPost_response.headers.get("Location"))
                                                    self.redirect_mail(urlPost_response.headers.get("Location"))

                                                elif urlPost_response.status_code == 200:
                                                    with open('o_0auth.html', 'w', encoding='utf-8') as file:
                                                        file.write(urlPost_response.text)
                                            else:
                                                print("not found ")
                                        else:
                                            print("skipUrl not found.")
                                    

                else:
                    print("urlPostMsa not found")
            else:
                print("PPFT input not found")

    def redirect_mail(self, url):
        print("redirect mail")
        print(url)
        print("code_verifier",self.code_verifier)

        headers = {
            'Cache-Control': 'max-age=0',
            'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-ch-ua-platform-version': '"10.0.0"',
            'Origin': 'https://login.live.com',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        mail_response = self.session.get(url, headers = headers)
        print(mail_response.status_code)
        if mail_response.status_code == 200:
            with open('mail_200.html', 'w', encoding='utf-8') as file:
                file.write(mail_response.text)
            log(f"Successfully logged in to mailbox with ${mail_response.status_code}")

        elif mail_response.status_code == 302:
            final_response = self.session.get(mail_response.headers.get("Location"), headers = headers, allow_redirects = True)
            print(final_response.status_code)
            with open('mail_302.html', 'w', encoding='utf-8') as file:
                file.write(final_response.text)
            log("Successfully logged in to mailbox")   
            request_params ={
                "client-request-id":self.request_id
            }
            fragment = urlparse(url).fragment
            params = parse_qs(fragment)
            code = params.get('code', [None])[0]
            payload= {
                "client_id":"9199bf20-a13f-4107-85dc-02114787ef48",
                "redirect_uri":"https://outlook.live.com/mail/",
                "scope":"https://outlook.office.com/.default openid profile offline_access",
                "code":code,
                "x-client-SKU":"msal.js.browser",
                "x-client-VER":"4.4.0",
                "x-ms-lib-capability":"retry-after, h429",
                "x-client-current-telemetry":"5|865,0,,,|,",
                "x-client-last-telemetry":"5|0|||0,0",
                "code_verifier":self.code_verifier, 
                "grant_type":"authorization_code",
                "client_info":"1",
                "claims":'{"access_token":{"xms_cc":{"values":["CP1"]}}}',
                "X-AnchorMailbox":"Oid:00000000-0000-0000-c632-750395a5618f@9188040d-6c67-4c5b-b112-36a304b66dad", # change this
            }
            refresh_headers = {
                'accept': '*/*',
                'accept-language': 'en-US,en;q=0.9',
                'content-type': 'application/x-www-form-urlencoded;charset=utf-8',
                'origin': 'https://outlook.live.com',
                'priority': 'u=1, i',
                'referer': 'https://outlook.live.com/',
                'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'cross-site',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            }
            refresh_token_response = self.session.post("https://login.microsoftonline.com/common/oauth2/v2.0/token", 
                                                       params = request_params, 
                                                       data = payload, 
                                                       headers = refresh_headers)
            print(refresh_token_response.status_code)
            refresh_token_data = refresh_token_response.json()
            if refresh_token_response.status_code == 200:
                refresh_token = refresh_token_data['refresh_token']
                print("refresh_token",refresh_token)
            elif refresh_token_response.status_code == 400:
                print(f"{refresh_token_data['error_description']}")

    def get_rules(self):
        url = "https://outlook.live.com/owa/0/service.svc?action=GetInboxRule&app=Mail&n=79"
        headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'action': 'GetInboxRule',
            'authorization': 'MSAuth1.0 usertoken="EwAYBOl3BAAUcDnR9grBJokeAHaUV8R3+rVHX+IAAV2YTMXd9cuFj2UPIF7JAt1UppD9mTbRk1T8dIm6gFjwkbtG+e3d4x4NYtUjr61NmNMO3ihWjW+2iSObs2IQsHE2IFObUL6OsDGJ3tZfijK5Hh/nTu5sC64brt+h4gECbTfLETTnpr8t2EYUQFrc5lzdLb1+rXsGEkywy41vVDogJrbB7zBrLfnyZ+ouZNUtQxBUvieg2jOK0Cv5KJK1LecEJhmduDvISKKXzo/JdrMgmbFS2s2TQT1FG7NT5udnU82g9cye3/346/h8G3D2VpESDLWpb8okgRDOUOz2XDMchZADp7RgpDdCROOMzxUL/xBRVaf7tO0Lrg98W/EhiQcQZgAAEKlmzx0dZM/fVZ4cCsv+LzjgApbY5eOKopXVaSG8V1IEXXzwYkHkM2uHuZEFV3Z1plQoTt34AOU0ILDLs4xjkR/8H+PWNLXBn+X41PJSL5JrmzCyVGV+fCEB2p4mqQ18XGPy/fwifaa8H7JSZkL7RyHqFepX4JAbJpkz2SMA0taU1a82Oh/LYFqcRrz4HYdwWwnEuLeT4IlPxLGEea9DhpzJ8o5teXlT7pHN/GKQXfT6rGKxojGhd+KVPAwUjPvwKhnf0Nx5JVfkqTQvLHo+EEH6yurkaiU6r4fbxwaGXu7QxrB7zRJql8u3ced6nv3tqOxjLlksbM7DhCic8K2N0g10USUXOOAokk4q649b233GLHlByz8mQitOEE16JKhDXPy8CAzenH+ZJrcJEFFA8sltnw/xYUEGbMefh45utYJcr0H6hVbxShzFTLOD6mWzPCPme+TjTftAjGkGOi87i1puzgt0m/EU45cVbU+9g7i1g8YkpP1E1284iBkdZDeYCzoOAJhJGTQyZjXMg2xGVLo0dsv/Xovt4eatd4b0HH+751xbvtt2Bz+ZmtXtXCgQrV6oZUWyAun5KUOA3C8wkUvNyUbnkAHTZcDhqI6Uwfe2hzgScUtk35pT5il4tvysiHdBTF+ry9wdOwBtYH811ZPBvLKBhk+5SUsIIHpRo0OQeQuKjCMklLVBHYaHcePgotpn6fXs/uqRtyvnMVmXkdDM4voRoQdl8glMkRMuTYgNLC9aPgc78i4ZAOrc13SLnPHXYovpceZd1IA2NRirokhfS38f6ntoU1IJExMbcVjpzAUfHl55DToW2WaLhMh/IVhezkDDblg1k0Pw7zvlLXujaZ1iKu5gqB49/3dpHFQRQHJFf7SsICOmcsEijAN5LA4Ov25fAyXL83ovoAef+dJMqN/dYzHyzld3/9kPYDajK9ANZF30Dzf4Qf164B1DjGsALu+FJx/QxFr2DdAJjT39o+wopmcJIvNZHSAhW1hrnbYgAw==", type="MSACT"',
            'content-length': '0',
            'content-type': 'application/json; charset=utf-8',
            'ms-cv': 'KuShXJ9KPtofsBEMa/qu+q.90',
            'origin': 'https://outlook.live.com',
            'prefer': 'exchange.behavior="IncludeThirdPartyOnlineMeetingProviders"',
            'priority': 'u=1, i',
            'referer': 'https://outlook.live.com/',
            'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            'x-anchormailbox': 'PUID:000640008EC8648E^@84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa',
            'x-owa-correlationid': 'b35acd82-faca-c001-01f3-536153b9963b',
            'x-owa-hosted-ux': 'false',
            'x-owa-sessionid': 'c460f0e3-7c5e-4452-8187-1b8eadba4d66',
            'x-owa-urlpostdata': '%7B%22__type%22%3A%22GetInboxRuleRequest%3A%23Exchange%22%2C%22Header%22%3A%7B%22__type%22%3A%22JsonRequestHeaders%3A%23Exchange%22%2C%22RequestServerVersion%22%3A%22V2018_01_08%22%2C%22TimeZoneContext%22%3A%7B%22__type%22%3A%22TimeZoneContext%3A%23Exchange%22%2C%22TimeZoneDefinition%22%3A%7B%22__type%22%3A%22TimeZoneDefinitionType%3A%23Exchange%22%2C%22Id%22%3A%22Belarus%20Standard%20Time%22%7D%7D%7D%2C%22UseServerRulesLoader%22%3Atrue%7D',
            'x-req-source': 'Mail',
            'x-tenantid': '84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa',
        }
        response = self.session.post(url, headers = headers) 
        print("get_rules")
        print(response.status_code)
        print(response.text)
        if response.status_code == 200:
            print(response.json())

    def remove_rules(self):
        url = "https://outlook.live.com/owa/0/service.svc?action=RemoveInboxRule&app=Mail&n=84"
        headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'action': 'RemoveInboxRule',
            'authorization': 'MSAuth1.0 usertoken="EwAYBOl3BAAUcDnR9grBJokeAHaUV8R3+rVHX+IAAV2YTMXd9cuFj2UPIF7JAt1UppD9mTbRk1T8dIm6gFjwkbtG+e3d4x4NYtUjr61NmNMO3ihWjW+2iSObs2IQsHE2IFObUL6OsDGJ3tZfijK5Hh/nTu5sC64brt+h4gECbTfLETTnpr8t2EYUQFrc5lzdLb1+rXsGEkywy41vVDogJrbB7zBrLfnyZ+ouZNUtQxBUvieg2jOK0Cv5KJK1LecEJhmduDvISKKXzo/JdrMgmbFS2s2TQT1FG7NT5udnU82g9cye3/346/h8G3D2VpESDLWpb8okgRDOUOz2XDMchZADp7RgpDdCROOMzxUL/xBRVaf7tO0Lrg98W/EhiQcQZgAAEKlmzx0dZM/fVZ4cCsv+LzjgApbY5eOKopXVaSG8V1IEXXzwYkHkM2uHuZEFV3Z1plQoTt34AOU0ILDLs4xjkR/8H+PWNLXBn+X41PJSL5JrmzCyVGV+fCEB2p4mqQ18XGPy/fwifaa8H7JSZkL7RyHqFepX4JAbJpkz2SMA0taU1a82Oh/LYFqcRrz4HYdwWwnEuLeT4IlPxLGEea9DhpzJ8o5teXlT7pHN/GKQXfT6rGKxojGhd+KVPAwUjPvwKhnf0Nx5JVfkqTQvLHo+EEH6yurkaiU6r4fbxwaGXu7QxrB7zRJql8u3ced6nv3tqOxjLlksbM7DhCic8K2N0g10USUXOOAokk4q649b233GLHlByz8mQitOEE16JKhDXPy8CAzenH+ZJrcJEFFA8sltnw/xYUEGbMefh45utYJcr0H6hVbxShzFTLOD6mWzPCPme+TjTftAjGkGOi87i1puzgt0m/EU45cVbU+9g7i1g8YkpP1E1284iBkdZDeYCzoOAJhJGTQyZjXMg2xGVLo0dsv/Xovt4eatd4b0HH+751xbvtt2Bz+ZmtXtXCgQrV6oZUWyAun5KUOA3C8wkUvNyUbnkAHTZcDhqI6Uwfe2hzgScUtk35pT5il4tvysiHdBTF+ry9wdOwBtYH811ZPBvLKBhk+5SUsIIHpRo0OQeQuKjCMklLVBHYaHcePgotpn6fXs/uqRtyvnMVmXkdDM4voRoQdl8glMkRMuTYgNLC9aPgc78i4ZAOrc13SLnPHXYovpceZd1IA2NRirokhfS38f6ntoU1IJExMbcVjpzAUfHl55DToW2WaLhMh/IVhezkDDblg1k0Pw7zvlLXujaZ1iKu5gqB49/3dpHFQRQHJFf7SsICOmcsEijAN5LA4Ov25fAyXL83ovoAef+dJMqN/dYzHyzld3/9kPYDajK9ANZF30Dzf4Qf164B1DjGsALu+FJx/QxFr2DdAJjT39o+wopmcJIvNZHSAhW1hrnbYgAw==", type="MSACT"',
            'content-length': '0',
            'content-type': 'application/json; charset=utf-8',
            'ms-cv': 'KuShXJ9KPtofsBEMa/qu+q.95',
            'origin': 'https://outlook.live.com',
            'prefer': 'exchange.behavior="IncludeThirdPartyOnlineMeetingProviders"',
            'priority': 'u=1, i',
            'referer': 'https://outlook.live.com/',
            'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            'x-anchormailbox': 'PUID:000640008EC8648E^@84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa',
            'x-owa-correlationid': 'b26143f0-ded1-1c21-98c4-035d82d686c8',
            'x-owa-hosted-ux': 'false',
            'x-owa-sessionid': 'c460f0e3-7c5e-4452-8187-1b8eadba4d66',
            'x-owa-urlpostdata': '%7B%22__type%22%3A%22RemoveInboxRuleRequest%3A%23Exchange%22%2C%22Header%22%3A%7B%22__type%22%3A%22JsonRequestHeaders%3A%23Exchange%22%2C%22RequestServerVersion%22%3A%22V2018_01_08%22%2C%22TimeZoneContext%22%3A%7B%22__type%22%3A%22TimeZoneContext%3A%23Exchange%22%2C%22TimeZoneDefinition%22%3A%7B%22__type%22%3A%22TimeZoneDefinitionType%3A%23Exchange%22%2C%22Id%22%3A%22Belarus%20Standard%20Time%22%7D%7D%7D%2C%22Identity%22%3A%7B%22DisplayName%22%3A%2200064000-8ec8-648e-0000-000000000000%5C%5C17388190521217777665%22%2C%22RawIdentity%22%3A%2200064000-8ec8-648e-0000-000000000000%5C%5C17388190521217777665%22%7D%7D',
            'x-req-source': 'Mail',
            'x-tenantid': '84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa',
        }
        response = self.session.post(url, headers = headers) 
        print(response.status_code)
        if response.status_code == 200:
            print(response.json())



if __name__ == "__main__":
    data = load_accounts('email.txt')
    header_order = [
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "origin",
        "upgrade-insecure-requests",
        "content-type",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "accept-encoding",
        "accept-language",
        "cookie",
        "priority"
    ]
    for i in range(1):
        tmoutlook = TMOutlook(
            account = data[i]
        )
        process = threading.Thread(target=tmoutlook.run, args=())
        log(f'Starting Bot ')
        process.start()
        time.sleep(3)