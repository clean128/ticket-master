import base64
from datetime import datetime,timezone
import hashlib
import json
import random


def log(text):
   print(f"[{datetime.now().strftime('%m-%d-%Y %H:%M:%S')}] - [{text}]")

def nonblank_lines():
    with open("proxies.txt") as f:
        stripped_lines = [line.strip() for line in f]
        return [line for line in stripped_lines if line]
    

def load_proxies_from_file(shuffle=True):
    proxies = nonblank_lines()

    if shuffle:
        random.shuffle(proxies)
    result = []

    for proxy in proxies:
        proxyTokens = proxy.split(':')

        proxyStr = ":".join(proxyTokens[0:2])

        if len(proxyTokens) == 4:
            proxyStr = ":".join(proxyTokens[2:]) + "@" + proxyStr

        result.append(proxyStr)
    return result

def load_accounts(file_path):
    accounts = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if line and ':' in line:
                    username, password = line.split(':', 1)
                    accounts.append((username.strip(), password.strip()))
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    return accounts