#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jun  1 16:32:59 2025

@author: pfiano
"""

import os
import re
import certifi
import urllib.parse
import configparser
import collections  # <-- added for case-sensitive config
from lxml import etree
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, AddressValueError
from cabby import create_client
import requests
from pathlib import Path
from cabby.exceptions import (
    HTTPError, UnsuccessfulStatusError, ServiceNotFoundError,
    AmbiguousServicesError, NoURIProvidedError
)

CONFIG_FILE = "configuration.cfg"

# Use OrderedDict and preserve case for keys
config = configparser.ConfigParser(dict_type=collections.OrderedDict)
config.optionxform = str
config.read(CONFIG_FILE)

USERNAME = config["otx"]["username"]
PASSWORD = config["otx"]["password"]
TAXII_HOST = config["otx"]["host"]
USE_HTTPS = config.getboolean("otx", "use_https")
DISCOVERY_PATH = config["otx"]["discovery_path"]

# ✅ Load namespace dictionary from config
ns = dict(config.items("namespace"))

LAST_POLL_FILE = "last_poll_time.txt"
os.environ['REQUESTS_CA_BUNDLE'] = certifi.where()


def load_last_poll_time():
    if Path(LAST_POLL_FILE).exists():
        with open(LAST_POLL_FILE, "r") as f:
            return datetime.fromisoformat(f.read().strip())
    return None

def save_last_poll_time(dt: datetime):
    with open(LAST_POLL_FILE, "w") as f:
        f.write(dt.isoformat())

def get_umbrella_token(key, secret):
    auth_url = config["api_umbrella"]["auth_url"]
    response = requests.post(
        auth_url,
        auth=(key, secret),
        data={'grant_type': 'client_credentials'}
    )
    response.raise_for_status()
    return response.json()['access_token']

def get_destination_list_id(token, list_name):
    list_url = config["api_umbrella"]["list_url"]
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.get(list_url, headers=headers)
    response.raise_for_status()
    for dlist in response.json().get('data', []):
        if dlist['name'].lower() == list_name.lower():
            return dlist['id']
    print(f"❌ Destination list '{list_name}' not found.")
    return None

def push_destinations_to_umbrella(destinations, token, destination_list_id):
    push_url_template = config["api_umbrella"]["push_url_template"]
    url = push_url_template.format(destination_list_id=destination_list_id)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = [{"destination": d, "comment": "Imported from OTX"} for d in destinations]
    response = requests.post(url, json=payload, headers=headers)
    try:
        result = response.json()
    except Exception:
        result = response.text
    if response.status_code == 200:
        print(f"✅ Successfully added {len(destinations)} destinations")
    elif response.status_code == 409:
        print("⚠️ Some or all destinations already existed")
    else:
        print(f"❌ Failed to add destinations: {response.status_code} - {result}")


# === TAXII Client ===
client = create_client(
    host=TAXII_HOST,
    use_https=USE_HTTPS,
    discovery_path=DISCOVERY_PATH
)
client.set_auth(username=USERNAME, password=PASSWORD)

try:
    collections = client.get_collections()
    collection = collections[0]
    print(f"📥 Polling OTX collection: {collection.name}")
    POLL_DAYS = config.getint("otx", "poll_days", fallback=10)
    begin_time = datetime.now(timezone.utc) - timedelta(days=POLL_DAYS)
    # begin_time = datetime.now(timezone.utc) - timedelta(days=10)
    content_blocks = list(client.poll(collection.name, begin_date=begin_time))
    last_blocks = content_blocks[-5:]
    
    ns = dict(config.items("namespace"))

    all_ips = set()
    all_urls = set()
    all_urls_stripped = set()
    all_domains = set()

    for block in last_blocks:
        xml_content = block.content.decode('utf-8')
        if xml_content.strip().startswith('%3C'):
            xml_content = urllib.parse.unquote(xml_content)
        tree = etree.fromstring(xml_content)

        url_nodes = tree.xpath('//URIObj:Value', namespaces=ns)
        urls = [n.text.strip() for n in url_nodes if n is not None and n.text]
        all_urls.update(urls)

        domain_nodes = tree.xpath('//DomainNameObj:Value', namespaces=ns)
        for node in domain_nodes:
            if node.text:
                all_domains.add(node.text.strip())

        ip_nodes = tree.xpath('//AddressObj:Address_Value', namespaces=ns)
        for node in ip_nodes:
            ip = node.text.strip()
            try:
                ip_obj = ip_address(ip)
                all_ips.add(str(ip_obj))
            except AddressValueError:
                continue

        for url in urls:
            try:
                parsed = urlparse(url)
                host = parsed.hostname
                if host:
                    try:
                        ip_obj = ip_address(host)
                        all_ips.add(str(ip_obj))
                    except AddressValueError:
                        all_urls_stripped.add(host)
            except ValueError:
                continue

    all_destinations = sorted(all_ips.union(all_urls_stripped).union(all_domains))

    if not all_destinations:
        print("ℹ️ No destinations found to push.")
        exit(0)

    print(f"\n🚀 Pushing {len(all_destinations)} destinations to all configured Umbrella orgs...")

    for section in config.sections():
        if section.startswith("umbrella_"):
            key = config[section]["key"]
            secret = config[section]["secret"]
            list_name = config[section]["destination_list_name"]
            org_id = config[section].get("org_id", "N/A")

            print(f"\n🔐 Connecting to Umbrella Org {org_id} ({section})...")
            try:
                token = get_umbrella_token(key, secret)
                dest_id = get_destination_list_id(token, list_name)
                if dest_id:
                    push_destinations_to_umbrella(all_destinations, token, dest_id)
                else:
                    print(f"❌ Destination list '{list_name}' not found in {section}")
            except Exception as e:
                print(f"❌ Failed for {section}: {e}")

except (HTTPError, UnsuccessfulStatusError, ServiceNotFoundError,
        AmbiguousServicesError, NoURIProvidedError, requests.RequestException) as e:
    print(f"[!] An error occurred: {e}")
