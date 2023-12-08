import urllib.request
import urllib
from pathlib import Path
import ipaddress

import configparser

import re
import os
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)

CURR_DIR = os.getcwd()
BASE_DIR: str = '/opt/firewall' if os.getlogin() == 'root' else CURR_DIR

def whitelist_matching_cidr(cidr, whitelist):

    if '/' not in cidr:
        return False

    network = ipaddress.ip_network(cidr, strict=False)
    for ip in whitelist:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj in network:
                return True
        except ValueError:
            pass
    return False


def normalize_ip(ip, show_errors=False):
    octets = ip.split('.')
    if len(octets) != 4:
        if show_errors:
            logging.error(f"Invalid IP: {ip}")
        return ""

    for i in range(len(octets)):
        value = int(octets[i])
        if value < 0 or value > 255:
            if show_errors:
                logging.error(f"Invalid IP: {ip}")
            return ""
        octets[i] = str(value)

    ip = '.'.join(octets)
    if ip == "0.0.0.0" or ip == "127.0.0.1":
        return ""

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return ""
    except Exception as ex:
        ip = ""

    return ip

def is_cidr_valid(cidr):
    parts = cidr.split('/')
    if len(parts) != 2:
        return False

    potential_ip, mask = parts
    try:
        ip = normalize_ip(potential_ip)
        if not ip or ip == "":
            return False

        if not mask.isdigit():
            return False
        mask = int(mask)
        if mask < 10 or mask > 32:
            return False
    except Exception as ex:
        return False

    return True


def extract_hostname_from_url(url):
    # Remove the protocol (http:// or https://)
    if "://" in url:
        url = url.split("://")[1]

    # Split by "/" to isolate the hostname
    hostname = url.split("/")[0]

    # If there's a colon (:) present, split by ":" to remove the port number
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    return hostname


def extract_ip(line):
    ip_pattern = r'\b(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.' \
                 r'(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.' \
                 r'(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.' \
                 r'(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\b'

    line = line.strip()
    if not line or line == '' or line.startswith("#"):
        return ''

    if '://' in line:
        line = extract_hostname_from_url(line)

    match = re.search(ip_pattern, line)
    if match:

        parts = line.split(",")
        parts = parts[0].split("#")
        parts = parts[0].split(" ")
        parts = parts[0].split("\t")
        parts = parts[0].split(":")

        if "/" in parts[0]:
            if is_cidr_valid(parts[0]):
                return parts[0]
            else:
                parts = parts[0].split("/")
                search = re.search(ip_pattern, parts[0])
                if search:
                    return normalize_ip(search.group(), True)
                else:
                    return ""
        else:
            return normalize_ip(match.group())
    else:
        return ""


def get_added_ips(directory_path, num_days):

    added_ips = set()
    if not os.path.exists(directory_path):
        print(f"Directory not found: {directory_path}")
        return added_ips

    now = datetime.now()

    # Iterate through files in the directory
    for filename in os.listdir(directory_path):

        # Check if the file name matches the expected format
        if filename.startswith('maltrail-ipset-added-') and filename.endswith('.list'):

            # Extract the date from the filename
            file_date_str = filename.replace('maltrail-ipset-added-', '').replace('.list', '')
            print(f"Processing {file_date_str} ...")

            # Convert the file date to a datetime object
            file_date_obj = datetime.strptime(file_date_str, '%Y-%m-%d')

            # Calculate the difference in days
            days_difference = (now - file_date_obj).days

            # Check if the file is within the specified date range
            if 0 <= days_difference < num_days:
                file_path = os.path.join(directory_path, filename)
                with open(file_path, "r") as file:
                    for line in file:
                        normalized_ip = extract_ip(line.strip())
                        if normalized_ip != "":
                            added_ips.add(normalized_ip)
    return added_ips

def get_ipset_from_file(filename):
    ipset = set()
    with open(filename, "r") as file:
        for line in file:
            normalized_ip = extract_ip(line.strip())
            if normalized_ip != "":
                ipset.add(normalized_ip)
    return ipset


def get_blacklist_ipset(config):

    whitelist = set()
    whitelist_ips = config.get('network', 'whitelist_ips', fallback=None)
    if whitelist_ips:
        for ip in whitelist_ips.split(','):
            ip = ip.strip()
            if ip:
                whitelist.add(ip)

    whitelist_ips = config.get('docker', 'whitelist_ips', fallback=None)
    if whitelist_ips:
        for ip in whitelist_ips.split(','):
            ip = ip.strip()
            if ip:
                whitelist.add(ip)

    blacklist = set()
    num_days = config.get('firewall', 'num_days_blocked', fallback='7')
    blocked_ips_dir = f"{BASE_DIR}/blocked_ips"
    added_ips = get_added_ips(blocked_ips_dir, num_days)
    for ip in added_ips:
        if ip not in whitelist:
            blacklist.add(ip)

    file_path = os.path.join(os.getcwd(), "trails.csv")
    default_file_url = Path(file_path).absolute().as_uri()

    urls = config.get('firewall', 'trail_urls', fallback=default_file_url)
    for url in urls.split(','):
        try:
            url = url.strip()
            for data in urllib.request.urlopen(url):
                try:
                    line = str(data, 'UTF-8')
                    ip = extract_ip(line)
                    if ip and ip not in whitelist and not whitelist_matching_cidr(ip, whitelist):
                        blacklist.add(ip)
                except Exception as exline:
                    logging.error(f"Error processing the line {line}: {exline}")
        except Exception as ex:
            logging.error(f"Error processing URL {url}: {ex}")

    return blacklist


def generate_ipset_file_from_url(config):

    ipset_name = config.get('firewall', 'ipset_trails_name', fallback='maltrail')
    dest_dir = f"{BASE_DIR}/ipsets-restore.d"

    ipset = get_blacklist_ipset(config)
    sorted_ipset = sorted(ipset)
    filename = f"{dest_dir}/{ipset_name}.deny"
    with open(filename, 'w') as file:
        file.write(f"create {ipset_name}-tmp -exist hash:net family inet hashsize 262144 maxelem 524287\n")
        file.write(f"create {ipset_name} -exist hash:net family inet hashsize 262144 maxelem 524287\n")

        for ip in sorted_ipset:
            if ip:
                file.write(f"add {ipset_name}-tmp {ip}\n")
                file.flush()

        file.write(f"swap {ipset_name} {ipset_name}-tmp\n")
        file.write(f"destroy {ipset_name}-tmp\n")
        file.flush()


def main():
    config_filename = os.path.join(BASE_DIR, "firewall.ini")
    if os.path.exists(config_filename):
        config = configparser.ConfigParser()
        config.read(config_filename)
        generate_ipset_file_from_url(config)
    else:
        logging.error("Missing firewall.ini, execute firewall-setup.py to create it!")


if __name__ == "__main__":
    main()

