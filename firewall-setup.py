#!/usr/bin/env python3

import requests
import configparser
import subprocess
import socket
import glob
import os

from pathlib import Path
from typing import Set


BASE_DIR: str = '/opt/firewall' if os.getlogin() == 'root' else os.getcwd()
IPSETS_RESTORE_DIR: str = f"{BASE_DIR}/ipsets-restore.d"
IPTABLES_RULES_V4 = f"${BASE_DIR}/iptables-v4.rules"


def is_public_ip(ip):
    octets = ip.split('.')
    if (
        octets[0] == '10' or octets[0] == '127' or
        (octets[0] == '172' and 16 <= int(octets[1]) <= 31) or
        (octets[0] == '192' and octets[1] == '168')
    ):
        return False
    else:
        return True


def get_host_public_ip() -> str:
    try:
        hostname = socket.getfqdn()
        ip_address = socket.gethostbyname(hostname)
        if is_public_ip(ip_address):
            return ip_address
    except socket.gaierror as e:
        print(f"Failed to retrieve public IP: {e}")
        return ""

    try:
        response = requests.get('https://ifconfig.co/json')
        ip = response.json()['ip']
        return ip
    except requests.RequestException as e:
        print(f"Failed to retrieve public IP: {e}")
        return ""


def get_interface_from_ip(ip_address: str) -> str:
    try:
        for interface in socket.if_nameindex():
            for addr_info in socket.getaddrinfo(interface[1], None):
                if addr_info[4][0] == ip_address:
                    return interface[1]  # Return the interface name associated with the IP
    except socket.error as e:
        print(f"Error: {e}")
    return ""


def get_ip_address(hostname: str) -> str:
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror as e:
        print(f"Error resolving hostname: {e}")
        return ""


def shell_execute(cmd: str, output_line_callback=None, show_output: bool = True, env_vars: dict = None):
    try:
        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)

        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   encoding='utf8', universal_newlines=True, env=env)

        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                output = output.strip()
                if output_line_callback:
                    output_line_callback(output)
                if show_output:
                    print(output)

        process.communicate()  # Ensure process is fully closed
        return process.returncode

    except subprocess.CalledProcessError as ex:
        print(f"Error executing command: {cmd}")
        print(f"Returned non-zero exit status: {ex.returncode}")
        print(f"Output:\n{ex.output}")

    except Exception as ex:
        print(f"An error occurred: {ex}")


def create_ipset(name: str, type: str, ips: Set[str]):
    filepath = f"{IPSETS_RESTORE_DIR}/{name}.{type}"
    with open(filepath, 'w') as file:
        file.write(f"ipset create {name}-tmp -exist hash:net family inet hashsize 16384 maxelem 131072\n")
        file.write(f"ipset create {name} -exist hash:net family inet hashsize 16384 maxelem 131072\n")
        for ip in ips:
            file.write(f"add {name} {ip}\n")
        file.write(f"swap {name} {name}-tmp\n")


def allow_ipset(ipset_name):
    # Allows all IPs in the ipset
    iptables_commands = [
        f"iptables -A INPUT -m set --match-set {ipset_name} src -j ACCEPT",
        f"iptables -A OUTPUT -m set --match-set {ipset_name} dst -j ACCEPT",
        f"iptables -A FORWARD -m set --match-set {ipset_name} src -j ACCEPT",
        f"iptables -A FORWARD -m set --match-set {ipset_name} dst -j ACCEPT"
    ]


def generate_default_configs(filename: str, config: configparser.ConfigParser):
    config.add_section('network')
    config.set('network', 'admin_hostname', 'my.home.hostname')

    host_ip_address = get_host_public_ip()
    config.set('network', 'public_ip', host_ip_address)
    host_network_interface = get_interface_from_ip(host_ip_address) or "eth0"
    config.set('network', 'public_interface', host_network_interface)
    config.set('network', 'whitelist_ips', host_ip_address)

    config.add_section('docker')
    config.set('docker', 'trusted_bridges', "br-router")
    config.set('docker', 'whitelist_ips', "172.17.0.1/12,172.200.0.1/12")

    config.add_section('firewall')
    config.set('firewall', 'allow_input_ports', "22,80,443")
    config.set('firewall', 'allow_output_ports', "0:65535")
    # config.set('firewall', 'allow_from_countries', "CA,BR,IN,US")
    config.set('firewall', 'allow_ports_from_docker_trust_bridges', "5432,80,443,8338")

    file_path = os.path.join(os.getcwd(), "trails.csv")
    file_url = Path(file_path).absolute().as_uri()
    config.set('firewall', 'trail_urls', file_url)
    config.set('firewall', 'num_days_blocked', '7')
    config.set('firewall', 'ipset_trails_name', 'maltrail')

    with open(filename, 'w') as configfile:
        config.write(configfile)


def create_or_replace_symbolic_link(target_path, link_path):
    try:
        if os.path.islink(link_path):
            os.unlink(link_path)
        os.symlink(target_path, link_path)
    except OSError as e:
        print(f"Error creating or replacing symbolic link '{link_path}': {e}")


def get_configs():
    config_filename = os.path.join(BASE_DIR, "firewall.ini")
    config = configparser.ConfigParser()
    if not os.path.exists(config_filename):
        generate_default_configs(config_filename, config)
    else:
        config.read(config_filename)
    return config

def load_ipsets():
    # Define patterns for file filtering
    file_patterns = ['*.allow', '*.deny', '*.docker']

    # Initialize an empty list to store matching files
    ipset_files = []

    # Iterate through each pattern and find matching files
    for pattern in file_patterns:
        files = glob.glob(f"{IPSETS_RESTORE_DIR}/{pattern}")
        ipset_files.extend(files)

    for filename in ipset_files:
        if os.path.isfile(filename):
            cmd = f"ipset restore < {filename}"
            shell_execute(cmd, show_output=True)


def generate_whitelist_ipsets(config):
    whitelist = set()
    public_ip = config.get('network', 'public_ip')
    if public_ip:
        whitelist.add(public_ip)

    private_ip = config.get('network', 'private_ip', fallback='')
    if private_ip:
        whitelist.add(private_ip)

    whitelist_ips = config.get('network', 'whitelist_ips', fallback='')
    for ip in whitelist_ips.split(','):
        ip = ip.strip()
        if ip != "":
            whitelist.add(ip)
    create_ipset('whitelist', 'allow', whitelist)

    docker_whitelist = set()
    whitelist_ips: str = config.get('docker', 'whitelist_ips', fallback='')
    for ip in whitelist_ips.split(','):
        ip = ip.strip()
        if ip != "":
            docker_whitelist.add(ip)
    create_ipset('whitelist', 'docker', docker_whitelist)


def generate_firewall_rules():
    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(IPSETS_RESTORE_DIR, exist_ok=True)

    config = get_configs()

    # using the existent pre-installed ipset-blacklist
    target = '/etc/ipset-blacklist/ip-blacklist.restore'
    link = f'{IPSETS_RESTORE_DIR}/blacklist.deny'
    create_or_replace_symbolic_link(target, link)

    generate_whitelist_ipsets(config)
    load_ipsets()

    # lazy load the admin ip from the remote host into the whitelist
    # because it's normally one dynamic ip
    admin_hostname = config.get('network', 'admin_hostname') or ''
    admin_ip_address = get_ip_address(admin_hostname)
    if admin_ip_address:
        shell_execute(f"ipset add whitelist {admin_ip_address}", show_output=True)

    # Clear the existing firewall rules
    iptable_commands = """
        iptables -F
        iptables -t nat -F
        iptables -t mangle -F
        iptables -X
    """
    shell_execute(iptable_commands, show_output=True)

    # Set default policies
    iptables_commands = """
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT
    """
    shell_execute(iptable_commands, show_output=True)

    # Discard invalid packets
    iptables_commands = """
        iptables -A INPUT -m state --state INVALID -j DROP
        iptables -A OUTPUT -m state --state INVALID -j DROP
        iptables -A FORWARD -m state --state INVALID -j DROP
    """
    shell_execute(iptable_commands, show_output=True)

    # Allow ICMP packets with rate limit
    iptables_commands = """
        iptables -A INPUT -p icmp --icmp-type 3 -m limit --limit 20/minute --limit-burst 100 -j ACCEPT
        iptables -A INPUT -p icmp --icmp-type 8 -m limit --limit 20/minute --limit-burst 100 -j ACCEPT
        iptables -A INPUT -p icmp --icmp-type 11 -m limit --limit 20/minute --limit-burst 100 -j ACCEPT   
        iptables -A INPUT -p icmp -j LOG --log-prefix "DROP ICMP: "
        iptables -A INPUT -p icmp -j DROP
    """
    shell_execute(iptable_commands, show_output=True)

    # Prevent external packets from using loopback addr
    nic = config.get('network', 'public_interface') or ''
    iptables_commands = f"""
        iptables -A INPUT -i {nic} -s $LOCALHOST -j DROP
        iptables -A INPUT -i {nic} -d $LOCALHOST -j DROP
        iptables -A FORWARD -i {nic} -s $LOCALHOST -j DROP
        iptables -A FORWARD -i {nic} -d $LOCALHOST -j DROP
    """
    shell_execute(iptable_commands, show_output=True)

    # Allow loopback interface (localhost)
    iptables_commands = """
        iptables -A INPUT  -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT
    """
    shell_execute(iptable_commands, show_output=True)

    # Keep state of the current connections
    shell_execute("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT", show_output=True)

    # Allow accepting connections from containers using these network bridges
    docker_trusted_bridges = config.get('docker', 'trusted_bridges') or ''
    docker_ports = config.get('firewall', 'allow_ports_from_docker_trust_bridges') or '22,80,443'
    for docker_bridge in docker_trusted_bridges.split(','):
        docker_bridge = docker_bridge.strip()
        shell_execute(f"iptables -A INPUT -i {docker_bridge} -p tcp -m multiport --dports {docker_ports} -j ACCEPT",
                      show_output=True)

    # Only accepting requests from the countries allowed list
    allow_from_countries = config.get('firewall', 'allow_from_countries', fallback='')
    if allow_from_countries:
        iptables_commands = f"""
            iptables -A INPUT -i {nic} -m geoip ! --src-cc {allow_from_countries} -j LOG --log-prefix "DROP INPUT not {allow_from_countries}" --log-level 6
            iptables -A INPUT -i {nic} -m geoip ! --src-cc {allow_from_countries} -j DROP
        """
        shell_execute(iptables_commands, show_output=True)

    # Allowed incoming traffic from the ports
    allow_input_ports = config.get('firewall', 'allow_input_ports') or '22,80,443'
    if allow_input_ports:
        for port in allow_input_ports.split(','):
            port = port.strip()
            shell_execute(f"iptables -A INPUT -i {nic} -p tcp --dport {port} -j ACCEPT", show_output=True)

    allow_output_ports = config.get('firewall', 'allow_output_ports') or ''
    if allow_output_ports:
        for port in allow_output_ports.split(','):
            port = port.strip()
            shell_execute(f"iptables -A OUTPUT -i {nic} -p tcp --dport {port} -j ACCEPT")

    # Allowed without restrictions
    shell_execute("""
        iptables -A OUTPUT  -m state --state NEW  -j ACCEPT
        iptables -A OUTPUT -p icmp -j ACCEPT   
    """, show_output=True)


def main():
    generate_firewall_rules()
    shell_execute(f"iptables-save > ${IPTABLES_RULES_V4}", show_output=True)


if __name__ == "__main__":
    main()

