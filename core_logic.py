# core_logic.py

import time
import asyncio
import json
import os
import ipaddress
import socket
from cryptography.fernet import Fernet
import requests
import urllib3
import logging

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Encryption key file
KEY_FILE = 'encryption.key'

# Configuration files
CONFIG_FILE = 'opnsense_config.enc'
CONFIG_JSON = 'config.json'

# Load encryption key
def load_encryption_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as file:
            return file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as file:
            file.write(key)
        return key

# Encryption and decryption functions
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(json.dumps(data).encode())
    return encrypted_data

def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return json.loads(decrypted_data)

# Load configurations
def load_configurations():
    if os.path.exists(CONFIG_FILE):
        encryption_key = load_encryption_key()
        with open(CONFIG_FILE, 'rb') as file:
            encrypted_data = file.read()
            configurations = decrypt_data(encrypted_data, encryption_key)
            return configurations
    elif os.path.exists(CONFIG_JSON):
        with open(CONFIG_JSON, 'r') as file:
            configurations = json.load(file)
            save_configurations(configurations)  # Encrypt and save
            return configurations
    else:
        raise FileNotFoundError("Configuration file not found.")

# Save configurations
def save_configurations(configurations):
    encryption_key = load_encryption_key()
    encrypted_data = encrypt_data(configurations, encryption_key)
    with open(CONFIG_FILE, 'wb') as file:
        file.write(encrypted_data)

# Core functionalities

def add_to_allowlist(ip_address, configurations):
    if ip_address in configurations['allowlist_ips']:
        return f"{ip_address} is already in the allowlist."
    configurations['allowlist_ips'].append(ip_address)
    save_configurations(configurations)
    return f"{ip_address} has been added to the allowlist."

def remove_from_allowlist(ip_address, configurations):
    if ip_address not in configurations['allowlist_ips']:
        return f"{ip_address} is not in the allowlist."
    configurations['allowlist_ips'].remove(ip_address)
    save_configurations(configurations)
    return f"{ip_address} has been removed from the allowlist."

def add_ip_to_alias(ip_address, configurations):
    alias_name = configurations['opnsense']['alias_name']
    url = f"https://{configurations['opnsense']['ip']}/api/firewall/alias_util/add/{alias_name}"

    # Send the IP address as part of the request data
    data = {
        "address": ip_address
    }

    # Make the request and log the response
    response = requests.post(url, auth=(configurations['opnsense']['api_key'], configurations['opnsense']['api_secret']), data=data, verify=False)
    logger.info(f"OPNsense Response (add IP): {response.status_code}, {response.text}")  # Log response

    if response.status_code == 200:
        return f"Successfully added {ip_address} to {alias_name}."
    else:
        return f"Failed to add {ip_address} to {alias_name}. Status code: {response.status_code}"

def remove_ip_from_alias(ip_address, configurations):
    alias_name = configurations['opnsense']['alias_name']
    url = f"https://{configurations['opnsense']['ip']}/api/firewall/alias_util/delete/{alias_name}"

    # Send the IP address as part of the request data
    data = {
        "address": ip_address
    }

    # Make the request and log the response
    response = requests.post(url, auth=(configurations['opnsense']['api_key'], configurations['opnsense']['api_secret']), data=data, verify=False)
    logger.info(f"OPNsense Response (remove IP): {response.status_code}, {response.text}")  # Log response

    if response.status_code == 200:
        return f"Successfully removed {ip_address} from {alias_name}."
    else:
        return f"Failed to remove {ip_address} from {alias_name}. Status code: {response.status_code}"

def apply_firewall_changes(configurations):
    url = f"https://{configurations['opnsense']['ip']}/api/firewall/filter/apply"

    # Make the request and log the response
    response = requests.post(url, auth=(configurations['opnsense']['api_key'], configurations['opnsense']['api_secret']), verify=False)
    logger.info(f"OPNsense Response (apply rules): {response.status_code}, {response.text}")  # Log response

    if response.status_code == 200:
        return "Firewall rules applied successfully."
    else:
        return f"Failed to apply firewall rules. Status code: {response.status_code}"

def is_valid_ip_or_cidr(ip_or_cidr):
    try:
        ipaddress.ip_network(ip_or_cidr, strict=False)
        return True
    except ValueError:
        return False

def is_rfc1918_address(ip):
    try:
        ip_obj = ipaddress.ip_network(ip, strict=False)
        return ip_obj.is_private
    except ValueError:
        return False  # Invalid IP or CIDR

def is_in_allowlist(ip_address, configurations):
    return ip_address in configurations['allowlist_ips']

def reverse_dns_lookup(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "No reverse DNS found"

def block_ip_temporarily(ip_address, configurations):
    if ip_address in configurations['permanently_banned_ips']:
        return f"IP {ip_address} is permanently banned and cannot be unblocked."

    if ip_address not in configurations['blocked_ips']:
        configurations['blocked_ips'][ip_address] = {
            'block_count': 1,
            'unblock_time': time.time() + configurations['block_timeout_seconds']
        }
    else:
        configurations['blocked_ips'][ip_address]['block_count'] += 1
        configurations['blocked_ips'][ip_address]['unblock_time'] = time.time() + configurations['block_timeout_seconds']

    block_count = configurations['blocked_ips'][ip_address]['block_count']

    if block_count >= 3:
        configurations['permanently_banned_ips'].append(ip_address)
        del configurations['blocked_ips'][ip_address]
        save_configurations(configurations)
        return f"IP {ip_address} has been permanently banned after 3 blocks."

    # Perform reverse DNS lookup for the IP (optional)
    hostname = reverse_dns_lookup(ip_address)

    # Add the IP to the OPNsense firewall alias
    result = add_ip_to_alias(ip_address, configurations)  # Call the function to add IP to alias
    if "Failed" in result:
        return result  # Return failure message if adding to alias fails

    save_configurations(configurations)
    return f"IP {ip_address} ({hostname}) has been temporarily blocked. This is block {block_count}."

def unban_ip(ip_address, configurations):
    # Check if the IP is permanently banned
    if ip_address in configurations['permanently_banned_ips']:
        configurations['permanently_banned_ips'].remove(ip_address)
        save_configurations(configurations)
        return f"IP {ip_address} has been removed from the permanent ban list."

    # Check if the IP is temporarily blocked
    if ip_address in configurations['blocked_ips']:
        del configurations['blocked_ips'][ip_address]
        save_configurations(configurations)
        return f"IP {ip_address} has been removed from the temporary block list."

    return f"IP {ip_address} is not currently banned."

def list_banned_ips(configurations):
    blocked_ips = configurations.get('blocked_ips', {})
    permanently_banned_ips = configurations.get('permanently_banned_ips', [])

    if not blocked_ips and not permanently_banned_ips:
        return "There are no currently tracked or banned IPs."

    banned_ips_list = []

    # List temporarily blocked IPs
    for ip, info in blocked_ips.items():
        hostname = reverse_dns_lookup(ip)
        banned_ips_list.append(f"IP: {ip} ({hostname}), Block Count: {info['block_count']}, Unblock Time: {time.ctime(info['unblock_time'])}")

    # List permanently banned IPs
    for ip in permanently_banned_ips:
        hostname = reverse_dns_lookup(ip)
        banned_ips_list.append(f"IP: {ip} ({hostname}), Permanently Banned")

    return "\n".join(banned_ips_list)

async def schedule_unblock(ip_address, configurations, message_channel, send_message):
    unblock_time = configurations['blocked_ips'][ip_address]['unblock_time']
    await asyncio.sleep(max(0, unblock_time - time.time()))  # Sleep until the unblock time

    # Remove the IP from the blocked list and unblock it
    if ip_address in configurations['blocked_ips']:
        result = remove_ip_from_alias(ip_address, configurations)
        del configurations['blocked_ips'][ip_address]
        save_configurations(configurations)
        await send_message(message_channel, result)

def toggle_auto_apply_firewall(configurations):
    # Toggle the value of auto_apply_firewall
    configurations['auto_apply_firewall'] = not configurations.get('auto_apply_firewall', False)

    # Save the updated configuration
    save_configurations(configurations)

    # Return a message indicating the new state
    if configurations['auto_apply_firewall']:
        return "Auto-apply of firewall rules is now enabled."
    else:
        return "Auto-apply of firewall rules is now disabled."

# Add any other core functions needed

