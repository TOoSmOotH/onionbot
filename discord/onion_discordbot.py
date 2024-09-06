import discord
import requests
import json
import os
import ipaddress  # For IP and CIDR validation
import socket  # For reverse DNS lookup
from cryptography.fernet import Fernet
import urllib3
import time
import asyncio

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# File to store the Discord token
TOKEN_FILE = 'token.txt'

# Files to store encrypted OPNsense configuration and admin data
CONFIG_FILE = 'opnsense_config.enc'
ADMIN_FILE = 'admin.enc'
USERS_FILE = 'users.enc'
KEY_FILE = 'encryption.key'

# Temporary block settings
configurations = {}
configurations['block_timeout_seconds'] = configurations.get('block_timeout_seconds', 3600)  # Default 1 hour

# Function to read the Discord bot token from the token file
def load_discord_token():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as file:
            return file.read().strip()
    else:
        raise FileNotFoundError(f"{TOKEN_FILE} not found. Please create the file and place your Discord token in it.")

# Function to generate or load an encryption key
def load_encryption_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as file:
            return file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as file:
            file.write(key)
        return key

# Function to encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(json.dumps(data).encode())
    return encrypted_data

# Function to decrypt data
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return json.loads(decrypted_data)

# Load the encryption key
encryption_key = load_encryption_key()

# Function to load the OPNsense configurations from an encrypted file
def load_configurations():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'rb') as file:
            encrypted_data = file.read()
            return decrypt_data(encrypted_data, encryption_key)
    return {}

# Function to save the OPNsense configurations to an encrypted file
def save_configurations(configurations):
    encrypted_data = encrypt_data(configurations, encryption_key)
    with open(CONFIG_FILE, 'wb') as file:
        file.write(encrypted_data)

# Function to load the admin user ID from an encrypted file
def load_admin_user_id():
    if os.path.exists(ADMIN_FILE):
        with open(ADMIN_FILE, 'rb') as file:
            encrypted_data = file.read()
            return decrypt_data(encrypted_data, encryption_key)
    return None

# Function to save the admin user ID to an encrypted file
def save_admin_user_id(admin_user_id):
    encrypted_data = encrypt_data(admin_user_id, encryption_key)
    with open(ADMIN_FILE, 'wb') as file:
        file.write(encrypted_data)

# Function to load the authorized users
def load_authorized_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'rb') as file:
            encrypted_data = file.read()
            return decrypt_data(encrypted_data, encryption_key)
    return []

# Function to save the authorized users
def save_authorized_users(authorized_users):
    encrypted_data = encrypt_data(authorized_users, encryption_key)
    with open(USERS_FILE, 'wb') as file:
        file.write(encrypted_data)

# Load the admin user ID, authorized users, and OPNsense configurations when the bot starts
admin_user_id = load_admin_user_id()
authorized_users = load_authorized_users()
configurations = load_configurations()

# Initialize settings for auto-apply, allowlist, and block tracking
configurations['auto_apply_firewall'] = configurations.get('auto_apply_firewall', False)
configurations['allowlist_ips'] = configurations.get('allowlist_ips', [])
configurations['blocked_ips'] = configurations.get('blocked_ips', {})  # {'ip': {'block_count': 0, 'unblock_time': 0}}
configurations['permanently_banned_ips'] = configurations.get('permanently_banned_ips', [])

# Load the Discord bot token
DISCORD_TOKEN = load_discord_token()

# Create an instance of a Discord client
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

# Function to add an IP to the allowlist
def add_to_allowlist(ip_address):
    if ip_address in configurations['allowlist_ips']:
        return f"{ip_address} is already in the allowlist."
    configurations['allowlist_ips'].append(ip_address)
    save_configurations(configurations)
    return f"{ip_address} has been added to the allowlist."

# Function to remove an IP from the allowlist
def remove_from_allowlist(ip_address):
    if ip_address not in configurations['allowlist_ips']:
        return f"{ip_address} is not in the allowlist."
    configurations['allowlist_ips'].remove(ip_address)
    save_configurations(configurations)
    return f"{ip_address} has been removed from the allowlist."

# Function to add IP to OPNsense alias
def add_ip_to_alias(ip_address):
    config = configurations
    alias_name = config['alias_name']
    url = f"https://{config['opnsense_ip']}/api/firewall/alias_util/add/{alias_name}"

    # Send the IP address as part of the request data
    data = {
        "address": ip_address
    }

    # Make the request and log the response
    response = requests.post(url, auth=(config['api_key'], config['api_secret']), data=data, verify=False)
    print(f"OPNsense Response (add IP): {response.status_code}, {response.text}")  # Log response

    if response.status_code == 200:
        return f"Successfully added {ip_address} to {alias_name}."
    else:
        return f"Failed to add {ip_address} to {alias_name}. Status code: {response.status_code}"

# Function to remove IP from OPNsense alias (for unblocking)
def remove_ip_from_alias(ip_address):
    config = configurations
    alias_name = config['alias_name']
    url = f"https://{config['opnsense_ip']}/api/firewall/alias_util/delete/{alias_name}"

    # Send the IP address as part of the request data
    data = {
        "address": ip_address
    }

    # Make the request and log the response
    response = requests.post(url, auth=(config['api_key'], config['api_secret']), data=data, verify=False)
    print(f"OPNsense Response (remove IP): {response.status_code}, {response.text}")  # Log response

    if response.status_code == 200:
        return f"Successfully removed {ip_address} from {alias_name}."
    else:
        return f"Failed to remove {ip_address} from {alias_name}. Status code: {response.status_code}"

# Function to list IPs in the OPNsense alias
def list_ips_in_alias():
    config = configurations
    alias_name = config['alias_name']
    url = f"https://{config['opnsense_ip']}/api/firewall/alias_util/list/{alias_name}"

    # Make the request and log the response
    response = requests.get(url, auth=(config['api_key'], config['api_secret']), verify=False)
    print(f"OPNsense Response (list IPs): {response.status_code}, {response.text}")  # Log response

    if response.status_code == 200:
        result = response.json()
        if 'rows' in result:
            ip_list = "\n".join([entry['ip'] for entry in result['rows']])
            return f"Current IPs in alias {config['alias_name']}:\n{ip_list}"
        else:
            return f"No IPs found in alias {config['alias_name']}."
    elif response.status_code == 404:
        return f"Alias {config['alias_name']} not found. Please check the alias name and try again."
    else:
        return f"Failed to retrieve IPs from alias {config['alias_name']}. Status code: {response.status_code}"
    
# Function to apply firewall changes using the filter API
def apply_firewall_changes():
    config = configurations
    url = f"https://{config['opnsense_ip']}/api/firewall/filter/apply"

    # Make the request and log the response
    response = requests.post(url, auth=(config['api_key'], config['api_secret']), verify=False)
    print(f"OPNsense Response (apply rules): {response.status_code}, {response.text}")  # Log response

    if response.status_code == 200:
        return "Firewall rules applied successfully."
    else:
        return f"Failed to apply firewall rules. Status code: {response.status_code}"

# Function to toggle the auto-apply firewall setting
def toggle_auto_apply_firewall():
    # Toggle the value of auto_apply_firewall
    configurations['auto_apply_firewall'] = not configurations.get('auto_apply_firewall', False)
    
    # Save the updated configuration
    save_configurations(configurations)

    # Return a message indicating the new state
    if configurations['auto_apply_firewall']:
        return "Auto-apply of firewall rules is now enabled."
    else:
        return "Auto-apply of firewall rules is now disabled."
    
# Function to validate if input is a valid IP or CIDR
def is_valid_ip_or_cidr(ip_or_cidr):
    try:
        ipaddress.ip_network(ip_or_cidr, strict=False)  # This validates both IPs and CIDR blocks
        return True
    except ValueError:
        return False

# Function to check if an IP address is an RFC1918 address (private network)
def is_rfc1918_address(ip):
    try:
        ip_obj = ipaddress.ip_network(ip, strict=False)
        return ip_obj.is_private
    except ValueError:
        return False  # Invalid IP or CIDR

# Function to check if an IP is in the allowlist
def is_in_allowlist(ip_address):
    return ip_address in configurations['allowlist_ips']

# Function to perform reverse DNS lookup
def reverse_dns_lookup(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "No reverse DNS found"

# Function to temporarily block an IP and schedule unblock
def block_ip_temporarily(ip_address, message_channel):
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

    # Perform reverse DNS lookup for the IP
    hostname = reverse_dns_lookup(ip_address)

    save_configurations(configurations)
    asyncio.create_task(schedule_unblock(ip_address, message_channel))
    return f"IP {ip_address} ({hostname}) has been temporarily blocked. This is block {block_count}."

# Function to unblock an IP after the timeout
async def schedule_unblock(ip_address, message_channel):
    unblock_time = configurations['blocked_ips'][ip_address]['unblock_time']
    await asyncio.sleep(max(0, unblock_time - time.time()))  # Sleep until the unblock time

    # Remove the IP from the blocked list and unblock it
    if ip_address in configurations['blocked_ips']:
        result = remove_ip_from_alias(ip_address)
        del configurations['blocked_ips'][ip_address]
        save_configurations(configurations)
        await message_channel.send(result)

# Function to list all banned IPs and their block counts
def list_banned_ips():
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

# Function to manually unban an IP
def unban_ip(ip_address):
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

# Discord event for when the bot is ready
@client.event
async def on_ready():
    print(f'We have logged in as {client.user}')

# Discord event for receiving messages
@client.event
async def on_message(message):
    global admin_user_id
    global configurations
    global authorized_users

    # Commented out logging every message for debugging
    # print(f"Message from {message.author.name}: {message.content}")

    # Ignore messages from the bot itself
    if message.author == client.user:
        return

    # Normalize message for ":lock: !block ip_address :lock:" format
    if message.content.startswith(':lock:') and message.content.endswith(':lock:'):
        message.content = message.content[6:-6].strip()

    # Ignore messages that don't start with '!'
    if not message.content.startswith('!'):
        return

    # Log the command to the console
    print(f"Command received: {message.content}")

    # Check if the message is in a guild (server)
    if message.guild is None:
        await message.channel.send("This bot only works in a server, not in DMs.")
        return

    # If no admin is set, assign the first user to message the bot as the admin
    if admin_user_id is None:
        admin_user_id = message.author.id
        save_admin_user_id(admin_user_id)  # Save the updated admin user ID
        await message.channel.send(f"{message.author.name} is now the admin of this bot!")

    # Shared commands (available to both admin and authorized users)
    if message.author.id == admin_user_id or message.author.id in authorized_users:
        # Help command
        if message.content.startswith('!help'):
            help_message = """
            ```Commands:
            !block <IP_ADDRESS>            : Block an IP address or CIDR block using the configured alias.
            !unban <IP_ADDRESS>            : Unban an IP address from the temporary or permanent ban list.
            !list_ips                      : List all IPs currently in the configured alias.
            !list_banned_ips               : List all banned IPs and their block counts.
            !apply_rules                   : Apply firewall rules.
            !allowlist add <IP_ADDRESS>    : Add an IP address to the allowlist (prevent it from being blocked).
            !allowlist remove <IP_ADDRESS> : Remove an IP address from the allowlist.
            !allowlist list                : Display all IP addresses in the allowlist.
            !help                          : Show this help message.

            Admin-only commands:
            !set_opnsense_ip <ip>          : Set the IP address of the OPNsense server.
            !set_opnsense_api_key <api_key> <api_secret> : Set the OPNsense API key and secret.
            !set_alias <alias_name>        : Set the alias that the bot will use for the !block command.
            !list_users                    : List all authorized users and the admin.
            !add_user <user_id>            : Add a user to the list of authorized users.
            !toggle_auto_apply             : Toggle automatic firewall rule application after a !block.
            !set_block_timeout <seconds>   : Set the timeout (in seconds) for temporary IP blocks.
            ```
            """
            await message.channel.send(help_message)

        # List banned IPs
        elif message.content.startswith('!list_banned_ips'):
            try:
                banned_ips_report = list_banned_ips()
                await message.channel.send(banned_ips_report)
            except Exception as e:
                await message.channel.send(f"An error occurred while listing banned IPs: {str(e)}")

        # List IPs currently in the alias
        elif message.content.startswith('!list_ips'):
            try:
                if 'opnsense_ip' not in configurations or 'api_key' not in configurations:
                    await message.channel.send("OPNsense configuration not fully set. Use !set_opnsense_ip and !set_opnsense_api_key to configure.")
                    return
                
                await message.channel.send("Fetching IP list, please wait...")
                ip_list = list_ips_in_alias()
                await message.channel.send(ip_list)
            
            except Exception as e:
                await message.channel.send(f"An error occurred while listing IPs: {str(e)}")

        # Block an IP
        elif message.content.startswith('!block'):
            try:
                ip_address = message.content.split(' ')[1]

                # Reject if the IP is a private (RFC1918) address
                if is_rfc1918_address(ip_address):
                    await message.channel.send(f"Cannot block RFC1918 private address {ip_address}.")
                    return

                # Check if the IP is in the allowlist
                if is_in_allowlist(ip_address):
                    await message.channel.send(f"Cannot block {ip_address} as it is in the allowlist.")
                    return

                if not is_valid_ip_or_cidr(ip_address):
                    await message.channel.send("Invalid IP address or CIDR block. Please provide a valid IP or CIDR.")
                    return

                result = block_ip_temporarily(ip_address, message.channel)
                await message.channel.send(result)

                # Check if auto-apply firewall rules is enabled
                if configurations['auto_apply_firewall']:
                    await message.channel.send("Auto-applying firewall rules, please wait...")
                    apply_result = apply_firewall_changes()
                    await message.channel.send(apply_result)

            except IndexError:
                await message.channel.send("Please provide an IP address to block. Usage: !block <IP_ADDRESS>")
            except Exception as e:
                await message.channel.send(f"An error occurred: {str(e)}")

        # Unban an IP
        elif message.content.startswith('!unban'):
            try:
                ip_address = message.content.split(' ')[1]
                
                # Validate if it's a correct IP or CIDR block
                if not is_valid_ip_or_cidr(ip_address):
                    await message.channel.send("Invalid IP address or CIDR block. Please provide a valid IP or CIDR.")
                    return

                result = unban_ip(ip_address)
                await message.channel.send(result)

            except IndexError:
                await message.channel.send("Please provide an IP address to unban. Usage: !unban <IP_ADDRESS>")
            except Exception as e:
                await message.channel.send(f"An error occurred while unbanning the IP: {str(e)}")

        # Handle allowlist commands
        elif message.content.startswith('!allowlist'):
            try:
                parts = message.content.split(' ')
                command = parts[1]

                if command == "add":
                    ip_address = parts[2]
                    result = add_to_allowlist(ip_address)
                    await message.channel.send(result)

                elif command == "remove":
                    ip_address = parts[2]
                    result = remove_from_allowlist(ip_address)
                    await message.channel.send(result)

                elif command == "list":
                    if configurations['allowlist_ips']:
                        allowlist = "\n".join(configurations['allowlist_ips'])
                        await message.channel.send(f"Allowlist:\n{allowlist}")
                    else:
                        await message.channel.send("The allowlist is currently empty.")
                
                else:
                    await message.channel.send("Invalid allowlist command. Use 'add', 'remove', or 'list'.")
            except IndexError:
                await message.channel.send("Usage: !allowlist <add/remove/list> <IP_ADDRESS>")

        # Apply firewall rules manually
        elif message.content.startswith('!apply_rules'):
            if 'opnsense_ip' not in configurations or 'api_key' not in configurations:
                await message.channel.send("OPNsense configuration not fully set. Use !set_opnsense_ip and !set_opnsense_api_key to configure.")
                return
            try:
                await message.channel.send("Applying firewall rules, please wait...")                
                result = apply_firewall_changes()
                await message.channel.send(result)
            except Exception as e:
                await message.channel.send(f"An error occurred while applying firewall rules: {str(e)}")

    # Admin-only commands
    if message.author.id == admin_user_id:
        # Set OPNsense IP address
        if message.content.startswith('!set_opnsense_ip'):
            try:
                opnsense_ip = message.content.split(' ')[1]
                configurations['opnsense_ip'] = opnsense_ip
                save_configurations(configurations)
                await message.channel.send(f"OPNsenseIP set to {opnsense_ip}.")
            except IndexError:
                await message.channel.send("Usage: !set_opnsense_ip <ip>")
            except Exception as e:
                await message.channel.send(f"An error occurred while setting the IP address: {str(e)}")

        # Set OPNsense API key and secret
        elif message.content.startswith('!set_opnsense_api_key'):
            try:
                parts = message.content.split(' ')
                if len(parts) != 3:
                    await message.channel.send("Usage: !set_opnsense_api_key <api_key> <api_secret>")
                    return

                api_key, api_secret = parts[1], parts[2]
                configurations['api_key'] = api_key
                configurations['api_secret'] = api_secret
                save_configurations(configurations)
                await message.channel.send("OPNsense API key and secret have been set.")
            except Exception as e:
                await message.channel.send(f"An error occurred while setting the API key and secret: {str(e)}")

        # Set alias name
        elif message.content.startswith('!set_alias'):
            try:
                alias_name = message.content.split(' ')[1]
                configurations['alias_name'] = alias_name
                save_configurations(configurations)
                await message.channel.send(f"Alias name set to {alias_name}.")
            except IndexError:
                await message.channel.send("Usage: !set_alias <alias_name>")
            except Exception as e:
                await message.channel.send(f"An error occurred while setting the alias: {str(e)}")

        # Set block timeout
        elif message.content.startswith('!set_block_timeout'):
            try:
                timeout_seconds = int(message.content.split(' ')[1])
                configurations['block_timeout_seconds'] = timeout_seconds
                save_configurations(configurations)
                await message.channel.send(f"Block timeout set to {timeout_seconds} seconds.")
            except IndexError:
                await message.channel.send("Usage: !set_block_timeout <seconds>")
            except ValueError:
                await message.channel.send("Invalid number of seconds. Please provide a valid integer.")
            except Exception as e:
                await message.channel.send(f"An error occurred while setting the block timeout: {str(e)}")

        # Add an authorized user
        elif message.content.startswith('!add_user'):
            try:
                new_user_id = int(message.content.split(' ')[1])
                if new_user_id not in authorized_users:
                    authorized_users.append(new_user_id)
                    save_authorized_users(authorized_users)
                    await message.channel.send(f"User {new_user_id} has been added to the authorized users list.")
                else:
                    await message.channel.send(f"User {new_user_id} is already an authorized user.")
            except IndexError:
                await message.channel.send("Please provide a user ID to add. Usage: !add_user <user_id>")
            except Exception as e:
                await message.channel.send(f"An error occurred while adding the user: {str(e)}")

        # Toggle the auto-apply firewall rules setting
        elif message.content.startswith('!toggle_auto_apply'):
            result = toggle_auto_apply_firewall()
            await message.channel.send(result)

        # List authorized users
        elif message.content.startswith('!list_users'):
            user_list = [f"Admin: {admin_user_id}"] + [f"User: {user}" for user in authorized_users]
            await message.channel.send("\n".join(user_list))

# Run the Discord bot
client.run(DISCORD_TOKEN)