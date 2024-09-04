import discord
import requests
import json
import os
import ipaddress  # For IP and CIDR validation
from cryptography.fernet import Fernet
import urllib3

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# File to store the Discord token
TOKEN_FILE = 'token.txt'

# Files to store encrypted OPNsense configuration and admin data
CONFIG_FILE = 'opnsense_config.enc'
ADMIN_FILE = 'admin.enc'
USERS_FILE = 'users.enc'
KEY_FILE = 'encryption.key'

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

# Load the Discord bot token
DISCORD_TOKEN = load_discord_token()

# Create an instance of a Discord client
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

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

# Function to validate if input is a valid IP or CIDR
def is_valid_ip_or_cidr(ip_or_cidr):
    try:
        ipaddress.ip_network(ip_or_cidr, strict=False)  # This validates both IPs and CIDR blocks
        return True
    except ValueError:
        return False

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

    # Ignore messages from the bot itself
    if message.author == client.user:
        return

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
            !list_ips                      : List all IPs currently in the configured alias.
            !apply_rules                   : Apply firewall rules.
            !help                          : Show this help message.
            Admin-only commands:
            !set_opnsense_ip <ip>         : Set the IP address of the OPNsense server.
            !set_opnsense_api_key <api_key> <api_secret> : Set the OPNsense API key and secret.
            !set_alias <alias_name>        : Set the alias that the bot will use for the !block command.
            !list_users                   : List all authorized users and the admin.
            ```
            """
            await message.channel.send(help_message)

        # Block an IP
        elif message.content.startswith('!block'):
            try:
                ip_address = message.content.split(' ')[1]
                if not is_valid_ip_or_cidr(ip_address):
                    await message.channel.send("Invalid IP address or CIDR block. Please provide a valid IP or CIDR.")
                    return

                result = add_ip_to_alias(ip_address)
                await message.channel.send(result)
            except IndexError:
                await message.channel.send("Please provide an IP address to block. Usage: !block <IP_ADDRESS>")
            except Exception as e:
                await message.channel.send(f"An error occurred: {str(e)}")

        # List IPs in the alias
        elif message.content.startswith('!list_ips'):
            if 'opnsense_ip' not in configurations or 'api_key' not in configurations or 'alias_name' not in configurations:
                await message.channel.send("OPNsense configuration not fully set. Use !set_opnsense_ip, !set_opnsense_api_key, and !set_alias to configure.")
                return
            try:
                ip_list = list_ips_in_alias()
                await message.channel.send(ip_list)
            except Exception as e:
                await message.channel.send(f"An error occurred while listing IPs: {str(e)}")

        # Apply firewall rules
        elif message.content.startswith('!apply_rules'):
            if 'opnsense_ip' not in configurations or 'api_key' not in configurations:
                await message.channel.send("OPNsense configuration not fully set. Use !set_opnsense_ip and !set_opnsense_api_key to configure.")
                return
            try:
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
                await message.channel.send(f"OPNsense IP set to {opnsense_ip}.")
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

        # List authorized users
        elif message.content.startswith('!list_users'):
            user_list = [f"Admin: {admin_user_id}"] + [f"User: {user}" for user in authorized_users]
            await message.channel.send("\n".join(user_list))

# Run the Discord bot
client.run(DISCORD_TOKEN)
