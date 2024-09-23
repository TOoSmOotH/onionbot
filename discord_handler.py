# discord_handler.py

import discord
import asyncio
from core_logic import (
    block_ip_temporarily,
    unban_ip,
    list_banned_ips,
    is_valid_ip_or_cidr,
    is_rfc1918_address,
    is_in_allowlist,
    add_to_allowlist,
    remove_from_allowlist,
    apply_firewall_changes,
    toggle_auto_apply_firewall,
    schedule_unblock,
    load_configurations,
    save_configurations
)

# Load configurations
configurations = load_configurations()

# Discord bot token
DISCORD_TOKEN = configurations['discord']['token']

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

# Admin user ID and authorized users
admin_user_id = configurations.get('admin_user_id')
authorized_users = configurations.get('authorized_users', [])

# Function to send messages (needed for schedule_unblock)
async def send_message(channel, message):
    await channel.send(message)

@client.event
async def on_ready():
    print(f'We have logged in as {client.user}')

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

    # If no admin is set, assign the first user to message the bot as the admin
    if admin_user_id is None:
        admin_user_id = message.author.id
        configurations['admin_user_id'] = admin_user_id
        save_configurations(configurations)
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
                banned_ips_report = list_banned_ips(configurations)
                await message.channel.send(banned_ips_report)
            except Exception as e:
                await message.channel.send(f"An error occurred while listing banned IPs: {str(e)}")

        # Block an IP
        elif message.content.startswith('!block'):
            try:
                ip_address = message.content.split(' ')[1]

                # Reject if the IP is a private (RFC1918) address
                if is_rfc1918_address(ip_address):
                    await message.channel.send(f"Cannot block RFC1918 private address {ip_address}.")
                    return

                # Check if the IP is in the allowlist
                if is_in_allowlist(ip_address, configurations):
                    await message.channel.send(f"Cannot block {ip_address} as it is in the allowlist.")
                    return

                if not is_valid_ip_or_cidr(ip_address):
                    await message.channel.send("Invalid IP address or CIDR block. Please provide a valid IP or CIDR.")
                    return

                result = block_ip_temporarily(ip_address, configurations)
                await message.channel.send(result)

                # Schedule unblock
                asyncio.create_task(schedule_unblock(ip_address, configurations, message.channel, send_message))

                # Check if auto-apply firewall rules is enabled
                if configurations.get('auto_apply_firewall', False):
                    await message.channel.send("Auto-applying firewall rules, please wait...")
                    apply_result = apply_firewall_changes(configurations)
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

                result = unban_ip(ip_address, configurations)
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
                    result = add_to_allowlist(ip_address, configurations)
                    await message.channel.send(result)

                elif command == "remove":
                    ip_address = parts[2]
                    result = remove_from_allowlist(ip_address, configurations)
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
            try:
                await message.channel.send("Applying firewall rules, please wait...")
                result = apply_firewall_changes(configurations)
                await message.channel.send(result)
            except Exception as e:
                await message.channel.send(f"An error occurred while applying firewall rules: {str(e)}")

    # Admin-only commands
    if message.author.id == admin_user_id:
        # Set OPNsense IP address
        if message.content.startswith('!set_opnsense_ip'):
            try:
                opnsense_ip = message.content.split(' ')[1]
                configurations['opnsense']['ip'] = opnsense_ip
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
                configurations['opnsense']['api_key'] = api_key
                configurations['opnsense']['api_secret'] = api_secret
                save_configurations(configurations)
                await message.channel.send("OPNsense API key and secret have been set.")
            except Exception as e:
                await message.channel.send(f"An error occurred while setting the API key and secret: {str(e)}")

        # Set alias name
        elif message.content.startswith('!set_alias'):
            try:
                alias_name = message.content.split(' ')[1]
                configurations['opnsense']['alias_name'] = alias_name
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
                    configurations['authorized_users'] = authorized_users
                    save_configurations(configurations)
                    await message.channel.send(f"User {new_user_id} has been added to the authorized users list.")
                else:
                    await message.channel.send(f"User {new_user_id} is already an authorized user.")
            except IndexError:
                await message.channel.send("Please provide a user ID to add. Usage: !add_user <user_id>")
            except Exception as e:
                await message.channel.send(f"An error occurred while adding the user: {str(e)}")

        # Toggle the auto-apply firewall rules setting
        elif message.content.startswith('!toggle_auto_apply'):
            result = toggle_auto_apply_firewall(configurations)
            await message.channel.send(result)

        # List authorized users
        elif message.content.startswith('!list_users'):
            user_list = [f"Admin: {admin_user_id}"] + [f"User: {user}" for user in authorized_users]
            await message.channel.send("\n".join(user_list))

def run_discord_bot():
    client.run(DISCORD_TOKEN)

