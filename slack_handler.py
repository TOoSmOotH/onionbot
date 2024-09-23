# slack_handler.py

import os
import asyncio
from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.socket_mode.aiohttp import AsyncSocketModeHandler

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

slack_app_token = configurations['slack']['app_token']
slack_bot_token = configurations['slack']['bot_token']

# Initialize the Slack app
app = AsyncApp(token=slack_bot_token)

# Admin user ID and authorized users
admin_user_id = configurations.get('admin_user_id')
authorized_users = configurations.get('authorized_users', [])

# Function to send messages (needed for schedule_unblock)
async def send_message(channel, message):
    await app.client.chat_postMessage(channel=channel, text=message)

# Command listener
@app.message(re.compile(r'^!(\w+)(.*)'))
async def handle_commands(message, say, context):
    global admin_user_id
    global configurations
    global authorized_users

    command = context['matches'][0]
    args = context['matches'][1].strip()
    user_id = message['user']
    channel_id = message['channel']

    # If no admin is set, assign the first user to message the bot as the admin
    if admin_user_id is None:
        configurations['admin_user_id'] = user_id
        save_configurations(configurations)
        await say(f"<@{user_id}> is now the admin of this bot!")

    # Shared commands (available to both admin and authorized users)
    if user_id == configurations['admin_user_id'] or user_id in authorized_users:
        if command == 'help':
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
            await say(help_message)

        elif command == 'block':
            try:
                ip_address = args.split(' ')[0]

                # Reject if the IP is a private (RFC1918) address
                if is_rfc1918_address(ip_address):
                    await say(f"Cannot block RFC1918 private address {ip_address}.")
                    return

                # Check if the IP is in the allowlist
                if is_in_allowlist(ip_address, configurations):
                    await say(f"Cannot block {ip_address} as it is in the allowlist.")
                    return

                if not is_valid_ip_or_cidr(ip_address):
                    await say("Invalid IP address or CIDR block. Please provide a valid IP or CIDR.")
                    return

                result = block_ip_temporarily(ip_address, configurations)
                await say(result)

                # Schedule unblock
                asyncio.create_task(schedule_unblock(ip_address, configurations, channel_id, send_message))

                # Check if auto-apply firewall rules is enabled
                if configurations.get('auto_apply_firewall', False):
                    await say("Auto-applying firewall rules, please wait...")
                    apply_result = apply_firewall_changes(configurations)
                    await say(apply_result)

            except IndexError:
                await say("Please provide an IP address to block. Usage: !block <IP_ADDRESS>")
            except Exception as e:
                await say(f"An error occurred: {str(e)}")

        # Handle other commands similarly...

    # Admin-only commands
    if user_id == configurations['admin_user_id']:
        if command == 'set_opnsense_ip':
            try:
                opnsense_ip = args.split(' ')[0]
                configurations['opnsense']['ip'] = opnsense_ip
                save_configurations(configurations)
                await say(f"OPNsense IP set to {opnsense_ip}.")
            except IndexError:
                await say("Usage: !set_opnsense_ip <ip>")
            except Exception as e:
                await say(f"An error occurred while setting the IP address: {str(e)}")

        # Handle other admin commands...

def run_slack_bot():
    asyncio.run(async_main())

async def async_main():
    handler = AsyncSocketModeHandler(app, slack_app_token)
    await handler.start_async()

