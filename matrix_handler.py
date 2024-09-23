# matrix_handler.py

import asyncio
from nio import AsyncClient, MatrixRoom, RoomMessageText
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

# Function to send messages (needed for schedule_unblock)
async def send_message(room, message):
    await room.client.room_send(
        room_id=room.room_id,
        message_type="m.room.message",
        content={
            "msgtype": "m.text",
            "body": message,
        }
    )

async def main():
    client = AsyncClient(configurations['matrix']['homeserver'], configurations['matrix']['user_id'])
    await client.login(configurations['matrix']['password'])

    # Admin user ID and authorized users
    admin_user_id = configurations.get('admin_user_id')
    authorized_users = configurations.get('authorized_users', [])

    async def message_callback(room: MatrixRoom, event: RoomMessageText):
        if event.sender == client.user_id:
            return

        message_text = event.body
        sender_id = event.sender

        # If no admin is set, assign the first user to message the bot as the admin
        if admin_user_id is None:
            configurations['admin_user_id'] = sender_id
            save_configurations(configurations)
            await send_message(room, f"{sender_id} is now the admin of this bot!")

        # Shared commands
        if sender_id == configurations['admin_user_id'] or sender_id in authorized_users:
            if message_text.startswith('!block'):
                try:
                    ip_address = message_text.split(' ')[1]

                    # Reject if the IP is a private (RFC1918) address
                    if is_rfc1918_address(ip_address):
                        await send_message(room, f"Cannot block RFC1918 private address {ip_address}.")
                        return

                    # Check if the IP is in the allowlist
                    if is_in_allowlist(ip_address, configurations):
                        await send_message(room, f"Cannot block {ip_address} as it is in the allowlist.")
                        return

                    if not is_valid_ip_or_cidr(ip_address):
                        await send_message(room, "Invalid IP address or CIDR block. Please provide a valid IP or CIDR.")
                        return

                    result = block_ip_temporarily(ip_address, configurations)
                    await send_message(room, result)

                    # Schedule unblock
                    asyncio.create_task(schedule_unblock(ip_address, configurations, room, send_message))

                    # Check if auto-apply firewall rules is enabled
                    if configurations.get('auto_apply_firewall', False):
                        await send_message(room, "Auto-applying firewall rules, please wait...")
                        apply_result = apply_firewall_changes(configurations)
                        await send_message(room, apply_result)

                except IndexError:
                    await send_message(room, "Please provide an IP address to block. Usage: !block <IP_ADDRESS>")
                except Exception as e:
                    await send_message(room, f"An error occurred: {str(e)}")

            # Handle other commands similarly...

    client.add_event_callback(message_callback, RoomMessageText)
    await client.sync_forever(timeout=30000)

def run_matrix_bot():
    asyncio.get_event_loop().run_until_complete(main())

