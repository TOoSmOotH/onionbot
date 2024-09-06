## This is a collection of bots useable with Security Onion

## Current chats supported

- Discord
- Slack (coming soon)

## Firewalls Supported

- OPNSense

## Features

- Block IP addresses or CIDR blocks using a configured alias.
- List all IPs currently in the configured OPNsense alias.
- Apply OPNsense firewall rules.
- Authorized users and admin roles for secure command execution.

## Bot Commands

| Command               | Description                                                                 | Who Can Run It?        |
|-----------------------|-----------------------------------------------------------------------------|------------------------|
| `!help`               | Displays a help message with all available commands.                        | Admin & Authorized Users|
| `!block <IP_ADDRESS>` | Blocks an IP address or CIDR block using the configured OPNsense alias.      | Admin & Authorized Users|
| `!list_ips`           | Lists all IPs in the configured OPNsense alias.                             | Admin & Authorized Users|
| `!apply_rules`        | Applies the firewall rules on OPNsense.                                      | Admin & Authorized Users|
| `!set_opnsense_ip`    | Sets the IP address of the OPNsense instance.                               | Admin Only             |
| `!set_opnsense_api_key <api_key> <api_secret>` | Sets the OPNsense API key and secret.              | Admin Only             |
| `!set_alias <alias_name>`  | Sets the alias used for blocking IP addresses.                           | Admin Only             |
| `!list_users`         | Lists all authorized users and the admin.                                   | Admin Only             |
| `!audit`              | Compares the local blocked list with the OPNsense alias for discrepancies.   | Admin & Authorized Users|
| `!allowlist add <IP_ADDRESS>` | Adds an IP to the allowlist to prevent it from being blocked.        | Admin & Authorized Users|
| `!allowlist remove <IP_ADDRESS>` | Removes an IP from the allowlist.                                 | Admin & Authorized Users|
| `!allowlist list`     | Lists all IPs in the allowlist.                                              | Admin & Authorized Users|
| `!unban <IP_ADDRESS>` | Unbans an IP from the temporary or permanent ban list.                       | Admin & Authorized Users|
| `!toggle_auto_apply`  | Toggles automatic firewall rule application after blocking an IP.           | Admin Only             |
| `!set_block_timeout <seconds>` | Sets the timeout duration for temporarily blocked IPs.              | Admin Only             |
