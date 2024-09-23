# Multi-Platform Chat Bot for OPNsense Firewall Management

Welcome to the **Multi-Platform Security Onion Bot**! This bot allows you to manage your OPNsense firewall by issuing commands through various chat platforms, including Discord, Slack, and Matrix. The bot is designed to be extensible, so you can add support for other platforms like Microsoft Teams, Google Chat, Rocket.Chat, or Mattermost based on your preference.

---

## Table of Contents

Features
Prerequisites
Installation
Configuration
Usage
Commands
Extending to Other Platforms
Security Considerations
Contributing
License
Acknowledgments
---

## Features

**Multi-Platform Support**: Connects to Discord, Slack, or Matrix based on user preference.
**OPNsense Firewall Management**: Interacts with OPNsense API to manage IP blocking.
**Command-Based Interaction**: Use chat commands to block/unblock IPs, manage allowlists, and apply firewall rules.
**Temporary and Permanent Blocking**: Temporarily block IPs with automatic unblocking or permanently ban IPs after multiple offenses.
**Allowlist Management**: Prevent specific IPs from being blocked by adding them to an allowlist.
**Auto-Apply Firewall Rules**: Option to automatically apply firewall changes after blocking an IP.
**Encryption**: Securely stores sensitive configurations using encryption.
---

## Prerequisites

**Python 3.6+**
**OPNsense Firewall**: Access to an OPNsense firewall with API access enabled.
**Chat Platform Tokens**: API tokens and credentials for your chosen chat platform(s).
---

## Installation

### 1. Clone the Repository

```bash git clone https://github.com/yourusername/yourrepository.git cd yourrepository ```

### 2. Install Dependencies

```bash pip install -r requirements.txt ```

Alternatively, install dependencies individually:

```bash pip install discord.py slack_bolt cryptography requests matrix-nio ```

For Matrix with E2E support:

```bash pip install matrix-nio
𝑒
2
𝑒
e2e ```

### 3. Set Up Configuration Files

Copy the example configuration file and modify it according to your setup:

```bash cp config.example.json config.json ```

**Note**: Ensure `config.json` and `encryption.key` are kept secure and not committed to version control.

---

## Configuration

### config.json

The `config.json` file holds all the necessary configurations for the bot, including platform selection, API tokens, and settings.

```json { "platform": "discord", "opnsense": { "ip": "your_opnsense_ip", "api_key": "your_api_key", "api_secret": "your_api_secret", "alias_name": "your_alias_name" }, "discord": { "token": "your_discord_token" }, "slack": { "app_token": "xapp-...", "bot_token": "xoxb-..." }, "matrix": { "homeserver": "https://your_matrix_homeserver", "user_id": "@youruser
", "password": "your_password" }, "block_timeout_seconds": 3600, "auto_apply_firewall": false, "allowlist_ips": [], "blocked_ips": {}, "permanently_banned_ips": [], "authorized_users": [] } ```

**Platform Selection**: Set the `"platform"` key to `"discord"`, `"slack"`, or `"matrix"` based on your preference.
**OPNsense Configuration**: Fill in your OPNsense firewall details.
**Chat Platform Configuration**: Provide the necessary API tokens and credentials for the chosen platform.
### Encryption Key

An `encryption.key` file will be generated automatically to encrypt sensitive data.
**Security Note**: Keep this file secure.
---

## Usage

### Run the Bot

```bash python main.py ```

The bot will read the platform selection from `config.json` and connect to the specified chat platform.

### Interact with the Bot

Use the defined commands in your chat platform to interact with the bot.
The first user to send a command becomes the admin by default.
---

## Commands

### Shared Commands (Admin and Authorized Users)

`!help`: Show the help message with available commands.
`!block <IP_ADDRESS>`: Block an IP address or CIDR block.
`!unban <IP_ADDRESS>`: Unban an IP address from the temporary or permanent ban list.
`!list_ips`: List all IPs currently in the configured OPNsense alias.
`!list_banned_ips`: List all banned IPs and their block counts.
`!apply_rules`: Apply firewall rules.
`!allowlist add <IP_ADDRESS>`: Add an IP address to the allowlist.
`!allowlist remove <IP_ADDRESS>`: Remove an IP address from the allowlist.
`!allowlist list`: Display all IP addresses in the allowlist.
### Admin-Only Commands

`!set_opnsense_ip <IP>`: Set the IP address of the OPNsense server.
`!set_opnsense_api_key <API_KEY> <API_SECRET>`: Set the OPNsense API key and secret.
`!set_alias <ALIAS_NAME>`: Set the alias name used for blocking IPs.
`!list_users`: List all authorized users and the admin.
`!add_user <USER_ID>`: Add a user to the list of authorized users.
`!toggle_auto_apply`: Toggle automatic firewall rule application after blocking an IP.
`!set_block_timeout <SECONDS>`: Set the timeout for temporary IP blocks.
---

## Extending to Other Platforms

To add support for additional chat platforms:

Create a Handler Script: Implement a handler similar to `discord_handler.py`, `slack_handler.py`, or `matrix_handler.py` for the new platform.
Update `config.json`: Add necessary configurations under a new key for the platform.
Modify `main.py`: Add the new platform to the platform selection logic.
Example for adding a platform called "teams":

```python # main.py

elif platform == 'teams': from teams_handler import run_teams_bot run_teams_bot() ```

---

## Security Considerations

**Credentials Handling**: Store API tokens and sensitive data securely. Do not commit them to version control.
**Encryption**: The bot uses encryption to store sensitive configurations securely.
**Permissions**: Ensure the bot has appropriate permissions on the chat platform and OPNsense firewall.
---

## Contributing

Contributions are welcome! Please follow these steps:

Fork the repository.
Create a new branch for your feature or bug fix.
Make your changes and commit them with clear messages.
Submit a pull request to the main branch.
---

## License

This project is licensed under the MIT License.

---

## Acknowledgments

**OPNsense**: For providing a powerful and open-source firewall platform.
**Discord.py**: For the Python library to interact with Discord.
**Slack Bolt**: For simplifying Slack bot development.
**Matrix-nio**: For providing the Matrix client library.
**Contributors**: Thank you to everyone who has contributed to this project.
---