
# Discord Bot

This repository contains a Discord bot built using Python. The bot uses the `discord.py` library to interact with the Discord API and supports operations such as blocking IP addresses, listing IPs, and applying firewall rules via OPNsense.

## Features

- Block IP addresses or CIDR blocks using a configured alias.
- List all IPs currently in the configured OPNsense alias.
- Apply OPNsense firewall rules.
- Authorized users and admin roles for secure command execution.

## Requirements

Before running the bot, make sure you have the following installed on your machine:

- Python 3.10 or higher: [Install Python](https://www.python.org/downloads/)

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/TOoSmOotH/onionbot.git
cd onionbot/discord
```

### 2. Set Up Environment Variables

Create a `.env` file in the root directory to store your Discord token.

```bash
DISCORD_TOKEN=your_discord_token_here
```

### 3. Install the Required Dependencies

You can install the required dependencies using `pip`:

```bash
pip install -r requirements.txt
```

### 4. Run the Bot

Once the dependencies are installed, you can run the bot with:

```bash
python onion_discordbot.py
```


## Configuration

### Required Environment Variables

Make sure to set the following variables either in the `.env` file or by passing them as environment variables:

- `DISCORD_TOKEN`: Your Discord bot token.


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

## Stopping the Bot

To stop the bot, press `CTRL+C` in the terminal where the bot is running.

## Troubleshooting

If you encounter issues while running the bot, you can check the logs for error messages and stack traces.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.