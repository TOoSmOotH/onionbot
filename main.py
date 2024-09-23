# main.py

import json
import sys
import os

def main():
    # Load configurations from config.json
    config_file = 'config.json'
    if not os.path.exists(config_file):
        print(f"Configuration file '{config_file}' not found.")
        sys.exit(1)

    with open(config_file, 'r') as f:
        configurations = json.load(f)

    platform = configurations.get('platform')
    if not platform:
        print("No platform specified in config.json. Please add a 'platform' key with value 'discord', 'slack', or 'matrix'.")
        sys.exit(1)

    platform = platform.lower()
    if platform == 'discord':
        from discord_handler import run_discord_bot
        run_discord_bot()
    elif platform == 'slack':
        from slack_handler import run_slack_bot
        run_slack_bot()
    elif platform == 'matrix':
        from matrix_handler import run_matrix_bot
        run_matrix_bot()
    else:
        print(f"Unsupported platform specified in config.json: {platform}")
        sys.exit(1)

if __name__ == "__main__":
    main()

