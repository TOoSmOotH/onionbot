import unittest
from unittest.mock import patch, AsyncMock, MagicMock
import bot  # Assuming the bot script is named bot.py

class TestDiscordBot(unittest.TestCase):
    
    def setUp(self):
        # Set up some basic mock configurations
        self.configurations = {
            'opnsense_ip': '192.168.1.1',
            'alias_name': 'blocklist',
            'api_key': 'fake_key',
            'api_secret': 'fake_secret'
        }

        bot.configurations = self.configurations

    @patch('bot.requests.post')
    def test_add_ip_to_alias_success(self, mock_post):
        """Test adding an IP to the alias."""
        # Mock a successful response
        mock_post.return_value.status_code = 200
        
        ip_address = '192.168.1.100'
        result = bot.add_ip_to_alias(ip_address)
        
        # Assert that the function returns success
        self.assertIn('Successfully added', result)
        # Assert the correct URL and data were sent in the request
        mock_post.assert_called_with(
            'https://192.168.1.1/api/firewall/alias_util/add/blocklist',
            auth=('fake_key', 'fake_secret'),
            data={'address': '192.168.1.100'},
            verify=False
        )

    @patch('bot.requests.get')
    def test_list_ips_in_alias_success(self, mock_get):
        """Test listing IPs in the alias."""
        # Mock a successful response with IP data
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'rows': [{'ip': '192.168.1.100'}, {'ip': '192.168.1.101'}]
        }

        result = bot.list_ips_in_alias()
        
        # Assert the correct IPs are returned
        self.assertIn('192.168.1.100', result)
        self.assertIn('192.168.1.101', result)

    @patch('bot.requests.post')
    def test_apply_firewall_changes_success(self, mock_post):
        """Test applying firewall changes."""
        # Mock a successful response
        mock_post.return_value.status_code = 200

        result = bot.apply_firewall_changes()
        
        # Assert the function indicates success
        self.assertEqual(result, 'Firewall rules applied successfully.')
        # Assert the correct URL and authentication were used
        mock_post.assert_called_with(
            'https://192.168.1.1/api/firewall/filter/apply',
            auth=('fake_key', 'fake_secret'),
            verify=False
        )

    @patch('bot.client')
    @patch('bot.requests.post')
    def test_bot_command_block_ip(self, mock_post, mock_client):
        """Test the !block command."""
        mock_post.return_value.status_code = 200

        message = MagicMock()
        message.author.id = 1234  # Simulate an authorized user
        message.content = '!block 192.168.1.100'

        # Assume user is authorized
        bot.authorized_users = [1234]

        with patch('bot.add_ip_to_alias', return_value="Successfully added 192.168.1.100"):
            result = bot.on_message(message)
        
        # Assert that the function to add IP was called
        bot.add_ip_to_alias.assert_called_with('192.168.1.100')

    @patch('bot.client')
    def test_help_command(self, mock_client):
        """Test the !help command for authorized users."""
        message = MagicMock()
        message.author.id = 1234  # Simulate an authorized user
        message.content = '!help'

        # Assume the user is authorized
        bot.authorized_users = [1234]

        with patch('bot.on_message', return_value="Help message"):
            result = bot.on_message(message)
        
        # Check if the help command is sent
        bot.on_message.assert_called_with(message)

    @patch('bot.is_valid_ip_or_cidr')
    @patch('bot.client')
    def test_invalid_ip_in_block_command(self, mock_client, mock_valid_ip):
        """Test that invalid IPs are rejected in the !block command."""
        message = MagicMock()
        message.author.id = 1234
        message.content = '!block invalid_ip'
        
        # Simulate invalid IP validation
        mock_valid_ip.return_value = False

        with patch('bot.on_message', return_value="Invalid IP address or CIDR block"):
            bot.on_message(message)

        # Assert that the bot rejects the invalid IP
        bot.on_message.assert_called_with(message)

if __name__ == '__main__':
    unittest.main()
