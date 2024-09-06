import unittest
from unittest.mock import patch, mock_open, MagicMock

class TestDiscordBot(unittest.TestCase):

    @patch('builtins.open', new_callable=mock_open, read_data='test_token')
    def test_load_discord_token(self, mock_file):
        token = load_discord_token()
        self.assertEqual(token, 'test_token')

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data=b'test_key')
    def test_load_encryption_key_existing(self, mock_exists, mock_file):
        key = load_encryption_key()
        self.assertEqual(key, b'test_key')

    @patch('os.path.exists', return_value=False)
    @patch('builtins.open', new_callable=mock_open)
    @patch('cryptography.fernet.Fernet.generate_key', return_value=b'new_test_key')
    def test_load_encryption_key_new(self, mock_generate_key, mock_file, mock_exists):
        key = load_encryption_key()
        self.assertEqual(key, b'new_test_key')

    def test_encrypt_decrypt_data(self):
        key = Fernet.generate_key()
        data = {'key': 'value'}
        encrypted_data = encrypt_data(data, key)
        decrypted_data = decrypt_data(encrypted_data, key)
        self.assertEqual(data, decrypted_data)

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data=b'encrypted_data')
    @patch('cryptography.fernet.Fernet.decrypt', return_value=b'{"key": "value"}')
    def test_load_configurations(self, mock_decrypt, mock_file, mock_exists):
        with patch('builtins.open', mock_open(read_data=b'encrypted_data')):
            configurations = load_configurations()
            self.assertEqual(configurations, {"key": "value"})

    @patch('builtins.open', new_callable=mock_open)
    @patch('cryptography.fernet.Fernet.encrypt', return_value=b'encrypted_data')
    def test_save_configurations(self, mock_encrypt, mock_file):
        configurations = {"key": "value"}
        save_configurations(configurations)
        mock_file().write.assert_called_once_with(b'encrypted_data')

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data=b'encrypted_data')
    @patch('cryptography.fernet.Fernet.decrypt', return_value=b'"admin_user_id"')
    def test_load_admin_user_id(self, mock_decrypt, mock_file, mock_exists):
        admin_user_id = load_admin_user_id()
        self.assertEqual(admin_user_id, "admin_user_id")

    @patch('builtins.open', new_callable=mock_open)
    @patch('cryptography.fernet.Fernet.encrypt', return_value=b'encrypted_data')
    def test_save_admin_user_id(self, mock_encrypt, mock_file):
        admin_user_id = "admin_user_id"
        save_admin_user_id(admin_user_id)
        mock_file().write.assert_called_once_with(b'encrypted_data')

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data=b'encrypted_data')
    @patch('cryptography.fernet.Fernet.decrypt', return_value=b'["user1", "user2"]')
    def test_load_authorized_users(self, mock_decrypt, mock_file, mock_exists):
        authorized_users = load_authorized_users()
        self.assertEqual(authorized_users, ["user1", "user2"])

    @patch('builtins.open', new_callable=mock_open)
    @patch('cryptography.fernet.Fernet.encrypt', return_value=b'encrypted_data')
    def test_save_authorized_users(self, mock_encrypt, mock_file):
        authorized_users = ["user1", "user2"]
        save_authorized_users(authorized_users)
        mock_file().write.assert_called_once_with(b'encrypted_data')

    def test_is_valid_ip_or_cidr(self):
        self.assertTrue(is_valid_ip_or_cidr("192.168.1.1"))
        self.assertTrue(is_valid_ip_or_cidr("192.168.1.0/24"))
        self.assertFalse(is_valid_ip_or_cidr("invalid_ip"))

    def test_is_rfc1918_address(self):
        self.assertTrue(is_rfc1918_address("192.168.1.1"))
        self.assertFalse(is_rfc1918_address("8.8.8.8"))

    def test_is_in_allowlist(self):
        configurations['allowlist_ips'] = ["192.168.1.1"]
        self.assertTrue(is_in_allowlist("192.168.1.1"))
        self.assertFalse(is_in_allowlist("8.8.8.8"))

    @patch('socket.gethostbyaddr', return_value=("hostname", [], []))
    def test_reverse_dns_lookup(self, mock_gethostbyaddr):
        hostname = reverse_dns_lookup("8.8.8.8")
        self.assertEqual(hostname, "hostname")

    @patch('requests.post')
    def test_add_ip_to_alias(self, mock_post):
        configurations.update({
            'alias_name': 'test_alias',
            'opnsense_ip': '127.0.0.1',
            'api_key': 'test_key',
            'api_secret': 'test_secret'
        })
        mock_post.return_value.status_code = 200
        result = add_ip_to_alias("8.8.8.8")
        self.assertIn("Successfully added", result)

    @patch('requests.post')
    def test_remove_ip_from_alias(self, mock_post):
        configurations.update({
            'alias_name': 'test_alias',
            'opnsense_ip': '127.0.0.1',
            'api_key': 'test_key',
            'api_secret': 'test_secret'
        })
        mock_post.return_value.status_code = 200
        result = remove_ip_from_alias("8.8.8.8")
        self.assertIn("Successfully removed", result)

    @patch('requests.get')
    def test_list_ips_in_alias(self, mock_get):
        configurations.update({
            'alias_name': 'test_alias',
            'opnsense_ip': '127.0.0.1',
            'api_key': 'test_key',
            'api_secret': 'test_secret'
        })
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {'rows': [{'ip': '8.8.8.8'}]}
        result = list_ips_in_alias()
        self.assertIn("Current IPs in alias", result)
        
if __name__ == '__main__':
    unittest