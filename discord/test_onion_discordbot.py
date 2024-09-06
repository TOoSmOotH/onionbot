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
    def test_load_encryption_key_new(self, mock_exists, mock_file):
        with patch('cryptography.fernet.Fernet.generate_key', return_value=b'new_key'):
            key = load_encryption_key()
            self.assertEqual(key, b'new_key')

    def test_encrypt_decrypt_data(self):
        key = Fernet.generate_key()
        data = {'test': 'data'}
        encrypted_data = encrypt_data(data, key)
        decrypted_data = decrypt_data(encrypted_data, key)
        self.assertEqual(data, decrypted_data)

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data=b'encrypted_data')
    @patch('cryptography.fernet.Fernet.decrypt', return_value=b'{"test": "data"}')
    def test_load_configurations(self, mock_exists, mock_file, mock_decrypt):
        with patch('cryptography.fernet.Fernet', return_value=MagicMock(decrypt=mock_decrypt)):
            configurations = load_configurations()
            self.assertEqual(configurations, {"test": "data"})

    @patch('builtins.open', new_callable=mock_open)
    def test_save_configurations(self, mock_file):
        data = {'test': 'data'}
        key = Fernet.generate_key()
        with patch('cryptography.fernet.Fernet.encrypt', return_value=b'encrypted_data'):
            save_configurations(data)
            mock_file().write.assert_called_once_with(b'encrypted_data')

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data=b'encrypted_data')
    @patch('cryptography.fernet.Fernet.decrypt', return_value=b'"admin_id"')
    def test_load_admin_user_id(self, mock_exists, mock_file, mock_decrypt):
        with patch('cryptography.fernet.Fernet', return_value=MagicMock(decrypt=mock_decrypt)):
            admin_id = load_admin_user_id()
            self.assertEqual(admin_id, "admin_id")

    @patch('builtins.open', new_callable=mock_open)
    def test_save_admin_user_id(self, mock_file):
        admin_id = "admin_id"
        key = Fernet.generate_key()
        with patch('cryptography.fernet.Fernet.encrypt', return_value=b'encrypted_data'):
            save_admin_user_id(admin_id)
            mock_file().write.assert_called_once_with(b'encrypted_data')

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data=b'encrypted_data')
    @patch('cryptography.fernet.Fernet.decrypt', return_value=b'["user1", "user2"]')
    def test_load_authorized_users(self, mock_exists, mock_file, mock_decrypt):
        with patch('cryptography.fernet.Fernet', return_value=MagicMock(decrypt=mock_decrypt)):
            users = load_authorized_users()
            self.assertEqual(users, ["user1", "user2"])

    @patch('builtins.open', new_callable=mock_open)
    def test_save_authorized_users(self, mock_file):
        users = ["user1", "user2"]
        key = Fernet.generate_key()
        with patch('cryptography.fernet.Fernet.encrypt', return_value=b'encrypted_data'):
            save_authorized_users(users)
            mock_file().write.assert_called_once_with(b'encrypted_data')

if __name__ == '__main__':
    unittest