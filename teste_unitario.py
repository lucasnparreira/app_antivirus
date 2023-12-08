import unittest
from unittest.mock import mock_open, patch, Mock

from main import verifica_virustotal_api

class TestVirusTotalAPI(unittest.TestCase):

    @patch('builtins.open', new_callable=mock_open)
    @patch('requests.post')
    def test_verifica_virustotal_api(self, mock_post, mock_open):
        # Configuração de mocks
        mock_post.return_value.json.return_value = {'response_code': 1, 'positives': 1}
        mock_open.return_value.__enter__.return_value.read.return_value = 'fake file content'

        # Chama a função
        verifica_virustotal_api('fake_api_key', 'fake_directory')

        # Verificações de chamadas
        mock_post.assert_called_once()
        mock_open.assert_called()

    # Adicione mais testes conforme necessário

if __name__ == '__main__':
    unittest.main()
