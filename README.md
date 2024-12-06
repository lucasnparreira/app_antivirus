VirusTotal App
O VirusTotal App é uma aplicação desktop em Python que permite analisar arquivos em um diretório utilizando a API do VirusTotal. A aplicação verifica os arquivos selecionados em busca de possíveis malwares e exibe os resultados de forma prática e organizada.

Funcionalidades
Seleção de Diretório: Escolha facilmente o diretório a ser analisado.
Análise de Arquivos: Verifica arquivos no diretório utilizando a API do VirusTotal.
Relatório de Resultados: Exibe o total de arquivos analisados e infectados.
Verificação de Conexão com a Internet: Garante que o aplicativo funcione apenas com conexão ativa.
Interface Gráfica (GUI): Desenvolvida com Tkinter para facilitar a interação do usuário.
Ícone na Bandeja do Sistema (experimental): Minimiza a aplicação para a bandeja.

Pré-requisitos
Certifique-se de ter os seguintes requisitos instalados:
Python 3.7 ou superior
Pacotes Python:
requests
tkinter (incluso no Python por padrão)
pystray
Pillow
Uma chave de API válida do VirusTotal.

Instalação
Clone o repositório ou baixe o código fonte:
git clone https://github.com/usuario/virustotal-app.git
cd virustotal-app

Instale as dependências:
pip install -r requirements.txt
Insira sua chave da API do VirusTotal:

Localize a constante API_KEY_VIRUSTOTAL no código e substitua pelo valor da sua chave.
Execute o aplicativo:
python app.py

Como Usar
Abra a aplicação.
Clique no botão Selecionar Diretório e escolha a pasta que deseja analisar.
Clique em Iniciar Análise para começar a verificação.
O total de arquivos analisados e infectados será exibido na interface.
A aplicação verifica automaticamente a conexão com a Internet e alerta em caso de problemas.

Estrutura do Projeto
virustotal-app/
├── app.py                # Código principal do aplicativo
├── antivirus_suite.ico   # Ícone da aplicação
└── README.md             # Documentação do projeto

Limitações
A análise depende da API do VirusTotal, que possui um limite de requisições gratuito.
