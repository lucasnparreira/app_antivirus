import os
import json
from tkinter import filedialog, ttk
from click import style
import requests
import tkinter as tk
from threading import Thread
from pystray import Icon, MenuItem as item
from PIL import Image

#constantes 
API_KEY_VIRUSTOTAL = '068e683a9bad1c79f52815fa16a51545ec1545a8a6e94dc05db1f84f73475287'
VALIDA_ERRO = False
DIRETORIO_SELECIONADO = ""
ANALISE_EM_ANDAMENTO = False

# Variáveis de resultados
total_arquivos_analisados = 0
total_arquivos_infectados = 0

#funcoes
def verifica_virustotal_api(api_key, diretorio):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}

    total_arquivos = 0
    arquivos_infectados = 0

    for raiz, diretorio, arquivos in os.walk(diretorio):
        for i, arquivo in enumerate(arquivos, start=1):
            caminho_arquivo = os.path.join(raiz, arquivo)

            with open(caminho_arquivo, 'rb') as arquivo_aberto:
                files = {'file': arquivo_aberto}
                resposta = requests.post(url, files=files, params=params)

            try:
                resultado = resposta.json()
            except json.JSONDecodeError:
                print(f'A resposta da API do VirusTotal não pôde ser decodificada como JSON. Resposta completa: {resposta.text}')
                continue

            if 'response_code' in resultado:
                total_arquivos += 1
                if resultado['response_code'] == 1:
                    positivos = resultado.get('positives', 0)
                    print(f'O arquivo {caminho_arquivo} foi verificado. Resultados: {positivos} detecções positivas no VirusTotal.')

                    if positivos > 0:
                        print('Atenção: O arquivo pode conter malware.')
                        arquivos_infectados += 1
                    else:
                        continue

                else:
                    print(f'A verificação do arquivo {caminho_arquivo} no VirusTotal falhou. Detalhes: {resultado["verbose_msg"]}')

            else:
                print(f'A resposta da API do VirusTotal não possui o campo "response_code". Resposta completa: {resultado}')
            

    print(f"Total de arquivos analisados : {total_arquivos}")
    print(f"Total de arquivos infectados : {arquivos_infectados}")
    
    
    result_label_02.config(text=f"{total_arquivos}")
    result_label_04.config(text=f"{arquivos_infectados}")

def valida_diretorio():
    diretorio_label_str = diretorio_label.cget("text")

    if DIRETORIO_SELECIONADO == "":
        diretorio_label.insert(0, "Erro - Informe o diretório")

    elif os.path.isdir(diretorio_label_str):
        pass
    else:
        diretorio_label.insert(0, "Erro - Diretório inválido -> ")
  

def verifica_chamada_api():
    global total_arquivos_analisados, total_arquivos_infectados
    valida_diretorio()

    if not VALIDA_ERRO and DIRETORIO_SELECIONADO:
        total_arquivos_analisados = 0
        total_arquivos_infectados = 0
        verifica_virustotal_api(API_KEY_VIRUSTOTAL, DIRETORIO_SELECIONADO)
    else:
        diretorio_label.config(state='normal')
        pass
        

def selecionar_diretorio():
    global DIRETORIO_SELECIONADO
    DIRETORIO_SELECIONADO = filedialog.askdirectory()
    if DIRETORIO_SELECIONADO:
        diretorio_var.set(DIRETORIO_SELECIONADO)


def para_analise():
    global ANALISE_EM_ANDAMENTO
    ANALISE_EM_ANDAMENTO = False
    window.destroy()

def on_minimize(icon, item):
    window.iconify()
    
def run_icon():
    # Adiciona um ícone à bandeja do sistema
    image = Image.open(r'/Users/lucasparreira/Documents/Projects/app_antivirus/antivirus_suite.ico')
    menu_def = (item('Parar Análise', para_analise),)
    icon = Icon("name", image, "Title", menu_def)
    icon.run(on_minimize)

def verifica_acesso_internet():
    try:
        # Tente fazer uma requisição a um site conhecido
        requests.get("http://www.google.com", timeout=5)
        return True
    except requests.ConnectionError:
        return False

def exibe_status_internet():
    if verifica_acesso_internet():
        status_label.config(text="")
    else:
        status_label.config(text="Sem conexão à Internet - Por favor verifique o acesso antes de utilizar o App.", fg="red")

    
# Tela principal
window = tk.Tk()
window.iconbitmap(r'/Users/lucasparreira/Documents/Projects/app_antivirus/antivirus_suite.ico')
window.title("VirusTotal App")
window.geometry("600x230")

# Variável StringVar para armazenar o diretório selecionado
diretorio_var = tk.StringVar()

# Iniciar a função run_icon em uma thread separada
#icon_thread = Thread(target=run_icon)
#icon_thread.start()

diretorio_label_titulo = tk.Label(text="Informe o diretório a ser analisado")
diretorio_label_titulo.place(x=5, y=10)

diretorio_label = tk.Label(textvariable=diretorio_var, width=37, state='normal')
diretorio_label.place(x=160, y=35)

btn_selecionar_diretorio = tk.Button(text="Selecionar Diretório", command=selecionar_diretorio)
btn_selecionar_diretorio.place(x=5, y=45)

select_button = tk.Button(text="Iniciar análise", command=verifica_chamada_api)
select_button.place(x=5, y=90)

# btn_parar_analise = tk.Button(text="Parar Análise", command=para_analise)
# btn_parar_analise.place(x=140, y=90)

result_label_01 = tk.Label(text="Total de arquivos analisados")
result_label_01.place(x=5, y=130)

result_label_02 = tk.Label(width=4)
result_label_02.place(x=190, y=130)

result_label_03 = tk.Label(text="Total de arquivos infectados")
result_label_03.place(x=5, y=160)

result_label_04 = tk.Label(width=4)
result_label_04.place(x=190, y=160)

status_label = tk.Label(text="Status da Internet: Verificando...", font=('Arial', 12))
status_label.place(x=5, y=200)

exibe_status_internet()

window.mainloop()