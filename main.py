import os
import json
import requests
import tkinter as tk

#constantes 
api_key_virustotal = '068e683a9bad1c79f52815fa16a51545ec1545a8a6e94dc05db1f84f73475287'
valida_erro = False 

#funcoes
def verifica_virustotal_api(api_key, diretorio):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}

    total_arquivos = 0
    arquivos_infectados = 0

    for raiz, diretorio, arquivos in os.walk(diretorio):
        for arquivo in arquivos:
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
                        #print('O arquivo parece estar livre de malware.')

                else:
                    print(f'A verificação do arquivo {caminho_arquivo} no VirusTotal falhou. Detalhes: {resultado["verbose_msg"]}')
            else:
                print(f'A resposta da API do VirusTotal não possui o campo "response_code". Resposta completa: {resultado}')

    print(f"Total de arquivos analisados : {total_arquivos}")
    print(f"Total de arquivos infectados : {arquivos_infectados}")
    if total_arquivos > 0 and arquivos_infectados > 0: 
        result_label_02.insert(0,f"{total_arquivos}")
        result_label_04.insert(0,f"{arquivos_infectados}")
    else:
        pass

def valida_diretorio():
    #print("Bunga")
    diretorio_label_str = diretorio_label.get()
    #print(diretorio_label_str)

    if diretorio_label.get() == "":
        diretorio_label.insert(0,"Erro - Informe o diretorio")
        valida_erro = True 
    
    elif os.path.isdir(diretorio_label_str): 
        pass
    else:
        diretorio_label.insert(0,"Erro - Diretorio invalido -> ")
        valida_erro = True 

    return None 

def verifica_chamada_api():
    valida_diretorio()
    verifica_virustotal_api(api_key_virustotal,diretorio_label.get())

# Tela principal
window = tk.Tk()
window.iconbitmap(r'C:\Users\U362062\Documents\Scripts\AntiVirus\antivirus_app\antivirus_suite.ico')
window.title("VirusTotal App")
window.geometry("400x200")

select_text = r'C:\Users\U362062\Documents'
#select_button = tk.Button(text="Iniciar analise", command=verificar_virus_virustotal(api_key_virustotal, select_text))
diretorio_label_titulo = tk.Label(text= r"Informe o diretorio a ser analisado - ex: C:\Users\U362062\Documents")
diretorio_label_titulo.place(x=5,y=10)
#diretorio_label_titulo.pack()
diretorio_label = tk.Entry(width=40)
diretorio_label.place(x=8,y=35)
#diretorio_label.pack()


select_button = tk.Button(text="Iniciar analise", command=verifica_chamada_api)
select_button.place(x=5,y=70)
#select_button.pack()

# Cria a label para exibir os totais 
result_label_01 = tk.Label(text= "Total de arquivos analisados")
result_label_01.place(x=5,y=110)
#result_label_01.pack(side="left",pady=2,padx=5)
result_label_02 = tk.Entry(width=4)
result_label_02.place(x=170,y=110)
#result_label_02.pack(side="left",pady=2,padx=2)

result_label_03 = tk.Label(text= "Total de arquivos infectados")
result_label_03.place(x=5,y=150)
#result_label_03.pack(pady=4,padx=5,side="left")
result_label_04 = tk.Entry(width=4)
result_label_04.place(x=170,y=150)
#result_label_04.pack(pady=4,padx=2,side="left")

# Mantem a janela do app ativa
window.mainloop()