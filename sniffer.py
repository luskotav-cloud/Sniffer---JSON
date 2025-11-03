import argparse
import json
import logging
from datetime import datetime
from pathlib import Path

from scapy.all import sniff, IP, TCP, UDP

# preset dos logs
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)
# variavel global
lista_com_jsons = []

# --- pacote ==> dicionario ---
def construcao_dicio(pacote):
    dados = {}
    
    # coloca o timestamp para analise
    dados["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    # verifica se o pacote utiliza a camada ip
    if IP in pacote:
        camada_ip = pacote[IP]
        dados["source_ip"] = camada_ip.src
        dados["destination_ip"] = camada_ip.dst
    
        # ve o tipo de pacote que é, se é tcp ou udp ou outro
        if TCP in pacote:
            camada_trans = pacote[TCP]
            dados["protocol"] = "TCP"
            dados["source_port"] = camada_trans.sport
            dados["destination_port"] = camada_trans.dport
            dados["flags"] = str(camada_trans.flags)
            dados["cabecalho"] = len(pacote[TCP].payload)
        elif UDP in pacote:
            camada_trans = pacote[UDP]
            dados["protocol"] = "UDP"
            dados["source_port"] = camada_trans.sport
            dados["destination_port"] = camada_trans.dport
            dados["flags"] = "N/A" # udp n tem flag
            dados["cabecalho"] = len(pacote[UDP].payload)
        else:
            dados["protocol"] = "IP"
            dados["source_port"] = "N/A"
            dados["destination_port"] = "N/A"
            dados["flags"] = "N/A"
            dados["cabecalho"] = len(camada_ip.payload)
    else: # caso não tenha camada ip, igual um arp, etc... ele retorna o sumario 
        dados["protocol"] = pacote.summary()
        dados["source_ip"] = "N/A"
        dados["destination_ip"] = "N/A"
        dados["source_port"] = "N/A"
        dados["destination_port"] = "N/A"
        dados["flags"] = "N/A"
        dados["cabecalho"] = len(pacote)

    return dados

# --- dicio ===> lista global ---
def listar_json(pacote):
    # usa a funcao passada para processar o pacote e jogar dentro da lista final.
    global lista_com_jsons
    
    try:
        dados_dicio = construcao_dicio(pacote)
        
        lista_com_jsons.append(dados_dicio)
        
        logger.info(f"Pacote processado e adicionado ({len(lista_com_jsons)}). Protocolo: {dados_dicio.get('protocol', 'N/A')}.")
        
    except Exception as e:
        logger.error(f"Erro ao processar e adicionar pacote à lista: {e}")

# --- Lista ==> Arquivo Final ---
def salvar_arquivo(caminho_arquivo):

    global lista_com_jsons
    
    output_arg = Path(caminho_arquivo)
    
    try:
        # cria o diretório se ele n existir
        output_arg.parent.mkdir(parents=True, exist_ok=True)

        # abre o arquivo em modo write ('w')
        with open(output_arg, 'w') as arquivo_final:
            # joga os jsons em um .json.
            json.dump(lista_com_jsons, arquivo_final, indent=4)
        
        logger.info(f"FIM DO SCRIPT. Dados salvos com sucesso em: {caminho_arquivo}")
        
    except Exception as e:
        logger.error(f"Erro ao salvar o arquivo JSON: {e}")

def main():
    # criacao de opcoes
    opcoes = argparse.ArgumentParser(
        description="Coletor de Pacotes de Rede que segue um fluxo sequencial de funções."
    )
    
    opcoes.add_argument(
        '--interface', '-i', type=str, required=True,
        help='Placa de rede para captura (ex: eth0).'
    )
    opcoes.add_argument(
        '--output', '-o', type=str, required=True,
        help='Caminho onde o arquivo JSON de saída será escrito (ex: saida.json).'
    )
    opcoes.add_argument(
        '--count', '-c', type=int, default=0,
        help='Quantidade de pacotes a serem capturados (0 para ilimitado).'
    )
    opcoes.add_argument(
        '--filter', '-f', type=str, default="",
        help='Critérios de filtro BPF (ex: "tcp port 80").'
    )
    
    args = opcoes.parse_args()
    
    logger.info(f"Iniciando coleta na interface: {args.interface}")
    
    # captura de pacotes
    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            count=args.count,
            prn=listar_json,
            store=False
        )
        
        logger.info(f"Coleta finalizada por contagem ou interrupção. Total de {len(lista_com_jsons)} pacotes coletados.")

    except KeyboardInterrupt:
        logger.warning("Coleta interrompida pelo usuário (Ctrl+C). Salvando dados...")
    
    except PermissionError:
        logger.error("Erro: Permissão negada. Execute com privilégios de administrador (sudo/root).")
        return
    except ImportError:
        logger.error("Erro: A biblioteca 'scapy' não foi encontrada.")
        return
    except Exception as e:
        logger.error(f"Ocorreu um erro inesperado: {e}")
        return

    # chama a funcao que leva a lista para um arquivo
    salvar_arquivo(args.output)


if __name__ == "__main__":
    main()