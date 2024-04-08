from scapy.all import sniff, IP, TCP, UDP, DNS
from scapy.all import rdpcap
from collections import Counter
import threading
from datetime import datetime
import time

#IMPORTS DE DESIGN-------------------
import customtkinter as ctk
from tkinter.scrolledtext import ScrolledText
import tkinter.messagebox as messagebox
from tkinter import filedialog
#------------------------------------

class ComercarCaptura:
    def __init__(self, output_textbox):
        self.pacotes = []
        self.ip_contador = Counter()
        self.detalhes_pacotes = []
        self.output_textbox = output_textbox

    def mostrar_pacotes_PCAP(self, file_path):
        self.output_textbox.config(state='normal')
        self.output_textbox.delete('1.0', 'end')  # Limpa o texto existente no widget
        try:
            pacotes = rdpcap(file_path)
            for pacote in pacotes:
                self.output_textbox.insert('end', f"{pacote.summary()}\n")
            self.output_textbox.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Erro", f"Ocorreu um erro ao abrir o arquivo: {str(e)}")

    def mostrar_o_pacote(self, packet):
        tempo_atual = time.time()

        packet_info = "-------------------------------------------------------------------------------------\n"
        if IP in packet:
            ip_layer = packet[IP]
            ip_src = ip_layer.src
            if ip_src in self.ip_contador:
                self.ip_contador[ip_src]["count"] += 1
                self.ip_contador[ip_src]["tempo"] = tempo_atual
            else:
                self.ip_contador[ip_src] = {"count": 1, "tempo": tempo_atual}

        if TCP in packet:
            tcp_layer = packet[TCP]
            packet_info += f"TCP: Porta {tcp_layer.sport} -> {tcp_layer.dport}\n"

        if UDP in packet:
            udp_layer = packet[UDP]
            packet_info += f"UDP: Porta {udp_layer.sport} -> {udp_layer.dport}\n"

        if DNS in packet:
            dns_layer = packet[DNS]
            dns_info = "DNS: " + (dns_layer.qd.qname.decode() if dns_layer.qd else "No Query")
            packet_info += f"{dns_info}\n"

        packet_info += f"Pacote Capturado: {packet.summary()}\n"
        packet_info += "-------------------------------------------------------------------------------------\n"
        self.detalhes_pacotes.append(packet_info)
        self.output_textbox.config(state='normal')
        self.output_textbox.insert('end', packet_info)
        self.output_textbox.config(state='disabled')
        self.output_textbox.see('end')

    def capturar_pacote(self, filtro=""):
        self.mostrar_na_interface(f"Começando a captura de pacotes com filtro: '{filtro}'. A captura durará 60 segundos.\n")
        sniff(prn=self.mostrar_o_pacote, store=False, filter=filtro, timeout=60)
        self.mostrar_na_interface("Relatório gerado.\n")
        self.gerar_relatorio()

    def gerar_relatorio(self):
        timestamp = datetime.now().strftime("%d-%m-%Y-----%H-%M-%S")
        nome_arquivo = f"relatorio_captura_{timestamp}.txt"
        with open(nome_arquivo, "w") as relatorio:
            relatorio.write(f"Relatório de Captura de Pacotes - {timestamp}\n")
            for detalhe in self.detalhes_pacotes:
                relatorio.write(f"{detalhe}\n")
        print(f"\nRelatório gerado como '{nome_arquivo}'.")

    def mostrar_na_interface(self, message):
        self.output_textbox.config(state='normal')
        self.output_textbox.insert('end', message)
        self.output_textbox.config(state='disabled')
        self.output_textbox.see('end')

    def verificar_seguranca(self):
        # Obtendo o tempo atual
        tempo_atual = time.time()

        # Detecção de potencial varredura de portas ou DoS
        for ip, count in self.ip_contador.items():
            # Pode ajustar esses valores se quiser.
            if count > 100 and (tempo_atual - self.ip_contador[ip]["tempo"]) < 60:
                self.mostrar_na_interface(
                    f"Atenção: possíveis atividades maliciosas detectadas! Alto tráfego do IP {ip}\n")


class AppInterface:
    def __init__(self, master):
        self.master = master
        master.title("Captura de Pacotes")

        self.output_textbox = ScrolledText(master)
        self.output_textbox.pack(fill='both', expand=True)

        self.captura = ComercarCaptura(self.output_textbox)

        # Configuração de botões usando customtkinter
        self.btn_all_packets = ctk.CTkButton(master, text="Capturar todos os pacotes", command=self.Captura_tudo_ai)
        self.btn_all_packets.pack(pady=10)

        self.btn_tcp_packets = ctk.CTkButton(master, text="Capturar apenas pacotes TCP", command=self.Começar_captura_tcp)
        self.btn_tcp_packets.pack(pady=10)

        self.btn_udp_packets = ctk.CTkButton(master, text="Capturar apenas pacotes UDP", command=self.Começar_captura_udp)
        self.btn_udp_packets.pack(pady=10)

        self.btn_choose_pcap = ctk.CTkButton(master, text="Escolher arquivo PCAP", command=self.escolher_PCAP)
        self.btn_choose_pcap.pack(pady=10)

        self.btn_exit = ctk.CTkButton(master, text="Encerrar", command=master.quit)
        self.btn_exit.pack(pady=10)

    def Captura_tudo_ai(self):
        threading.Thread(target=self.captura.capturar_pacote).start()

    def Começar_captura_tcp(self):
        threading.Thread(target=self.captura.capturar_pacote, args=("tcp",)).start()

    def Começar_captura_udp(self):
        threading.Thread(target=self.captura.capturar_pacote, args=("udp",)).start()

    def escolher_PCAP(self):
        file_path = filedialog.askopenfilename(filetypes=[("Arquivos PCAP", "*.pcap"), ("Todos os arquivos", "*.*")])
        if file_path:
            threading.Thread(target=self.captura.mostrar_pacotes_PCAP, args=(file_path,)).start()


if __name__ == "__main__":
    root = ctk.CTk()
    app = AppInterface(root)
    root.mainloop()
