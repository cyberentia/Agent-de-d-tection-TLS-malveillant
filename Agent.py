import socket
import threading
from tkinter import Tk, Label, Button
import csv
import sys
import asyncio
import requests
from io import StringIO
from pystray import Icon, Menu, MenuItem
from PIL import Image, ImageDraw, ImageFont
from plyer import notification
import shutil
import subprocess
import os
import pyshark
import win32gui
import win32process
import win32con
import psutil
import time

#  Masquer les fenêtres de tshark et dumpcap
def hide_windows_by_name(targets=("tshark.exe", "dumpcap.exe")):
    def enum_window_callback(hwnd, pid_list):
        try:
            tid, pid = win32process.GetWindowThreadProcessId(hwnd)
            p = psutil.Process(pid)
            if p.name().lower() in targets:
                # Cache la fenêtre
                win32gui.ShowWindow(hwnd, win32con.SW_HIDE)
        except Exception:
            pass
    while True:
        win32gui.EnumWindows(enum_window_callback, None)
        time.sleep(0.5)

#  Interface réseau automatique
def get_best_interface():
    candidates = []
    net_if_addrs = psutil.net_if_addrs()
    net_if_stats = psutil.net_if_stats()
    for iface in net_if_addrs:
        if "vmnet" in iface.lower() or "virtual" in iface.lower() or "loopback" in iface.lower():
            continue
        if iface in net_if_stats and net_if_stats[iface].isup:
            for snic in net_if_addrs[iface]:
                if snic.family == socket.AF_INET and not snic.address.startswith("169.254."):
                    candidates.append(iface)
                    break
    return candidates[0] if candidates else None

#  Exemple de capture silencieuse avec Pyshark
def start_capture():

    interface = get_best_interface()
    if interface:
        print(f" Capture sur l'interface : {interface}")
        # On ajoute creationflags dans override_popen_kwargs
        creationflags = 0x08000000 if os.name == 'nt' else 0
        capture = pyshark.LiveCapture(
            interface=interface,
            override_popen_kwargs={'creationflags': creationflags}
        )
        for packet in capture.sniff_continuously(packet_count=5):
            print(packet)
    else:
        print(" Aucune interface réseau valide trouvée.")

#  Fenêtre rouge d’alerte
import pyperclip


def show_red_alert(title, message, vt_url=None, block_cmd=None):
    root = Tk()
    root.title(title)
    root.configure(bg='red')
    root.resizable(False, False)

    label = Label(root, text=message, bg='red', fg='white',
                  font=('Helvetica', 14, 'bold'), wraplength=500, justify='center')
    label.pack(padx=20, pady=(20, 10))

    # Bouton pour copier la commandepyinstal
    if block_cmd:
        def copy_cmd():
            pyperclip.copy(block_cmd)

        copy_button = Button(root, text="📋 Copier la commande", command=copy_cmd,
                             bg='white', fg='black', font=('Helvetica', 12), width=25)
        copy_button.pack(pady=(0, 10))

    # Bouton lien VirusTotal
    if vt_url:
        def open_vt():
            import webbrowser
            webbrowser.open(vt_url)

        vt_button = Button(root, text="Vérifier sur VirusTotal!", command=open_vt,
                           bg='white', fg='blue', font=('Helvetica', 12, 'bold'), width=25)
        vt_button.pack(pady=(0, 10))

    # Bouton OK
    ok_button = Button(root, text="OK", command=root.destroy,
                       bg='white', fg='red', font=('Helvetica', 12, 'bold'), width=10)
    ok_button.pack(pady=(0, 15))

    root.update_idletasks()
    width = label.winfo_reqwidth() + 40
    height = label.winfo_reqheight() + 180
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"{width}x{height}+{x}+{y}")
    root.mainloop()


#  GREASE
GREASE_VALUES = {
    '0x0a0a', '0x1a1a', '0x2a2a', '0x3a3a',
    '0x4a4a', '0x5a5a', '0x6a6a', '0x7a7a',
    '0x8a8a', '0x9a9a', '0xaaaa', '0xbaba',
    '0xcaca', '0xdada', '0xeaea', '0xfafa',
    "0a0a", "1a1a", "2a2a", "3a3a", "4a4a", 
    "5a5a", "6a6a", "7a7a", "8a8a", "9a9a",
    "aaaa", "baba", "caca", "dada", "eaea", 
    "fafa"
}

#  JA3S CSV load
def load_ja3s_dictionary():
    """
    Télécharge et charge les correspondances JA3S ↔ App dans un dictionnaire.
    Retourne un dictionnaire vide en cas d’échec.
    """
    ja3s_dict = {}
    url = "https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.csv"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            csv_data = StringIO(response.text)
            reader = csv.reader(csv_data)
            for row in reader:
                if len(row) == 2:
                    ja3_hash, app_name = row
                    ja3s_dict[ja3_hash.strip()] = app_name.strip()
        else:
            print(f" Échec du téléchargement JA3S ({response.status_code})")
    except Exception as e:
        print(f" Erreur lors du chargement de la liste JA3S : {e}")
    return ja3s_dict
ja3s_dict = load_ja3s_dictionary()
#  Extraction JA3S
def extract_ja3s(packet):
    try:
        tls = getattr(packet, "tls", None)
        if not tls:
            print(" Pas de couche TLS")
            return None, None

        #   tente d'extraire les valeurs directement
        ja3s_string = getattr(tls, "handshake_ja3s_full", None)
        ja3s_hash = getattr(tls, "handshake_ja3s", None)

        if not ja3s_string or not ja3s_hash:
            #  En fallback : inspecter les records manuellement
            records = getattr(tls, "record", [])
            if not isinstance(records, list):
                records = [records]

            for record in records:
                handshake = getattr(record, "handshake", None)
                if isinstance(handshake, list):  # Si plusieurs handshakes
                    for h in handshake:
                        ja3s_string = getattr(h, "ja3s_full", None)
                        ja3s_hash = getattr(h, "ja3s", None)
                        if ja3s_string and ja3s_hash:
                            break
                else:  # un seul handshake
                    ja3s_string = getattr(handshake, "ja3s_full", None)
                    ja3s_hash = getattr(handshake, "ja3s", None)
                if ja3s_string and ja3s_hash:
                    break

        return ja3s_string, ja3s_hash

    except Exception as e:
        print(f" Exception extract_ja3s : {e}")
        return None, None

#  Mémoire des ClientHello
client_cache = {}
def sniff_clients():
    asyncio.set_event_loop(asyncio.new_event_loop())
    capture_client = pyshark.LiveCapture(interface=interface, display_filter='tls.handshake.type == 1')
    for pkt in capture_client.sniff_continuously():
        try:
            if not hasattr(pkt, 'tls') or not hasattr(pkt, 'ip'):
                continue
            if hasattr(pkt.tcp, 'stream'):
                stream_id = getattr(pkt.tcp, 'stream', None)
                sni = getattr(pkt.tls, 'handshake_extensions_server_name', None)
                if stream_id and sni:
                    client_cache[stream_id] = {
                        'sni': sni,
                        'src': pkt.ip.src,
                        'dst': pkt.ip.dst
                    }
                    #  Affichage client
                  #  print(f" ClientHello - Stream {stream_id}")
                  #  print(f" SNI : {sni}")
                  #  print(f" From {pkt.ip.src} → {pkt.ip.dst}")
                  #  print("=" * 50)
        except Exception as e:
            continue
def check_threatfox(ioc):
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"Content-Type": "application/json"}
    payload = {
        "query": "search_ioc",
        "search_term": ioc
    }
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=5)
        if response.status_code == 200 and "application/json" in response.headers.get("Content-Type", ""):
            return response.json()
        else:
            print(f" Réponse inattendue de ThreatFox : {response.status_code}")
            return None
    except Exception as e:
        print(f" Erreur lors de l'appel à ThreatFox : {e}")
        return None
        
def sniff_servers():
    seen_ja3s = set()
    asyncio.set_event_loop(asyncio.new_event_loop())
    capture_server = pyshark.LiveCapture(
        interface=interface,
        display_filter='tls.handshake.type == 2',
        use_json=True,
        include_raw=False
    )
    last_heartbeat = time.time()
    tls_count = 0
    max_packets = 200  # Limite de paquets TLS ServerHello à traiter
    for pkt in capture_server.sniff_continuously():
        try:
            tls_count += 1
            if tls_count >= max_packets:
                print(f"🔚 Limite de {max_packets} paquets atteinte. Fin de la capture.")
                tls_count=0
            if tls_count % 10 == 0:
                print(f" TLS capturés : {tls_count}")
            if not hasattr(pkt, 'tls') or not hasattr(pkt, 'ip'):
                continue
            if time.time() - last_heartbeat > 10:
                print(":) Sniff_servers actif...")
                last_heartbeat = time.time()
            if hasattr(pkt.tcp, 'stream'):
                stream_id = pkt.tcp.stream
                ja3s_str, ja3s_digest = extract_ja3s(pkt)
                if not ja3s_digest or ja3s_digest in seen_ja3s:
                    continue
                if not ja3s_digest:
                    print(" ServeurHello sans JA3S valide (extensions/cipher manquants)")
                    print(f" From {pkt.ip.src} → {pkt.ip.dst}")
                    print("=" * 50)
                    continue
                seen_ja3s.add(ja3s_digest)
                if stream_id in client_cache:
                    client_info = client_cache[stream_id]
                    sni = client_info.get('sni', 'Nom de domaine inconnu')
                    app = ja3s_dict.get(ja3s_digest)
                    if app:
                        #  JA3S légitime, trouvé dans Salesforce
                        print(f"ℹ JA3S légitime : {app} ({ja3s_digest})")
                    else:
                        #  Inconnu → on interroge ThreatFox et cherche des signes de menace
                        print(f"❔ JA3S inconnu : {ja3s_digest}")

                        #  Analyse ThreatFox
                        tf_ip_result = check_threatfox(pkt.ip.src)
                        tf_sni_result = check_threatfox(sni) if sni and sni != "SNI inconnu" else None
                        tf_ja3s_result = check_threatfox(ja3s_digest)
                        found = False
                        for source_name, result in [
                            ("IP", tf_ip_result),
                            ("JA3S", tf_ja3s_result),
                            ("SNI", tf_sni_result)
                        ]:
                            if result and result.get("query_status") == "ok" and result.get("data"):
                                for entry in result["data"]:
                                    malware = entry.get("malware", "Inconnu")
                                    threat_type = entry.get("threat_type", "N/A")
                                    confidence = entry.get("confidence_level", "N/A")

                                    print(
                                        f"{source_name} référencé sur ThreatFox : {malware} ({threat_type}, confiance : {confidence})")

                                    notification.notify(
                                        title=f"JA3S détecté via {source_name}",
                                        message=f"{malware} ({ja3s_digest})\nType: {threat_type} / Confiance: {confidence}",
                                        timeout=6
                                    )
                                    block_cmd = f"New-NetFirewallRule -DisplayName 'Blocage JA3S - {pkt.ip.src}' -Direction Outbound -RemoteAddress {pkt.ip.src} -Action Block -Protocol TCP -Profile Any"
                                    message = (
                                        f" Menace détectée par ThreatFox via {source_name}\n"
                                        f"SNI : {sni}\n"
                                        f"IP : {pkt.ip.src}\n"
                                        f"Type : {threat_type} / Confiance : {confidence}\n\n"
                                        f"Vous pouvez bloquer cette IP avec la commande PowerShell :\n"
                                        f"{block_cmd}\n\n"
                                        f"Mais avant vérifier aussi sur VirusTotal pour confirmer votre choix !"
                                    )
                                    vt_url = f"https://www.virustotal.com/gui/ip-address/{pkt.ip.src}/detection"
                                    show_red_alert("Alerte menace", message, vt_url=vt_url, block_cmd=block_cmd)
                                    found = True
                                    break  # stop loop dès qu’une détection est faite
                        if not found:
                            print(" JA3S non listé sur ThreatFox (IP, JA3S ou SNI).")

        except Exception as e:
            print(f"Erreur dans sniff_servers : {e}")
            continue

#  Ajout au démarrage Windows
def add_to_startup(exe_name="Agent.exe"):
    startup_path = os.path.join(os.getenv("APPDATA"), r"Microsoft\Windows\Start Menu\Programs\Startup")
    exe_path = os.path.join(os.getcwd(), exe_name)
    if os.path.exists(exe_path) and not os.path.exists(os.path.join(startup_path, exe_name)):
        shutil.copy(exe_path, startup_path)

#  Icône système
def create_letter_icon(letter="J"):
    image = Image.new('RGB', (64, 64), 'red')
    draw = ImageDraw.Draw(image)
    try:
        font = ImageFont.truetype("arial.ttf", 36)
    except:
        font = ImageFont.load_default()
    bbox = draw.textbbox((0, 0), letter, font=font)
    w = bbox[2] - bbox[0]
    h = bbox[3] - bbox[1]
    draw.text(((64 - w) / 2, (64 - h) / 2), letter, fill="white", font=font)
    return image

def quit_action(icon, item):
    icon.stop()
def open_console(icon, item):
    exe_path = os.path.abspath(sys.argv[0])
    subprocess.Popen(
        ['cmd.exe', '/k', exe_path],
        creationflags=0
    )

def start_systray():
    icon = Icon("JA3S Agent")
    icon.icon = create_letter_icon("J")
    icon.menu = Menu(
        MenuItem(" Quitter", quit_action)
    )
    threading.Thread(target=sniff_clients, daemon=True).start()
    time.sleep(5)  #  attendre que les premiers ClientHello soient capturés
    threading.Thread(target=sniff_servers, daemon=True).start()
    icon.run()

#  Lancement
interface = get_best_interface()
if not interface:
    print(" Aucune interface détectée")
    exit()
else:
    print(f" Interface sélectionnée : {interface}")

if __name__ == "__main__":
    # Lance la surveillance et masquage des fenêtres tshark/dumpcap
    threading.Thread(target=hide_windows_by_name, daemon=True).start()
    start_systray()
