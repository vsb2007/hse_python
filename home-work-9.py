from scapy.all import *
from scapy.layers.inet import IP, TCP
import random
import sys
from scapy.layers.http import *  # or load_layer("http")
from scapy.layers.l2 import Ether

from sqlalchemy.sql.functions import count

# packets = sniff(iface="en0",count=10)
# print(packets)
URL = "https://google-gruyere.appspot.com/453300002388336502849593553943424418716/"

http_request = Ether() / IP(dst="google-gruyere.appspot.com") / TCP(dport=80, flags="S") / Raw(load="GET / HTTP/1.1\r\nHost: google-gruyere.appspot.com\r\n\r\n")

# Отправляем пакет
print(sendp(http_request))
