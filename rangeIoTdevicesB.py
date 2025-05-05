from collections import Counter
import sys 
from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt 
import manuf 
import matplotlib.pyplot as plt  
import numpy as np
import time
import pickle
class Network: 
    def __init__(self, ssid):
        self.ssid = ssid
        self.APlist = [] # list to hold all detected accesspoints 
        self.stationList = [] # list to hold all clients in network 
        self.security = ""
        self.isMesh = False 
    def APinNetwork(self, inAddr):
         for address in self.APlist:
             if inAddr == address:
                 return True
         return False #utility function to check if AP in network 
    def stationInNetwork(self, inAddr):
        if inAddr in self.stationList: 
            return True #same thing but for devices 
        return False


def getMfgr(mac):
    oui = mac[0:8]
    p = manuf.MacParser()
    manufacturer = p.get_manuf_long(oui)
    if manufacturer is not None:
        return manufacturer
    if manufacturer is None:
        macDict = {"ff:ff:ff": "Error", "cc:5e:f8": "Cloud Network Technology Singapore Pte Ltd.", "50:91:e3": "TP-Link Systems Inc", "00:92:a5": "LG innotek", "24:e5:0f": "Google, Inc.", "5c:47:5e": "Ring LLC", "50:fd:d5": "SJI Industry company", "64:49:7d": "Intel Corporate", "90:48:6c": "Ring LLC", "b8:2c:a0": "Resideo", "34:7d:e4": "Shenzhen Bilian Electronic Co., Ltd", "4c:31:2d": "Sichuan AI-link Technology", "64:17:cd": "Samsung Electronics Co., Ltd", "e8:4c:4a": "Amazon Technologies Inc.", "54:f2:9f": "Hunan FN-Link Technology Limited", "b0:a7:32": "Espressif Inc.", "78:6c:84": "Amazon Technologies Inc.", "64:9a:63": "Ring LLC", "c4:de:e2": "Espressif Inc.", "48:a2:e6": "Resideo", "ac:c9:06": "Apple, Inc.", "b4:61:e9": "Sichuan AI-link Technology", "08:f9:e0": "Espressif Inc.", "44:3d:54": "Amazon Tech Inc.", "9c:a2:f4": "TP-Link Systems Inc.", "1c:90:ff": "Tuya Smart Inc", "44:42:01": "Amazon Tech Inc.", "74:37:5f": "Sercomm Phillipines Inc", "bc:f4:d4": "Cloud Network Tech Singapore Pte. Ltd", "28:7e:80": "Hui Zhou Gasoshengda Tech Co, Ltd", "7c:63:05": 'Amazon Tech Inc.', "84:3e:1d": "Hui Zhou Gaoshengda Tech Co, Ltd", "a8:51:ab": "Apple, Inc", "0c:29:8f": "Tesla, inc"} # Dictionary of OUI
        if oui in macDict:
            return macDict[oui]
    return "Unknown"

def isIOT(mac):
    manufacturer = getMfgr(mac).upper()
    iotMfgrs = ["THE CHAMBERLAIN GROUP", "ESPRESSIF INC.", "AMAZON TECHNOLOGIES INC.", "ALARM.COM", "RING LLC", "IROBOT CORPORATION", "TUYA SMART INC", "GENERAL ELECTRIC", "FN-LINK TECHNOLOGY LIMITED", "FACEBOOK INC", "SICHUAN AI-LINK TECHNOLOGY CO", "ECOBEE", "TESLA", "TEXAS INSTRUMENTS", "AURA HOME", "SONOS", "AMPAK TECHNOLOGY", "UNIVERSAL GLOBAL SCIENTIFIC", "HUNAN FN-LINK", "LIFI LABS", "WYZE LABS", "SERCOMM CORP", "ARLO", "DWNET TECHNOLOGIES", "SHENZHEN GIEC", "BOSE CORPORATION", "PART II RESEARCH", "BLINK BY AMAZON", "ROBOROCK", "SEONGJI INDUSTRY COMPANY", "COULOMB TECHNOLOGIES", "ALTOBEAM", "MAYTRONICS", "SKY LIGHT DIGITAL", "GE LIGHTING", "QOLSYS", "SLIM DEVICES INC", "LG INNOTEK", "SMART INNOVATION LLC", "SELECT COMFORT", "SHENZEN APICAL", "NEST LABS", "ORBIT IRRIGATION", "NEURIO TECHNOLOGY INC", "CHENGDU MEROSS", "RAIN BIRD CORPORATION", "SMART INNOVATIONS LLC", "ORBIT IRRIGATION", "INVENTEK", "SIMPLISAFE", "AZUREWAVE", "SHENZHEN TROLINK", "DURATECH ENTERPRISE", "NIGHT OWL SP", "LINKSPRITE", "FORTH-SYSTEME", "WHITE RODGERS", "SKYBELL", "WIZ", "RESIDEO", "KYOCERA", "REOLINK", "LOGITECH"]
    for name in iotMfgrs: 
        if name in manufacturer:
            return True 
    return False 
def iotInNet(network):
    iotCounter = 0 
    for device in network.stationList:
        if isIOT(device):
            iotCounter += 1 
    return iotCounter 
class OUI: 
    def __init__(self, oui):
        self.oui = oui 
        self.name = getMfgr(oui)  
        self.count = 1 # simple class to represent OUI 
    def incrementCount(self):
        self.count += 1 #utility method to increment the count of a particular OUI 


# Begin mainfunc 
if len(sys.argv) < 2: 
    print("Usage: rangeIoTdevices.py <input binary data file>")
else: 
    dataFile = open(sys.argv[1], 'rb') 
    networkArray = pickle.load(dataFile) 
    zeroIoTdevices = 0 
    oneto3IoTdevices = 0
    fourto6IoTdevices = 0 
    sixPlusIoT = 0 
    for network in networkArray:
        if len(network.stationList) > 0:
            #        for device in network.stationList:
             #   print("MAC: "+device+" MfGr: "+getMfgr(device))
            #print(str(network.ssid)+" "+str(iotInNet(network)))
            if iotInNet(network) == 0:
                zeroIoTdevices += 1 
            if iotInNet(network) > 0 and iotInNet(network) <= 3:
                oneto3IoTdevices += 1 
            if iotInNet(network) > 3 and iotInNet(network) <= 6: 
                fourto6IoTdevices += 1 
            if iotInNet(network) > 6: 
                sixPlusIoT += 1 
    print("Zero IoT devices : "+str(zeroIoTdevices))
    print("1-3 IoT devices : "+str(oneto3IoTdevices))
    print("4-6 IoT devices : "+str(fourto6IoTdevices))
    print("6+ IoT devices : "+str(sixPlusIoT))
    x = np.array(["0 IoT devices", "1-3 IoT devices", "4-6 IoT devices", "7+ IoT devices"]) 
    y = np.array([zeroIoTdevices, oneto3IoTdevices, fourto6IoTdevices, sixPlusIoT])
    plt.figure(num=sys.argv[1])
    plt.bar(x,y)
    plt.show()
# TODO - take data from this and place into network 
# also, you need to build something that gets a ratio of ssid type - iot direct printer etc  
