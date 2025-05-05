
from collections import Counter
import sys 
from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt 
import manuf 
import matplotlib.pyplot as plt  
import numpy as np
import time
import pickle
ouiArray = [] # array of unique OUI 
totalIoTcount = 0 
totalDeviceCount = 0
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
        macDict = {"ff:ff:ff": "Error", "cc:5e:f8": "Cloud Network Technology Singapore Pte Ltd.", "50:91:e3": "TP-Link Systems Inc", "00:92:a5": "LG innotek", "24:e5:0f": "Google, Inc.", "5c:47:5e": "Ring LLC", "50:fd:d5": "SJI Industry company", "64:49:7d": "Intel Corporate", "90:48:6c": "Ring LLC", "b8:2c:a0": "Resideo", "34:7d:e4": "Shenzhen Bilian Electronic Co., Ltd", "4c:31:2d": "Sichuan AI-link Technology", "64:17:cd": "Samsung Electronics Co., Ltd", "e8:4c:4a": "Amazon Technologies Inc.", "54:f2:9f": "Hunan FN-Link Technology Limited", "b0:a7:32": "Espressif Inc.", "78:6c:84": "Amazon Technologies Inc.", "64:9a:63": "Ring LLC", "c4:de:e2": "Espressif Inc.", "48:a2:e6": "Resideo", "ac:c9:06": "Apple, Inc.", "b4:61:e9": "Sichuan AI-link Technology", "08:f9:e0": "Espressif Inc.", "44:3d:54": "Amazon Tech Inc.", "9c:a2:f4": "TP-Link Systems Inc.", "1c:90:ff": "Tuya Smart Inc", "44:42:01": "Amazon Tech Inc.", "74:37:5f": "Sercomm Phillipines Inc", "bc:f4:d4": "Cloud Network Tech Singapore Pte. Ltd", "28:7e:80": "Hui Zhou Gasoshengda Tech Co, Ltd", "7c:63:05": 'Amazon Tech Inc.', "84:3e:1d": "Hui Zhou Gaoshengda Tech Co, Ltd", "a8:51:ab": "Apple, Inc", "0c:29:8f": "Tesla, inc", "40:5d:82": "Netgear", "ba:2c:a0": "Resideo"} # Dictionary of OUI
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
class OUI: 
    def __init__(self, oui):
        self.oui = oui 
        self.name = getMfgr(oui)  
        self.count = 1 # simple class to represent OUI 
    def incrementCount(self):
        self.count += 1 #utility method to increment the count of a particular OUI 






def net2String(network):
    global totalDeviceCount 
    global totalIoTcount
    global ouiArray
    returnString = "SSID: "+str(network.ssid)+" AP count: "+str(len(network.APlist))+" Device count: "+str(len(network.stationList))+" Security:" + network.security+ "\n" 

    #Takes a network object and converts it into a string
    for AP in network.APlist:
        returnString += "Access point MAC: "+AP+" Mfgr: "+getMfgr(AP)+" \n"
    for station in network.stationList:
        totalDeviceCount += 1
        if isIOT(station):
            totalIoTcount += 1 
        addOUI = True 
        for oui in ouiArray:
            if oui.oui == station[0:8]:
                oui.count += 1 
                addOUI = False 
        if addOUI:
            ouiArray.append(OUI(station[0:8]))
        returnString += " *---> Station MAC : "+station+ " Mfgr: "+getMfgr(station)+" \n"
    return(returnString)

        



# Begin main function here 
displayOUI = False 
displayPrinterNetworks = True 
displayDirectNetworks = True 
displayIoTNetworks = True 
displayStandardNetworks = True
totalNetworkCount = 0 
iotNetworkArray = []
directNetworkArray = []
printerNetworkArray = [] 
standardNetworkArray = [] 
printerSubstrings = ["EPSON", "PRINT-", "OFFICEJET", "ENVY", "-HP", "LASERJET", "DESKJET", "PRINTER", "BROTHER", "SERIES", "PHOTOSMART"] #substrings that indicate a likely printer SSID  
standaloneIOTsubstrings = [ "RANGE]", "OVEN]", "ARLO", "NGHUB", "LG_", "FRIDGE]", "THERMOSTAT", "WEMO.", "WASHER", "DRYER", "COOKTOP]", "SHARK_", "SPEAKER", "PWRVIEW", "NTGR_VMB", "TESLAWALLCONNECTOR", "NESTHUB", "SMART BULB", "CHIMEPRO", "WYZE", "TESLAPV", "LEDNET", "FS FORTH-SYSTEME", "LINKSPRITE", "WHITE RODGERS"] #substrings that indicate a likely IOT SSID 
if len(sys.argv) < 2:
    print("Usage: analyzeNetworks.py <input binary network array file> <output .txt filename> <options>")
    print("Options: -noPrinters -noDirect -noIOT -noStandard")
 
else:
    if "-noPrinters" in sys.argv: 
        displayPrinterNetworks = False 
    if "-noIOT" in sys.argv: 
        displayIoTNetworks = False 
    if "-noDirect" in sys.argv: 
        displayDirectNetworks = False
    if "-noStandard" in sys.argv: 
        displayStandardNetworks = False
    # Handling display options 
    dataFile = open(sys.argv[1], 'rb')
    networkArray = pickle.load(dataFile)
    for network in networkArray:
        isPrinter = False 
        isDirect = False 
        isIoT = False 
        isStandard = True 
        ssidU = str(network.ssid).upper()
        for string in printerSubstrings:
            if string in ssidU:
                isPrinter = True
                isStandard = False 
        if not isPrinter and "DIRECT-" in ssidU:
            isDirect = True
            isStandard = False 
        for string in standaloneIOTsubstrings:
            if string in ssidU: 
                isDirect = False  
                isStandard = False
                isIoT = True 
        if isPrinter:
            printerNetworkArray.append(network)
            continue 
        if isDirect:
            directNetworkArray.append(network) 
            continue 
        if isIoT: 
            iotNetworkArray.append(network) 
            continue
        if isStandard: 
            standardNetworkArray.append(network)

    outputFile = open(sys.argv[2], "w")
    if displayStandardNetworks:
        outputFile.write("* * * Standard networks ↓ \n")
        for network in standardNetworkArray:
            outputFile.write(net2String(network))
    if displayPrinterNetworks:
        outputFile.write("* * * Printer networks ↓ \n")
        for network in printerNetworkArray:
            outputFile.write(net2String(network)) 
    if displayDirectNetworks:
        outputFile.write("* * * WiFi direct networks ↓ \n") 
        for network in directNetworkArray:
            outputFile.write(net2String(network))
    if displayIoTNetworks:
        outputFile.write("* * * IoT A/P networks ↓ \n")
        for network in iotNetworkArray:
            outputFile.write(net2String(network))
    outputFile.write("* * * * * * Unknown OUIs below. \n")
    for OUI in ouiArray:
        if OUI.name == "Unknown":
            outputFile.write("Name: "+OUI.name+" OUI: "+OUI.oui+" Count: "+str(OUI.count)+" \n")
    outputFile.write("* * * * * * Known OUIs below. \n")
    for OUI in ouiArray:
        if OUI.name != "Unknown":
            outputFile.write("Name: "+OUI.name+" OUI: "+OUI.oui+" Count: "+str(OUI.count)+" \n")
    print("Total device count: "+str(totalDeviceCount)+" Total IoT device count: "+str(totalIoTcount))
    print("Total network count: "+str(len(networkArray))+" Total IoT SSID count: "+str(len(iotNetworkArray))+" Total std. network count: "+str(len(standardNetworkArray)))
            






