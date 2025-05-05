from collections import Counter
import sys 
from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt 
import manuf 
import matplotlib.pyplot as plt  
import numpy as np
import pandas as pd 
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
def categorizeIoTdevice(mac):
    mfgr = getMfgr(mac).upper()
    print(mfgr)
    iotCameraOUIs = ["WYZE", "SKYBELL", "RING", "BLINK BY AMAZON", "ARLO", "REOLINK", "NIGHT OWL SP", "DWNET", "DURATECH"]
    smallDeviceOUIs = ["ESPRESSIF", "SELECT COMFORT", "WIZ", "PART II RESEARCH", "LIFI LABS", "GENERAL ELECTRIC", "GE LIGHTING", "SERCOMM"]
    evChargingOUIs = ["TESLA", "NEURIO"]
    homeMgmtOUIs = ["ROBOROCK", "IROBOT", "ORBIT IRRIGATION", "RAIN BIRD"]
    securityOUIs = ["SIMPLISAFE", "ALARM.COM", "CHAMBERLAIN"]
    for name in iotCameraOUIs:
        if name in mfgr: 
            return "camera"
    for name in smallDeviceOUIs:
        if name in mfgr: 
            return "smalldevice"
    for name in evChargingOUIs:
        if name in mfgr: 
            return "EVcharging"
    for name in homeMgmtOUIs:
        if name in mfgr:
            return "homemgmt" 
    for name in securityOUIs:
        if name in mfgr:
            return "security"
    return "other"

class dataFile:
    def __init__(self, name, cameraCount, smallDeviceCount, evChargingCount, homeMgmtCount, securityCount, totalIoTCount, totalDeviceCount):
        self.name = name # holds the name of the origin file 
        self.cameraCount = cameraCount
        self.smallDeviceCount = smallDeviceCount 
        self.evChargingCount = evChargingCount 
        self.homeMgmtCount = homeMgmtCount 
        self.securityCount = securityCount 
        self.totalIoTCount = totalIoTCount 
        self.totalDeviceCount = totalDeviceCount
       dataFileArray = []
labelArray = []
processedFileArray = []

if len(sys.argv) < 2: 
    print("Usage: categorizeDevices.py <input binary data file 1> <input binary data file 2> .. additional binary data files ")
    print("To add labels, use the option -labels <label for datafile 1> <label for datafile 2> .. additional label for datafile")
     
    sys.exit(-1)
else:
    labels = False  
    for i in range(1, len(sys.argv)):
        string = sys.argv[i]
        if string != "-labels":
            print(string)
            f = open(string, 'rb')
            dataFileArray.append(f)
            #open the data files 
        if string == "-labels":
            break
        # labels are not data files - -labels terminates the commandline args 
    for string in sys.argv:
        if string == "-labels":
            labels = True #dont do anything until the labels portion of the arglist is reached 
            continue
        if labels:
            labelArray.append(string) 
 
    for file in dataFileArray:
        networkArray = pickle.load(file)
        cameraCount = 0 
        smallDeviceCount = 0 
        homeMgmtCount = 0
        securityCount = 0 
        evChargingCount = 0 
        totalDeviceCount = 0 
        totalIoTcount = 0 
        for network in networkArray:
            hasCamera = False
            hasSmallDevice = False 
            hasEVcharging = False 
            hasHomeMgmt = False 
            hasSecurity = False 
            hasGenIoT = False 
            for device in network.stationList:
                totalDeviceCount += 1 
                if isIOT(device):
                    hasGenIoT = True 
                    category = categorizeIoTdevice(device)
                    #print(category)
                    if category == "camera":
                        hasCamera = True 
                    if category == "smalldevice": 
                        hasSmallDevice = True  
                    if category == "EVcharging":
                        hasEVcharging = True  
                    if category == "homemgmt":
                        hasHomeMgmt = True  
                    if category == "security":
                        hasSecurity = True
            if hasCamera:
                cameraCount += 1 
            if hasSmallDevice:
                smallDeviceCount += 1 
            if hasEVcharging:
                evChargingCount += 1 
            if hasHomeMgmt:
                homeMgmtCount += 1 
            if hasSecurity: 
                securityCount += 1
            if hasGenIoT:
                totalIoTcount += 1 
        df = dataFile(file.name, cameraCount, smallDeviceCount, evChargingCount, homeMgmtCount, securityCount, totalIoTcount, totalDeviceCount)
        processedFileArray.append(df)
        x = np.zeros((len(dataFileArray), 6))
        y = []
        count = 0 
        for df in processedFileArray:

            x[count, 0] = df.cameraCount
            x[count, 1] = df.smallDeviceCount 
            x[count, 2] = df.evChargingCount
            x[count, 3] = df.homeMgmtCount 
            x[count, 4] = df.securityCount
            x[count, 5] = df.totalIoTCount
            count += 1 
    for i in range(0, len(processedFileArray)):
        if i < len(labelArray): 
            y.append(labelArray[i])
        else:
            y.append("-") # setup labels on the graph
print(x)
for df in processedFileArray:
        print(df.name)
        print("Cameras: "+str(df.cameraCount)+" Small devices: "+str(df.smallDeviceCount)+" EV charging: "+str(df.evChargingCount)+" Home mgmt: "+str(df.homeMgmtCount)+" Security: "+str(df.securityCount)+ " General IoT: "+str(df.totalIoTCount))
df = pd.DataFrame(x,
                 index=y,
                 columns=pd.Index(['Cams', 'Pwr', 'EV.', 'HmMnt.', 'Sec.', 'GenIoT'], 
                 name='SSID with types of IoT devices')).round(2)
 # print info to console 

df.plot(kind='bar',figsize=(10,4), width=.75)

ax = plt.gca()
pos = []
for bar in ax.patches:
    pos.append(bar.get_x()+bar.get_width()/2.)


ax.set_xticks(pos,minor=True)
lab = []
for i in range(len(pos)):
    l = df.columns.values[i//len(df.index.values)]
    lab.append(l)

ax.set_xticklabels(lab,minor=True)
ax.tick_params(axis='x', which='major', pad=15, size=2)
plt.setp(ax.get_xticklabels(), rotation=0)

plt.show()

        
        
    





    

