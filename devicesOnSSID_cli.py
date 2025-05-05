from collections import Counter
import sys 
from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt 
import manuf 

class Network:
    def __init__(self, ssid):
        self.ssid = ssid
        self.APlist = [] # list to hold all detected accesspoints 
        self.stationList = [] # list to hold all clients in network 
        self.noOfIOT = 0 # number of IOT devices on network detected 
        self.security = ""
    def APinNetwork(self, inAddr):
         for address in self.APlist:
             if inAddr == address:
                 return True
         return False
    def stationInNetwork(self, inAddr):
        if inAddr in self.stationList: 
            return True 
        return False 
class OUI: 
    def __init__(self, name): 
        self.name = name  
        self.count = 1 # simple class to represent OUI 
    def incrementCount(self):
        self.count += 1 #utility method to increment the count of a particular OUI 
    
def getMfgr(mac): 
    p = manuf.MacParser()
    manufacturer = p.get_manuf_long(mac)
    return manufacturer or "Unknown"
def isIOTDevice(mac):
    devMfgr = getMfgr(mac).upper()
      
    iotMfgrs = ["THE CHAMBERLAIN GROUP", "ESPRESSIF INC.", "AMAZON TECHNOLOGIES INC.", "ALARM.COM", "RING LLC", "IROBOT CORPORATION", "TUYA SMART INC", "GENERAL ELECTRIC", "FN-LINK TECHNOLOGY LIMITED", "FACEBOOK INC", "SICHUAN AI-LINK TECHNOLOGY CO", "ECOBEE", "TESLA", "TEXAS INSTRUMENTS", "AURA HOME", "SONOS", "AMPAK TECHNOLOGY", "UNIVERSAL GLOBAL SCIENTIFIC", "HUNAN FN-LINK", "LIFI LABS", "WYZE LABS", "SERCOMM CORP", "ARLO", "DWNET TECHNOLOGIES", "SHENZHEN GIEC", "BOSE CORPORATION", "PART II RESEARCH", "BLINK BY AMAZON", "ROBOROCK", "SEONGJI INDUSTRY COMPANY", "COULOMB TECHNOLOGIES", "ALTOBEAM", "MAYTRONICS", "SKY LIGHT DIGITAL", "GE LIGHTING", "QOLSYS", "SLIM DEVICES INC", "LG INNOTEK", "SMART INNOVATION LLC", "SELECT COMFORT", "SHENZEN APICAL", "NEST LABS", "ORBIT IRRIGATION", "NEURIO TECHNOLOGY INC", "CHENGDU MEROSS", "RAIN BIRD CORPORATION", "SMART INNOVATIONS LLC", "ORBIT IRRIGATION", "INVENTEK", "SIMPLISAFE", "THUNDERCOMM", "AZUREWAVE", "SHENZHEN TROLINK", "DURATECH ENTERPRISE", "NIGHT OWL SP", "LINKSPRITE", "FORTH-SYSTEME", "WHITE RODGERS", "SKYBELL"] 
    for name in iotMfgrs:
        if name in devMfgr: 
            return True 
    return False 
    
def validDeviceAddress(macAddress):
    # determines whether or not a MAC address is multicast/broadcast - a valid
    # device address would contain an OUI 
    oui = macAddress[0:8]
    multicastOUI = ["33:33:00", "ff:ff:ff", "00:00:5e", "01:00:5e", "33:33:ff"]
    # these OUI identify broadcast or multicast MACaddress.
    if oui in multicastOUI:
        return False 
    return True
    

def getDevicesConnectedToNetworks(pcap_file):
    networkArray = [] # array of network   
    dataSenderArray = [] # array of possible client MAC 
    for packet in pcap_file:
        addSSID = True
        # look for beacon frames, check ssid, if network doesnt already exist create it with that ssid 
        if packet.type == 0 and packet.subtype == 8:
            for network in networkArray:
                if packet.info == network.ssid:
                    addSSID = False 
            if addSSID:
                networkArray.append(Network(packet.info))
    

    for packet in pcap_file: 
        if packet.type == 0 and packet.subtype == 8: # Checking for beacon frames 
            for network in networkArray:
                if packet.info == network.ssid and not network.APinNetwork(packet.addr2):
                    # print("Detected SSID: "+packet.info.decode()+" From A/P: "+packet.addr2)
                    netstats = packet.getlayer(Dot11Beacon).network_stats() 
                   # print(netstats['crypto'])
                    network.security = str(netstats['crypto'])
                    network.APlist.append(packet.addr2) # build a picture of what APs are transmitting which SSIDs
# check for packets sent to and from an AP and associate stations talking to an AP with a network 
    for packet in pcap_file: 
        if packet.type == 2: 
 
            for network in networkArray:
                if network.APinNetwork(packet.addr1) and not network.stationInNetwork(packet.addr2):
                    if (validDeviceAddress(packet.addr2)): 
                        # checking for broad/multicast - these are not valid station MAC, so do not count them  
                        network.stationList.append(packet.addr2)
                        if isIOTDevice(packet.addr2):
                            network.noOfIOT += 1 
                elif network.APinNetwork(packet.addr2) and not network.stationInNetwork(packet.addr1):
                    if (validDeviceAddress(packet.addr1)):
                        network.stationList.append(packet.addr1) # dont add broadcast to array of clients as it isn't a valid address and is unhelpful
                        if isIOTDevice(packet.addr1):
                            network.noOfIOT += 1 
    return(networkArray)




            
                    
                



        

            


# Main function of sorts
displayAPMAC = False
displayDeviceMAC = False
showIOT = True
showDirect = True 
showPrinters = True 
showStandard = True  
printerSubstrings = ["EPSON", "PRINT-", "OFFICEJET", "ENVY", "-HP", "LASERJET", "DESKJET", "PRINTER", "BROTHER", "SERIES", "PHOTOSMART"] 
standaloneIOTsubstrings = [ "RANGE]", "OVEN]", "ARLO", "NGHUB", "LG_", "FRIDGE]", "THERMOSTAT", "WEMO.", "WASHER", "DRYER", "COOKTOP]", "SHARK_", "SPEAKER", "PWRVIEW", "NTGR_VMB", "TESLAWALLCONNECTOR", "NESTHUB", "SMART BULB", "CHIMEPRO", "WYZE", "TESLAPV", "LEDNET", "FS FORTH-SYSTEME", "LINKSPRITE", "WHITE RODGERS"] #substrings that indicate a likely IOT network
totalSSIDcount = 0 
iotSSIDcount = 0 
directSSIDcount = 0 
printerSSIDcount = 0 
displayedSSIDcount = 0
totalIOTcount = 0 
totalDeviceCount = 0
iotOUIarray = [] 
# Settings to display AP and station MAC 
if (len(sys.argv) < 2):
    print("Usage: devicesOnSSID.py <pcap file> <options> (Options: -showDeviceMAC, -showAPMAC, -noIOT, -noDirect, -noPrinters, noStandard)")
    sys.exit(1)
else:
    networkArray = getDevicesConnectedToNetworks(rdpcap(sys.argv[1]))
    if "-showDeviceMAC" in sys.argv:
        displayDeviceMAC = True 
    if "-showAPMAC" in sys.argv:
        displayAPMAC = True
    if "-noIOT" in sys.argv: 
        showIOT = False
    if "-noDirect" in sys.argv: 
        showDirect = False
    if "-noPrinters" in sys.argv: 
        showPrinters = False 
    if "-noStandard" in sys.argv: 
        showStandard = False 
    
    for network in networkArray:
        totalSSIDcount += 1 
        printNetwork = True 
        networkType = "Standard WiFi network"
        decodedSSID = network.ssid.decode(errors='ignore') 
        dSSIDupper = decodedSSID.upper() # uppercased SSID for making educated guesses based upon the content of the SSID 
        # order here should be to check for WiFi direct first (since printers *are* wi-fi direct)
 

        if "DIRECT-" in dSSIDupper:
            networkType = "Other WiFi Direct (Device-to-device)"
            directSSIDcount += 1
            if not showDirect:
                printNetwork = False
        for string in printerSubstrings:
            if string in dSSIDupper:
                if "DIRECT-" not in dSSIDupper:
                    directSSIDcount += 1 # printers are wifi direct, not all printer SSID indicate as such, so increment wifi direct even if not explicitly indicated
                networkType = "WiFi Direct (Printer)"
                printerSSIDcount += 1
                if showPrinters and not showDirect:
                    printNetwork = True 
                if not showPrinters: 
                    printNetwork = False 
                break 
        for string in standaloneIOTsubstrings:
            if string in dSSIDupper:
                networkType = "IoT device control or setup"
                iotSSIDcount += 1
                if not showIOT:
                    printNetwork = False
                break
        for device in network.stationList:
            if isIOTDevice(device):
                inArray = False 
                for oui in iotOUIarray:
                    if getMfgr(device) == oui.name:
                        oui.incrementCount() 
                        inArray = True
                if not inArray:
                    iotOUIarray.append(OUI(getMfgr(device))) 
                    #code to build a list of common iot oui 


        totalDeviceCount += len(network.stationList)
        totalIOTcount += network.noOfIOT
        if networkType == "Standard WiFi network" and not showStandard:
            continue  
        if not printNetwork:
            continue  
 # Code to run only if the options specify this SSID is to be output goes below 
   
        print("SSID : "+decodedSSID+" | Devices: "+str(len(network.stationList))+ " | APs: "+str(len(network.APlist)) +" | Likely type: "+networkType+ " | Security: "+network.security +" | No. of IOT devices: "+str(network.noOfIOT))
        displayedSSIDcount += 1 


        
        if displayAPMAC:
            for AP in network.APlist:
                print("Access point in network: " + AP)
        if displayDeviceMAC: 
            for station in network.stationList:
                print(" > Station MAC: " + station + " > Mfgr: "+getMfgr(station) + " > IOT Device? > "+str(isIOTDevice(station)))

    print("Total SSIDs: "+str(totalSSIDcount)+" | WiFi Direct SSIDs: "+str(directSSIDcount)+ " | Printer SSIDs: "+str(printerSSIDcount)+ " | IoT direct SSIDs: "+str(iotSSIDcount))
    #TODO: Make this display an average of Iot devices per home 
    print("Devices: "+str(totalDeviceCount) + " IOT devices: "+str(totalIOTcount))
    print("Displayed "+str(displayedSSIDcount)+" SSIDs. ")
    if showIOT:
        for oui in iotOUIarray:
            print("IoT OUI: "+oui.name+ " Device count: "+ str(oui.count))


