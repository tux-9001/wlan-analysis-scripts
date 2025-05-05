from collections import Counter
import sys 
from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp 
import manuf 
import matplotlib.pyplot as plt  
import numpy as np
import time
import pickle
class Network:
    def __init__(self, ssid, security):
        self.ssid = ssid
        self.APlist = [] # list to hold all detected accesspoints 
        self.stationList = [] # list to hold all clients in network 
        self.security = security
        self.isMesh = False
    def APinNetwork(self, inAddr):
         for address in self.APlist:
             if inAddr == address:
                 return True
         return False
    def stationInNetwork(self, inAddr):
        if inAddr in self.stationList: 
            return True 
        return False 


masterAPlist = []

def deviceAuthenticated(packet, sType):
    # simple utility func to verify device is actually authd 
    if sType != "OPEN": 
        if (packet.FCfield & 0x40) != 0: # checks for protected bit presence in data-frame - in a non-open network, the protected bit is present in exchanged dataframes post auth 

            return True 
        return False
    if sType == "OPEN":
        #but if its open, any dataframe means its associated :)
        return True 
    
def get_encryption(pkt):
    if pkt.haslayer(Dot11Beacon): 
        be = pkt[Dot11Beacon]
    else: 
        be = pkt[Dot11ProbeResp]
    ssid = pkt[Dot11Elt].info.decode(errors="ignore")
   # print(pkt.info)
   # print(str(bool(be.cap & 0x10)))
   # if not (be.cap & 0x10):
    #    return "OPEN"
    
    # walk through all 802.11 IEs
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 48:
            return "WPA2"
        if elt.ID == 221 and elt.info.startswith(b"\x00P\xF2\x01"):
            return "WPA"
        elt = elt.payload.getlayer(Dot11Elt)
    return "OPEN"
def validDeviceAddress(macAddress):
    # determines whether or not a MAC address is multicast/broadcast - a valid
    # device address would contain an OUI 
    oui = macAddress[0:8]
    if macAddress[0:5] == "33:33":
        return False
    # 33:33 is ipv6 multicast, assume invalid 
    multicastOUI = ["33:33:00", "ff:ff:ff", "00:00:5e", "01:00:5e", "33:33:ff", "01:80:c2", "01:00:0c"]
    # these OUI identify broadcast or multicast MACaddress.
    if oui in multicastOUI:
        return False 
    return True
    
def getDevicesConnectedToNetworks(pcap_file):
    networkArray = [] # array of network   
    dataSenderArray = [] # array of possible client MAC
    for packet in pcap_file:
        addSSID = True
        # look for probe-response frames, check ssid, if network doesnt already exist create it with that ssid 
        if packet.type == 0 and packet.subtype == 5:
            for network in networkArray:
                if packet.info == network.ssid:
                    addSSID = False 
            if addSSID:
                print("Probe response found - SSID: "+str(packet.info))
                networkArray.append(Network(packet.info, get_encryption(packet)))
 
    for packet in pcap_file:
        addSSID = True
        # look for beacon frames, check ssid, if network doesnt already exist create it with that ssid 
        if packet.type == 0 and packet.subtype == 8:
            for network in networkArray:
                if packet.info == network.ssid:
                    addSSID = False 
            if addSSID:
                networkArray.append(Network(packet.info, get_encryption(packet)))
    for packet in pcap_file:
        if packet.type == 0 and packet.subtype == 5: # Checking for probe-response frames 
            for network in networkArray:
                if packet.info == network.ssid and not network.APinNetwork(packet.addr2):
                    # print("Detected SSID: "+packet.info.decode()+" From A/P: "+packet.addr2)
                    #netstats = packet.getlayer(Dot11Beacon).network_stats() 
                   # print(netstats['crypto'])
                    #network.security = str(netstats['crypto'])
                    network.APlist.append(packet.addr2) # build a picture of what APs are transmitting which SSIDs
# check for packets sent to and from an AP and associate stations talking to an AP with a network 
   

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
            # print(packet.subtype)
            DS = packet.FCfield & 0x3
            toDS = DS & 0x1 != 0
            fromDS = DS & 0x2 != 0
             # Look for frames going into the DS 
            if toDS and not fromDS:
                #print("To DS, but... " +"to "+str(toDS)+" from "+str(fromDS)+ "Src: "+ packet.addr2+" Dst: "+packet.addr1)
                
                if validDeviceAddress(packet.addr2):
                    for network in networkArray: 
                        if network.APinNetwork(packet.addr1): 
                            if not network.stationInNetwork(packet.addr2) and deviceAuthenticated(packet, network.security):
                                network.stationList.append(packet.addr2)
                               # check for client transmitting packet to AP - addr2 receiver is an AP 

    for packet in pcap_file:
        if packet.type == 2:
            #print(packet.subtype)
            DS = packet.FCfield & 0x3
            toDS = DS & 0x1 != 0
            fromDS = DS & 0x2 != 0
             # Look for frames going out of the DS 
            if not toDS and fromDS:
                # print("Frm DS, but... " +"to "+str(toDS)+" from "+str(fromDS)+ "Src: "+ packet.addr2+" Dst: "+packet.addr1)
                if validDeviceAddress(packet.addr1):
                    for network in networkArray: 
                        if network.APinNetwork(packet.addr2):
                            if not network.stationInNetwork(packet.addr1) and deviceAuthenticated(packet, network.security):
                                network.stationList.append(packet.addr1)
                               # check for AP transmitting packet to client - addr1 source is an AP 
                            

 

      
            elif toDS and fromDS:
                #If both to/from DS flags raised, mesh network, both sides AP in same network
                print ("Both flags raised!")
                for network in networkArray:
                    if network.APinNetwork(packet.addr1) or network.APinNetwork(packet.addr2):
                        network.isMesh = True 

  
            if not toDS and not fromDS:
                print("Neither flag raised ?")
                pass  


    return(networkArray)




            
                    
                



        

            

def netType(ssid):
    ssid = str(ssid).upper()
    print(ssid)
    standaloneIOTsubstrings = [ "RANGE]", "OVEN]", "ARLO", "NGHUB", "LG_", "FRIDGE]", "THERMOSTAT", "WEMO.", "WASHER", "DRYER", "COOKTOP]", "SHARK_", "SPEAKER", "PWRVIEW", "NTGR_VMB", "TESLAWALLCONNECTOR", "NESTHUB", "SMART BULB", "CHIMEPRO", "WYZE", "TESLAPV", "LEDNET", "FS FORTH-SYSTEME", "LINKSPRITE", "WHITE RODGERS"] #substrings that indicate a likely IOT network
    printerSubstrings = ["EPSON", "PRINT-", "OFFICEJET", "ENVY", "-HP", "LASERJET", "DESKJET", "PRINTER", "BROTHER", "SERIES", "PHOTOSMART"] 
    for name in printerSubstrings:
        if name in ssid:
            return "Printer"
    if "DIRECT-" in ssid:
        return "Direct (Other)"
    for name in standaloneIOTsubstrings: 
        if name in ssid:
            print("IOT "+ssid)
            return "IoT"







    return "Standard"
# Main function of sorts
showEmpty = False 
showDirect = True 
showPrinters = True 
showStandard = True  

totalSSIDcount = 0 
iotSSIDcount = 0 
directSSIDcount = 0 
printerSSIDcount = 0 
displayedSSIDcount = 0
totalIOTcount = 0 
totalDeviceCount = 0

# Settings to display AP and station MAC 
if (len(sys.argv) < 3):
    print("Usage: readNetworks.py <input pcap file> <output binary file name>")

    print("This utility builds a picture of networks and devices connected to them by reading beaconframes for SSID, then output them to a file")
    sys.exit(1)
else:
    start = time.time()
    print("Beginning analysis...")

    networkArray = getDevicesConnectedToNetworks(rdpcap(sys.argv[1]))
    originLength = len(networkArray)
    
    networkArray = list(filter(lambda network : (len(network.stationList) != 0) or (netType(network.ssid) != "Standard"), networkArray)) 

    
  #  for network in networkArray:
  #      print("SSID: "+str(network.ssid)+" Devices: "+str(len(network.stationList)))
    outFile = open(sys.argv[2], 'ab')
    pickle.dump(networkArray, outFile)
    outFile.close()
    end = time.time()
    print("Found "+str(originLength)+" networks in "+str(end - start) +" seconds. Wrote "+str(len(networkArray))+" networks to output")
    




  

 



