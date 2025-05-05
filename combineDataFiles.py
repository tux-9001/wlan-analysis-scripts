
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

if len(sys.argv) < 4: 
    print("Usage: combineDataFiles.py <binary datafile 1> <binary datafile 2> <output file> -chkDupes")
else: 
    input1 = open(sys.argv[1], 'rb')
    input2 = open(sys.argv[2], 'rb')
    output = open(sys.argv[3], 'wb')
    arr1 = pickle.load(input1) 
    arr2 = pickle.load(input2)
    outArr = []
    if "-chkDupes" in sys.argv:
        print("Using duplicate-checking (slightly slower) logic")
        for network in arr1:
            outArr.append(network)
        for network in arr2: 
            addNet = True 
            for net in outArr:
                if net.ssid == network.ssid:
                    for station in network.stationList:
                        if station not in net.stationList: 
                            net.stationList.append(station)
                        else: 
                            print("Duplicate STA "+station)
                    addNet = False 
                    # checking for duplicates - combine the station list if they're same, but don't add a duplicate entry. 
            if addNet: 
                outArr.append(network)
    if "-chkDupes" not in sys.argv:
        outArr = arr1+arr2 
    pickle.dump(outArr, output)
