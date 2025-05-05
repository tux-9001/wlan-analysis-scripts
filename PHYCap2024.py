from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt

def phy_protocol_distribution_and_examples(pcap_file):
    packets = rdpcap(pcap_file)

    # Stores the highest PHY supported by each unique BSSID
    highest_phy_per_ap = {}

    for packet in packets:
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr2  # BSSID of the AP
            elements = packet.getlayer(Dot11Elt)  # Access the first Dot11Elt

            # Flags for detecting PHY support
            has_ht_capabilities = False
            has_vht_capabilities = False
            has_he_capabilities = False  # Correctly identifying 802.11ax (HE)

            while isinstance(elements, Dot11Elt):
                if elements.ID == 45:  # HT Capabilities
                    has_ht_capabilities = True
                elif elements.ID == 191:  # VHT Capabilities
                    has_vht_capabilities = True
                elif elements.ID == 255:  # Check for Extended Tag
                    if len(elements.info) > 0 and elements.info[0] == 35:  # HE Capabilities, considering the first byte as the Ext Tag Number
                        has_he_capabilities = True

                elements = elements.payload  # Move to the next element

            # Update the highest PHY supported
            if has_he_capabilities:  # Setting 802.11ax based on HE Capabilities
                highest_phy_per_ap[bssid] = '802.11ax'
            elif has_vht_capabilities:
                highest_phy_per_ap[bssid] = '802.11ac'
            elif has_ht_capabilities:
                highest_phy_per_ap[bssid] = '802.11n'
            else:
                highest_phy_per_ap.setdefault(bssid, '802.11a/g')

    # Find an example BSSID for each PHY type
    example_bssids = {}
    for bssid, phy in highest_phy_per_ap.items():
        if phy not in example_bssids:  # If an example for this PHY hasn't been added yet
            example_bssids[phy] = bssid

    # Count the occurrence of each PHY
    phy_distribution = {phy: list(highest_phy_per_ap.values()).count(phy) for phy in set(highest_phy_per_ap.values())}

    total_aps = len(highest_phy_per_ap)

    # Display the PHY distribution and example BSSIDs
    print("PHY Protocol Distribution among APs and Example BSSIDs:")
    for phy, count in phy_distribution.items():
        percentage = (count / total_aps) * 100 if total_aps > 0 else 0
        example_bssid = example_bssids.get(phy, 'N/A')
        print(f"{phy}: {count} APs ({percentage:.2f}%) - Example BSSID: {example_bssid}")

# Example usage
pcap_file_path = input("Enter the path to your PCAP file: ")
phy_protocol_distribution_and_examples(pcap_file_path)
