import pyshark


def get_top_encryption_methods(pcap_file):
    # Create a dictionary to store encryption methods and their counts
    encryption_counts = {}

    # Open the PCAP file
    cap = pyshark.FileCapture(pcap_file)

    # Iterate through packets in the PCAP file
    for packet in cap:
        try:


            # Check if the packet has the wlan.mgt layer and the wlan_rsn_akms_list attribute
            if 'wlan.mgt' in packet and 'wlan_rsn_akms_list' in packet['wlan.mgt'].field_names:
                wlan_mgt = packet['wlan.mgt']
                encryption_method = wlan_mgt.wlan_rsn_akms_list

                # Update the count for the encryption method in the dictionary
                if encryption_method in encryption_counts:
                    encryption_counts[encryption_method] += 1
                else:
                    encryption_counts[encryption_method] = 1
        except AttributeError:
            # Skip packets that don't have the 'wlan.mgt' layer
            continue

    cap.close()

    # Sort the encryption methods by count in descending order
    sorted_encryption_methods = sorted(encryption_counts.items(), key=lambda x: x[1], reverse=True)

    # Return the top 3 encryption methods
    return sorted_encryption_methods[:3]


pcap_file = input("Enter the path to the PCAP file: ")

top_encryption_methods = get_top_encryption_methods(pcap_file)

print("Top 3 Encryption Methods:")
for method, count in top_encryption_methods:
    print(f"{method}: {count} packets")