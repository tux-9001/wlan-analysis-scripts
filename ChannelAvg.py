import pyshark
from collections import Counter

def capture_and_find_top_channels(pcap_file):
    channel_list = []


    cap = pyshark.FileCapture(pcap_file)

    for packet in cap:
        wlan_radio = packet.wlan_radio
        if wlan_radio and hasattr(wlan_radio, 'channel'):
            channel = wlan_radio.channel
            channel_list.append(int(channel))


    cap.close()

    # Count the occurrence of each channel
    channel_counts = Counter(channel_list)

    # Find the top 3 channels
    top_channels = channel_counts.most_common(3)

    return top_channels


pcap_file = input("Enter the path to the pcap file: ")

# Call the function to capture channels and find the top 3
top_channels = capture_and_find_top_channels(pcap_file)

print("Top 3 Channels Used:")
for channel, count in top_channels:
    print(f"Channel {channel}: {count} packets")
