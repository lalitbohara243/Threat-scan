import pyshark
import time
import matplotlib.pyplot as plt
from tabulate import tabulate

def capture_packets(interface, packet_count=50):
    """
    Captures network packets and updates the plots with packet information.

    Args:
        interface (str): The network interface to capture packets from.
        packet_count (int): The maximum number of packets to capture.
    """
    # Create a live packet capture object
    capture = pyshark.LiveCapture(interface=interface)
    start_time = time.time()

    packet_info_list = []  # List to store packet information
    total_bandwidth_utilization = 0
    packets_sent = 0

    # Create subplots for histogram, pie chart, and statistical values
    fig, axes = plt.subplots(2, 2, figsize=(10, 8))
    histogram_axes = axes[0, 0]
    pie_axes = axes[0, 1]
    statistical_values_text = axes[1, 0]

    # Remove the empty subplot
    fig.delaxes(axes[1, 1])

    for packet in capture.sniff_continuously():
        # Analyze the packet and store the information
        packet_info = analyze_packet(packet)
        packet_info_list.append(packet_info)
        total_bandwidth_utilization += packet_info['Packet Length']
        packets_sent += 1

        # Update and display the plots
        update_plots(packet_info_list, total_bandwidth_utilization, packets_sent, start_time, histogram_axes, pie_axes, statistical_values_text)

        # Break the loop after reaching the packet_count
        if packets_sent >= packet_count:
            break

    # Print packet information in a table
    print_packet_info_table(packet_info_list)

    # Keep the plot window open
    plt.show(block=True)


def analyze_packet(packet):
    """
    Analyzes a network packet and extracts specific information.

    Args:
        packet: The network packet object.

    Returns:
        dict: Packet information including source IP, destination IP, protocol, packet length, DNS query, and DNS response.
    """
    packet_info = {
        'Source IP': packet.ip.src if hasattr(packet, 'ip') else 'N/A',
        'Destination IP': packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
        'Protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else 'None',
        'Packet Length': int(packet.length),
        'DNS Query': packet.dns.qry_name if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name') else 'N/A',
        'DNS Response': packet.dns.resp_name if hasattr(packet, 'dns') and hasattr(packet.dns, 'resp_name') else 'N/A'
    }

    return packet_info


def print_packet_info_table(packet_info_list):
    """
    Prints packet information in a table.

    Args:
        packet_info_list (list): List of packet information dictionaries.
    """
    headers = ['Source IP', 'Destination IP', 'Protocol', 'Packet Length', 'DNS Query', 'DNS Response']
    data = [[packet_info.get(header, 'N/A') for header in headers] for packet_info in packet_info_list]

    print(tabulate(data, headers=headers, tablefmt='fancy_grid'))


def update_histogram(packet_info_list, histogram_axes):
    """
    Updates the histogram plot with packet length information.

    Args:
        packet_info_list (list): List of packet information dictionaries.
        histogram_axes: Axes object for the histogram plot.
    """
    histogram_axes.clear()
    packet_lengths = [int(packet_info['Packet Length']) for packet_info in packet_info_list]
    histogram_axes.hist(packet_lengths, bins=10, alpha=0.5)
    histogram_axes.set_xlabel('Packet Length')
    histogram_axes.set_ylabel('Frequency')
    histogram_axes.set_title('Distribution of Packet Lengths')


def update_pie_chart(packet_info_list, pie_axes):
    """
    Updates the pie chart plot with protocol distribution information.

    Args:
        packet_info_list (list): List of packet information dictionaries.
        pie_axes: Axes object for the pie chart plot.
    """
    pie_axes.clear()
    protocols = {}
    for packet_info in packet_info_list:
        protocol = packet_info['Protocol']
        protocols[protocol] = protocols.get(protocol, 0) + 1

    labels = list(protocols.keys())
    counts = list(protocols.values())
    pie_axes.pie(counts, labels=labels, autopct='%1.1f%%', startangle=90)
    pie_axes.set_title('Protocol Distribution')


def update_statistical_values(packet_info_list, total_bandwidth_utilization, packets_sent, start_time, statistical_values_text):
    """
    Updates the statistical values displayed in the plot.

    Args:
        packet_info_list (list): List of packet information dictionaries.
        total_bandwidth_utilization (int): Total bandwidth utilization.
        packets_sent (int): Total packets sent.
        start_time (float): Start time of packet capture.
        statistical_values_text: Text object for displaying statistical values.
    """
    statistical_values_text.clear()

    # Calculate statistical values
    packet_count = len(packet_info_list)
    capture_duration = time.time() - start_time
    packet_rate = round(packets_sent / capture_duration, 2)
    avg_packet_length = round(total_bandwidth_utilization / packet_count, 2)
    avg_bandwidth_utilization = round(total_bandwidth_utilization / capture_duration, 2)

    # Display statistical values
    statistical_values_text.axis('off')
    statistical_values_text.text(0.5, 0.5,
                                 f"Total Packets Sent: {packets_sent}\n"
                                 f"Packet Rate: {packet_rate} packets/second\n"
                                 f"Avg. Packet Length: {avg_packet_length} bytes\n"
                                 f"Avg. Bandwidth Utilization: {avg_bandwidth_utilization} bytes/second",
                                 fontsize=12, verticalalignment='center')


def update_plots(packet_info_list, total_bandwidth_utilization, packets_sent, start_time, histogram_axes, pie_axes, statistical_values_text):
    """
    Updates all plots with the latest packet information and statistical values.

    Args:
        packet_info_list (list): List of packet information dictionaries.
        total_bandwidth_utilization (int): Total bandwidth utilization.
        packets_sent (int): Total packets sent.
        start_time (float): Start time of packet capture.
        histogram_axes: Axes object for the histogram plot.
        pie_axes: Axes object for the pie chart plot.
        statistical_values_text: Text object for displaying statistical values.
    """
    # Update the plots with new data
    update_histogram(packet_info_list, histogram_axes)
    update_pie_chart(packet_info_list, pie_axes)
    update_statistical_values(packet_info_list, total_bandwidth_utilization, packets_sent, start_time, statistical_values_text)
    plt.pause(0.01)  # Pause to allow the plots to be updated


def initialize_network_monitor():
    """
    Initializes and starts the network monitoring process.
    """
    interface = "Wi-Fi"  # Replace with your actual interface name
    capture_packets(interface, packet_count=50)  # Capture50 packets

if __name__ == "__main__":
    initialize_network_monitor()
