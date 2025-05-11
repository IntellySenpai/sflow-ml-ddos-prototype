import json
import threading
from config import *
from utils import *
from external_checks import *

# Stores state per agent
agent_state = {}  # { agent: { "bucket": [], "ready": False } }

# Total packets counter.
total_packets = 0
total_packets_lock = threading.Lock()

def parse_flow_metric(timestamp, sflow_log):
    """Function to parse sFlow metrics."""
    parts = sflow_log.strip().split(",")

    # Prepend timestamp and create tuple
    values = [timestamp, *parts]

    # Add None values at the end
    values_with_padding = values + [None,] * 5

    return values_with_padding


def process_bucket(agent, bucket):
    """Process a bucket of sFlow metrics belonging to an agent. One bucket consists
    of FLOW packet samples obtained between two CNTR interface counters."""
    global total_packets

    if len(bucket) < 2:
        return

    # Compute metrics and get bucket total packets
    interface_metrics, bucket_packets = compute_cntr_metrics(bucket[0], bucket[-1])

    # Update global counter safely
    with total_packets_lock:
        total_packets += bucket_packets

    # Process FLOW packet samples
    for flow in bucket[1:-2]:
        flow.extend([0] * 48)
        # Add interface counters processed metrics.
        flow[21:32] = interface_metrics[:11]
        # Add counter of packets.
        flow[73] = total_packets

        # Check if Ethertype is IPv4
        if flow[7] == "0x0800":
            flow[36] = 1
            # Store IP Source Address
            src_ip = flow[10]
            flow[32] = 0 if is_private_ipv4(src_ip) else 1
            # Enrich using source IP address
            if flow[32] == 1:
                enrich_based_on_src_ip(src_ip, flow)

            # Store IP Protocol Number
            ip_proto = flow[12]

            # IP Protocol is TCP
            if ip_proto == '6':
                flow[33] = 1
                check_tcp_udp_ports(flow[15], flow)
                check_tcp_udp_ports(flow[16], flow)
                are_ports_well_known(flow[15], flow[16], flow)
                parse_tcp_flags(flow[17], flow)
            # IP Protocol is UDP
            elif ip_proto == '17':
                flow[34] = 1
                check_tcp_udp_ports(flow[15], flow)
                check_tcp_udp_ports(flow[16], flow)
                are_ports_well_known(flow[15], flow[16], flow)
            # IP Protocol is ICMP
            elif ip_proto == '1':
                flow[34] = 1
                get_icmp_data(int(flow[15]), int(flow[16]), flow)
            # Other L4 protocol
            else:
                flow[37] = 1
        else:
            flow[36] = 0

        # Sent to preprocessor-2 via UDP
        socket_send.sendto(str(flow).encode('utf-8'), (UDP_IP_PREPROCESSOR_2, UDP_PORT_PREPROCESSOR_2))


# TODO ['2025-04-16T18:16:24Z', 'FLOW', '10.0.1.100', '0', '0', '985d82115449', '00163e0decf2', '0x0800', '0', '0', '142.252.218.157', '10.10.10.10', '6', '0x00', '121', '80', '58114', '0x12', '62', '44', '1', '204.2', '1481.2', '3.5', '4.4', '0', '0', '0.0', '0', '0', '0.0', '0.0', 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '10', None, False, 0, 0, 0, 0, 0, 0, 0]
# TODO REMOVE THE FALSE AND OTHER TYPES OF DATA TYPES FROM EXTERNAL CHECKS!!!

# Create UDP Thread.
print(f"Listening for sFlow logs on UDP {UDP_PORT}...")
while True:
    data, addr = sock.recvfrom(65535)
    try:
        line = data.decode('utf-8')
        parts = line.split(" ")
        timestamp = parts[1]
        # Parse and process sFlow metrics.
        flow_data = " ".join(parts[7:])
        flow_data = parse_flow_metric(timestamp, flow_data)
        # Store metric type: CNTR or FLOW.
        log_type = flow_data[1]

        # Ignore "CNTR" flows with no interface index like:
        # ['2025-04-08T17:48:33Z', 'CNTR', '10.0.1.100', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0']
        if log_type == "CNTR" and flow_data[3] == '0':
            continue  # Skip this line and process the next one

        # Store Agent IP Address
        agent = flow_data[2]

        # Initialize agent state
        if agent not in agent_state:
            agent_state[agent] = {"bucket": [], "ready": False}

        state = agent_state[agent]

        if log_type == "CNTR":
            if not state["ready"]:
                # First CNTR seen
                state["bucket"] = [flow_data]
                state["ready"] = True
            else:
                # Closing previous bucket, start new one
                state["bucket"].append(flow_data)
                bucket_to_process = state["bucket"][:]

                # Process in a background thread
                threading.Thread(target=process_bucket, args=(agent, bucket_to_process)).start()

                # Start next bucket with this CNTR
                state["bucket"] = [flow_data]

        elif log_type == "FLOW" and state["ready"]:
            state["bucket"].append(flow_data)

    except Exception as e:
        print(f"Error parsing incoming data: {e}")


