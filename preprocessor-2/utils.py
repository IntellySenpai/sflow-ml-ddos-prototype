from config import *
import socket
import threading
import time
import ast
from datetime import datetime, timedelta
import numpy as np
import psycopg2
import os

LOG_FILE_PATH = os.environ.get("LOG_FILE_PATH", "./logs/output.log")

# Global metadata dictionary and a lock for thread-safe access.
# Each flow_id maps to a dictionary with its state info.
metadata = {}
metadata_lock = threading.Lock()
datapath_id_counter = 1
total_samples = 0

# Create persistent connection to TimescaleDB.
conn.autocommit = True


def convert_row_to_dict(row, header):
    """
    Converts a list (row) to a dictionary using the provided header list.
    """
    if len(row) < len(header):
        print("Row has fewer elements than expected!")
        return None
    return dict(zip(header, row))


def parse_timestamp(ts_str):
    """
    Parses a timestamp string of the form "2025-04-17T20:40:17Z".
    The "Z" is converted to UTC offset.
    """
    try:
        # Replace 'Z' with '+00:00' to indicate UTC.
        ts_str = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str)
    except Exception as e:
        print(f"Error parsing timestamp '{ts_str}': {e}")
        return datetime.utcnow()


def enrich_record(record):
    """
    Computes and adds new columns to the record, and updates metadata.
    New columns:
      - flow_id: Concatenation of src_ip (from "src_ip"),
                 udp_src_port_tcp_src_port_icmp_type,
                 dst_ip, and udp_dst_port_tcp_dst_port_icmp_code.
      - datapath_id: Unique ID per unique flow.
      - flow_duration_sec: Difference (in seconds) between the current timestamp
                           and the first timestamp for this flow.
      - sample_class_count: Number of times the same sample (flow) is found.
      - sample_class_byte_count: Sum of packet sizes for this sample class.
      - avg_class_packet_size: sample_class_byte_count divided by sample_class_count.
      - sample_class_packets: (sample_class_count / total_samples) multiplied by record["total_number_of_packets"].
      - sample_class_bytes: avg_class_packet_size multiplied by sample_class_packets.
    """
    global datapath_id_counter, total_samples

    # Increment total samples processed.
    total_samples += 1

    # Parse the timestamp.
    ts = parse_timestamp(record.get("timestamp", ""))

    # Use the relevant fields from the record.
    src_ip = record.get("src_ip", "")
    dst_ip = record.get("dst_ip", "")
    udp_src_port = record.get("udp_src_port_tcp_src_port_icmp_type", "")
    udp_dst_port = record.get("udp_dst_port_tcp_dst_port_icmp_code", "")

    # Create the flow_id by concatenating the selected fields.
    flow_id = f"{src_ip}{udp_src_port}{dst_ip}{udp_dst_port}"
    record["flow_id"] = flow_id

    # Convert packet_size (stored under key "packet_size") to integer.
    try:
        packet_size = int(record.get("packet_size", 0))
    except Exception:
        packet_size = 0

    with metadata_lock:
        if flow_id not in metadata:
            # New sample: initialize metadata for this flow.
            metadata[flow_id] = {
                "datapath_id": datapath_id_counter,
                "start_time": ts,
                "last_seen": ts,
                "sample_class_count": 1,
                "sample_class_byte_count": packet_size
            }
            record["datapath_id"] = datapath_id_counter
            datapath_id_counter += 1
            flow_duration_sec = 0.0
            sample_class_count = 1
            sample_class_byte_count = packet_size
        else:
            # Existing sample: update its counters.
            flow_data = metadata[flow_id]
            record["datapath_id"] = flow_data["datapath_id"]
            flow_duration_sec = (ts - flow_data["start_time"]).total_seconds()
            sample_class_count = flow_data["sample_class_count"] + 1
            sample_class_byte_count = flow_data["sample_class_byte_count"] + packet_size

            # Update metadata.
            flow_data["sample_class_count"] = sample_class_count
            flow_data["sample_class_byte_count"] = sample_class_byte_count
            flow_data["last_seen"] = ts

    # Calculate derived metrics.
    avg_class_packet_size = sample_class_byte_count / sample_class_count if sample_class_count > 0 else np.nan

    # It is assumed that record contains a value for the total number of packets.
    total_number_of_packets = record.get("total_number_of_packets", 0)
    sample_class_packets = (sample_class_count / total_samples) * total_number_of_packets if total_samples > 0 else np.nan
    sample_class_bytes = avg_class_packet_size * sample_class_packets if not np.isnan(avg_class_packet_size) else np.nan

    # Add the computed values to the record.
    record["flow_duration_sec"] = flow_duration_sec
    record["sample_class_count"] = sample_class_count
    record["sample_class_byte_count"] = sample_class_byte_count
    record["avg_class_packet_size"] = avg_class_packet_size
    record["sample_class_packets"] = sample_class_packets
    record["sample_class_bytes"] = sample_class_bytes

    return record


def insert_into_db(record):
    """
    Inserts a record into the 'sflow_data' table.
    The record should contain all the fields listed in the INSERT statement.
    """
    query = """
    INSERT INTO sflow_data (
        timestamp, type, agent_ip, inputPort, outputPort, src_mac, dst_mac,
        ethernet_type, in_vlan, out_vlan, src_ip, dst_ip, ip_protocol, ip_tos, ip_ttl,
        udp_src_port_tcp_src_port_icmp_type, udp_dst_port_tcp_dst_port_icmp_code,
        tcp_flags, packet_size, ip_size, sampling_rate,
        avg_ingress_unicast_pps, avg_egress_unicast_pps, avg_ingress_multicast_pps,
        avg_egress_multicast_pps, avg_ingress_broadcast_pps, bucket_number_of_packets,
        avg_ingress_bytes_per_second, avg_egress_bytes_per_second,
        avg_ingress_discards_per_second, avg_ingress_errors_per_second,
        avg_ingress_unknown_per_second, is_public_ip, is_tcp, is_udp, is_icmp,
        is_l3_ip_protocol, is_other_l4_protocol, is_tor_exit_node, is_user_whitelisted,
        is_src_port_well_known, is_dst_port_well_known, is_chargen, is_dns, is_dhcp,
        is_http, is_ntp, is_netbios, is_snmp, is_ssdp, is_ldap, is_smb, is_https,
        is_memcached, is_ldaps, is_tcp_syn, is_tcp_synack, is_tcp_ack, is_tcp_rst,
        is_tcp_fin, is_tcp_bogus_flags, is_icmp_request, is_icmp_echo_reply,
        is_icmp_dest_unreachable, is_icmp_redirect, is_icmp_time_exceeded,
        is_icmp_mask_request, is_icmp_timestamp_request, abuseipdb_score,
        abuseipdb_usage_type, abuseipdb_whitelist, abuseipdb_tor, abuseipdb_reports,
        total_number_of_packets, flow_id, datapath_id, flow_duration_sec,
        sample_class_count, sample_class_byte_count, avg_class_packet_size,
        sample_class_packets, sample_class_bytes
    )
    VALUES (
        %(timestamp)s, %(type)s, %(agent_ip)s, %(inputPort)s, %(outputPort)s, %(src_mac)s, %(dst_mac)s,
        %(ethernet_type)s, %(in_vlan)s, %(out_vlan)s, %(src_ip)s, %(dst_ip)s, %(ip_protocol)s,
        %(ip_tos)s, %(ip_ttl)s, %(udp_src_port_tcp_src_port_icmp_type)s,
        %(udp_dst_port_tcp_dst_port_icmp_code)s, %(tcp_flags)s, %(packet_size)s, %(ip_size)s,
        %(sampling_rate)s, %(avg_ingress_unicast_pps)s, %(avg_egress_unicast_pps)s,
        %(avg_ingress_multicast_pps)s, %(avg_egress_multicast_pps)s,
        %(avg_ingress_broadcast_pps)s, %(bucket_number_of_packets)s,
        %(avg_ingress_bytes_per_second)s, %(avg_egress_bytes_per_second)s,
        %(avg_ingress_discards_per_second)s, %(avg_ingress_errors_per_second)s,
        %(avg_ingress_unknown_per_second)s, %(is_public_ip)s, %(is_tcp)s, %(is_udp)s,
        %(is_icmp)s, %(is_l3_ip_protocol)s, %(is_other_l4_protocol)s,
        %(is_tor_exit_node)s, %(is_user_whitelisted)s, %(is_src_port_well_known)s,
        %(is_dst_port_well_known)s, %(is_chargen)s, %(is_dns)s, %(is_dhcp)s, %(is_http)s,
        %(is_ntp)s, %(is_netbios)s, %(is_snmp)s, %(is_ssdp)s, %(is_ldap)s, %(is_smb)s,
        %(is_https)s, %(is_memcached)s, %(is_ldaps)s, %(is_tcp_syn)s, %(is_tcp_synack)s,
        %(is_tcp_ack)s, %(is_tcp_rst)s, %(is_tcp_fin)s, %(is_tcp_bogus_flags)s,
        %(is_icmp_request)s, %(is_icmp_echo_reply)s, %(is_icmp_dest_unreachable)s,
        %(is_icmp_redirect)s, %(is_icmp_time_exceeded)s, %(is_icmp_mask_request)s,
        %(is_icmp_timestamp_request)s, %(abuseipdb_score)s, %(abuseipdb_usage_type)s,
        %(abuseipdb_whitelist)s, %(abuseipdb_tor)s, %(abuseipdb_reports)s,
        %(total_number_of_packets)s, %(flow_id)s, %(datapath_id)s, %(flow_duration_sec)s,
        %(sample_class_count)s, %(sample_class_byte_count)s, %(avg_class_packet_size)s,
        %(sample_class_packets)s, %(sample_class_bytes)s
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(query, record)
        conn.commit()
    except Exception as e:
        print(f"Error inserting record: {e}")
    finally:
        cursor.close()


def log_message(message):
    with open(LOG_FILE_PATH, "a") as log_file:
        log_file.write(message + "\n")


def process_log_row(row_str):
    """
    Expects row_str to be a string representation of a Python list (as you receive from syslog).
    Converts it into a dictionary using the HEADER, enriches it with new columns, and
    then (optionally) inserts it into the database.
    """
    try:
        # Safely convert the incoming string to a Python list.
        row = ast.literal_eval(row_str)
    except Exception as e:
        print(f"Error parsing row: {e}")
        return

    record = convert_row_to_dict(row, HEADER)
    if record is None:
        return

    # Enrich the record by computing new columns and updating metadata.
    enriched_record = enrich_record(record)

    # For demonstration, print the enriched record.
    print("Enriched Record")
    log_message(str(enriched_record))

    # Uncomment the following line to insert the record into TimescaleDB.
    insert_into_db(enriched_record)


def udp_listener(host='0.0.0.0', port=5514):
    """
    Starts a UDP server that listens for your Syslog messages. Each incoming message
    is expected to be a string representation of a list (as shown in your sample data).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"Listening for Syslog UDP data on {host}:{port}")

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            row_str = data.decode('utf-8').strip()
            process_log_row(row_str)
        except Exception as e:
            print(f"Error processing UDP packet: {e}")


def cleanup_metadata():
    """
    Periodically cleans up stale flows from metadata. Any flow not updated within
    METADATA_TTL_SECONDS is removed.
    """
    while True:
        time.sleep(60)  # Run cleanup every 60 seconds.
        cutoff = datetime.now() - timedelta(seconds=METADATA_TTL_SECONDS)
        with metadata_lock:
            stale_keys = [fid for fid, data in metadata.items() if data["last_seen"] < cutoff]
            for fid in stale_keys:
                del metadata[fid]
                print(f"Cleaned up metadata for flow {fid}")


def start_udp_thread():
    """
    Starts the UDP listener thread.
    """
    udp_thread = threading.Thread(target=udp_listener, args=('0.0.0.0', 5514), daemon=True)
    udp_thread.start()
    return udp_thread


def start_cleanup_thread():
    """
    Starts the metadata cleanup thread.
    """
    cleanup_thread = threading.Thread(target=cleanup_metadata, daemon=True)
    cleanup_thread.start()
    return cleanup_thread
