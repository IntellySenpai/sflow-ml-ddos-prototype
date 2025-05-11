import threading
from datetime import datetime
import os
from external_checks import *
from config import ABUSE_IPDB_API_KEY, DB_PATH
import sqlite3


def parse_timestamp(ts: str) -> datetime:
    """Parse timestamp."""
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def calculate_avg_per_second(val1, val2, delta_time):
    """Calculate average of two values over delta_time seconds."""
    # Ignore counters of value "4294967295".
    if val1 == "4294967295" or val2 == "4294967295":
        return '0'
    return str((int(val2) - int(val1)) / delta_time)


def compute_cntr_metrics(counter1, counter2):
    """Compute CNTR metrics using the values and delta time."""

    # Compute delta time in seconds.
    time1 = parse_timestamp(counter1[0])
    time2 = parse_timestamp(counter2[0])
    delta_time = (time2 - time1).total_seconds()

    # Compute bucket count of packets.
    bucket_number_of_packets = int(counter2[9]) - int(counter1[9])

    metrics = [
        calculate_avg_per_second(counter1[9], counter2[9], delta_time),   # avg_ingress_unicast_pps
        calculate_avg_per_second(counter1[16], counter2[16], delta_time), # avg_egress_unicast_pps
        calculate_avg_per_second(counter1[10], counter2[10], delta_time), # avg_ingress_multicast_pps
        calculate_avg_per_second(counter1[17], counter2[17], delta_time), # avg_egress_multicast_pps
        calculate_avg_per_second(counter1[11], counter2[11], delta_time), # avg_ingress_broadcast_pps
        bucket_number_of_packets,                                          # bucket_number_of_packets
        calculate_avg_per_second(counter1[8], counter2[8], delta_time),   # avg_ingress_bytes_per_second
        calculate_avg_per_second(counter1[15], counter2[15], delta_time), # avg_egress_bytes_per_second
        calculate_avg_per_second(counter1[12], counter2[12], delta_time), # avg_ingress_discards_per_second
        calculate_avg_per_second(counter1[13], counter2[13], delta_time), # avg_ingress_errors_per_second
        calculate_avg_per_second(counter1[14], counter2[14], delta_time), # avg_ingress_unknown_per_second
    ]

    return metrics, bucket_number_of_packets


def enrich_based_on_src_ip(src_ip, flow):
    """Enrich the flow data with IP info, abuse info, and TOR Exit Nodes lists."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # Check AbuseIPDB info
        cursor.execute("""
            SELECT abuseipdb_whitelist, abuseipdb_score, abuseipdb_tor, abuseipdb_reports, abuseipdb_usage_type
            FROM ip_abuse_info WHERE ip = ?
        """, (src_ip,))
        result = cursor.fetchone()
        # If result in the SQLite use it, otherwise make API request.
        if result:
            flow[68] = result[1]  # abuse_score
            flow[69] = result[4]  # abuse_usage_type
            flow[70] = result[0]  # abuse_is_whitelisted
            flow[71] = result[2]  # abuse_is_tor
            flow[72] = result[3]  # abuse_reports
        else:
            abuse_info = query_abuse_ipdb_api(src_ip, ABUSE_IPDB_API_KEY)
            # Save into database
            cursor.execute("""
                INSERT INTO ip_abuse_info (ip, abuseipdb_whitelist, abuseipdb_score, abuseipdb_tor, abuseipdb_reports, abuseipdb_usage_type)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                src_ip,
                abuse_info.get("abuseipdb_whitelist"),
                abuse_info.get("abuseipdb_score"),
                abuse_info.get("abuseipdb_tor"),
                abuse_info.get("abuseipdb_reports"),
                abuse_info.get("abuseipdb_usage_type")
            ))
            conn.commit()

            flow[68] = abuse_info.get("abuseipdb_score")
            flow[69] = abuse_info.get("abuseipdb_usage_type")
            flow[70] = abuse_info.get("abuseipdb_whitelist")
            flow[71] = abuse_info.get("abuseipdb_tor")
            flow[72] = abuse_info.get("abuseipdb_reports")

        # Check TOR Exit Node Info
        cursor.execute("SELECT 1 FROM ip_tor_exit_node_info WHERE ip = ?", (src_ip,))
        result = cursor.fetchone()
        flow[38] = 1 if result else 0

    except sqlite3.Error as e:
        print(f"[ERROR] SQLite error during enrichment for {src_ip}: {e}")
    finally:
        conn.close()


def get_icmp_data(icmp_type, icmp_code, flow):
    """Marks known ICMP-based attacks in flow[61] to flow[67] based on type/code."""

    # Make sure they're integers
    icmp_type = int(icmp_type)
    icmp_code = int(icmp_code)

    # ICMP attack types

    # 61: ICMP Echo Request (Ping flood)
    if icmp_type == 8 and icmp_code == 0:
        flow[61] = 1  # is_icmp_request

    # 62: ICMP Echo Reply (used in some reflective floods)
    if icmp_type == 0 and icmp_code == 0:
        flow[62] = 1  # is_icmp_echo_reply

    # 63: ICMP Destination Unreachable (used in scanning or crafted attacks)
    if icmp_type == 3:
        flow[63] = 1  # is_icmp_dest_unreachable

    # 64: ICMP Redirect (can be used maliciously for MITM)
    if icmp_type == 5:
        flow[64] = 1  # is_icmp_redirect

    # 65: ICMP Time Exceeded (used in traceroute or evasion)
    if icmp_type == 11:
        flow[65] = 1  # is_icmp_time_exceeded

    # 66: ICMP Address Mask Request (very rare, suspicious)
    if icmp_type == 17:
        flow[66] = 1  # is_icmp_mask_request

    # 67: ICMP Timestamp Request (can be abused for reflection)
    if icmp_type == 13:
        flow[67] = 1  # is_icmp_timestamp_request


def check_tcp_udp_ports(port, flow):
    """Check for known DDoS TCP/UDP Ports."""
    port = str(port)

    ddos_ports = {
        "19": 42,     # chargen
        "53": 43,     # DNS
        "67": 44,     # DHCP (server)
        "68": 44,     # DHCP (client)
        "80": 45,     # HTTP
        "123": 46,    # NTP
        "137": 47,    # NetBIOS
        "161": 48,    # SNMP
        "1900": 49,   # SSDP
        "389": 50,    # LDAP
        "445": 51,    # SMB
        "443": 52,    # HTTPS
        "11211": 53,  # Memcached
        "636": 54,     # LDAPS
        "8080": 55,  # Alt HTTP
    }

    if port in ddos_ports:
        flow[ddos_ports[port]] = 1


def are_ports_well_known(src_port, dst_port,flow):
    """Check if ports are well known."""
    if int(src_port) <= 1023:
        flow[40] = 1
    if int(dst_port) <= 1023:
        flow[41] = 1


def parse_tcp_flags(hex_str, flow):
    """Parse TCP Flags."""
    # Remove "0x" prefix and convert to integer
    flags_int = int(hex_str, 16)

    # Flag bits
    FIN = 1 << 0
    SYN = 1 << 1
    RST = 1 << 2
    PSH = 1 << 3
    ACK = 1 << 4
    URG = 1 << 5
    ECE = 1 << 6
    CWR = 1 << 7

    # Set specific flow flags based on combinations
    if flags_int & SYN and not flags_int & ACK:
        flow[55] = 1  # is_tcp_syn
    elif flags_int & SYN and flags_int & ACK:
        flow[56] = 1  # is_tcp_synack
    elif flags_int & ACK and not flags_int & SYN:
        flow[57] = 1  # is_tcp_ack

    if flags_int & RST:
        flow[58] = 1  # is_tcp_rst
    if flags_int & FIN:
        flow[59] = 1  # is_tcp_fin

    # Detect bogus/rare/unusual flag combinations
    valid_combinations = [
        SYN,
        SYN | ACK,
        ACK,
        FIN,
        RST,
        FIN | ACK,
        PSH | ACK,
        RST | ACK
    ]

    if flags_int not in valid_combinations:
        flow[60] = 1  # is_tcp_bogus_flags