import os
import psycopg2
import socket

METADATA_TTL_SECONDS = int(os.environ.get("METADATA_TTL_SECONDS"))


# Timescale connection
conn = psycopg2.connect(
    host=os.getenv("TIMESCALEDB_HOST"),
    database=os.getenv("TIMESCALE_DB"),
    user=os.getenv("TIMESCALE_USER"),
    password=os.getenv("TIMESCALE_PASSWORD")
)

# Header for incoming logs
HEADER = [
    "timestamp", "type", "agent_ip", "inputPort", "outputPort", "src_mac", "dst_mac",
    "ethernet_type", "in_vlan", "out_vlan", "src_ip", "dst_ip", "ip_protocol", "ip_tos",
    "ip_ttl", "udp_src_port_tcp_src_port_icmp_type", "udp_dst_port_tcp_dst_port_icmp_code",
    "tcp_flags", "packet_size", "ip_size", "sampling_rate", "avg_ingress_unicast_pps",
    "avg_egress_unicast_pps", "avg_ingress_multicast_pps", "avg_egress_multicast_pps",
    "avg_ingress_broadcast_pps", "bucket_number_of_packets", "avg_ingress_bytes_per_second",
    "avg_egress_bytes_per_second", "avg_ingress_discards_per_second", "avg_ingress_errors_per_second",
    "avg_ingress_unknown_per_second", "is_public_ip", "is_tcp", "is_udp", "is_icmp", "is_l3_ip_protocol",
    "is_other_l4_protocol", "is_tor_exit_node", "is_user_whitelisted", "is_src_port_well_known",
    "is_dst_port_well_known", "is_chargen", "is_dns", "is_dhcp", "is_http", "is_ntp", "is_netbios",
    "is_snmp", "is_ssdp", "is_ldap", "is_smb", "is_https", "is_memcached", "is_ldaps", "is_tcp_syn",
    "is_tcp_synack", "is_tcp_ack", "is_tcp_rst", "is_tcp_fin", "is_tcp_bogus_flags", "is_icmp_request",
    "is_icmp_echo_reply", "is_icmp_dest_unreachable", "is_icmp_redirect", "is_icmp_time_exceeded",
    "is_icmp_mask_request", "is_icmp_timestamp_request", "abuseipdb_score", "abuseipdb_usage_type",
    "abuseipdb_whitelist", "abuseipdb_tor", "abuseipdb_reports", "total_number_of_packets"
]