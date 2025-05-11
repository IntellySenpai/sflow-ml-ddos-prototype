import re
import requests
import os
import threading
import time
import schedule
import ipaddress

# Global flag for abuse IPDB rate limit
abuse_ipdb_limit_reached = False


def is_private_ipv4(ip):
    """Check if IP Address is private using RFC1918."""
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        return ip_obj.is_private
    except ipaddress.AddressValueError:
        return False  # Not a valid IPv4 address


def is_valid_ipv4(ip):
    """Check if a string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def map_abuseipdb_usage_type_to_int(usage_type_str):
    """Map AbuseIPDB usage type string to a numerical value."""
    usage_type_map = {
        "Commercial": "1",
        "Organization": "2",
        "Government": "3",
        "Military": "4",
        "University/College/School": "5",
        "Library": "6",
        "Content Delivery Network": "7",
        "Fixed Line ISP": "8",
        "Mobile ISP": "9",
        "Data Center/Web Hosting/Transit": "10",
        "Search Engine Spider": "11",
        "Reserved": "12"
    }

    return usage_type_map.get(usage_type_str, "0")


def query_abuse_ipdb_api(src_ip, token):
    """Query AbuseIPDB API with rate-limit handling. Requires Access Token"""
    global abuse_ipdb_limit_reached

    if not is_valid_ipv4(src_ip):
        raise ValueError("Invalid IPv4 address format")

    if abuse_ipdb_limit_reached:
        # Skip request if rate-limited
        return {
            "ip": src_ip,
            "abuseipdb_whitelist": 0,
            "abuseipdb_score": 0,
            "abuseipdb_tor": 0,
            "abuseipdb_reports": 0,
            "abuseipdb_usage_type": 0
        }

    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': src_ip,
        'maxAgeInDays': '365'
    }
    headers = {
        'Accept': 'application/json',
        'Key': token
    }

    response = requests.get(url, headers=headers, params=querystring)

    # Handle rate limit response
    if response.status_code == 429:
        abuse_ipdb_limit_reached = True
        retry_after = int(response.headers.get('Retry-After', '60'))  # default to 60 if missing
        threading.Timer(retry_after, reset_abuse_ipdb_flag).start()
        return {
            "ip": src_ip,
            "abuseipdb_whitelist": 0,
            "abuseipdb_score": 0,
            "abuseipdb_tor": 0,
            "abuseipdb_reports": 0,
            "abuseipdb_usage_type": 0
        }

    data = response.json().get("data", {})

    return {
        "ip": src_ip,
        "abuseipdb_whitelist": int(data.get("isWhitelisted")),
        "abuseipdb_score": int(data.get("abuseConfidenceScore")),
        "abuseipdb_tor": int(data.get("isTor")),
        "abuseipdb_reports": int(data.get("totalReports")),
        "abuseipdb_usage_type": map_abuseipdb_usage_type_to_int(data.get("usageType"))
    }

