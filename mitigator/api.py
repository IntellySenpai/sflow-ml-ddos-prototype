import os
import threading
import logging
import json
from flask import Flask, request, jsonify
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

app = Flask(__name__)

EXABGP_PIPE = '/run/exabgp.in'
DEFAULT_TIMEOUT = int(os.getenv("BGP_BLACKHOLE_WITHDRAW_TIMEOUT"))  # Default to 60 seconds if not set
BLACKHOLE_FILE = "/var/log/blackholes.json"

def load_blackholes():
    """Load blackhole routes from a file."""
    if os.path.exists(BLACKHOLE_FILE):
        with open(BLACKHOLE_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_blackholes(data):
    """Save blackhole routes to a file."""
    with open(BLACKHOLE_FILE, "w") as f:
        json.dump(data, f)

def withdraw_route(ip):
    """Withdraw a blackhole route from ExaBGP and remove it from monitoring."""
    if not os.path.exists(EXABGP_PIPE):
        logging.error("ExaBGP pipe not found. Cannot withdraw %s", ip)
        return

    route = f"withdraw route {ip}/32 next-hop self\n"

    try:
        with open(EXABGP_PIPE, "w") as pipe:
            pipe.write(route)
        logging.info("Auto-withdrawn: %s", ip)

        # Remove from blackhole tracking
        blackholes = load_blackholes()
        if ip in blackholes:
            del blackholes[ip]
            save_blackholes(blackholes)

    except Exception as e:
        logging.error("Error withdrawing %s: %s", ip, str(e))

@app.route('/announce', methods=['POST'])
def announce():
    """Announce a blackhole route and schedule auto-withdrawal."""
    data = request.json
    ip = data.get('ip')
    timeout = int(data.get('timeout', DEFAULT_TIMEOUT))
    community = os.getenv("BGP_BLACKHOLE_COMMUNITY")

    if not os.path.exists(EXABGP_PIPE):
        return jsonify({"error": "ExaBGP pipe not found"}), 500

    route = f"announce route {ip}/32 next-hop self community {community}\n"

    try:
        with open(EXABGP_PIPE, "w") as pipe:
            pipe.write(route)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # Calculate expiration timestamp
    expires_at = (datetime.now() + timedelta(seconds=timeout)).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Save blackhole route with expiration time
    blackholes = load_blackholes()
    blackholes[ip] = {"timeout": timeout, "expires_at": expires_at}
    save_blackholes(blackholes)

    # Schedule automatic withdrawal
    timer = threading.Timer(timeout, withdraw_route, args=[ip])
    timer.start()

    logging.info("Announced %s with auto-withdraw in %d seconds (expires at %s)", ip, timeout, expires_at)

    return jsonify({"status": "announced", "route": ip, "timeout": timeout, "expires_at": expires_at})

@app.route('/withdraw', methods=['POST'])
def withdraw():
    """Manually withdraw a blackhole route."""
    data = request.json
    ip = data.get('ip')

    if not os.path.exists(EXABGP_PIPE):
        return jsonify({"error": "ExaBGP pipe not found"}), 500

    withdraw_route(ip)
    return jsonify({"status": "withdrawn", "route": ip})

@app.route('/blackholes', methods=['GET'])
def get_blackholes():
    """Return the currently announced blackhole routes."""
    return jsonify(load_blackholes())

@app.route('/metrics', methods=['GET'])
def metrics():
    """Expose blackhole data for Prometheus in a structured format."""
    blackholes = load_blackholes()
    output = ["# HELP blackhole_route_active 1 if route is active, 0 otherwise",
              "# TYPE blackhole_route_active gauge"]

    for ip, details in blackholes.items():
        timeout = details.get("timeout", 60)  # Default to 60 if missing
        expires_at = details.get("expires_at", "N/A")  # Now correctly stored

        output.append(f'blackhole_route_active{{ip="{ip}", timeout="{timeout}", expires_at="{expires_at}"}} 1')

    return "\n".join(output), 200, {'Content-Type': 'text/plain'}


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
