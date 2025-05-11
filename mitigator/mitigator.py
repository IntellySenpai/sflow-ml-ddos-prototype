import os
import subprocess
from time import sleep
from jinja2 import Template

# Generate exabgp.conf from template
with open("exabgp.conf.j2") as f:
    template = Template(f.read())

config = template.render(
    LOCAL_AS=os.getenv("BGP_LOCAL_AS"),
    PEER_AS=os.getenv("BGP_PEER_AS"),
    ROUTER_ID=os.getenv("BGP_ROUTER_ID"),
    PEERS=os.getenv("BGP_PEERS").split(",")
)

with open("exabgp.conf", "w") as f:
    f.write(config)

# Start ExaBGP
process = subprocess.Popen(['exabgp', 'exabgp.conf'], env=os.environ)

# Wait for ExaBGP to create the named pipe
EXABGP_PIPE = "/run/exabgp.in"
timeout = 10  # Maximum wait time in seconds
elapsed = 0

while not os.path.exists(EXABGP_PIPE) and elapsed < timeout:
    sleep(1)
    elapsed += 1

if not os.path.exists(EXABGP_PIPE):
    print("Error: ExaBGP did not create the named pipe")
    exit(1)

# Keep process running
while True:
    sleep(1)
