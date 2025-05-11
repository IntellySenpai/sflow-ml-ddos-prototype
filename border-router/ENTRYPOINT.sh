#!/usr/bin/env bash

set -e

for DAEMON in $FRR_DAEMONS; do
    if [ -s "/usr/lib/frr/${DAEMON}" ]; then
        touch /etc/frr/${DAEMON}.conf
        sed -i "s/^${DAEMON}=no/${DAEMON}=yes/" /etc/frr/daemons
    else
        echo "No such daemon: ${DAEMON}"
    fi

    # Special handling for BGP config
    if [ "$DAEMON" == "bgpd" ]; then
        cat <<EOF > /etc/frr/bgpd.conf
!
! Zebra configuration for peering with ExaBGP
!   $(date +%Y/%m/%d)
!
frr version 2.0
frr defaults traditional
!
router bgp ${BGP_LOCAL_AS}
 bgp router-id ${BGP_ROUTER_ID}
 neighbor ${EXABGP_IP} remote-as ${BGP_LOCAL_AS}
 vnc defaults
  response-lifetime 3600
  exit-vnc
!
line vty
!
EOF
    fi
done

# Restart FRR with new configuration
service frr restart > /dev/null 2>&1

# Keep container alive for debugging or exec access
exec bash

# Optional: cleanup on exit (won't be reached with exec bash)
service frr stop > /dev/null 2>&1
