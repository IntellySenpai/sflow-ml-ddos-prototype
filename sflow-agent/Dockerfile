FROM rockylinux:9

WORKDIR /root

# Install EPEL repository and necessary packages
RUN dnf install -y epel-release && \
    dnf install -y wget iproute net-tools tcpreplay && \
    dnf clean all

# Download and install hsflowd
RUN wget -O hsflowd.rpm https://github.com/sflow/host-sflow/releases/download/v2.0.53-1/hsflowd-redhat9-2.0.53-1.x86_64.rpm && \
    dnf install -y ./hsflowd.rpm && \
    rm -f hsflowd.rpm

# Download hsflowd configuration and replace existing one \
# Polling 10 and Sampling 500:
RUN wget -O /etc/hsflowd.conf https://gist.githubusercontent.com/IntellySenpai/d80bac66403102262b5304f0443436f2/raw/8f08adc9edeab05aecb892714ddc5b6fa9c1556e/hsflowd.conf
# Polling 5 and Sampling 1000:
# RUN wget -O /etc/hsflowd.conf https://gist.githubusercontent.com/IntellySenpai/6ba5ce733aa20c57e326b3ca9f6b8384/raw/a46a5a6a5390a2fe7ddd6ae79f28ba877d7f38cc/hsflowd.conf
# Polling 10 and Sampling 1000:
# RUN wget -O /etc/hsflowd.conf https://gist.githubusercontent.com/IntellySenpai/b327187bba9dd718aabd9c6694db6f52/raw/d9987893884b174cf67b8d62b8bc5931e3cf64d9/hsflowd.conf
# Polling 5 and Sampling 500:
# RUN wget -O /etc/hsflowd.conf https://gist.githubusercontent.com/IntellySenpai/6301a44a5bc91f868b635cb8bb8f1acf/raw/a39dd491cb6e12e7a5ba6e47e36cd53ab35134aa/hsflowd.conf
# Polling 2 and Sampling 1 - FOR TESTING ONLY!
# RUN wget -O /etc/hsflowd.conf https://gist.githubusercontent.com/IntellySenpai/30cee907a70758b53656103466dba47b/raw/6906b2daea9ece311fa706e1f013ad829ef92b69/hsflowd.conf

# Create pcap directory and download a sample pcap file
RUN mkdir -p /pcap
#RUN mkdir -p /pcap && \
#    wget -O /pcap/amp.TCP.reflection.SYNACK.pcap https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/amp.TCP.reflection.SYNACK.pcap && \
#   wget -O /pcap/amp.TCP.syn.optionallyACK.optionallysamePort.pcapng https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/amp.TCP.syn.optionallyACK.optionallysamePort.pcapng && \
#    wget -O /pcap/amp.UDP.DNSANY.pcap https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/amp.UDP.DNSANY.pcap && \
#    wget -O /pcap/amp.UDP.IOT.port37810.JSON.pcap https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/amp.UDP.IOT.port37810.JSON.pcap
#    wget -O /pcap/amp.UDP.UBNT.src10001.pcapng https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/amp.UDP.UBNT.src10001.pcapng && \
#    wget -O /pcap/amp.UDP.bacnet.IOT.37810.pcapng https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/amp.UDP.bacnet.IOT.37810.pcapng && \
#    wget -O /pcap/amp.UDP.isakmp.pcap https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/amp.UDP.isakmp.pcap && \
#    wget -O /pcap/amp.UDP.manyprotocols.pcapng https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/amp.UDP.manyprotocols.pcapng && \
#    wget -O /pcap/amp.UDP.memcached.ntp.cldap.pcap https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/amp.UDP.memcached.ntp.cldap.pcap && \
#    wget -O /pcap/amp.UDP.snmp.src161.pcapng https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/amp.UDP.snmp.src161.pcapng && \
#    wget -O /pcap/amp.dns.RRSIG.fragmented.pcap https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/amp.dns.RRSIG.fragmented.pcap && \
#    wget -O /pcap/pkt.ICMP.largeempty.pcap https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/pkt.ICMP.largeempty.pcap && \
#    wget -O /pcap/pkt.IPV4.randomprotofield.pcap https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/pkt.IPV4.randomprotofield.pcap && \
#    wget -O /pcap/pkt.TCP.DOMINATE.syn.ecn.cwr.pcapng https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/pkt.TCP.DOMINATE.syn.ecn.cwr.pcapng && \
#    wget -O /pcap/pkt.TCP.synflood.spoofed.pcap https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/pkt.TCP.synflood.spoofed.pcap && \
#    wget -O /pcap/pkt.UDP.fragmented.pcap https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/pkt.UDP.fragmented.pcap && \
#    wget -O /pcap/pkt.UDP.null.pcapng https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/pkt.UDP.null.pcapng && \
#    wget -O /pcap/pkt.UDP.rdm.fixedlength.pcapng https://github.com/StopDDoS/packet-captures/raw/refs/heads/main/pkt.UDP.rdm.fixedlength.pcapng


# Set environment variable for collector IP (default can be overridden at runtime)
ENV COLLECTOR_IP=192.168.1.1

RUN echo XXXXX!

# Start script to update hsflowd.conf and run services
CMD sed -i "s/X.X.X.X/${COLLECTOR_IP}/g" /etc/hsflowd.conf && \
    /usr/sbin/hsflowd && \
#   tcpreplay --intf1=eth0 --pps 10 -v /pcap/*.pcap
#   Play at original speed
   tcpreplay --intf1=eth0 --multiplier=1 -v /pcap/*.pcap
#   Play loop multiple times
#   tcpreplay --intf1=eth0 --loop=1000 --mbps=1000 -v /pcap/*.pcap
#   Play at maximum speed
#   tcpreplay --intf1=eth0 --topspeed --loop=10 -v /pcap/*.pcap
