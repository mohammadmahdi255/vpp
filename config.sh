#!/bin/bash

# set -e

# file_name="ipv46.pcap"
# file_dir="/root/projects/bordar"

# MainInputLinkName="input"
# PeerMainInputLinkName="input-p"

# ip link delete ${MainInputLinkName} || true

# ip link add ${MainInputLinkName} type veth peer ${PeerMainInputLinkName}

# ip link set dev ${MainInputLinkName} mtu 9000
# ip link set dev ${PeerMainInputLinkName} mtu 9000

# ip link set dev ${MainInputLinkName} up
# ip link set dev ${PeerMainInputLinkName} up

# ip link set promisc on dev ${MainInputLinkName}
# ip link set promisc on dev ${PeerMainInputLinkName}

# vppctl create host-interface name ${MainInputLinkName}
# vppctl set interface state host-${MainInputLinkName} up
# vppctl set interface promisc on host-${MainInputLinkName}
# vppctl set interface mtu 9000 host-${MainInputLinkName}

# # vppctl clear trace
# # vppctl trace add af-packet-input 100

# vppctl set interface feature host-${MainInputLinkName} ethernet-detunnel arc device-input

# echo "send traffic by: tcpreplay -i ${PeerMainInputLinkName} ${file_dir}/${file_name}"

# /home/mahdi255/nemati/pcap/hp-erm-1.cap
# /home/mahdi255/nemati/pcap/ipv4frags.pcap
# /home/mahdi255/nemati/pcap/vlan.pcap

vppctl packet-generator new \
    limit 49546457546 \
    name fragtest \
    pcap /home/mahdi255/nemati/pcap/ipv4frags.pcap \
    node ethernet-detunnel

vppctl packet-generator enable
# vppctl packet-generator disable  # to stop
